import asyncio
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest

from agentprov.browser_custody import NativeCustody, _fields


BOOT = "12345678-1234-1234-1234-123456789abc"


@unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux pidfd required")
class CustodyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.data = root / "data"
        self.data.mkdir()
        self.output = root / "operator"
        self.output.mkdir(mode=0o700)
        self.child = subprocess.Popen(["sleep", "60"])
        self.addCleanup(self.stop_child)
        self.c = NativeCustody(self.output, self.data, "run")
        self.c.pid, self.c.pidfd = self.child.pid, os.pidfd_open(self.child.pid)
        self.addCleanup(self.c.close)
        self.c.output = self.output
        self.c.host_id, self.c.boot_id = "a" * 32, BOOT
        self.c.pid_namespace = os.readlink("/proc/self/ns/pid")
        self.c.scope = {"browser_id": "owned-browser", "context_id": "context-1"}
        self.c.fence_ns = time.monotonic_ns()
        async def send(method):
            self.assertEqual(method, "SystemInfo.getProcessInfo")
            return {"processInfo": [{"type": "browser", "id": self.child.pid}]}
        self.browser = SimpleNamespace(capture=SimpleNamespace(scope=dict(self.c.scope)), cdp=SimpleNamespace(send=send))
        with closing(sqlite3.connect(self.data / "agentprov.db")) as db:
            db.execute("CREATE TABLE events(id TEXT, raw_event_id TEXT, run_id TEXT, pid INT, source TEXT, payload TEXT,event_type TEXT)")
            db.commit()

    def stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.wait(timeout=5)

    def event(self, *, pid=None, changes=None, run="run", wrapper=None, kind="file_open", nested=False):
        pid = self.child.pid if pid is None else pid
        raw = {"host_id": self.c.host_id, "boot_id": BOOT, "process_start_ns": "100",
               "process_instance_id": f"{BOOT}:{pid}:100", "monotonic_ns": str(time.monotonic_ns()),
               "procfs_pid": self.child.pid, "procfs_pid_namespace": self.c.pid_namespace}
        raw.update(changes or {})
        body = {"runtime_process_identity": "agentprov.runtime_process/v3", "payload": {"raw": raw} if nested else raw}
        body.update(wrapper or {})
        with closing(sqlite3.connect(self.data / "agentprov.db")) as db:
            db.execute("INSERT INTO events VALUES ('observed','raw',?,?,'agentprov_ebpf',?,?)", (run, pid, json.dumps(body), kind))
            db.commit()

    async def test_live_observation_preserves_kernel_pid_in_translated_namespace(self):
        self.event(pid=987654, nested=True)
        self.assertTrue(await self.c.observe(self.browser))
        self.assertEqual(self.c.identity["pid"], 987654)
        witness = json.loads((self.output / "launch-witness.json").read_text())
        self.assertEqual(witness["procfs_pid"], self.child.pid)
        self.assertEqual(witness["native_event"]["id"], "observed")

    async def test_old_wrong_host_namespace_and_other_run_are_not_authority(self):
        for changes, run in [({"monotonic_ns": str(self.c.fence_ns - 1)}, "run"),
                             ({"host_id": "b" * 32}, "run"),
                             ({"procfs_pid_namespace": "pid:[different]"}, "run"),
                             ({}, "another-run")]:
            self.event(changes=changes, run=run)
        self.assertFalse(await self.c.observe(self.browser))
        self.assertFalse((self.output / "launch-witness.json").exists())

    async def test_exited_pidfd_rejects_a_replayed_numeric_pid(self):
        self.event()
        self.stop_child()
        with self.assertRaisesRegex(RuntimeError, "exited"):
            await self.c.observe(self.browser)

    async def test_changed_cdp_scope_rejects_old_process(self):
        self.event()
        self.browser.capture.scope["context_id"] = "context-2"
        with self.assertRaisesRegex(RuntimeError, "scope changed"):
            await self.c.observe(self.browser)

    async def test_conflicting_nested_host_never_selects_convenient_layer(self):
        self.event(wrapper={"host_id": "b" * 32})
        self.assertFalse(await self.c.observe(self.browser))

    async def test_multiple_births_in_live_window_rejected(self):
        self.event()
        self.event(changes={"process_start_ns": "101", "process_instance_id": f"{BOOT}:{self.child.pid}:101"})
        with self.assertRaisesRegex(RuntimeError, "conflicting native birth"):
            await self.c.observe(self.browser)

    async def test_owned_launch_exec_is_usable_before_cdp_attach(self):
        self.c.launch_marker = "apb-unique-owned-launch"
        self.event(kind="execve", changes={"monotonic_ns": str(self.c.fence_ns - 1), "argv": [self.c.launch_marker]})
        self.assertTrue(await self.c.observe(self.browser))
        self.assertEqual(self.c.witness["basis"], "owned_launcher_cdp_pidfd_and_kernel_exec")

    async def test_other_launch_marker_is_not_a_birth_witness(self):
        self.c.launch_marker = "apb-this-launch"
        self.event(kind="execve", changes={"monotonic_ns": str(self.c.fence_ns - 1), "argv": ["apb-other-launch"]})
        self.assertFalse(await self.c.observe(self.browser))

    async def test_real_wrapper_preserves_pid_arguments_and_short_launch_marker(self):
        capture = self.data.parent / "capture"
        capture.mkdir()
        launcher = self.c.prepare(SimpleNamespace(path=capture / "events.jsonl"), "/bin/sleep")
        process = subprocess.Popen([launcher, "5"])
        try:
            for _ in range(100):
                command = Path(f"/proc/{process.pid}/cmdline").read_bytes().split(b"\0")
                if command[0] == self.c.launch_marker.encode():
                    break
                await asyncio.sleep(.01)
            self.assertLessEqual(len(command[0]), 31)
            self.assertEqual(command[:2], [self.c.launch_marker.encode(), b"5"])
            receipt = json.loads(self.c.launch_receipt.read_text())
            self.assertEqual(receipt["pid"], process.pid)
            self.assertEqual(receipt["start_ticks"], Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
        finally:
            process.terminate()
            process.wait(timeout=5)


class EnvelopeTests(unittest.TestCase):
    def test_conflicting_pid_namespace(self):
        with self.assertRaises(ValueError):
            _fields({"procfs_pid_namespace": "pid:[1]", "raw": {"procfs_pid_namespace": "pid:[2]"}})


if __name__ == "__main__":
    unittest.main()
