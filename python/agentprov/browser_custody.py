"""Operator-side custody for the Chromium instance launched by BrowserRuntime.

The owned launcher and live CDP connection select the browser process. A Linux
pidfd keeps that selection tied to its lifetime while the matching kernel exec
or a later observation supplies the exact nanosecond birth identity.
"""

import asyncio
import base64
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import select
import sqlite3
import stat
import sys
import time
import uuid
from urllib.parse import quote

from .browser_receipts import MAX_HISTORY_BYTES, digest, private_directory


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _write(path, value):
    raw = _bytes(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fields(body):
    """Reject conflicting envelope identities instead of picking one layer."""
    values = {}
    for _ in range(8):
        if not isinstance(body, dict):
            raise ValueError("invalid native event envelope")
        for key in ("host_id", "boot_id", "process_instance_id", "process_start_ns", "monotonic_ns",
                    "procfs_pid", "procfs_pid_namespace", "argv"):
            value = body.get(key)
            if value is not None:
                valid = (isinstance(value, list) and all(isinstance(v, str) for v in value)) if key == "argv" else (
                    type(value) is int if key == "procfs_pid" else isinstance(value, str))
                if not valid or key in values and values[key] != value:
                    raise ValueError("conflicting native event identity")
                values[key] = value
        nested = body.get("payload", body.get("raw"))
        if nested is None:
            return values
        body = nested
    raise ValueError("native event envelope depth exceeded")


class NativeCustody:
    """Opt-in launcher authority; one instance accompanies one owned Browser."""

    def __init__(self, directory, data_dir, run_id):
        self.directory, self.data_dir = Path(directory).absolute(), Path(data_dir).resolve(strict=True)
        if not run_id or not isinstance(run_id, str) or len(run_id.encode()) > 512:
            raise ValueError("native custody requires an existing run")
        self.run_id, self.pidfd, self.scope, self.identity = run_id, None, None, None
        self.witness, self.ready = None, False
        self.observation_lock = asyncio.Lock()
        self.launch_path = self.launch_receipt = None
        self.launch_marker = None
        self.executable_sha256 = None

    def prepare(self, browser, executable):
        """A unique, operator-owned exec path supplies a kernel launch witness.

        The wrapper writes its own PID once and execs Chromium without forking.
        A fresh 128-bit argv[0] marker fits the Sensor's 31-byte argument limit,
        even when the executable and operator directory have long paths.
        The marker appears in native exec argv even when the browser is idle
        after CDP attaches. Nothing is read from a transcript or an imported log.
        """
        if not hasattr(os, "pidfd_open"):
            raise RuntimeError("native Browser custody requires Linux pidfd support")
        private_directory(self.directory, create=True)
        operator = self.directory.resolve(strict=True)
        capture = browser.path.parent.resolve(strict=True)
        if any(operator == p or operator.is_relative_to(p) or p.is_relative_to(operator)
               for p in (capture, self.data_dir)):
            raise ValueError("custody authority must be separate from capture and data directories")
        launch = operator / ("launch-" + str(uuid.uuid4()))
        launch.mkdir(mode=0o700)
        self.launch_path, self.launch_receipt = launch / "chromium", launch / "process.json"
        executable = str(Path(executable).resolve(strict=True))
        self.launch_marker = "apb-" + base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
        hasher = hashlib.sha256()
        with open(executable, "rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                hasher.update(block)
        self.executable_sha256 = hasher.hexdigest()
        code = ("#!" + sys.executable + "\nimport os,sys,json\n"
                "os.umask(0o077)\n"
                "pid=os.getpid()\n"
                "start=open('/proc/self/stat').read().rsplit(')',1)[1].split()[19]\n"
                "with open(" + repr(str(self.launch_receipt)) + ", 'x') as f:\n"
                " json.dump({'pid':pid,'start_ticks':start},f);f.flush();os.fsync(f.fileno())\n"
                "os.execv(" + repr(executable) + ", [" + repr(self.launch_marker) + "] + sys.argv[1:])\n")
        with self.launch_path.open("x") as stream:
            stream.write(code)
            os.fchmod(stream.fileno(), 0o700)
            stream.flush()
            os.fsync(stream.fileno())
        return str(self.launch_path)

    async def start(self, browser):
        if not hasattr(os, "pidfd_open") or not Path("/proc/sys/kernel/random/boot_id").is_file():
            raise RuntimeError("native Browser custody requires Linux pidfd support")
        capture = browser.path.parent.resolve(strict=True)
        private_directory(self.directory, create=True)
        operator = self.directory.resolve(strict=True)
        if any(operator == p or operator.is_relative_to(p) or p.is_relative_to(operator)
               for p in (capture, self.data_dir)):
            raise ValueError("custody authority must be separate from capture and data directories")
        self.scope = dict(browser.capture.scope)
        if str(uuid.UUID(self.scope["browser_id"])) != self.scope["browser_id"]:
            raise ValueError("owned browser identifier is not canonical")
        self.output = operator / self.scope["browser_id"]
        self.output.mkdir(mode=0o700)
        try:
            self.host_id = Path("/proc/1/root/etc/machine-id").read_text().strip().lower()
        except PermissionError:
            # Unprivileged launchers cannot traverse PID 1's root. This value
            # still has to match the collector's host ID and current boot.
            self.host_id = Path("/etc/machine-id").read_text().strip().lower()
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.pid_namespace = os.readlink("/proc/self/ns/pid")
        if (len(self.host_id) != 32 or self.host_id == "0" * 32 or
                any(c not in "0123456789abcdef" for c in self.host_id) or
                str(uuid.UUID(self.boot_id)) != self.boot_id):
            raise RuntimeError("collector host identity unavailable")
        self.pid = await self._browser_pid(browser)
        self.pidfd = os.pidfd_open(self.pid)
        # The second control-plane query is after pidfd acquisition. A process
        # that exited/reused its numeric PID cannot pass the lifetime check.
        if await self._browser_pid(browser) != self.pid or not self._alive():
            self.close()
            raise RuntimeError("owned browser lifetime changed during binding")
        if self.launch_receipt:
            launched = json.loads(self.launch_receipt.read_text())
            current_ticks = Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
            if launched != {"pid": self.pid, "start_ticks": current_ticks}:
                raise RuntimeError("owned launcher and CDP process identities differ")
        self.fence_ns = time.monotonic_ns()
        self.ready = True
        _write(self.output / "launch-start.json", {"scope": self.scope, "run_id": self.run_id,
               "procfs_pid": self.pid, "procfs_pid_namespace": self.pid_namespace,
               "host_id": self.host_id, "boot_id": self.boot_id, "opened_monotonic_ns": str(self.fence_ns),
               "launch_path": str(self.launch_path) if self.launch_path else None,
               "launch_marker": self.launch_marker, "executable_sha256": self.executable_sha256})

    async def _browser_pid(self, browser):
        if browser.capture.scope != self.scope:
            raise RuntimeError("Browser scope changed during custody")
        info = await browser.cdp.send("SystemInfo.getProcessInfo")
        processes = info.get("processInfo", [])
        if not isinstance(processes, list) or len(processes) > 1024:
            raise RuntimeError("browser process inventory exceeded limit")
        roots = [p.get("id") for p in processes if p.get("type") == "browser"]
        if len(roots) != 1 or type(roots[0]) is not int or roots[0] <= 0:
            raise RuntimeError("owned browser process identity unavailable")
        return roots[0]

    def _alive(self):
        if self.pidfd is None:
            return False
        poller = select.poll()
        poller.register(self.pidfd, select.POLLIN)
        return not poller.poll(0)

    async def observe(self, browser):
        # Concurrent tab operations may return from CDP together. Publish the
        # single durable witness before another observer reuses its identity.
        async with self.observation_lock:
            return await self._observe(browser)

    async def _observe(self, browser):
        if self.identity:
            return True
        if not self._alive() or await self._browser_pid(browser) != self.pid:
            raise RuntimeError("owned browser exited before native identity was recorded")
        now = time.monotonic_ns()
        uri = "file:" + quote(str(self.data_dir / "agentprov.db")) + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            rows = db.execute("SELECT id,raw_event_id,pid,payload,event_type FROM events WHERE run_id=? "
                              "AND source='agentprov_ebpf' AND (pid=? OR json_extract(payload,'$.procfs_pid')=? "
                              "OR json_extract(payload,'$.payload.procfs_pid')=? OR json_extract(payload,'$.raw.procfs_pid')=? "
                              "OR json_extract(payload,'$.payload.raw.procfs_pid')=?) "
                              "ORDER BY rowid DESC LIMIT 4097", (self.run_id, self.pid, self.pid, self.pid, self.pid, self.pid)).fetchall()
        if len(rows) > 4096 or sum(len(r[3]) for r in rows) > 32 << 20:
            raise RuntimeError("native Browser identity lookup exceeded limit")
        matches = {}
        for event_id, raw_id, native_pid, payload, kind in rows:
            body = json.loads(payload)
            if not raw_id or body.get("runtime_process_identity") != "agentprov.runtime_process/v3":
                continue
            try:
                f = _fields(body)
                at, born = int(f["monotonic_ns"]), int(f["process_start_ns"])
                instance = f"{self.boot_id}:{native_pid}:{born}"
                launched_exec = (kind == "execve" and self.launch_marker is not None and
                                 (f.get("argv") or [None])[0] == self.launch_marker)
                if (f["host_id"] == self.host_id and f["boot_id"] == self.boot_id and
                        f["procfs_pid"] == self.pid and f["procfs_pid_namespace"] == self.pid_namespace and
                        f["process_instance_id"] == instance and 0 < born <= at <= now and born <= self.fence_ns and
                        (at >= self.fence_ns or launched_exec)):
                    matches[instance] = {"id": event_id, "raw_event_id": raw_id, "monotonic_ns": str(at),
                                         "pid": native_pid, "owned_launch_exec": launched_exec}
            except (ValueError, KeyError):
                continue
        if not self._alive():
            raise RuntimeError("owned browser exited while resolving native identity")
        if len(matches) > 1:
            raise RuntimeError("conflicting native birth identities for one live browser")
        if not matches:
            return False
        instance, event = next(iter(matches.items()))
        identity = {"role": "browser", "host_id": self.host_id, "pid": event["pid"],
                    "process_instance_id": instance}
        witness = {"schema_version": "agentprovenance.browser_launch_witness/v1", "scope": self.scope,
                        "run_id": self.run_id, **identity,
                        "basis": "owned_launcher_cdp_pidfd_and_kernel_exec" if event["owned_launch_exec"] else "owned_cdp_pidfd_and_live_kernel_observation",
                        "procfs_pid": self.pid, "procfs_pid_namespace": self.pid_namespace,
                        "opened_monotonic_ns": str(self.fence_ns), "checked_monotonic_ns": str(now),
                        "launch_marker": self.launch_marker, "executable_sha256": self.executable_sha256,
                        "native_event": event}
        _write(self.output / "launch-witness.json", witness)
        self.identity, self.witness = identity, witness
        return True

    def seal(self, runtime):
        """Seal this launch's closed journal; never upgrade earlier generations."""
        if not self.ready:
            return
        receipts = runtime.receipts
        receipts.refresh()
        logs = [(name, log) for name, log in receipts.logs.items() if log["scope"] == self.scope]
        if receipts.gap or len(logs) != 1:
            raise RuntimeError("owned capture cannot be sealed")
        name, log = logs[0]
        if log["corrupt"] or log["partial"]:
            raise RuntimeError("owned capture journal is corrupt or incomplete")
        path = runtime.capture_dir / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_HISTORY_BYTES:
                raise RuntimeError("unsafe owned capture journal")
            raw = stream.read(MAX_HISTORY_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (after.st_mtime_ns, after.st_ctime_ns, after.st_size):
            raise RuntimeError("owned capture changed while sealing")
        if not raw.endswith(b"\n") or len(raw) != log["offset"]:
            raise RuntimeError("owned capture prefix changed")
        values = [receipts.result(op)["browser_receipt"] for op in log["operations"]
                  if log["operations"][op]["accept"] is not None]
        if not values:
            raise RuntimeError("owned capture has no accepted operations")
        bridge_id = "agentprov-owned-browser/v1"
        config_digest = digest({"bridge": bridge_id, "placement": runtime.browser.placement,
                                "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                "executable_sha256": self.executable_sha256,
                                "run_id": self.run_id})
        manifest = {"schema_version": "agentprovenance.browser_owned_capture/v1", "run_id": self.run_id,
                    "placement": runtime.browser.placement, "bridge_id": bridge_id, "bridge_config_digest": config_digest,
                    "logs": [{"name": name, "scope": self.scope, "prefix_bytes": len(raw),
                              "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}]}
        manifest_name = "owned-" + self.scope["browser_id"] + ".json"
        pin = _write(runtime.capture_dir / manifest_name, manifest)
        receipt_path = self.output / "receipts.json"
        _write(receipt_path, values)
        config = {"directory": str(runtime.capture_dir), "manifest_name": manifest_name, "manifest_sha256": pin,
                  "run_id": self.run_id, "placement": runtime.browser.placement, "bridge_id": bridge_id,
                  "bridge_config_digest": config_digest}
        config_path = self.output / "browser-import.json"
        _write(config_path, config)
        report = {"native": "supported" if self.identity else "unresolved", "scope": self.scope,
                  "capture_config": str(config_path), "receipts": str(receipt_path),
                  "gap": None if self.identity else "live_native_process_identity_missing",
                  "diagnostic": runtime.custody_error}
        if self.identity:
            custody = {"schema_version": "agentprovenance.browser_runtime_custody/v1",
                       "capture_config": str(config_path), "receipts": str(receipt_path), "run_id": self.run_id,
                       "manifest_sha256": pin, "bridge_id": bridge_id, "bridge_config_digest": config_digest,
                       "mappings": [{"scope": self.scope, "receipt_digest": values[0]["digest"], **self.identity}]}
            _write(self.output / "browser-runtime.json", custody)
            report["runtime_config"] = str(self.output / "browser-runtime.json")
        _write(self.output / "report.json", report)

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
