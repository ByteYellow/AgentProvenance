"""Optional live kernel checks; install python/notebook-requirements.txt first."""

import asyncio
import importlib.util
import json
import pathlib
import tempfile
import unittest

from agentprov.notebook_mcp import NotebookRuntime


@unittest.skipUnless(importlib.util.find_spec("jupyter_client") and importlib.util.find_spec("ipykernel"), "optional Jupyter dependencies absent")
class NotebookRuntimeLiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_persistent_kernel_late_output_timeout_and_restart(self):
        with tempfile.TemporaryDirectory() as root:
            work = pathlib.Path(root) / "work"
            work.mkdir()
            placement = {k: k for k in ("producer_id", "namespace", "instance_id", "generation", "notebook_id")}
            runtime = NotebookRuntime(work, pathlib.Path(root) / "capture", placement)
            try:
                await runtime.start()
                first = await runtime.execute("import threading, time\nx = 42\nthreading.Thread(target=lambda: (time.sleep(0.6), print('LATE_A', flush=True)), daemon=True).start()")
                self.assertEqual(first["execution_status"], "ok")
                second = await runtime.execute("assert x == 42\nprint('SECOND')")
                self.assertEqual(second["execution_status"], "ok")
                timeout = await runtime.execute("from pathlib import Path\nPath('once').write_text('one')\ntime.sleep(0.5)", 0.1)
                self.assertEqual(timeout["execution_status"], "unknown")
                await asyncio.sleep(0.8)
                self.assertEqual(runtime.result(timeout["notebook_request"]["message_id"])["execution_status"], "ok")
                late = runtime.result(first["notebook_request"]["message_id"])
                self.assertTrue(any("LATE_A" in o["text"] for o in late["outputs"]))
                restarted = await runtime.restart()
                self.assertNotEqual(restarted["scope"]["kernel_session_id"], first["notebook_request"]["scope"]["kernel_session_id"])
                fresh = await runtime.execute("assert 'x' not in globals()")
                self.assertEqual(fresh["execution_status"], "ok")
            finally:
                await runtime.close()
            rows = [json.loads(line) for p in (pathlib.Path(root) / "capture").glob("*.jsonl") for line in p.read_text().splitlines()]
            self.assertEqual(sum(r.get("direction") == "send" for r in rows), 4)
            self.assertEqual(sum(r.get("type") == "notebook_session" for r in rows), 2)
            self.assertEqual((work / "once").read_text(), "one")


if __name__ == "__main__":
    unittest.main()
