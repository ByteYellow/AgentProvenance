import asyncio
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentprov.browser_mcp import BrowserRuntime, MAX_OUTPUT_BYTES


class FakeBrowser:
    def __init__(self):
        self.capture = SimpleNamespace(scope={k: k for k in (
            "producer_id", "namespace", "instance_id", "generation", "browser_id", "context_id")}, stopped=False)
        self.pages, self.first_page, self.failure = {"a": None, "b": None}, "a", None
        self.sent, self.gate, self.error = [], asyncio.Event(), False

    async def operation(self, page, action, value, *, operation_id):
        self.sent.append((page, action, operation_id))
        await self.gate.wait()
        if self.error:
            raise RuntimeError("private browser exception")
        return {"text": "x" * (MAX_OUTPUT_BYTES + 1), "unselected": "PRIVATE"}

    async def close(self):
        self.capture.stopped = True


class BrowserMCPTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        placement = {k: k for k in ("producer_id", "namespace", "instance_id", "generation")}
        self.runtime = BrowserRuntime(Path(self.temp.name) / "capture", placement)
        self.runtime.browser = FakeBrowser()
        self.addAsyncCleanup(self.runtime.close)

    async def test_timeout_poll_preserves_one_operation(self):
        result = await self.runtime.execute("a", "click", "#once", .1)
        self.assertEqual(result["waiting_state"], "pending")
        self.assertEqual(result["execution_status"], "unknown")
        op = result["browser_operation"]["operation_id"]
        for _ in range(3):
            self.assertEqual(self.runtime.result(op)["operation"], "read")
        self.runtime.browser.gate.set()
        await self.runtime.requests[op]["task"]
        result = self.runtime.result(op)
        self.assertEqual(result["execution_status"], "ok")
        self.assertEqual(result["waiting_state"], "settled")
        self.assertEqual(len(self.runtime.browser.sent), 1)
        self.assertTrue(result["output_truncated"])
        self.assertEqual(len(result["output"]["text"]), MAX_OUTPUT_BYTES)
        self.assertNotIn("unselected", result["output"])
        result["browser_operation"]["scope"]["generation"] = "changed"
        self.assertEqual(self.runtime.result(op)["browser_operation"]["scope"]["generation"], "generation")

    async def test_cancelled_wait_does_not_cancel_execution(self):
        waiting = asyncio.create_task(self.runtime.execute("a", "click", "#once"))
        await asyncio.sleep(0)
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        self.runtime.browser.gate.set()
        request = next(iter(self.runtime.requests.values()))
        await request["task"]
        self.assertEqual(request["status"], "ok")
        self.assertEqual(len(self.runtime.browser.sent), 1)

    async def test_parallel_pages_and_pending_budget(self):
        with patch("agentprov.browser_mcp.MAX_PENDING", 2):
            a, b = await asyncio.gather(self.runtime.execute("a", "click", "#once", .1),
                                       self.runtime.execute("b", "click", "#once", .1))
            self.assertNotEqual(a["browser_operation"]["operation_id"], b["browser_operation"]["operation_id"])
            self.assertEqual({x[0] for x in self.runtime.browser.sent}, {"a", "b"})
            with self.assertRaises(RuntimeError):
                await self.runtime.execute("a", "read_text")

    async def test_failure_stays_unknown_and_capture_failure_blocks_next(self):
        self.runtime.browser.error = True
        self.runtime.browser.gate.set()
        result = await self.runtime.execute("a", "click", "#once")
        self.assertEqual(result["execution_status"], "unknown")
        self.assertEqual(result["execution_reason"], "operation_incomplete")
        self.runtime.browser.failure = "capture_failed"
        self.assertEqual(self.runtime.result(result["browser_operation"]["operation_id"])["capture_status"], "partial")
        with self.assertRaises(RuntimeError):
            await self.runtime.execute("a", "click", "#once")
        self.assertEqual(len(self.runtime.browser.sent), 1)

    async def test_invalid_input_does_not_execute(self):
        for page, action, value, timeout in (("missing", "click", "x", 1), ("a", "eval", "x", 1),
                ("a", "navigate", "file:///private", 1), ("a", "click", "x" * 16385, 1),
                ("a", "click", "x", 0), ("a", "click", "x", 61), ("a", "click", "x", float("nan"))):
            with self.assertRaises(ValueError):
                await self.runtime.execute(page, action, value, timeout)
        self.assertEqual(self.runtime.browser.sent, [])
        with self.assertRaises(ValueError):
            self.runtime.result("absent")


if __name__ == "__main__":
    unittest.main()
