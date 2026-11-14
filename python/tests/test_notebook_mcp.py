import asyncio
import pathlib
import tempfile
import unittest

from agentprov.notebook_mcp import MAX_OUTPUT_BYTES, NotebookRuntime


class FakeClient:
    def __init__(self):
        self.session = self.shell_channel = self
        self.sent = []

    def msg(self, kind, content):
        return {"header": {"session": "frontend", "msg_id": "r" + str(len(self.sent)),
                           "msg_type": kind}, "content": content}

    def send(self, message):
        self.sent.append(message)


class FakeRecorder:
    def __init__(self, fail=False):
        self.fail, self.messages = fail, []

    def record(self, channel, direction, message):
        if self.fail:
            raise OSError("fixture disk error")
        self.messages.append(message)


class NotebookMCPTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        placement = {k: k for k in ("producer_id", "namespace", "instance_id", "generation", "notebook_id")}
        self.runtime = NotebookRuntime(self.temp.name, pathlib.Path(self.temp.name) / "capture", placement)
        self.runtime.scope = {**placement, "kernel_id": "kernel", "kernel_session_id": "kernel-session"}
        self.runtime.client, self.runtime.recorder = FakeClient(), FakeRecorder()

    async def test_timeout_queries_do_not_repeat_side_effects(self):
        result = await self.runtime.execute("counter += 1", 0.1)
        self.assertEqual(result["execution_status"], "unknown")
        self.assertEqual(result["notebook_request"]["message_id"], "r0")
        for _ in range(3):
            self.assertEqual(self.runtime.result("r0")["operation"], "read")
        self.assertEqual(len(self.runtime.client.sent), 1)
        self.assertEqual(len(self.runtime.recorder.messages), 1)

    async def test_cancelled_wait_still_keeps_request(self):
        task = asyncio.create_task(self.runtime.execute("side_effect()"))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.runtime.result("r0")["execution_status"], "unknown")
        self.assertEqual(len(self.runtime.client.sent), 1)

    async def test_record_failure_is_unknown_and_blocks_new_execution(self):
        self.runtime.recorder.fail = True
        result = await self.runtime.execute("side_effect()")
        self.assertEqual(result["execution_status"], "unknown")
        self.assertEqual(result["capture_reason"], "request_send_or_record_failed")
        with self.assertRaises(RuntimeError):
            await self.runtime.execute("side_effect()")
        self.assertEqual(len(self.runtime.client.sent), 1)

    async def test_reply_idle_and_late_output_have_distinct_meanings(self):
        await self.runtime.execute("counter += 1", 0.1)
        request = self.runtime.requests["r0"]
        observe = self.runtime._observe
        observe(request, "iopub", {"header": {"msg_id": "idle", "msg_type": "status"},
                                    "content": {"execution_state": "idle"}})
        self.assertEqual(self.runtime.result("r0")["execution_status"], "unknown")
        observe(request, "shell", {"header": {"msg_id": "reply", "msg_type": "execute_reply"},
                                    "content": {"status": "ok"}})
        observe(request, "iopub", {"header": {"msg_id": "late", "msg_type": "stream"},
                                    "content": {"text": "late output"}})
        result = self.runtime.result("r0")
        self.assertEqual(result["execution_status"], "ok")
        self.assertEqual(result["outputs"][0]["message_id"], "late")
        observe(request, "iopub", {"header": {"msg_id": "large", "msg_type": "stream"},
                                    "content": {"text": "x" * (MAX_OUTPUT_BYTES + 1)}})
        result = self.runtime.result("r0")
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(sum(len(x["text"].encode()) for x in result["outputs"]), MAX_OUTPUT_BYTES)

    async def test_invalid_input_does_not_send(self):
        for code, timeout in (("", 1), ("x" * 262145, 1), ("x", 0), ("x", 121), ("x", float("nan"))):
            with self.assertRaises(ValueError):
                await self.runtime.execute(code, timeout)
        with self.assertRaises(ValueError):
            self.runtime.result("absent")
        self.assertEqual(self.runtime.client.sent, [])


if __name__ == "__main__":
    unittest.main()
