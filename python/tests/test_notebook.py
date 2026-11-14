import json
import pathlib
import tempfile
import unittest

from agentprov.notebook import Recorder, SCOPE_FIELDS


class NotebookRecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "messages.jsonl"
        self.scope = {key: key for key in SCOPE_FIELDS}
        self.message = {"header": {"session": "kernel_session_id", "msg_id": "out", "msg_type": "stream"},
                        "content": {"text": "hello"}, "parent_header": {}, "buffers": []}

    def test_private_new_file_and_native_identity(self):
        with Recorder(self.path, self.scope, client_version="test") as recorder:
            recorder.record("iopub", "receive", self.message)
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual(rows[1]["message"]["header"], self.message["header"])
        self.assertNotIn("buffers", rows[1]["message"])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            Recorder(self.path, self.scope, client_version="test")

    def test_budget_is_recorded_and_cannot_resume(self):
        with Recorder(self.path, self.scope, client_version="test", max_messages=1) as recorder:
            recorder.record("iopub", "receive", self.message)
            for _ in range(2):
                with self.assertRaises(ValueError):
                    recorder.record("iopub", "receive", self.message)
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[-1]["reason"], "capture_budget_exceeded")

    def test_kernel_restart_and_credentials_rejected(self):
        with Recorder(self.path, self.scope, client_version="test") as recorder:
            self.message["header"]["session"] = "new-kernel"
            with self.assertRaisesRegex(ValueError, "kernel identity changed"):
                recorder.record("iopub", "receive", self.message)
        with self.assertRaises(ValueError):
            Recorder(str(self.path) + "new", {**self.scope, "key": "SECRET"}, client_version="test")


if __name__ == "__main__":
    unittest.main()
