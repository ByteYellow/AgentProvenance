import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("capture_demo", Path(__file__).with_name("capture.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CaptureManifestTests(unittest.TestCase):
    def test_source_and_input_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "agentprov"
            binary.write_bytes(b"sample executable")
            version = "agentprov version v1.0.0-dev (" + "a" * 40 + "; unknown; linux/arm64)"
            with patch.object(capture, "run", return_value=types.SimpleNamespace(stdout=version)):
                identity = capture.capture_identity(binary)
            self.assertEqual(identity["source_commit"], "a" * 40)
            self.assertEqual(identity["sensor"]["binary_sha256"], capture.file_identity(binary)["sha256"])
            self.assertEqual(identity["sensor"]["command"], ["sensor", "stream"])
            paths = {item["path"] for item in identity["inputs"]}
            self.assertIn("workspace/settings.json", paths)
            self.assertIn("task-before.txt", paths)
            self.assertFalse(any("__pycache__" in name for name in paths))

    def test_unknown_build_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "agentprov"
            binary.write_bytes(b"development binary")
            with patch.object(capture, "run", return_value=types.SimpleNamespace(stdout="agentprov version dev (unknown; unknown; linux/arm64)")):
                self.assertIsNone(capture.capture_identity(binary)["source_commit"])

    def test_models_use_saved_configuration_and_both_paginators(self):
        entries = [
            {"id": "root-header", "kind": "configuration", "status": "request/header", "source": {"session_id": "root"}, "content": {"state": "stored", "ref": "body"}},
            {"id": "omitted", "kind": "configuration", "status": "request/header", "content": {"state": "omitted"}},
            {"id": "unrelated", "kind": "configuration", "status": "permission/preset"},
        ]
        text = json.dumps({"header": {"config": {"provider": "deepseek-official", "model": "deepseek-flash", "apiKey": "never-copy"}, "tools": ["never-copy-tools"]}})
        split = 42

        def fake_run(argv):
            if "list" in argv:
                more = argv[-1] == ""
                value = {"entries": entries[:1] if more else entries[1:], "has_more": more, "next_cursor": "next" if more else ""}
            else:
                offset = int(argv[argv.index("--offset") + 1])
                value = {"content": text[:split] if offset == 0 else text[split:], "has_more": offset == 0, "next_offset": split if offset == 0 else len(text)}
            return types.SimpleNamespace(stdout=json.dumps(value))

        with patch.object(capture, "run", side_effect=fake_run):
            value = capture.recorded_models(["agentprov"], "run")
        self.assertEqual(value, [{"entry_id": "root-header", "session_id": "root", "provider": "deepseek-official", "model": "deepseek-flash"}])
        self.assertNotIn("never-copy", json.dumps(value))

    def test_stalled_entry_cursor_fails(self):
        with patch.object(capture, "run", return_value=types.SimpleNamespace(stdout=json.dumps({"entries": [], "has_more": True, "next_cursor": ""}))):
            with self.assertRaisesRegex(RuntimeError, "cursor"):
                capture.recorded_models(["agentprov"], "run")

    def test_coverage_is_kept_separate(self):
        launch = {"runtime_capture": {"status": "partial", "node_pending_events": 7, "run_dropped_events": None, "issues": ["node_backlog_at_seal"], "capabilities_end": {"large": "omitted"}},
                  "artifact_capture": {"status": "partial", "stored": 3, "omitted": 2, "failed": 0, "files": []}}
        result = capture.capture_summary(launch)
        self.assertEqual(result["runtime"]["node_pending_events"], 7)
        self.assertIsNone(result["runtime"]["run_dropped_events"])
        self.assertNotIn("capabilities_end", result["runtime"])
        self.assertEqual(result["artifacts"]["omitted"], 2)


if __name__ == "__main__":
    unittest.main()
