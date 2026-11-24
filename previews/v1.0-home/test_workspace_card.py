import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from workspace_card import RUN, summarize, workspace_card


class TestWorkspaceCard(unittest.TestCase):
    def test_packaged_operations(self):
        archive = BASE.parent / "v1.0-reader/fixtures/workspace-contract.zip"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(root)
            rows = workspace_card(root)["rows"]
        self.assertEqual([r["tool"] for r in rows], ["workspace_edit", "workspace_write", "workspace_bash"])
        self.assertEqual((rows[2]["before"], rows[2]["after"], rows[2]["path"], rows[2]["size"]),
                         (3, 4, "result.txt", 25))
        self.assertEqual(rows[1]["next"], "reread")
        self.assertNotIn("path", rows[1])
        self.assertNotIn("digest", rows[1])

    def test_cross_call_and_stale_snapshot(self):
        entry = {"id": "entry", "tool_name": "workspace_bash", "tool_call_id": "mine"}
        result = {"schema": "agentprovenance.workspace_tool_result/v1", "run_id": RUN,
                  "tool_call_id": "mine", "ok": True, "operation_ref": "own",
                  "view": {"last_receipt": {"tool_call_id": "other", "ref": "own"}}}
        with self.assertRaisesRegex(ValueError, "does not belong"):
            summarize(entry, result)
        result["view"]["last_receipt"] = {"tool_call_id": "mine", "ref": "previous"}
        with self.assertRaisesRegex(ValueError, "does not belong"):
            summarize(entry, result)
        result["run_id"] = "other"
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            summarize(entry, result)


if __name__ == "__main__":
    unittest.main()
