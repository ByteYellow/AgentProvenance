import json
from pathlib import Path
import tempfile
import unittest

from accept_seccheck_faults import latest_status, require_preserved_records, spool_inventory, wait_for


class FaultAcceptanceChecks(unittest.TestCase):
    def test_status_ignores_incomplete_last_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_text('{"state":"listening"}\n{"state":')
            self.assertEqual(latest_status(path), {"state": "listening"})

    def test_spool_preserves_identity_and_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {"RawEventID": "seccheck:abc", "Payload": '{"path":"/tmp/result"}'}
            (root / "pending.jsonl").write_text(json.dumps(record) + "\n")
            self.assertEqual(spool_inventory(root), {record["RawEventID"]: record})
            (root / "duplicate.jsonl").write_text(json.dumps(record) + "\n")
            self.assertEqual(len(spool_inventory(root)), 1)
            record["Payload"] = "{}"
            (root / "conflict.jsonl").write_text(json.dumps(record) + "\n")
            with self.assertRaisesRegex(RuntimeError, "conflicting"):
                spool_inventory(root)

    def test_partial_spool_cannot_pass_as_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "partial.jsonl").write_text('{"RawEventID":')
            with self.assertRaises(json.JSONDecodeError):
                spool_inventory(root)

    def test_wait_propagates_failure(self):
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            wait_for(lambda: False, "no producer", timeout=0)
        self.assertEqual(wait_for(lambda: 7, "ready"), 7)

    def test_preservation_requires_real_evidence(self):
        with self.assertRaisesRegex(RuntimeError, "requires committed"):
            require_preserved_records({}, {})
        for after in ({}, {"record": "changed"}):
            with self.assertRaisesRegex(RuntimeError, "changed or disappeared"):
                require_preserved_records({"record": "body"}, after)
        require_preserved_records({"record": "body"}, {"record": "body", "later": "body"})


if __name__ == "__main__":
    unittest.main()
