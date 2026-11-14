"""Keyless checks for the real-agent acceptance assertions."""

import copy
import hashlib
import json
import pathlib
import sqlite3
import tempfile
import unittest
from unittest import mock

import accept_execution_native as accept


def report(call="call-a", cgroup="123"):
    return {"attempt": {"local_run_id": "run-" + call,
                        "request": {"source": {"session_id": "session", "tool_call_id": call},
                                    "command": {"argv": ["/bin/bash", "-lc", "python3 analyze.py"]}},
                        "state": {"execution": "succeeded", "delivery": "acknowledged"}},
            "checkpoint": {"scope": {"cgroup_id": cgroup}, "capture_report": {
                "state": "incomplete", "issues": ["scope_state_sampling_gap"],
                "scope_progress": {"state": "settled", "pending": 0, "sampling_gaps": 1}}}}


def hook(call="call-a"):
    return {"session_id": "session", "tool_use_id": call, "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": "python3 analyze.py"}}


class NativeAssertionsTest(unittest.TestCase):
    def test_real_gap_is_preserved_and_distinct_calls_pass(self):
        accept.validate_reports([report(), report("call-b", "456")], [hook(), hook("call-b")])

    def test_reject_wrong_source_or_shared_scope(self):
        cases = [
            ([report()], []),
            ([report()], [hook(), hook()]),
            ([report(), report("call-b")], [hook(), hook("call-b")]),
            ([report(), report()], [hook()]),
            ([report(cgroup="logical-scope")], [hook()]),
        ]
        for reports, hooks in cases:
            with self.subTest(reports=reports, hooks=hooks), self.assertRaises(RuntimeError):
                accept.validate_reports(reports, hooks)

    def test_reject_wrong_command(self):
        actual = hook()
        actual["tool_input"]["command"] = "python3 different.py"
        with self.assertRaisesRegex(RuntimeError, "differs"):
            accept.validate_reports([report()], [actual])

    def test_reject_unsettled_or_hidden_gap(self):
        for changed in ["pending", "dropped_issue", "sealed", "error"]:
            value = report()
            capture = value["checkpoint"]["capture_report"]
            if changed == "pending":
                capture["scope_progress"]["pending"] = 1
            elif changed == "dropped_issue":
                capture["issues"] = []
            elif changed == "sealed":
                capture["state"] = "sealed"
            else:
                capture["error"] = "failed"
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                accept.validate_reports([value], [hook()])

    def test_reject_execution_or_delivery_failure(self):
        for dimension in ("execution", "delivery"):
            value = report()
            value["attempt"]["state"][dimension] = "unknown"
            with self.subTest(dimension=dimension), self.assertRaises(RuntimeError):
                accept.validate_reports([value], [hook()])


class SavedEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = pathlib.Path(self.temp.name).resolve()
        data = self.output / "data"
        data.mkdir()
        self.db = sqlite3.connect(data / "agentprov.db")
        self.addCleanup(self.db.close)
        self.db.executescript("CREATE TABLE provenance_objects (run_id TEXT, hash TEXT, path TEXT);"
                              "CREATE TABLE events (id TEXT,run_id TEXT,cgroup_id TEXT,payload TEXT,source TEXT,event_type TEXT);")
        value = report()
        self.run_id = value["attempt"]["local_run_id"]
        body = json.dumps(accept.EXPECTED)
        chunk = self.object({"content": body})
        self.body_ref = chunk
        manifest = self.object({"text_manifest": {"sha256": hashlib.sha256(body.encode()).hexdigest(), "chunks": [{"ref": chunk}]}})
        checkpoint = copy.deepcopy(value["checkpoint"])
        checkpoint["result"] = {"artifact_capture": {"files": [{"path": "totals.json", "content_ref": manifest}]}}
        value["checkpoint_ref"] = self.object(checkpoint)
        self.value = value
        accept.save(self.output / "result.json", {"reports": [value]})
        self.insert_event("/task/totals.json", "123")

    def object(self, payload):
        raw = json.dumps({"payload": payload}).encode()
        digest = hashlib.sha256(raw).hexdigest()
        path = self.output / digest
        path.write_bytes(raw)
        self.db.execute("INSERT INTO provenance_objects VALUES (?,?,?)", (self.run_id, "sha256:" + digest, str(path)))
        self.db.commit()
        return "sha256:" + digest

    def insert_event(self, path, cgroup, extra=None):
        payload = {"payload": {"raw": {"path": path, "extra": extra}}}
        self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)", ("event-a", self.run_id, cgroup, json.dumps(payload), "agentprov_ebpf", "file_write"))
        self.db.commit()

    def verify(self):
        with mock.patch.object(accept, "run", return_value='{"errors":0,"warnings":0}'):
            return accept.verify_saved(pathlib.Path("unused-unit-fixture"), self.output)

    def test_received_body_and_exact_file_event(self):
        result = self.verify()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["native_file_events"][0]["event_id"], "event-a")
        self.assertEqual(len(result["artifacts"]), 1)

    def test_path_in_unrelated_payload_does_not_match(self):
        self.db.execute("DELETE FROM events")
        self.insert_event("/task/other.json", "123", "/task/totals.json")
        with self.assertRaisesRegex(RuntimeError, "native output write is missing"):
            self.verify()

    def test_cross_scope_event_is_rejected(self):
        self.db.execute("UPDATE events SET cgroup_id='456'")
        self.db.commit()
        with self.assertRaisesRegex(RuntimeError, "another scope"):
            self.verify()

    def test_tampered_received_object_is_rejected(self):
        row = self.db.execute("SELECT path FROM provenance_objects WHERE hash=?", (self.body_ref,)).fetchone()
        pathlib.Path(row[0]).write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
            self.verify()

    def test_capture_report_mismatch_is_rejected(self):
        self.value["checkpoint"]["capture_report"]["scope_progress"]["sampling_gaps"] = 0
        accept.save(self.output / "result.json", {"reports": [self.value]})
        with self.assertRaisesRegex(RuntimeError, "capture report differs"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
