"""Workspace composition contracts; synthetic rows never represent hardware PASS."""
import argparse
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import common
import run
import workspace_case as case
from test_contracts import pinned


TARGET = {"producer_id": "operator", "instance_id": "pod-1", "generation": "g-1"}


class WorkspaceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {"target": dict(TARGET), "workspace_id": "workspace", "run_id": "run-1", "root": "/guest/work"}
        self.db = sqlite3.connect(self.root / "agentprov.db")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE provenance_objects(hash,object_type,path,run_id);
            CREATE TABLE fork_attempts(id,snapshot_id,rollout_id,tool_call_id,workspace_path);
            CREATE TABLE rollouts(id,run_id);
            CREATE TABLE execution_context_bindings(cgroup_id,run_id,attempt_id,tool_call_id,binding_source);
            CREATE TABLE events(id,raw_event_id,cgroup_id,correlation_method,run_id,tool_call_id,source,payload,event_type);
            INSERT INTO fork_attempts VALUES ('attempt','snapshot','rollout','tool','/guest/work');
            INSERT INTO rollouts VALUES ('rollout','run-1');
            INSERT INTO execution_context_bindings VALUES ('123','run-1','attempt','tool','zero_sdk_record');
            INSERT INTO events VALUES ('event','raw','123','cgroup_time_window:cgroup_id+time','run-1','','agentprov_ebpf','{"attempt_id":"attempt"}','execve');
            INSERT INTO events VALUES ('file','raw-file','123','cgroup_time_window:cgroup_id+time','run-1','','agentprov_ebpf','{"attempt_id":"attempt"}','file_open');
        """)
        for operation in ("read", "edit", "write", "execute"):
            receipt = {"operation": operation, "exit_code": 0, "input_manifest_ref": "input", "output_manifest_ref": "output",
                       "input_revision": 3, "output_revision": 4,
                       "record": {"run_id": "run-1", "attempt_id": "attempt", "base_snapshot_id": "snapshot"}}
            common.save(self.root / (operation + ".json"), {"payload": {"binding": {
                "target": dict(TARGET), "workspace_id": "workspace", "root": "/guest/work", "mode": "remote-authoritative"}, "receipt": receipt}})
            self.db.execute("INSERT INTO provenance_objects VALUES (?,?,?,?)", (
                "sha256:" + common.digest(self.root / (operation + ".json")), "workspace_operation",
                str(self.root / (operation + ".json")), "run-1"))
        self.db.commit()

    def inspect(self):
        return case.inspect_workspace(self.root, self.config, native=True)

    def test_same_cgroup_and_cgroup_correlation(self):
        evidence = self.inspect()
        self.assertEqual(len(evidence["native_events"]), 2)
        self.assertEqual(evidence["association"], "owned_record_cgroup")
        self.assertTrue(all(e["tool_call_id"] == "" for e in evidence["native_events"]))

    def test_birth_identity_correlation_with_same_cgroup_is_valid(self):
        self.db.execute("UPDATE events SET correlation_method='kernel_process_instance:boot+pid+start_time'")
        self.db.commit()
        self.assertEqual(self.inspect()["cgroup_id"], "123")

    def test_birth_identity_cannot_borrow_another_cgroup(self):
        self.db.execute("UPDATE events SET correlation_method='kernel_process_instance:boot+pid+start_time',cgroup_id='456'")
        self.db.commit()
        with self.assertRaisesRegex(common.Blocked, "native events"):
            self.inspect()

    def test_pid_only_correlation_is_not_native_scope_proof(self):
        self.db.execute("UPDATE events SET correlation_method='pid_time_window'")
        self.db.commit()
        with self.assertRaises(common.Blocked):
            self.inspect()

    def test_logical_scope_and_missing_events_rejected(self):
        for statement in ("UPDATE execution_context_bindings SET cgroup_id='logical-1'", "DELETE FROM events"):
            with self.subTest(statement=statement):
                self.db.execute("UPDATE execution_context_bindings SET cgroup_id='123'")
                self.db.execute(statement)
                self.db.commit()
                with self.assertRaises(common.Blocked):
                    self.inspect()

    def test_same_cgroup_different_attempt_cannot_supply_events(self):
        self.db.execute("UPDATE events SET payload=?", (json.dumps({"attempt_id": "another-attempt"}),))
        self.db.commit()
        with self.assertRaisesRegex(common.Blocked, "native events"):
            self.inspect()

    def test_hash_valid_but_wrong_generation_rejected(self):
        path = self.root / "read.json"
        obj = common.load(path)
        obj["payload"]["binding"]["target"]["generation"] = "g-other"
        common.save(path, obj)
        self.db.execute("UPDATE provenance_objects SET hash=? WHERE path=?", ("sha256:" + common.digest(path), str(path)))
        self.db.commit()
        with self.assertRaisesRegex(common.Blocked, "generation"):
            self.inspect()


class WorkspaceCompositionTests(unittest.TestCase):
    def test_default_pins_and_pod_unchanged(self):
        self.assertEqual(case.option_issues(None, pinned(), None), [])
        args = argparse.Namespace(namespace="fixture", node="node-1")
        pod = run.pod_manifest(args, pinned(), "owned", Path("/assets"), Path("/data"))
        self.assertNotIn("--workspace-case", pod["spec"]["containers"][0]["command"])
        enabled = run.pod_manifest(args, pinned(), "owned", Path("/assets"), Path("/data"), workspace_case="contract")
        self.assertEqual(enabled["spec"]["containers"][0]["command"][-2:], ["--workspace-case", "contract"])
        self.assertEqual(enabled["spec"], {**pod["spec"], "containers": enabled["spec"]["containers"]})
        self.assertEqual(len(enabled["spec"]["volumes"]), 3)
        self.assertFalse(enabled["spec"]["automountServiceAccountToken"])

    def test_requested_mode_requires_pins_and_verifier(self):
        lock = pinned()
        self.assertEqual(len(case.option_issues("contract", lock, None)), 2)
        lock["workspace"]["mcp_version"] = "2.3.0"
        self.assertEqual(case.option_issues("contract", lock, "/verifier"), [])
        self.assertEqual(len(case.option_issues("harness", lock, "/verifier")), 2)

    def test_blocked_fixture_stays_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control, output = root / "control", root / "output"
            control.mkdir()
            output.mkdir()
            common.save(control / "workspace-target.json", TARGET)
            common.save(output / "report.json", {"status": "blocked", "failure_code": "sensor_requires_linux"})
            lock = pinned()
            lock["workspace"]["mcp_version"] = "2.3.0"
            with patch.object(case, "command"), patch.object(case, "digest", return_value="f" * 64), \
                    patch.object(case, "deliver_workspace") as delivery:
                with self.assertRaisesRegex(common.Blocked, "sensor_requires_linux"):
                    case.run_case(root / "binary", root / "verifier", root / "fixture", root / "python",
                                  control, output, {"target": TARGET}, lock, {}, "contract")
                delivery.assert_not_called()
            report = common.load(output / "kata-workspace.json")
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["failure_code"], "sensor_requires_linux")

    def test_sensor_boot_generation_and_lifetime_rejections(self):
        lock = pinned()
        execution = {"target": TARGET, "backend": {"guest": {"guest_boot_id": "boot-1"}}}
        producer = {"version": lock["sensor"]["version"], "commit": lock["sensor"]["source_sha"],
                    "placement": "guest_kernel", "boot_id": "boot-1"}
        sensor = {"status": "passed", "drain": "collector_stopped_store_empty", "target": TARGET, "run_id": "run-1",
                  "ready": {"collector_running": True, "capabilities": {"ready": True, "collector_id": "collector-1", "producer": producer}},
                  "final": {"collector_running": False, "capabilities": {"status": "stopped", "collector_id": "collector-1", "producer": producer}}}
        case.validate_sensor(sensor, {"run_id": "run-1"}, execution, lock)
        for field in ("target", "boot", "collector", "drain"):
            changed = copy.deepcopy(sensor)
            if field == "target":
                changed["target"]["generation"] = "other"
            elif field == "boot":
                changed["final"]["capabilities"]["producer"]["boot_id"] = "other"
            elif field == "collector":
                changed["final"]["capabilities"]["collector_id"] = "other"
            else:
                changed["drain"] = "pending"
            with self.subTest(field=field), self.assertRaises(common.Blocked):
                case.validate_sensor(changed, {"run_id": "run-1"}, execution, lock)


if __name__ == "__main__":
    unittest.main()
