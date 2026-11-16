import asyncio
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import accept_workspace as acceptance


def status(running=True):
    return {"collector_running": running, "capabilities_historical": not running,
            "capabilities": {"ready": running, "status": "ready" if running else "stopped", "collector_id": "collector-1",
                             "producer": {"placement": "guest_kernel", "version": "fixture", "commit": "fixture", "boot_id": "boot-1"},
                             "probes": [{"name": "exec", "required": True, "status": "attached"}]},
            "capture": {"counters": {"captured": 2, "ingested": 2, "expired_uncorrelated": 3}, "queued_batches": 0,
                        "queued_bytes": 0, "pending_events": 0, "cleanup_pending_batches": 0}}


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.base = self.root / "contract"
        self.config_path, self.config = acceptance.layout(self.base, "contract")
        self.options = SimpleNamespace(sensor=True, sensor_placement="guest_kernel", sensor_ready_timeout=0.03, sensor_drain_timeout=0.03)

    def seed_evidence(self):
        data = Path(self.config["data_dir"])
        data.mkdir()
        self.database = data / "agentprov.db"
        with sqlite3.connect(self.database) as db:
            db.executescript("""
                CREATE TABLE fork_attempts (id TEXT,tool_call_id TEXT,snapshot_id TEXT,workspace_path TEXT,exit_code INTEGER);
                CREATE TABLE tool_calls (id TEXT,attempt_id TEXT,run_id TEXT);
                CREATE TABLE execution_context_bindings (id TEXT,run_id TEXT,attempt_id TEXT,tool_call_id TEXT,cgroup_id TEXT,binding_source TEXT);
                CREATE TABLE events (id TEXT,run_id TEXT,tool_call_id TEXT,cgroup_id TEXT,source TEXT,raw_event_id TEXT,event_type TEXT,correlation_method TEXT,payload TEXT);
                CREATE TABLE provenance_objects (hash TEXT,path TEXT,run_id TEXT,object_type TEXT);
            """)
            db.execute("INSERT INTO fork_attempts VALUES ('attempt','tool','snapshot',?,0)", (self.config["root"],))
            db.execute("INSERT INTO tool_calls VALUES ('tool','attempt',?)", (self.config["run_id"],))
            db.execute("INSERT INTO execution_context_bindings VALUES ('binding',?,'attempt','tool','123','zero_sdk_record')", (self.config["run_id"],))
            for number, kind in enumerate(("execve", "file_open")):
                db.execute("INSERT INTO events VALUES (?,?, '', '123','agentprov_ebpf',?,?,?,?)",
                           ("event-" + str(number), self.config["run_id"], "raw-" + str(number), kind,
                            "kernel_process_instance:host+boot+pid+start", json.dumps({"attempt_id": "attempt"})))
        self.object_path = data / "receipt.json"
        self.obj = {"run_id": self.config["run_id"], "payload": {
            "binding": {k: self.config[k] for k in ("target", "root", "workspace_id")},
            "receipt": {"record": {"run_id": self.config["run_id"], "attempt_id": "attempt", "base_snapshot_id": "snapshot"},
                        "input_manifest_ref": "sha256:input", "output_manifest_ref": "sha256:output"}}}
        self.save_receipt()

    def save_receipt(self):
        raw = json.dumps(self.obj).encode()
        self.object_path.write_bytes(raw)
        with sqlite3.connect(self.database) as db:
            db.execute("DELETE FROM provenance_objects")
            db.execute("INSERT INTO provenance_objects VALUES (?,?,?,'workspace_operation')",
                       ("sha256:" + hashlib.sha256(raw).hexdigest(), str(self.object_path), self.config["run_id"]))

    def execute(self, query, args=()):
        with sqlite3.connect(self.database) as db:
            db.execute(query, args)

    def assert_failure(self, code, function):
        with self.assertRaises(acceptance.AcceptanceFailure) as caught:
            function()
        self.assertEqual(caught.exception.code, code)
        return caught.exception


class SensorEvidenceTests(FixtureTests):
    def setUp(self):
        super().setUp()
        self.seed_evidence()

    def test_scope_only_native_events_match_owned_record_and_generation(self):
        evidence = acceptance.verify_sensor_records(self.config)
        self.assertEqual(evidence["attempt_id"], "attempt")
        self.assertEqual(evidence["target"], self.config["target"])
        self.assertEqual(evidence["association"], "owned_record_cgroup")
        self.assertEqual(len(evidence["native_events"]), 2)
        self.assertTrue(all(e["tool_call_id"] == "" for e in evidence["native_events"]))
        self.assertTrue(all(e["cgroup_id"] == "123" for e in evidence["native_events"]))

    def test_owned_cgroup_scope_method_remains_scope_only(self):
        self.execute("UPDATE events SET correlation_method='cgroup_time_window:cgroup_id+time'")
        self.assertEqual(len(acceptance.verify_sensor_records(self.config)["native_events"]), 2)

    def test_process_anchor_does_not_duplicate_the_owned_cgroup_binding(self):
        self.execute("INSERT INTO execution_context_bindings VALUES ('process-anchor',?,'attempt','tool','','zero_sdk_record')", (self.config["run_id"],))
        self.assertEqual(acceptance.verify_sensor_records(self.config)["binding_id"], "binding")

    def test_record_events_are_not_sensor_events(self):
        self.execute("UPDATE events SET source='record'")
        self.assert_failure("sensor_record_events_missing", lambda: acceptance.verify_sensor_records(self.config))

    def test_other_run_or_scope_or_attempt_does_not_satisfy_capture(self):
        for column, value in (("run_id", "other"), ("cgroup_id", "124"), ("payload", '{"attempt_id":"other"}')):
            with self.subTest(column=column):
                with sqlite3.connect(self.database) as db:
                    original = db.execute("SELECT " + column + " FROM events LIMIT 1").fetchone()[0]
                self.execute("UPDATE events SET " + column + "=?", (value,))
                self.assert_failure("sensor_record_events_missing", lambda: acceptance.verify_sensor_records(self.config))
                self.execute("UPDATE events SET " + column + "=?", (original,))

    def test_pid_time_proximity_is_rejected(self):
        self.execute("UPDATE events SET correlation_method='pid_time_window:pid+time'")
        self.assert_failure("sensor_record_events_missing", lambda: acceptance.verify_sensor_records(self.config))

    def test_logical_scope_is_blocked(self):
        self.execute("UPDATE execution_context_bindings SET cgroup_id='agentprov-record-attempt'")
        error = self.assert_failure("sensor_cgroup_unavailable", lambda: acceptance.verify_sensor_records(self.config))
        self.assertIsInstance(error, acceptance.AcceptanceBlocked)

    def test_native_exec_without_file_observation_fails(self):
        self.execute("DELETE FROM events WHERE event_type='file_open'")
        self.assert_failure("sensor_record_events_missing", lambda: acceptance.verify_sensor_records(self.config))

    def test_wrong_receipt_generation_cannot_borrow_record(self):
        self.obj["payload"]["binding"]["target"] = {**self.config["target"], "generation": "old"}
        self.save_receipt()
        self.assert_failure("sensor_workspace_binding_mismatch", lambda: acceptance.verify_sensor_records(self.config))

    def test_wrong_receipt_run_cannot_borrow_record(self):
        self.obj["payload"]["receipt"]["record"]["run_id"] = "other"
        self.save_receipt()
        self.assert_failure("sensor_workspace_binding_mismatch", lambda: acceptance.verify_sensor_records(self.config))

    def test_modified_receipt_hash_fails(self):
        self.object_path.write_text("{}")
        self.assert_failure("sensor_workspace_evidence_invalid", lambda: acceptance.verify_sensor_records(self.config))

    def test_missing_receipt_fails(self):
        self.execute("DELETE FROM provenance_objects")
        self.assert_failure("sensor_workspace_receipt_missing", lambda: acceptance.verify_sensor_records(self.config))


class SensorLifecycleTests(FixtureTests):
    def make_capture(self, final=None):
        sensor = acceptance.SensorCapture(self.base, Path("/fixture/agentprov"), self.config, self.options)
        sensor.process = mock.Mock()
        sensor.process.poll.return_value = None
        sensor.process.wait.return_value = 0
        sensor.report = {"status": "ready", "ready": status()}
        sensor.status = mock.Mock(return_value=final if final is not None else status(False))
        return sensor

    def test_default_does_not_start_any_sensor_process(self):
        with mock.patch.object(acceptance.subprocess, "Popen") as popen:
            with acceptance.SensorCapture(self.base, Path("/unused"), self.config) as sensor:
                self.assertEqual(sensor.report, {"status": "off"})
        popen.assert_not_called()
        self.assertFalse((self.base / "sensor.json").exists())

    def test_non_linux_is_blocked_and_preserved(self):
        with mock.patch.object(acceptance.platform, "system", return_value="Darwin"):
            error = self.assert_failure("sensor_requires_linux", lambda: acceptance.SensorCapture(self.base, Path("/unused"), self.config, self.options).__enter__())
        self.assertIsInstance(error, acceptance.AcceptanceBlocked)
        self.assertEqual(json.loads((self.base / "sensor.json").read_text())["status"], "blocked")

    def test_linux_without_delegation_is_blocked(self):
        with mock.patch.object(acceptance.platform, "system", return_value="Linux"), mock.patch.object(acceptance.os, "access", return_value=False):
            error = self.assert_failure("sensor_cgroup_unavailable", lambda: acceptance.SensorCapture(self.base, Path("/unused"), self.config, self.options).__enter__())
        self.assertIsInstance(error, acceptance.AcceptanceBlocked)

    def test_success_requires_stopped_empty_capture_and_evidence(self):
        self.seed_evidence()
        sensor = self.make_capture()
        self.assertIsNone(sensor.finish(None))
        sensor.process.terminate.assert_called_once()
        sensor.process.wait.assert_called_once_with(timeout=self.options.sensor_drain_timeout)
        self.assertEqual(sensor.report["status"], "passed")
        self.assertEqual(json.loads((self.base / "sensor-final.json").read_text()), status(False))

    def test_empty_queues_without_actual_record_evidence_fail(self):
        sensor = self.make_capture()
        with mock.patch.object(acceptance, "verify_sensor_records", side_effect=acceptance.AcceptanceFailure("sensor_record_events_missing", "missing")):
            error = sensor.finish(None)
        self.assertEqual(error.code, "sensor_record_events_missing")
        self.assertEqual(sensor.report["status"], "failed")

    def test_pending_spool_cleanup_cannot_pass(self):
        final = status(False)
        final["capture"]["cleanup_pending_batches"] = 1
        sensor = self.make_capture(final)
        self.assertEqual(sensor.finish(None).code, "sensor_drain_incomplete")

    def test_kernel_drop_cannot_pass(self):
        final = status(False)
        final["capture"]["counters"]["kernel_dropped_events"] = 1
        sensor = self.make_capture(final)
        self.assertEqual(sensor.finish(None).code, "sensor_capture_loss")

    def test_collector_replacement_cannot_pass(self):
        final = status(False)
        final["capabilities"]["collector_id"] = "replacement"
        sensor = self.make_capture(final)
        self.assertEqual(sensor.finish(None).code, "sensor_lifetime_mismatch")

    def test_early_clean_exit_cannot_pass(self):
        sensor = self.make_capture()
        sensor.process.poll.return_value = 0
        self.assertEqual(sensor.finish(None).code, "sensor_stopped_unexpectedly")

    def test_timeout_kills_and_reaps_owned_process(self):
        sensor = self.make_capture()
        sensor.process.wait.side_effect = [subprocess.TimeoutExpired("sensor", 1), -9]
        self.assertEqual(sensor.finish(None).code, "sensor_drain_timeout")
        sensor.process.kill.assert_called_once()
        self.assertEqual(sensor.process.wait.call_count, 2)

    def test_task_failure_survives_cleanup_failure_without_replay(self):
        sensor = self.make_capture()
        sensor.status.side_effect = acceptance.AcceptanceFailure("sensor_status_failed", "status")
        original = acceptance.AcceptanceFailure("artifact_mismatch", "task")
        self.assertIs(sensor.finish(original), original)
        self.assertEqual(sensor.report["cleanup_failure"], "sensor_status_failed")
        sensor.process.terminate.assert_called_once()

    def test_permissions_failure_is_blocked_and_collector_reaped(self):
        sensor = acceptance.SensorCapture(self.base, Path("/unused"), self.config, self.options)
        process = mock.Mock()
        process.poll.return_value = 1
        process.wait.return_value = 1
        with mock.patch.object(acceptance.platform, "system", return_value="Linux"), \
                mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(acceptance.os, "access", return_value=True), \
                mock.patch.object(acceptance.subprocess, "Popen", return_value=process), \
                mock.patch.object(sensor, "log_tail", return_value="load eBPF objects: operation not permitted"), \
                mock.patch.object(sensor, "status", return_value=status(False)):
            error = self.assert_failure("sensor_prerequisite_unavailable", sensor.__enter__)
        self.assertIsInstance(error, acceptance.AcceptanceBlocked)
        process.wait.assert_called_once()

    def test_ready_log_alone_is_not_readiness(self):
        sensor = acceptance.SensorCapture(self.base, Path("/unused"), self.config, self.options)
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch.object(acceptance.platform, "system", return_value="Linux"), \
                mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(acceptance.os, "access", return_value=True), \
                mock.patch.object(acceptance.subprocess, "Popen", return_value=process), \
                mock.patch.object(sensor, "log_tail", return_value="agentprov sensor stream: ready probes-attached"), \
                mock.patch.object(sensor, "status", return_value=status(False)), \
                mock.patch.object(acceptance.time, "monotonic", side_effect=[0, 0, 1]), mock.patch.object(acceptance.time, "sleep"):
            self.assert_failure("sensor_ready_timeout", sensor.__enter__)
        process.terminate.assert_called_once()

    def test_real_child_ready_status_sigterm_and_drain(self):
        self.seed_evidence()
        binary = self.root / "fake-agentprov"
        binary.write_text("#!" + sys.executable + "\n" + """
import json, pathlib, signal, sys, time
root = pathlib.Path(sys.argv[sys.argv.index('--data-dir') + 1])
marker = root / 'collector.running'
if 'status' in sys.argv:
    running = marker.exists()
    ready = json.loads((root / 'ready-fixture.json').read_text())
    ready['collector_running'] = running
    ready['capabilities_historical'] = not running
    ready['capabilities']['ready'] = running
    ready['capabilities']['status'] = 'ready' if running else 'stopped'
    print(json.dumps(ready))
else:
    def stop(signum, frame):
        marker.unlink()
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    marker.touch()
    print('agentprov sensor stream: ready probes-attached', file=sys.stderr, flush=True)
    while True:
        time.sleep(0.01)
""")
        binary.chmod(0o700)
        (Path(self.config["data_dir"]) / "ready-fixture.json").write_text(json.dumps(status()))
        self.options.sensor_ready_timeout = self.options.sensor_drain_timeout = 5
        with mock.patch.object(acceptance.platform, "system", return_value="Linux"), \
                mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(acceptance.os, "access", return_value=True):
            with acceptance.SensorCapture(self.base, binary, self.config, self.options) as sensor:
                self.assertIsNone(sensor.process.poll())
                self.assertEqual(sensor.report["ready"]["capabilities"]["producer"]["placement"], "guest_kernel")
        self.assertEqual(sensor.process.returncode, 0)
        self.assertEqual(sensor.report["drain"], "collector_stopped_store_empty")
        self.assertFalse((Path(self.config["data_dir"]) / "collector.running").exists())


class TargetAndEntryTests(FixtureTests):
    def test_operator_target_is_copied_and_original_is_unchanged(self):
        path = self.root / "target.json"
        acceptance.write_json(path, self.config["target"])
        original = path.read_bytes()
        target = acceptance.load_target(path)
        new_path, config = acceptance.layout(self.root / "harness", "harness", target)
        Path(config["target_file"]).write_text('{"generation":"recreated"}')
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(json.loads(new_path.read_text())["target"], self.config["target"])

    def test_group_writable_target_is_rejected(self):
        path = self.root / "target.json"
        acceptance.write_json(path, self.config["target"])
        path.chmod(0o660)
        self.assert_failure("unsafe_target_file", lambda: acceptance.load_target(path))

    def test_invalid_and_oversized_target_is_rejected(self):
        path = self.root / "target.json"
        acceptance.write_json(path, {"generation": "partial"})
        self.assert_failure("invalid_target_file", lambda: acceptance.load_target(path))
        path.write_text(" " * 16385)
        self.assert_failure("invalid_target_file", lambda: acceptance.load_target(path))

    def test_symlink_target_is_rejected(self):
        path = self.root / "target.json"
        acceptance.write_json(path, self.config["target"])
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            acceptance.load_target(link)

    def test_default_entry_remains_keyless_sensor_off(self):
        output = self.root / "default"
        result = {"status": "passed", "record_attempts": 1}
        with mock.patch.object(sys, "argv", ["accept_workspace", "--output", str(output), "--agentprov", str(Path(__file__).resolve()), "--python-package", str(self.root)]), \
                mock.patch.object(acceptance.importlib.metadata, "version", return_value="fixture"), \
                mock.patch.object(acceptance, "contract_acceptance", new=mock.AsyncMock(return_value=result)) as contract, \
                mock.patch.object(acceptance, "harness_acceptance") as harness, contextlib.redirect_stdout(io.StringIO()):
            acceptance.main()
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["sensor"], "off")
        self.assertEqual(report["harness"], {"status": "not_requested"})
        self.assertFalse(contract.call_args.args[3].sensor)
        harness.assert_not_called()

    def test_blocked_entry_exit_two_has_machine_readable_reason(self):
        output = self.root / "blocked"
        with mock.patch.object(sys, "argv", ["accept_workspace", "--output", str(output), "--agentprov", str(Path(__file__).resolve()), "--python-package", str(self.root), "--sensor"]), \
                mock.patch.object(acceptance.importlib.metadata, "version", return_value="fixture"), \
                mock.patch.object(acceptance.platform, "system", return_value="Darwin"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                acceptance.main()
        self.assertEqual(caught.exception.code, 2)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual((report["status"], report["failure_code"]), ("blocked", "sensor_requires_linux"))
        self.assertEqual(report["contract"]["sensor"]["status"], "blocked")

    def test_missing_mcp_reports_blocked_without_starting_a_collector(self):
        output = self.root / "missing-mcp"
        with mock.patch.object(sys, "argv", ["accept_workspace", "--output", str(output), "--agentprov", str(Path(__file__).resolve()), "--python-package", str(self.root), "--sensor"]), \
                mock.patch.object(acceptance.importlib.metadata, "version", side_effect=acceptance.importlib.metadata.PackageNotFoundError("mcp")), \
                mock.patch.object(acceptance.subprocess, "Popen") as popen, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                acceptance.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(json.loads((output / "report.json").read_text())["failure_code"], "mcp_dependency_missing")
        popen.assert_not_called()

    def test_each_phase_gets_its_own_store_and_collector(self):
        paths = []
        class Capture:
            enabled = True
            report = {"status": "passed"}
            def __init__(self, base, binary, config, options):
                paths.append(config["data_dir"])
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        with mock.patch.object(acceptance, "SensorCapture", Capture), \
                mock.patch.object(acceptance, "contract_tools", new=mock.AsyncMock(return_value={"status": "passed"})) as contract, \
                mock.patch.object(acceptance, "harness_tools", return_value={"status": "passed"}) as harness:
            first = asyncio.run(acceptance.contract_acceptance(self.root / "another-contract", Path("/binary"), Path("/python"), self.options))
            second = acceptance.harness_acceptance(self.root / "harness", Path("/binary"), Path("/python"), Path("/claude"), self.options)
        self.assertNotEqual(paths[0], paths[1])
        self.assertEqual(first["sensor"]["status"], "passed")
        self.assertEqual(second["sensor"]["status"], "passed")
        contract.assert_awaited_once()
        harness.assert_called_once()


if __name__ == "__main__":
    unittest.main()
