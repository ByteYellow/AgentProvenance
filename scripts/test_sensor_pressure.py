import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import accept_sensor_overhead as overhead
from accept_sensor_pressure import capability_snapshots, fixture_run, inspect_records


def report_fixture():
    runs = []
    for workload in overhead.WORKLOADS:
        for profile in overhead.PROFILES:
            for repeat in range(1, 4):
                row = {"workload": workload, "profile": profile, "repeat": repeat, "passed": True,
                       "workload_seconds": float(repeat), "workload_cpu_seconds": .4 * repeat}
                if profile != "off":
                    row.update(sensor_cpu_seconds=.2 * repeat, peak_rss_kib=1024 * repeat,
                               fixture_output_bytes=1000 * repeat, output_bytes=2000 * repeat,
                               compressed_output_bytes=100 * repeat, startup_seconds=.1, drain_seconds=.2)
                runs.append(row)
    return {"schema_version": overhead.SCHEMA, "passed": True, "run_id": "baseline",
            "sensor_sha256": "old", "environment": {"kernel": "fixed", "cpu_count": 4},
            "workloads": {k: list(v) for k, v in overhead.WORKLOADS.items()},
            "profiles": overhead.PROFILES, "repeats": 3, "measurement_sha256": {"script": "fixed"},
            "fixture_source_sha256": "source", "fixture_binary_sha256": "executable",
            "compiler": "cc fixed", "runs": runs}


class SensorPressureTests(unittest.TestCase):
    def inspect(self, rows):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            data = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
            path.write_bytes(data)
            return inspect_records(path), data

    def test_exact_counts_and_bytes_exclude_other_processes(self):
        rows = [{"comm": "sensor-pressure", "event_type": kind}
                for kind in ("file_open", "syscall_result", "process_exit")]
        rows += [{"comm": "other", "event_type": "file_open"}]
        result, data = self.inspect(rows)
        self.assertEqual(result["counts"], {"file_open": 1, "syscall_result": 1, "process_exit": 1})
        self.assertEqual(result["output_bytes"], len(data))
        self.assertLess(result["fixture_output_bytes"], len(data))
        self.assertEqual(result["output_sha256"], hashlib.sha256(data).hexdigest())

    def test_drops_keep_resources_separate(self):
        result, _ = self.inspect([
            {"event_type": "resource_pressure", "resource": "sensor_ringbuf", "dropped_delta": 2},
            {"event_type": "resource_pressure", "resource": "sensor_ringbuf", "dropped_delta": 3},
            {"event_type": "resource_pressure", "resource": "sensor_access_state", "dropped_delta": 7}])
        self.assertEqual(result["kernel_drops"], 5)
        self.assertEqual(result["resource_drops"]["sensor_access_state"], 7)

    def test_state_status_is_node_level(self):
        result, _ = self.inspect([{"event_type": "access_control_state", "state": {
            "identity": {"status": "process_exited"}, "seccomp": {"status": "unavailable"}}}])
        self.assertEqual(result["node_access_state_status_counts"],
                         {"identity:process_exited": 1, "apparmor:unknown": 1, "seccomp:unavailable": 1})
        self.assertEqual(result["fixture_output_bytes"], 0)

    def test_invalid_record_fails(self):
        with self.assertRaises(ValueError):
            self.inspect([[]])

    def test_ready_capabilities_survive_shutdown(self):
        reports = [{"ready": False, "status": "starting"}, {"ready": True, "status": "degraded"},
                   {"ready": False, "status": "stopped"}]
        log = "\n".join("agentprov-sensor: capabilities " + json.dumps(row) for row in reports)
        result = capability_snapshots(log)
        self.assertEqual(result["last_ready_capabilities"], reports[1])
        self.assertEqual(result["last_capabilities"], reports[2])
        self.assertIsNone(capability_snapshots("no report")["last_ready_capabilities"])
        with self.assertRaises(ValueError):
            capability_snapshots("agentprov-sensor: capabilities []")

    def test_all_loss_channels_and_missing_readiness_fail(self):
        result = {"passed": True, "peak_rss_kib": 1024, "last_ready_capabilities": {"ready": True},
                  "last_capabilities": {}, "resource_drops": {}}
        self.assertTrue(overhead.capture_passes(result))
        result["last_capabilities"] = {"tls_discovery": {"event_discovery": {"queue_drops": 1}}}
        self.assertFalse(overhead.capture_passes(result))
        result["last_capabilities"] = {}
        result["resource_drops"] = {"sensor_access_state": 1}
        self.assertFalse(overhead.capture_passes(result))
        result["resource_drops"] = {}
        result["last_ready_capabilities"] = None
        self.assertFalse(overhead.capture_passes(result))

    def test_child_cpu_and_exit_status(self):
        result = fixture_run("/usr/bin/true", 0, 0)
        self.assertGreater(result["workload_seconds"], 0)
        self.assertGreaterEqual(result["workload_cpu_seconds"], 0)
        with self.assertRaisesRegex(RuntimeError, "exited with 1"):
            fixture_run("/usr/bin/false", 0, 0)

    def test_frozen_medians_and_allowances(self):
        budget = overhead.freeze(report_fixture(), .25)
        self.assertEqual(budget["limits"]["minimal/burst"]["workload_seconds"],
                         {"baseline_median": 2., "maximum": 2.52})
        self.assertEqual(budget["limits"]["default/paced"]["peak_rss_kib"]["maximum"], 2560)

    def test_candidate_checks_every_case(self):
        report = report_fixture()
        budget = overhead.freeze(report, .25)
        report.update(run_id="candidate", sensor_sha256="new")
        checks = overhead.check(report, budget)
        self.assertEqual(len(checks), 18)
        self.assertTrue(all(item["passed"] for item in checks))
        for row in report["runs"]:
            if row["profile"] == "default" and row["workload"] == "paced":
                row["peak_rss_kib"] *= 2
        self.assertEqual(sum(not item["passed"] for item in overhead.check(report, budget)), 1)

    def test_changed_environment_instrument_and_fixture_reject(self):
        original = report_fixture()
        budget = overhead.freeze(original, .25)
        for field in ("environment", "measurement_sha256", "fixture_binary_sha256", "compiler", "profiles"):
            changed = copy.deepcopy(original)
            changed.update(run_id="candidate")
            changed[field] = "changed"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "identity differs"):
                overhead.check(changed, budget)

    def test_missing_failed_and_repeated_samples_reject(self):
        for mutation in (lambda r: r["runs"].pop(),
                         lambda r: r["runs"][0].update(passed=False),
                         lambda r: r["runs"][1].update(repeat=1)):
            report = report_fixture()
            mutation(report)
            with self.assertRaises(ValueError):
                overhead.freeze(report, .25)

    def test_unknown_rss_is_not_zero(self):
        report = report_fixture()
        report["runs"][3]["peak_rss_kib"] = None
        with self.assertRaisesRegex(ValueError, "invalid.*peak_rss"):
            overhead.freeze(report, .25)

    def test_off_has_no_fake_collection_metrics(self):
        summary = overhead.summaries(report_fixture()["runs"])["off/burst"]
        self.assertNotIn("peak_rss_kib", summary)
        self.assertNotIn("output_bytes", summary)
        self.assertEqual(summary["relative_to_off"], 1)

    def test_bad_budget_and_reused_baseline_reject(self):
        report = report_fixture()
        budget = overhead.freeze(report, .25)
        with self.assertRaisesRegex(ValueError, "fresh measurement"):
            overhead.check(report, budget)
        report["run_id"] = "candidate"
        del budget["limits"]["default/paced"]
        with self.assertRaisesRegex(ValueError, "missing cases"):
            overhead.check(report, budget)
        for value in (float("nan"), -1, 2):
            with self.assertRaises(ValueError):
                overhead.freeze(report, value)

    def test_budget_reports_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "budget.json"
            overhead.save(path, {"old": True})
            with self.assertRaises(FileExistsError):
                overhead.save(path, {"new": True})
            self.assertEqual(json.loads(path.read_text()), {"old": True})


if __name__ == "__main__":
    unittest.main()
