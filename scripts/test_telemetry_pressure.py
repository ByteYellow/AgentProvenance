import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

SPEC = importlib.util.spec_from_file_location("pressure", Path(__file__).with_name("accept_telemetry_100k_pressure.py"))
pressure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pressure)


def report():
    return {"schema_version": pressure.SCHEMA, "passed": True,
            "environment": {"machine": "aarch64", "cpu_count": 4},
            "profile": {"events": 100000, "name": "falco-execve-no-policy/v1"},
            "binary_sha256": "a" * 64, "script_sha256": "b" * 64,
            "metrics": {name: 100 for name in pressure.METRICS}}


class PressureTest(unittest.TestCase):
    def test_linux_cpu_time_accepts_spaces_and_parentheses_in_comm(self):
        fields = ["S"] + ["0"] * 10 + ["20", "30"] + ["999"] * 8
        self.assertEqual(pressure.cpu_seconds("123 (test (process)) " + " ".join(fields), 100), .5)

    def test_percentiles_keep_empty_unknown_and_reject_bad_values(self):
        self.assertIsNone(pressure.percentiles([])["p95_ms"])
        self.assertEqual(pressure.percentiles(list(range(1, 31)))["p95_ms"], 29)
        self.assertEqual(pressure.percentiles(list(range(1, 31)))["p99_ms"], 30)
        for value in (-1, float("nan"), float("inf")):
            with self.assertRaisesRegex(ValueError, "latency"):
                pressure.percentiles([value])

    def test_storage_excludes_fixture_but_includes_wal_and_spool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ingest").mkdir()
            (root / "ingest/fixture").write_bytes(b"input")
            (root / "db").write_bytes(b"123")
            (root / "db-wal").write_bytes(b"12345")
            (root / "spool").mkdir()
            (root / "spool/batch").write_bytes(b"12")
            self.assertEqual(pressure.storage(root)["logical_bytes"], 10)

    def test_generate_matches_original_fixture_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            pressure.generate(path, 10)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(rows), 10)
            self.assertEqual(rows[-1]["output_fields"]["proc.pid"], 1009)
            with self.assertRaises(FileExistsError):
                pressure.generate(path, 10)

    def test_http_failures_are_not_successful_latency_samples(self):
        client = pressure.Client("http://127.0.0.1:1", "not-a-real-token")
        for status in (401, 403, 500):
            with patch.object(client.opener, "open", side_effect=urllib.error.HTTPError(
                    client.url, status, "fixture", None, None)):
                with self.assertRaises(urllib.error.HTTPError):
                    client.request("/v1/health")

    def test_page_requires_actual_bounded_rows_and_total(self):
        page = {"schema_version": "agentprovenance.telemetry_events/v1", "event_count": 5,
                "events": [{}] * 5, "total_count": 100000, "has_more": True,
                "next_cursor": "next", "result_set_id": "sha256:x", "page_hash": "sha256:y"}
        pressure.validate_page(page, 100000)
        for key, value in (("events", []), ("event_count", 6), ("total_count", 99999),
                           ("next_cursor", ""), ("page_hash", "")):
            with self.assertRaises(ValueError):
                pressure.validate_page(dict(page, **{key: value}), 100000)

    def freeze(self, root, reports=None):
        reports = reports or [dict(report(), generated_at=str(i)) for i in range(3)]
        paths = []
        for index, item in enumerate(reports):
            path = root / f"baseline-{index}.json"
            pressure.write_json(path, item)
            paths.append(path)
        return pressure.freeze(paths, .25)

    def test_frozen_budget_allows_new_binary_but_rejects_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = self.freeze(Path(directory))
            candidate = report()
            candidate["binary_sha256"] = "c" * 64
            self.assertTrue(pressure.check_budget(candidate, budget)["passed"])
            candidate["metrics"]["drain_ms"] = 126
            result = pressure.check_budget(candidate, budget)
            self.assertFalse(result["passed"])
            self.assertEqual(result["checks"]["drain_ms"]["maximum"], 125)

    def test_budget_rejects_different_environment_profile_or_instrumentation(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = self.freeze(Path(directory))
            for key in ("environment", "profile", "script_sha256"):
                candidate = report()
                candidate[key] = "different"
                with self.assertRaisesRegex(ValueError, "candidate mismatch"):
                    pressure.check_budget(candidate, budget)

    def test_unknown_failed_or_nonfinite_measurements_cannot_freeze(self):
        for invalid in (dict(report(), passed=False),
                        dict(report(), metrics={}),
                        dict(report(), metrics={name: float("nan") for name in pressure.METRICS})):
            with self.assertRaises(ValueError):
                pressure.validate_report(invalid)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            pressure.write_json(path, report())
            with self.assertRaisesRegex(ValueError, "distinct"):
                pressure.freeze([path] * 3, .25)
            with self.assertRaisesRegex(ValueError, "three"):
                pressure.freeze([path], .25)

    def test_baseline_versions_cannot_be_mixed(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = [dict(report(), generated_at=str(i)) for i in range(3)]
            reports[-1]["binary_sha256"] = "c" * 64
            with self.assertRaisesRegex(ValueError, "baseline mismatch"):
                self.freeze(Path(directory), reports)

    def test_report_and_budget_files_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            pressure.write_json(path, {"original": True})
            with self.assertRaises(FileExistsError):
                pressure.write_json(path, {"original": False})
            self.assertEqual(json.loads(path.read_text()), {"original": True})


if __name__ == "__main__":
    unittest.main()
