import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

import accept_context_cost as cost


def report():
    samples = []
    for harness in ("browser", "jupyter"):
        for preset in cost.PRESETS:
            for repeat in range(1, 4):
                samples.append({"harness": harness, "preset": preset, "repeat": repeat,
                                "passed": True, "native_identity_sha256": harness,
                                "metrics": {name: 10 for name in cost.METRICS}})
    return {"schema_version": cost.SCHEMA, "passed": True, "run_id": "baseline",
            "binary_sha256": "old", "environment": {"architecture": "arm64"},
            "inputs": {"browser": [{"sha256": "fixed", "bytes": 123}]},
            "measurement_sha256": "instrument", "repeats": 3, "samples": samples}


class ContextCostTest(unittest.TestCase):
    def test_frozen_budget_and_fresh_candidate(self):
        baseline = report()
        budget = cost.freeze(baseline)
        candidate = copy.deepcopy(baseline)
        candidate.update(run_id="candidate", binary_sha256="new")
        checks = cost.check(candidate, budget)
        self.assertEqual(len(checks), 68)
        self.assertTrue(all(item["passed"] for item in checks))
        self.assertEqual(budget["limits"]["browser/detailed"]["cpu_seconds"]["maximum"], 12.55)
        self.assertEqual(budget["limits"]["browser/detailed"]["store_bytes"]["maximum"], 12.5)

    def test_regression_fails_without_changing_budget(self):
        baseline = report()
        budget = cost.freeze(baseline)
        before = copy.deepcopy(budget)
        candidate = copy.deepcopy(baseline)
        candidate["run_id"] = "candidate"
        for sample in candidate["samples"]:
            if sample["harness"] == "browser" and sample["preset"] == "detailed":
                sample["metrics"]["replay_bytes"] = 30
        self.assertEqual(sum(not item["passed"] for item in cost.check(candidate, budget)), 1)
        self.assertEqual(budget, before)

    def test_reject_failed_or_missing_samples(self):
        for mutate in (lambda r: r.update(passed=False),
                       lambda r: r["samples"].pop(),
                       lambda r: r["samples"][0].update(passed=False),
                       lambda r: r["samples"][0].update(repeat=2)):
            with self.subTest(mutate=mutate):
                value = report()
                mutate(value)
                with self.assertRaises(ValueError):
                    cost.freeze(value)

    def test_unknown_nonfinite_and_boolean_metrics_fail(self):
        for number in (None, float("nan"), float("inf"), -1, True):
            with self.subTest(number=number):
                value = report()
                value["samples"][0]["metrics"]["store_bytes"] = number
                with self.assertRaises(ValueError):
                    cost.freeze(value)

    def test_association_changes_fail(self):
        value = report()
        value["samples"][2]["native_identity_sha256"] = "different-parent"
        with self.assertRaisesRegex(ValueError, "native associations"):
            cost.freeze(value)

    def test_environment_input_instrument_mismatch(self):
        baseline = report()
        budget = cost.freeze(baseline)
        for name in ("environment", "inputs", "measurement_sha256"):
            candidate = copy.deepcopy(baseline)
            candidate.update(run_id="new")
            candidate[name] = "changed"
            with self.assertRaisesRegex(ValueError, "identity"):
                cost.check(candidate, budget)
        with self.assertRaisesRegex(ValueError, "fresh"):
            cost.check(baseline, budget)

    def test_missing_budget_metric_rejected(self):
        value = report()
        budget = cost.freeze(value)
        del budget["limits"]["browser/detailed"]["store_bytes"]
        value["run_id"] = "new"
        with self.assertRaisesRegex(ValueError, "metrics"):
            cost.check(value, budget)

    def test_native_identity_is_order_independent_and_body_independent(self):
        entries = [{"kind": "tool_call", "tool_call_id": "a", "source": {"harness": "jupyter", "session_id": "s"},
                    "notebook": {"message_id": "1"}, "content": {"state": "stored"}},
                   {"kind": "tool_result", "tool_call_id": "a", "source": {"harness": "jupyter", "session_id": "s"},
                    "notebook": {"parent_message_id": "1"}}]
        alternate = copy.deepcopy(entries[::-1])
        alternate[1]["content"] = {"state": "omitted"}
        self.assertEqual(cost.native_identity(entries), cost.native_identity(alternate))
        alternate[0]["notebook"]["parent_message_id"] = "2"
        self.assertNotEqual(cost.native_identity(entries), cost.native_identity(alternate))

    def test_measured_child_exit_and_private_logs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = cost.execute([sys.executable, "-c", "print('ok')"], root / "success")
            self.assertEqual(result["exit_code"], 0)
            self.assertGreater(result["wall_seconds"], 0)
            self.assertGreater(result["peak_rss_bytes"], 0)
            self.assertEqual((root / "success").stat().st_mode & 0o777, 0o700)
            with self.assertRaisesRegex(ValueError, "CLI failed"):
                cost.execute([sys.executable, "-c", "raise SystemExit(7)"], root / "failure")
            self.assertEqual(json.loads((root / "failure/measurement.json").read_text())["exit_code"], 7)

    def test_timeout_reaps_child_and_retains_measurement(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "timeout"
            with self.assertRaisesRegex(ValueError, "CLI failed"):
                cost.execute([sys.executable, "-c", "import time; time.sleep(60)"], root, timeout=.1)
            result = json.loads((root / "measurement.json").read_text())
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["exit_code"], -9)

    def test_storage_is_logical_bytes_and_save_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cost.save(root / "a.json", {"one": 1})
            result = cost.store_inventory(root)
            self.assertEqual(result["bytes"], (root / "a.json").stat().st_size)
            with self.assertRaises(FileExistsError):
                cost.save(root / "a.json", {"two": 2})

    def test_replay_selection_requires_exact_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "replay.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("export-inventory.json", json.dumps({"signed": False,
                                 "contents": {"context_entries": 4, "attachment_refs": 1}}))
            cost.replay_inventory(path, 4, 1)
            for entries, attachments in ((3, 1), (4, 0)):
                with self.assertRaises(ValueError):
                    cost.replay_inventory(path, entries, attachments)


if __name__ == "__main__":
    unittest.main()
