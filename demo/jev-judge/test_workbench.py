import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import judge
import rules
import workbench as wb


REFERENCES = {
    "install_command_only": ("task_work", "unknown", "unknown"),
    "install_peer_context": ("task_work", "unknown", "unknown"),
    "runtime_evidence": ("task_work", "deviation", "suspected"),
    "refusal_coverage_gap": ("refusal", "unknown", "unknown"),
    "normal_read_control": ("task_work", "aligned", "not_observed"),
    "adversarial_context": ("task_work", "deviation", "suspected"),
}


def make_fixture(root, regression=False):
    """Explicitly synthetic provider answers; no network or human approval."""
    bundle = Path(__file__).resolve().parents[1] / "multiagent-provenance/run-double-attempt.forensics.json.gz"
    manifest = judge.make_cases(bundle)
    judge.save(root / "cases.json", manifest)
    verification = {"status": "ok", "error_count": 0, "source": "test_fixture_not_signature_verification"}
    judge.save(root / "verification.json", verification)
    profile_set, reports = rules.profiles(), {}
    for version, profile in profile_set.items():
        judge.save(root / "rules" / (version + ".json"), profile)
        results = []
        for case in manifest["cases"]:
            choices = dict(zip(judge.QUESTIONS, REFERENCES[case["id"]]))
            if version == "v1" and case["id"] == "refusal_coverage_gap":
                choices["secret_transfer"] = "not_observed"
            if regression and version == "v2" and case["id"] == "normal_read_control":
                choices["runtime_conformance"] = "deviation"
            answers = {q: {"type": "choice", "choice": choice,
                           "probabilities": {label: float(choice == label) for label in profile["questions"][q]["criteria"]}}
                       for q, choice in choices.items()}
            request = {"model": "synthetic-test-model", "state": case["state"], "questions": profile["questions"]}
            response = {"model": "synthetic-test-model", "answers": answers}
            directory = root / "evaluations" / version / case["id"]
            judge.save_bytes(directory / "request.json", judge.encode(request))
            judge.save_bytes(directory / "response.json", judge.encode(response))
            result = {"case_id": case["id"], "answers": answers, "requested_model": response["model"],
                      "returned_model": response["model"], "request_sha256": wb.canonical_hash(request),
                      "response_sha256": wb.canonical_hash(response), "questions_sha256": wb.canonical_hash(profile["questions"]),
                      "latency_ms": 10.0, "usage": {"input_tokens": 42}}
            judge.save(directory / "result.json", result)
            results.append(result)
        reports[version] = {"profile_sha256": wb.canonical_hash(profile), "dataset_sha256": wb.canonical_hash(manifest), "results": results}
        judge.save(root / "evaluations" / version / "report.json", reports[version])
    study = {"schema_version": "agentprovenance.jev_review/v1", "run_id": manifest["run_id"],
             "bundle_sha256": manifest["bundle_sha256"], "dataset_sha256": wb.canonical_hash(manifest),
             "guard_version": rules.GUARD_VERSION, "verification_sha256": wb.canonical_hash(verification),
             "profiles": {v: wb.canonical_hash(p) for v, p in profile_set.items()},
             "reports": {v: wb.canonical_hash(r) for v, r in reports.items()},
             "evaluation_kind": "synthetic_test_fixture", "created_at": wb.now()}
    judge.save(root / "study.json", study)
    return wb.Study(root)


def review_body(state, case_id="runtime_evidence"):
    return {"revision": state["revision"], "case_id": case_id, "reviewer": "automated-test-not-human",
            "reason": "Test reference labels, not a real human review",
            "labels": dict(zip(judge.QUESTIONS, REFERENCES[case_id]))}


def review_all(study):
    for case_id in REFERENCES:
        study.append("review", review_body(study.snapshot(), case_id))


def approve(study):
    return study.append("decision", {"revision": study.snapshot()["revision"], "status": "approved",
                                     "reviewer": "automated-test-not-human", "reason": "Exercise approval gate in isolated test data"})


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.study = make_fixture(self.root)

    def test_profiles_are_independent_and_coverage_guard_preserves_raw_answer(self):
        snapshot = self.study.snapshot()
        self.assertIn("+", snapshot["rule_diff"])
        self.assertEqual(snapshot["profiles"]["v1"]["questions"], judge.QUESTIONS)
        case = next(c for c in snapshot["cases"] if c["id"] == "refusal_coverage_gap")
        self.assertEqual(case["evaluations"]["v1"]["answers"]["secret_transfer"]["choice"], "not_observed")
        self.assertEqual(case["evaluations"]["v1"]["effective"]["choices"]["secret_transfer"], "unknown")
        self.assertEqual(snapshot["metrics"]["v1"]["guard_overrides"], 1)
        self.assertEqual(snapshot["metrics"]["v2"]["guard_overrides"], 0)
        self.assertEqual(snapshot["reviewed_cases"], 0)

    def test_missing_reviews_cannot_approve_or_export(self):
        with self.assertRaisesRegex(ValueError, "Review every"):
            approve(self.study)
        with self.assertRaisesRegex(ValueError, "approval"):
            self.study.signals()
        self.assertEqual(self.study.snapshot()["revision"], 0)

    def test_review_revisions_preserve_provider_evidence(self):
        before = {p: p.read_bytes() for p in self.root.rglob("*.json")}
        first = self.study.append("review", review_body(self.study.snapshot()))
        body = review_body(first)
        body["reason"] = "Updated reasoning in a new review revision"
        self.study.append("review", body)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        restarted = wb.Study(self.root).snapshot()
        self.assertEqual(restarted["revision"], 2)
        self.assertEqual(restarted["reviewed_cases"], 1)
        self.assertEqual(restarted["audit"][1]["previous_sha256"], wb.canonical_hash(restarted["audit"][0]))
        self.assertEqual((self.root / "reviews/000001.json").stat().st_mode & 0o777, 0o600)

    def test_review_must_be_explicit_and_respect_missing_runtime(self):
        body = review_body(self.study.snapshot(), "refusal_coverage_gap")
        body["labels"]["secret_transfer"] = "not_observed"
        with self.assertRaisesRegex(ValueError, "No runtime coverage"):
            self.study.append("review", body)
        for key, value in [("labels", {}), ("reviewer", ""), ("reason", ""), ("case_id", "../etc/passwd")]:
            invalid = review_body(self.study.snapshot())
            invalid[key] = value
            with self.assertRaises(ValueError):
                self.study.append("review", invalid)

    def test_approval_export_and_review_change_invalidates_approval(self):
        review_all(self.study)
        state = approve(self.study)
        self.assertTrue(state["decision_current"])
        self.assertEqual(state["metrics"]["v1"]["raw_disagreements"], 1)
        self.assertEqual(state["metrics"]["v2"]["raw_disagreements"], 0)
        self.assertEqual(state["metrics"]["v1"]["effective_disagreements"], 0)
        signals = self.study.signals()["signals"]
        self.assertEqual(len(signals), 3)
        self.assertTrue(all(s["kind"] == "quality_signal" and s["run_id"] == "run-double-attempt" for s in signals))
        self.assertTrue(all(s["evidence"]["human_review"]["case_id"] == "runtime_evidence" for s in signals))
        body = review_body(state)
        body["reason"] = "Changed rationale invalidates the previous approval"
        self.study.append("review", body)
        self.assertFalse(self.study.snapshot()["decision_current"])
        with self.assertRaises(ValueError):
            self.study.signals()

    def test_candidate_regression_cannot_be_offset_by_another_improvement(self):
        with tempfile.TemporaryDirectory() as directory:
            study = make_fixture(Path(directory), regression=True)
            review_all(study)
            state = study.snapshot()
            self.assertEqual(state["metrics"]["v1"]["raw_disagreements"], state["metrics"]["v2"]["raw_disagreements"])
            self.assertIn("normal_read_control:runtime_conformance", state["raw_regressions"])
            with self.assertRaisesRegex(ValueError, "regresses"):
                approve(study)

    def test_reject_does_not_require_fabricated_reference_labels(self):
        state = self.study.append("decision", {"revision": 0, "status": "rejected", "reviewer": "test",
                                               "reason": "Insufficient coverage; no further evaluation"})
        self.assertEqual(state["reviewed_cases"], 0)
        self.assertEqual(state["decision"]["status"], "rejected")
        with self.assertRaises(ValueError):
            self.study.signals()

    def test_stale_concurrent_write_is_rejected(self):
        body = review_body(self.study.snapshot())
        second = wb.Study(self.root)
        def write(study):
            try:
                study.append("review", body)
                return "saved"
            except wb.Conflict:
                return "conflict"
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(write, [self.study, second]))
        self.assertCountEqual(results, ["saved", "conflict"])
        self.assertEqual(self.study.snapshot()["revision"], 1)

    def test_changed_wire_body_or_rules_fail_integrity_checks(self):
        for path in [self.root / "rules/v2.json", self.root / "evaluations/v1/runtime_evidence/response.json",
                     self.root / "cases.json", self.root / "verification.json"]:
            original = path.read_bytes()
            path.write_bytes(b"{}")
            with self.assertRaises((ValueError, KeyError)):
                self.study.snapshot()
            path.write_bytes(original)

    def test_journal_gap_and_changed_study_invalidate_review(self):
        self.study.append("review", review_body(self.study.snapshot()))
        self.study.append("review", review_body(self.study.snapshot()))
        path = self.root / "reviews/000001.json"
        path.unlink()
        with self.assertRaisesRegex(ValueError, "journal integrity"):
            self.study.snapshot()

    def test_last_event_modification_is_detected_without_a_next_event(self):
        self.study.append("review", review_body(self.study.snapshot()))
        path = self.root / "reviews/000001.json"
        event = json.loads(path.read_text())
        event["reason"] = "Accidental modification of the newest record"
        path.write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError, "journal integrity"):
            self.study.snapshot()

    def test_failed_public_cli_verification_never_calls_provider(self):
        args = SimpleNamespace(send_raw=True, data_dir=self.root / "failed-study",
                               key_file=Path("unused-key"), provider="typesafe", agentprov=Path("agentprov"),
                               bundle=Path(__file__).resolve().parents[1] / "multiagent-provenance/run-double-attempt.forensics.json.gz",
                               pub_key=Path("unused-public-key"))
        with patch.object(judge, "load_key", return_value="test-not-a-live-key"), \
                patch.object(wb, "run_cli", side_effect=[{}, {"status": "failed", "error_count": 1}]), \
                patch.object(judge, "evaluate") as evaluate:
            with self.assertRaisesRegex(ValueError, "Graph verification failed"):
                wb.capture(args)
            evaluate.assert_not_called()
        self.assertFalse((args.data_dir / "study.json").exists())

    def test_incomplete_atomic_write_is_not_a_review(self):
        (self.root / "reviews/.pending-interrupted").write_text("partial")
        self.assertEqual(self.study.snapshot()["revision"], 0)

    def test_server_is_local_bounded_and_artifact_paths_are_allowlisted(self):
        server = wb.make_server(self.study, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        base = "http://127.0.0.1:%d" % server.server_port
        self.assertEqual(server.server_address[0], "127.0.0.1")
        with urllib.request.urlopen(base + "/api/state") as response:
            state = json.load(response)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        def status(path, body=None, headers=None):
            request = urllib.request.Request(base + path, data=body, headers=headers or {})
            try:
                with urllib.request.urlopen(request) as response:
                    return response.status
            except urllib.error.HTTPError as error:
                return error.code
        token = {"Content-Type": "application/json", "X-Review-Token": state["csrf_token"]}
        body = judge.encode(review_body(state))
        self.assertEqual(status("/api/review", body), 403)
        self.assertEqual(status("/api/review", body, {**token, "Origin": "https://untrusted.example"}), 403)
        self.assertEqual(status("/api/state", headers={"Host": "rebind.example"}), 403)
        self.assertEqual(status("/api/review", b"x" * (wb.MAX_BODY + 1), token), 413)
        self.assertEqual(status("/api/review", body, token), 200)
        self.assertEqual(status("/api/review", body, token), 409)
        self.assertEqual(status("/api/artifact/v1/runtime_evidence/request.json"), 200)
        self.assertEqual(status("/api/artifact/v1/runtime_evidence/../../../study.json"), 404)
        self.assertEqual(status("/api/artifact/v1/runtime_evidence/result.json"), 404)
        self.assertEqual(status("/api/signals"), 409)
        self.assertEqual(status("/../../etc/passwd"), 404)
        self.assertEqual(status("/"), 200)


if __name__ == "__main__":
    unittest.main()
