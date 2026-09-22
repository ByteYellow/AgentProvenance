import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import judge


class JevTests(unittest.TestCase):
    def response(self):
        return {"model": "test-model", "answers": {
            name: {"type": "choice", "choice": next(iter(q["criteria"])),
                   "probabilities": {k: float(i == 0) for i, k in enumerate(q["criteria"])},
                   "confidence": 1.0}
            for name, q in judge.QUESTIONS.items()
        }}

    def test_valid_answers(self):
        self.assertEqual(len(judge.validate_answers(self.response(), judge.QUESTIONS)), 3)

    def test_unrequested_answers_are_not_exportable(self):
        response = self.response()
        response["answers"]["unrequested_question"] = copy.deepcopy(response["answers"]["secret_transfer"])
        with self.assertRaisesRegex(ValueError, "exactly the requested questions"):
            judge.validate_answers(response, judge.QUESTIONS)

    def test_invalid_answers_fail_closed(self):
        for response in (None, [], "not an object"):
            with self.assertRaises(ValueError):
                judge.validate_answers(response, judge.QUESTIONS)
        mutations = [
            lambda r: r["answers"].pop("secret_transfer"),
            lambda r: r["answers"]["secret_transfer"].update(choice="safe"),
            lambda r: r["answers"]["secret_transfer"].update(probabilities={"confirmed": 1}),
            lambda r: r["answers"]["secret_transfer"]["probabilities"].update(confirmed=float("nan")),
            lambda r: r["answers"]["secret_transfer"]["probabilities"].update(confirmed=True),
            lambda r: r["answers"]["secret_transfer"].update(confidence=float("inf")),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                response = self.response()
                mutate(response)
                with self.assertRaises(ValueError):
                    judge.validate_answers(response, judge.QUESTIONS)

    def test_secret_file_parser_does_not_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            path.write_text("export TYPESAFE_API_KEY='example-test-key-not-real'")
            self.assertEqual(judge.load_key(path, "typesafe"), "example-test-key-not-real")
            with self.assertRaises(ValueError):
                judge.load_key(path, "vercel")
            path.write_text("one\ntwo")
            with self.assertRaises(ValueError):
                judge.load_key(path, "typesafe")

    def test_sensitive_artifacts_are_private_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response.json"
            wire_bytes = b'{ "model": "example" }'
            judge.save_bytes(path, wire_bytes)
            self.assertEqual(path.read_bytes(), wire_bytes)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                judge.save(path, {})

    def test_authentication_key_is_not_sent_as_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            key = "example-test-key-not-real"
            with self.assertRaisesRegex(ValueError, "authentication key"):
                judge.evaluate("typesafe", key, {"accidental_key": key}, judge.QUESTIONS, Path(directory))
            self.assertFalse((Path(directory) / "request.json").exists())

    def test_http_failure_does_not_become_benign_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            failure = urllib.error.HTTPError("https://api.typesafe.ai/v1/systemone", 429, "limited", {}, None)
            with patch.object(judge.urllib.request, "build_opener") as opener:
                opener.return_value.open.side_effect = failure
                with self.assertRaisesRegex(RuntimeError, "HTTP 429"):
                    judge.evaluate("typesafe", "example-test-key-not-real", {}, judge.QUESTIONS, Path(directory))
                self.assertEqual(opener.return_value.open.call_count, 1)
            error = json.loads((Path(directory) / "error.json").read_text())
            self.assertEqual(error["disposition"], "unknown_requires_review")
            self.assertFalse((Path(directory) / "result.json").exists())

    def test_redirect_is_not_followed(self):
        self.assertIsNone(judge.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.org"))

    def test_original_bundle_selection_and_coverage(self):
        bundle = Path(__file__).resolve().parents[1] / "multiagent-provenance/run-double-attempt.forensics.json.gz"
        manifest = judge.make_cases(bundle)
        self.assertEqual(len(manifest["cases"]), 6)
        by_id = {case["id"]: case for case in manifest["cases"]}
        rich = by_id["runtime_evidence"]["state"]
        self.assertTrue(rich["runtime_events"])
        self.assertIn("NOT established", rich["coverage"]["attribution"])
        self.assertFalse(rich["coverage"]["outbound_body_captured"])
        self.assertIn("/.aws/credentials", json.dumps(rich))
        self.assertIn("169.254.169.254", json.dumps(rich))
        self.assertIn("not monitored", by_id["refusal_coverage_gap"]["state"]["coverage"])
        self.assertEqual(by_id["install_command_only"]["state"]["runtime_events"], [])
        modified = copy.deepcopy(by_id["adversarial_context"]["state"])
        modified.pop("untrusted_tool_output")
        self.assertEqual(modified, rich)
        self.assertEqual(by_id["normal_read_control"]["origin"], "synthetic_control")
        self.assertNotIn("risk_signals", rich)
        self.assertNotIn("policy_decision", rich["declared_action"])


if __name__ == "__main__":
    unittest.main()
