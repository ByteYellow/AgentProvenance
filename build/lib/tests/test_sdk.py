"""Stdlib-unittest tests for the AgentProvenance Python SDK.

These mock the agentprov CLI (no binary or DB needed) and lock the SDK's
RL-facing surfaces: reward reduction, online trajectory scoring, unified-signal
read-back, the evaluator registry, and report determinism.

Run: python3 -m unittest discover -s python/tests
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import agentprov_eval as ap


class FakeClient(ap.Client):
    """Client whose run_cli is replaced by a canned-response dispatcher."""

    def __init__(self, responses):
        super().__init__(timeout=1)
        self._responses = responses
        self.calls = []

    def run_cli(self, args, *, input_text=None):
        self.calls.append(list(args))
        key = args[0] if args else ""
        if key == "signals":
            key = "signals"
        elif key == "signal" and len(args) > 1:
            key = "signal:" + args[1]
        payload = self._responses.get(key, {})
        return ap.CommandResult(args=list(args), returncode=0, stdout=json.dumps(payload), stderr="")


class SignalTests(unittest.TestCase):
    def test_to_dict_omits_empty(self):
        s = ap.Signal.reward_feature("win", 1.0, "passed")
        d = s.to_dict()
        self.assertEqual(d["kind"], ap.KIND_REWARD_FEATURE)
        self.assertEqual(d["score"], 1.0)
        self.assertNotIn("label", d)

    def test_dataset_label_carries_label(self):
        s = ap.Signal.dataset_label("cls", "good", 0.5, "ok")
        self.assertEqual(s.to_dict()["label"], "good")


class RegistryTests(unittest.TestCase):
    def test_rule_decorator_and_evaluate(self):
        reg = ap.Registry(name="t")

        @reg.rule(name="always_one")
        def _(ctx):
            return ap.Signal.reward_feature("always_one", 1.0, "r")

        report = ap.evaluate_context({"run_id": "run-1"}, registry=reg, engine="t")
        self.assertEqual(report["run_id"], "run-1")
        self.assertEqual(report["signal_count"], 1)
        self.assertEqual(report["signals"][0]["name"], "always_one")
        self.assertTrue(report["page_hash"].startswith("sha256:"))

    def test_report_hash_is_deterministic(self):
        reg = ap.Registry()
        reg.register(lambda ctx: ap.Signal.penalty("p", -1.0, "r"), name="p")
        a = ap.evaluate_context({"run_id": "r"}, registry=reg, engine="e")
        b = ap.evaluate_context({"run_id": "r"}, registry=reg, engine="e")
        self.assertEqual(a["page_hash"], b["page_hash"])


class RewardTests(unittest.TestCase):
    def _score(self):
        return ap.TrajectoryScore(
            run_id="r",
            record_manifest={},
            context={},
            report={"signals": [
                {"kind": ap.KIND_REWARD_FEATURE, "name": "win", "score": 1.0},
                {"kind": ap.KIND_PENALTY, "name": "slow", "score": -0.3},
                {"kind": ap.KIND_QUALITY_SIGNAL, "name": "q", "score": 9.0},
            ]},
        )

    def test_default_reward_excludes_quality(self):
        self.assertAlmostEqual(self._score().reward(), 0.7)

    def test_weighted_reward(self):
        self.assertAlmostEqual(self._score().reward(weights={"win": 2.0}), 2.0)

    def test_include_kinds_override(self):
        r = self._score().reward(include_kinds=(ap.KIND_QUALITY_SIGNAL,))
        self.assertAlmostEqual(r, 9.0)


class ClientTests(unittest.TestCase):
    def test_score_trajectory_assembles_report(self):
        client = FakeClient({
            "record": {"run_id": "run-x", "schema_version": "agentprovenance.record_manifest/v1"},
            "signal:context": {"run_id": "run-x", "risks": [], "runtime_events": []},
        })
        reg = ap.Registry(name="rl")
        reg.register(lambda ctx: ap.Signal.reward_feature("ok", 1.0, "r"), name="ok")

        score = client.score_trajectory(["echo", "hi"], reg, run_id="run-x")
        self.assertIsInstance(score, ap.TrajectoryScore)
        self.assertEqual(score.run_id, "run-x")
        self.assertAlmostEqual(score.reward(), 1.0)
        # record then signal context were both invoked.
        self.assertEqual(client.calls[0][0], "record")
        self.assertIn(["signal", "context", "--run", "run-x"], client.calls)

    def test_signals_readback(self):
        client = FakeClient({
            "signals": {"schema_version": "agentprovenance.signals/v1", "count": 2,
                        "counts": {"security": 1, "quality": 1}, "signals": []},
        })
        out = client.signals("run-x")
        self.assertEqual(out["schema_version"], "agentprovenance.signals/v1")
        self.assertEqual(out["counts"]["security"], 1)
        self.assertEqual(client.calls[0], ["signals", "list", "--run", "run-x", "--json"])

    def test_signals_dimension_filter(self):
        client = FakeClient({"signals": {"signals": []}})
        client.signals("run-x", dimension="quality")
        self.assertIn("--dimension", client.calls[0])
        self.assertIn("quality", client.calls[0])


class DaemonModeTests(unittest.TestCase):
    """Daemon hot-path routing: with daemon_url set, record/eval_context/signals
    go over HTTP instead of forking the CLI."""

    def _serve(self, routes):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, key):
                body = json.dumps(routes.get(key, {})).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self._reply(self.path.split("?")[0])

            def do_GET(self):
                self._reply(self.path.split("?")[0])

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def _cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(_cleanup)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def test_record_and_signals_over_daemon(self):
        url = self._serve({
            "/v1/record": {"run_id": "run-daemon", "status": "passed"},
            "/v1/signals": {"schema_version": "agentprovenance.signals/v1", "count": 0, "counts": {}, "signals": []},
            "/v1/signal/context": {"run_id": "run-daemon", "risks": []},
        })
        client = ap.Client(daemon_url=url, timeout=5)
        rec = client.record(["echo", "hi"], run_id="run-daemon")
        self.assertEqual(rec["run_id"], "run-daemon")
        sigs = client.signals("run-daemon")
        self.assertEqual(sigs["schema_version"], "agentprovenance.signals/v1")
        ctx = client.eval_context("run-daemon")
        self.assertEqual(ctx["run_id"], "run-daemon")

    def test_score_trajectory_full_daemon_path(self):
        url = self._serve({
            "/v1/record": {"run_id": "run-d2", "status": "passed"},
            "/v1/signal/context": {"run_id": "run-d2", "risks": []},
        })
        client = ap.Client(daemon_url=url, timeout=5)
        reg = ap.Registry(name="rl")
        reg.register(lambda ctx: ap.Signal.reward_feature("ok", 1.0, "r"), name="ok")
        score = client.score_trajectory(["echo", "hi"], reg, run_id="run-d2")
        self.assertEqual(score.run_id, "run-d2")
        self.assertAlmostEqual(score.reward(), 1.0)


class BatchRecordFaultToleranceTests(unittest.TestCase):
    class _Client(ap.Client):
        def __init__(self):
            super().__init__(timeout=1)

        def record(self, command, **kwargs):
            if "boom" in command:
                raise RuntimeError("boom failed")
            return {"run_id": "ok", "status": "passed"}

    def test_continue_on_error_captures_failures(self):
        jobs = [{"command": ["echo", "a"]}, {"command": ["boom"]}, {"command": ["echo", "b"]}]
        out = self._Client().batch_record(jobs, continue_on_error=True)
        self.assertEqual(len(out), 3)
        self.assertEqual(out[1]["status"], "failed")
        self.assertIn("boom", out[1]["error"])
        self.assertEqual(out[1]["index"], 1)
        self.assertEqual(out[0]["status"], "passed")

    def test_missing_command_captured(self):
        out = self._Client().batch_record([{"command": ["echo"]}, {}], continue_on_error=True)
        self.assertEqual(out[1]["status"], "failed")
        self.assertIn("missing command", out[1]["error"])

    def test_raises_without_continue(self):
        with self.assertRaises(RuntimeError):
            self._Client().batch_record([{"command": ["boom"]}])


class IterEvalContextsTests(unittest.TestCase):
    def test_streams_jsonl_from_binary(self):
        import stat
        import tempfile

        d = tempfile.mkdtemp()
        script = os.path.join(d, "agentprov")
        with open(script, "w") as f:
            f.write('#!/bin/sh\n')
            f.write('printf \'{"run_id":"r1"}\\n{"run_id":"r2"}\\n\'\n')
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)

        client = ap.Client(binary=script, timeout=5)
        got = list(client.iter_eval_contexts(batch_id="b"))
        self.assertEqual([c["run_id"] for c in got], ["r1", "r2"])

    def test_nonzero_exit_raises(self):
        import stat
        import tempfile

        d = tempfile.mkdtemp()
        script = os.path.join(d, "agentprov")
        with open(script, "w") as f:
            f.write('#!/bin/sh\necho "boom" 1>&2\nexit 3\n')
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)

        client = ap.Client(binary=script, timeout=5)
        with self.assertRaises(RuntimeError):
            list(client.iter_eval_contexts(batch_id="b"))


class ValidationTests(unittest.TestCase):
    def test_valid_signal_passes(self):
        ap.Signal.reward_feature("win", 1.0, "r").validate()  # no raise

    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            ap.validate_signal_dict({"name": "", "kind": ap.KIND_PENALTY, "score": -1.0})

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            ap.validate_signal_dict({"name": "x", "kind": "nonsense", "score": 1.0})

    def test_non_numeric_score_rejected(self):
        with self.assertRaises(ValueError):
            ap.validate_signal_dict({"name": "x", "kind": ap.KIND_REWARD_FEATURE, "score": "high"})

    def test_import_signals_validates_before_send(self):
        client = FakeClient({"signal:import": {"ok": True}})
        with self.assertRaises(ValueError):
            client.import_signals("run-x", [{"name": "x", "kind": "bogus", "score": 1.0}])
        # no CLI call should have been made (validation failed first)
        self.assertEqual(client.calls, [])


if __name__ == "__main__":
    unittest.main()
