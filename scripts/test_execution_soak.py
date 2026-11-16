"""Keyless unit tests and a bounded loopback HTTP fixture smoke.

Run normal tests: python3 -m unittest discover -s scripts -p test_execution_soak.py -v
Run the longer fixture smoke (at most 60 seconds, no existing daemon touched):
  AGENTPROV_SOAK_SMOKE_SECONDS=55 python3 -m unittest discover -s scripts -p test_execution_soak.py -v
Set AGENTPROV_SOAK_SMOKE_OUTPUT to a new directory to retain only the smoke's
report, bounded samples, and fixture description (never its token/config files).

The fixture executes only /bin/echo; its native health/checkpoints are synthetic.
Procfs parsing and PID reuse are tested independently with temporary proc files.
"""

import contextlib
import copy
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import accept_execution_soak as soak


CONFIG = {"caller": {"principal_id": "fixture-operator", "producer_id": "fixture-caller", "namespace": "fixture"},
          "target": {"producer_id": "fixture-executor", "instance_id": "owned", "generation": "first"},
          "capture": {"mode": "native"}}
TOKEN = "unit-secret-not-for-report"


def health():
    return {"schema_version": "agentprovenance.daemon_health/v1", "ready": True, "status": "ok",
            "coverage_status": "no_recorded_gaps", **{key: 0 for key in soak.QUEUES},
            "native_capture": {**{key: 0 for key in soak.NATIVE_GAUGES}, "counters": {"captured": 2, "ingested": 2}}}


def readiness():
    return {"schema_version": soak.SCHEMA, "target": CONFIG["target"], "principal_id": CONFIG["caller"]["principal_id"],
            "source_producer_id": CONFIG["caller"]["producer_id"], "source_namespace": CONFIG["caller"]["namespace"],
            "worker_running": True, "native_capture": True, "capture_ready": True}


def completed(request, attempt_id="attempt-fixture"):
    return {"attempt": {"id": attempt_id, "request": request, "request_hash": "a" * 64,
                        "state": {"execution": "succeeded", "capture": "sealed"}},
            "checkpoint_ref": "sha256:" + "b" * 64,
            "checkpoint": {"attempt_id": attempt_id, "request_hash": "a" * 64,
                           "source": request["source"], "target": request["target"],
                           "capture_report": {"state": "sealed", "start": {"at": "fixture"}, "end": {"at": "fixture"},
                                              "scope_progress": {"state": "settled", "events": 2, "ingested": 2,
                                                                 "dropped": 0, "failed": 0, "pending": 0, "sampling_gaps": 0}}}}


class Fixture:
    def __init__(self):
        self.requests, self.stops, self.attempts = [], [], {}
        self.health_calls = 0
        self.stuck, self.wrong_identity, self.drop_admission = False, False, False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, status, value):
                raw = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    return self.send(401, {"secret": TOKEN})
                if self.path == "/v1/execution-readiness":
                    value = readiness()
                    if owner.wrong_identity:
                        value["target"] = dict(value["target"], generation="foreign")
                    return self.send(200, value)
                if self.path == "/v1/health":
                    owner.health_calls += 1
                    value = health()
                    value["native_capture"]["counters"] = {"captured": owner.health_calls * 2, "ingested": owner.health_calls * 2}
                    if owner.health_calls == 1:
                        value["queued_spool"] = 1
                        value["queued_spool_bytes"] = 4096
                    if owner.health_calls == 2:
                        value["ready"] = False
                        value["status"] = "unavailable"
                        value["checks"] = {"storage": {"reason": TOKEN + "/private/fixture-path"}}
                        return self.send(503, value)
                    return self.send(200, value)
                if self.path == "/v1/large":
                    return self.send(200, {"body": "x" * soak.MAX_RESPONSE})
                if self.path == "/v1/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://192.0.2.1/never-follow?token=" + TOKEN)
                    self.end_headers()
                    return
                if self.path == "/v1/slow":
                    time.sleep(.3)
                    return self.send(200, {})
                attempt = owner.attempts.get(self.path.removeprefix("/v1/executions/"))
                if attempt:
                    value = completed(attempt["request"], attempt["id"])
                    if owner.stuck:
                        value["attempt"]["state"]["execution"] = "running"
                    return self.send(200, value)
                return self.send(404, {"error": "fixture_missing"})

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    return self.send(401, {})
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path.endswith("/stop"):
                    owner.stops.append(self.path.split("/")[-2])
                    return self.send(202, {"status": "stop_requested"})
                if self.path != "/v1/executions":
                    return self.send(404, {})
                owner.requests.append(body)
                argv = body["command"]["argv"]
                if len(argv) != 2 or argv[0] != "/bin/echo" or not argv[1].startswith("soak-"):
                    return self.send(400, {})
                subprocess.run(argv, check=True, capture_output=True, timeout=1)
                attempt_id = "attempt-" + str(len(owner.requests))
                attempt = {"id": attempt_id, "request": body}
                owner.attempts[attempt_id] = attempt
                if owner.drop_admission:
                    self.close_connection = True
                    return
                return self.send(202, {"attempt": attempt, "reused": False})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class ContractTests(unittest.TestCase):
    def test_loopback_only_and_no_credentials_or_url_paths(self):
        self.assertEqual(soak.loopback_url("http://localhost:8080/"), "http://127.0.0.1:8080")
        self.assertEqual(soak.loopback_url("http://[::1]:8080"), "http://[::1]:8080")
        for value in ["http://example.com:80", "http://192.0.2.1:80", "http://127.0.0.1", "ftp://127.0.0.1:80",
                      "http://user:secret@127.0.0.1:80", "http://127.0.0.1:80/a", "http://127.0.0.1:80?token=x", "http://127.0.0.1:80#x"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                soak.loopback_url(value)

    def test_independent_foreground_requests(self):
        first = soak.request_for(CONFIG, "nonce", 0, 10)
        second = soak.request_for(CONFIG, "nonce", 1, 10)
        self.assertNotEqual(first["operation_id"], second["operation_id"])
        self.assertNotEqual(first["dispatch_id"], second["dispatch_id"])
        self.assertNotEqual(first["source"]["tool_call_id"], second["source"]["tool_call_id"])
        self.assertEqual(first["command"]["argv"], ["/bin/echo", first["operation_id"]])
        self.assertTrue(first["command"]["disable_snapshot"])
        self.assertNotIn("previous_attempt_id", first)

    def test_readiness_must_match_operator_target_and_principal(self):
        soak.validate_readiness(readiness(), CONFIG)
        for key in ["target", "principal_id", "source_namespace", "source_producer_id", "worker_running", "capture_ready"]:
            value = readiness()
            value[key] = False
            with self.subTest(key=key), self.assertRaises(soak.APIError):
                soak.validate_readiness(value, CONFIG)

    def test_health_projection_preserves_unknowns_and_omits_raw_errors(self):
        value = health()
        value["native_capture"]["last_error"] = TOKEN
        value["checks"] = {"storage": {"reason": "/private/secret"}}
        projected = soak.health_projection(value)
        self.assertTrue(projected["native_error_present"])
        self.assertNotIn(TOKEN, json.dumps(projected))
        self.assertNotIn("/private", json.dumps(projected))
        del value["native_capture"]
        value["queued_spool"] = None
        projected = soak.health_projection(value)
        self.assertIsNone(projected["counters"]["captured"])
        self.assertIsNone(projected["native"]["pending_events"])
        self.assertIsNone(projected["queues"]["queued_spool"])

    def test_counter_resets_are_not_negative_loss_or_zero(self):
        delta, resets = soak.counter_delta({"drop": 8, "read": 3}, {"drop": 1, "read": 9, "missing": None})
        self.assertEqual(resets, ["drop"])
        self.assertIsNone(delta["drop"])
        self.assertIsNone(delta["missing"])
        self.assertEqual(delta["read"], 6)

    def test_completed_scope_consistency_and_real_gap_failures(self):
        request = soak.request_for(CONFIG, "n", 1, 10)
        value = completed(request)
        self.assertEqual(soak.completion(value, request, "attempt-fixture", True)["checkpoint_consistency"], "matched")
        starting = copy.deepcopy(value)
        starting["attempt"]["state"]["execution"] = "starting"
        self.assertIsNone(soak.completion(starting, request, "attempt-fixture", True))
        for mutation in ["source", "hash", "gap", "pending", "incomplete", "foreign_id"]:
            value = copy.deepcopy(completed(request))
            if mutation == "source":
                value["checkpoint"]["source"] = {}
            elif mutation == "hash":
                value["checkpoint"]["request_hash"] = "changed"
            elif mutation == "foreign_id":
                value["attempt"]["id"] = "other"
            elif mutation == "incomplete":
                value["checkpoint"]["capture_report"]["state"] = "incomplete"
            else:
                value["checkpoint"]["capture_report"]["scope_progress"]["sampling_gaps" if mutation == "gap" else "pending"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(soak.APIError):
                soak.completion(value, request, "attempt-fixture", True)

    def test_trends_and_observed_vs_unobserved_recovery(self):
        value = soak.trend([(0, 10), (10, 20), (20, 30), (30, None)])
        self.assertEqual(value["slope_per_hour"], 3600)
        self.assertEqual(value["p95"], 30)
        self.assertIsNone(soak.trend([(0, 0)])["slope_per_hour"])
        samples = [{"elapsed_seconds": 0, "ok": True}, {"elapsed_seconds": 2, "ok": False},
                   {"elapsed_seconds": 5, "ok": True}, {"elapsed_seconds": 6, "ok": False}]
        recovery = soak.recovery_intervals(samples, "ok", 8)
        self.assertEqual(recovery["intervals"][0]["duration_seconds"], 3)
        self.assertFalse(recovery["intervals"][1]["recovered"])
        self.assertEqual(soak.recovery_intervals(samples[:1], "ok", 8)["status"], "not_observed")

    def test_jsonl_bounds_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "samples.jsonl"
            log = soak.JSONL(path, 1, 100)
            try:
                log.write({"sample": 1})
                with self.assertRaisesRegex(soak.APIError, "jsonl_limit"):
                    log.write({"sample": 2})
                self.assertLessEqual(path.stat().st_size, 100)
                with self.assertRaises(FileExistsError):
                    soak.JSONL(path, 1, 100)
            finally:
                log.stream.close()
            log = soak.JSONL(path.with_name("small.jsonl"), 10, 5)
            try:
                with self.assertRaises(soak.APIError):
                    log.write({"sample": 1})
                self.assertEqual(log.bytes, 0)
            finally:
                log.stream.close()


class ProcTests(unittest.TestCase):
    def test_stat_command_parentheses_and_proc_birth_identity(self):
        fields = ["S"] + ["0"] * 49
        fields[11], fields[12], fields[19], fields[21] = "30", "20", "1234567", "42"
        text = "42 (name ) with ( spaces) " + " ".join(fields)
        self.assertEqual(soak.proc_stat(text, 42), {"start_ticks": 1234567, "cpu_ticks": 50, "rss_pages": 42})
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / "sys/kernel/random").mkdir(parents=True)
            (root / "sys/kernel/random/boot_id").write_text("fixture-boot")
            (root / "42/ns").mkdir(parents=True)
            (root / "42/stat").write_text(text)
            (root / "42/ns/pid").symlink_to("pid:[42]")
            current = soak.read_process(42, root)
            self.assertEqual(current["status"], "ok")
            self.assertEqual(current["identity"]["start_ticks"], 1234567)
            self.assertEqual(current["identity"]["boot_id"], "fixture-boot")
            self.assertEqual(current["rss_bytes"], 42 * os.sysconf("SC_PAGE_SIZE"))
            self.assertEqual(soak.read_process(43, root)["status"], "unavailable")

    def test_pid_reuse_cannot_create_cpu_delta_or_rss_trend(self):
        previous = {"status": "ok", "identity": {"boot_id": "boot", "pid": 42, "start_ticks": 100}, "cpu_seconds": 2, "rss_bytes": 100}
        current = dict(previous, cpu_seconds=3)
        self.assertEqual(soak.process_sample(current, previous, previous["identity"], 2)["cpu_percent"], 50)
        for identity in [dict(previous["identity"], start_ticks=200), dict(previous["identity"], boot_id="new")]:
            reused = dict(current, identity=identity)
            value = soak.process_sample(reused, previous, previous["identity"], 2)
            self.assertEqual(value["status"], "identity_changed")
            self.assertIsNone(value["cpu_percent"])
            self.assertIsNone(value["rss_bytes"])


class HTTPTests(unittest.TestCase):
    def test_health_503_keeps_json_and_errors_do_not_leak_secrets(self):
        with Fixture() as fixture:
            api = soak.API(fixture.url, TOKEN)
            api.call("GET", "/v1/health")
            status, body = api.call("GET", "/v1/health")
            self.assertEqual(status, 503)
            self.assertFalse(soak.health_projection(body)["ready"])
            with self.assertRaisesRegex(soak.APIError, "http_401") as error:
                soak.API(fixture.url, "wrong").call("GET", "/v1/health")
            self.assertNotIn(TOKEN, str(error.exception))

    def test_redirect_oversize_and_wall_deadline(self):
        with Fixture() as fixture:
            api = soak.API(fixture.url, TOKEN)
            with self.assertRaisesRegex(soak.APIError, "http_302"):
                api.call("GET", "/v1/redirect")
            with self.assertRaisesRegex(soak.APIError, "response_too_large"):
                api.call("GET", "/v1/large")
            started = time.monotonic()
            with self.assertRaises(soak.APIError):
                api.call("GET", "/v1/slow", timeout=.05)
            self.assertLess(time.monotonic() - started, .25)

    def test_environment_proxy_is_ignored(self):
        with Fixture() as fixture, mock.patch.dict(os.environ, {"http_proxy": "http://192.0.2.1:9", "HTTP_PROXY": "http://192.0.2.1:9", "NO_PROXY": "", "no_proxy": ""}):
            self.assertTrue(soak.API(fixture.url, TOKEN).call("GET", "/v1/execution-readiness")[1]["worker_running"])


class SmokeTests(unittest.TestCase):
    def invoke(self, fixture, root, duration="1.5", extra=(), output=None):
        config, token = root / "operator.json", root / "token"
        config.write_text(json.dumps(CONFIG))
        token.write_text(TOKEN)
        output = output or root / "result"
        argv = [sys.executable, str(pathlib.Path(soak.__file__).resolve()), "--url", fixture.url,
                "--config", str(config), "--token-file", str(token), "--daemon-pid", str(os.getpid()),
                "--agentprov", sys.executable, "--output", str(output), "--duration-seconds", duration,
                "--sample-interval", "0.2" if float(duration) < 10 else "2", "--operation-interval", "0.3" if float(duration) < 10 else "10",
                "--operation-timeout", "0.7", "--request-timeout", "0.2", *extra]
        process = subprocess.run(argv, capture_output=True, text=True, timeout=float(duration) + 5,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        report = json.loads((output / "report.json").read_text())
        jsonl = (output / "samples.jsonl").read_text()
        self.assertNotIn(TOKEN, process.stdout + process.stderr + jsonl + json.dumps(report))
        self.assertNotIn("/private/fixture-path", jsonl)
        return process, report, jsonl

    def test_bounded_smoke(self):
        seconds = float(os.environ.get("AGENTPROV_SOAK_SMOKE_SECONDS", "1.5"))
        self.assertTrue(1 <= seconds <= 60)
        destination = os.environ.get("AGENTPROV_SOAK_SMOKE_OUTPUT")
        output = pathlib.Path(destination) if destination else None
        with Fixture() as fixture, tempfile.TemporaryDirectory() as temp:
            process, report, jsonl = self.invoke(fixture, pathlib.Path(temp), str(seconds), output=output)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(report["status"], "completed")
            self.assertGreater(report["operation_count"], 0)
            self.assertEqual(report["q01_24h"]["status"], "PENDING")
            self.assertFalse(report["q01_24h"]["duration_met"])
            self.assertEqual(report["q01_24h"]["reason"], "short_run")
            self.assertGreaterEqual(report["actual_duration_seconds"], seconds)
            self.assertLess(report["actual_duration_seconds"], seconds + 1)
            self.assertEqual(report["source"]["binary_sha256"], soak.sha256(sys.executable))
            self.assertRegex(report["source"]["source_sha"], r"^[a-f0-9]{40}$")
            self.assertEqual(report["source"]["script_sha256"], soak.sha256(soak.__file__))
            self.assertEqual(len({request["operation_id"] for request in fixture.requests}), len(fixture.requests))
            self.assertEqual(fixture.stops, [])
            self.assertEqual(report["availability_recovery"]["status"], "observed")
            self.assertTrue(report["availability_recovery"]["intervals"][0]["recovered"])
            self.assertTrue(report["backlog_recovery"]["intervals"][0]["recovered"])
            self.assertLessEqual(len(jsonl.encode()), report["jsonl"]["max_bytes"])
            if output:
                descriptor = {"smoke_kind": "owned_loopback_fixture", "native_health_and_checkpoints": "synthetic",
                              "command_executed": "/bin/echo", "business_daemon_contacted": False,
                              "binary_role": "Python fixture host, not an AgentProvenance daemon",
                              "test_script_sha256": soak.sha256(__file__),
                              "procfs_available": pathlib.Path("/proc/self/stat").exists(),
                              "actual_duration_seconds": report["actual_duration_seconds"],
                              "report_sha256": soak.sha256(output / "report.json"),
                              "samples_sha256": soak.sha256(output / "samples.jsonl")}
                with (output / "fixture.json").open("x") as stream:
                    json.dump(descriptor, stream, indent=2)
                    stream.write("\n")
            if seconds >= 10:
                print(json.dumps({"smoke_kind": "owned_loopback_fixture", "native_health": "synthetic", "command": "/bin/echo",
                                  **{key: report[key] for key in ("actual_duration_seconds", "sample_count", "operation_count", "q01_24h")}}))

    def test_stop_only_owned_attempt_on_timeout(self):
        with Fixture() as fixture, tempfile.TemporaryDirectory() as temp:
            fixture.stuck = True
            process, report, _ = self.invoke(fixture, pathlib.Path(temp), extra=("--operation-timeout", ".1"))
            self.assertEqual(process.returncode, 2)
            self.assertEqual(report["stop_reason"], "owned_operation_timeout")
            self.assertEqual(fixture.stops, ["attempt-1"])
            self.assertEqual(report["cleanup"]["status"], "stop_requested")

    def test_wrong_target_fails_before_submission(self):
        with Fixture() as fixture, tempfile.TemporaryDirectory() as temp:
            fixture.wrong_identity = True
            process, report, _ = self.invoke(fixture, pathlib.Path(temp))
            self.assertEqual(process.returncode, 2)
            self.assertEqual(report["stop_reason"], "operator_identity_mismatch")
            self.assertEqual(fixture.requests, [])

    def test_record_cap_is_early_stop_not_success(self):
        with Fixture() as fixture, tempfile.TemporaryDirectory() as temp:
            process, report, jsonl = self.invoke(fixture, pathlib.Path(temp), extra=("--max-records", "1"))
            self.assertEqual(process.returncode, 2)
            self.assertEqual(report["stop_reason"], "jsonl_limit")
            self.assertEqual(len(jsonl.splitlines()), 1)
            self.assertEqual(report["q01_24h"]["status"], "PENDING")

    def test_lost_admission_is_not_resubmitted_or_stopped_by_guess(self):
        with Fixture() as fixture, tempfile.TemporaryDirectory() as temp:
            fixture.drop_admission = True
            process, report, _ = self.invoke(fixture, pathlib.Path(temp))
            self.assertEqual(process.returncode, 2)
            self.assertEqual(len(fixture.requests), 1)
            self.assertEqual(fixture.stops, [])
            self.assertEqual(report["uncertain_admission"]["operation_id"], fixture.requests[0]["operation_id"])


if __name__ == "__main__":
    unittest.main()
