"""Keyless regression checks for native concurrent/fault acceptance."""

import concurrent.futures
import http.client
import http.server
import json
import pathlib
import sqlite3
import tempfile
import threading
import types
import unittest
from unittest import mock
import urllib.request

import accept_execution_native_matrix as matrix
from test_execution_native import hook, report


def native_report(case, cgroup):
    value = report("tool-" + case, cgroup)
    value["attempt"]["id"] = "attempt-" + case
    value["attempt"]["request"]["source"]["session_id"] = "session-" + case
    value["native_hooks"] = [dict(hook("tool-" + case), session_id="session-" + case)]
    return value


def recovery():
    before = {"status": "receipt_persisted", "delivery_id": "package", "manifest_sha256": "sha256:manifest",
              "receipt": {"payload": "signed-receipt"}, "bundle_sha256": "sha256:bundle"}
    case = {"collection_before": before, "collection_after": dict(before, status="acknowledged")}
    fault = {"delivery_id": "package", "receipt": before["receipt"], "manifest_sha256": "sha256:manifest"}
    return [case], fault


class MatrixAssertionsTest(unittest.TestCase):
    def test_two_native_sessions_and_barrier_pass(self):
        matrix.validate_overlap([native_report("a", "123"), native_report("b", "456")], [{"case": "a"}, {"case": "b"}])

    def test_missing_or_duplicate_barrier_arrival_fails(self):
        for arrivals in ([], [{"case": "a"}], [{"case": "a"}, {"case": "b"}, {"case": "a"}]):
            with self.subTest(arrivals=arrivals), self.assertRaisesRegex(RuntimeError, "barrier"):
                matrix.validate_overlap([native_report("a", "123"), native_report("b", "456")], arrivals)

    def test_shared_session_or_execution_fails(self):
        for field in ("session_id", "id", "local_run_id"):
            reports = [native_report("a", "123"), native_report("b", "456")]
            if field == "session_id":
                reports[1]["attempt"]["request"]["source"][field] = "session-a"
                reports[1]["native_hooks"][0][field] = "session-a"
            else:
                reports[1]["attempt"][field] = reports[0]["attempt"][field]
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                matrix.validate_overlap(reports, [{"case": "a"}, {"case": "b"}])

    def test_different_native_commands_fail(self):
        reports = [native_report("a", "123"), native_report("b", "456")]
        reports[1]["native_hooks"][0]["tool_input"]["command"] = "other"
        reports[1]["attempt"]["request"]["command"]["argv"][2] = "other"
        with self.assertRaisesRegex(RuntimeError, "not identical"):
            matrix.validate_overlap(reports, [{"case": "a"}, {"case": "b"}])

    def test_recovery_changes_only_acknowledgment_status(self):
        matrix.validate_receipt_recovery(*recovery())
        for field in ("delivery_id", "manifest_sha256", "bundle_sha256", "receipt", "status"):
            cases, fault = recovery()
            cases[0]["collection_after"][field] = "changed"
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "changed"):
                matrix.validate_receipt_recovery(cases, fault)

    def test_fault_must_match_actual_persisted_receipt(self):
        cases, fault = recovery()
        for bad in (None, dict(fault, delivery_id="other"), dict(fault, receipt={}), dict(fault, manifest_sha256="other")):
            with self.subTest(fault=bad), self.assertRaises(RuntimeError):
                matrix.validate_receipt_recovery(cases, bad)
        cases[0]["collection_before"]["status"] = "acknowledged"
        with self.assertRaisesRegex(RuntimeError, "not observed"):
            matrix.validate_receipt_recovery(cases, fault)

    def test_final_barrier_rejects_silent_repeated_execution(self):
        args = types.SimpleNamespace(output=pathlib.Path("unused-unit-fixture"))
        for arrivals in (("a", "b"), ("a", "b", "a", "b"), ("a", "b", "a", "a")):
            with self.subTest(arrivals=arrivals), mock.patch.object(matrix.native, "load", return_value={
                "barrier": [{"case": case} for case in arrivals],
            }), self.assertRaisesRegex(RuntimeError, "additional or missing"):
                matrix.verify(args)


class FixtureTest(unittest.TestCase):
    def server(self, handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        return server

    def test_barrier_requires_both_native_commands(self):
        fixture = matrix.Fixture("http://127.0.0.1:1")
        with self.assertRaises(TimeoutError):
            fixture.barrier("a", timeout=0.01)
        fixture = matrix.Fixture("http://127.0.0.1:1")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(fixture.barrier, "a")
            self.assertEqual(fixture.barrier("b"), {"released": True})
            self.assertEqual(first.result(), {"released": True})
        self.assertEqual({row["case"] for row in fixture.arrivals}, {"a", "b"})
        self.assertEqual(fixture.barrier("a"), {"released": True})

    def test_receipt_is_lost_only_after_upstream_accepts_and_only_once(self):
        requests = []
        payload = {"delivery": {"manifest": {"id": "package"}, "manifest_sha256": "digest", "receipt": {"payload": "signed"}}}

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                requests.append(self.rfile.read(int(self.headers["Content-Length"])))
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        upstream = self.server(Upstream)
        fixture = matrix.Fixture("http://127.0.0.1:" + str(upstream.server_port))
        relay = self.server(fixture.handler())
        request = urllib.request.Request("http://127.0.0.1:" + str(relay.server_port) + "/v1/execution-deliveries/package/receipt", data=b'{"receipt":"test"}')
        with self.assertRaises(http.client.RemoteDisconnected):
            urllib.request.urlopen(request)
        self.assertEqual(len(requests), 1)
        self.assertEqual(fixture.fault["receipt"], payload["delivery"]["receipt"])
        with urllib.request.urlopen(request) as response:
            self.assertEqual(json.load(response), payload)
        self.assertEqual(requests, [b'{"receipt":"test"}'] * 2)

    def test_upstream_failure_is_not_a_lost_ack(self):
        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.send_error(500)

        upstream = self.server(Upstream)
        fixture = matrix.Fixture("http://127.0.0.1:" + str(upstream.server_port))
        relay = self.server(fixture.handler())
        request = urllib.request.Request("http://127.0.0.1:" + str(relay.server_port) + "/v1/execution-deliveries/package/receipt", data=b'{}')
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        self.assertEqual(error.exception.code, 500)
        self.assertIsNone(fixture.fault)

    def test_relay_rejects_nonlocal_or_credential_urls(self):
        for url in ("https://example.com", "http://user@127.0.0.1", "http://127.0.0.1/path", "http://127.0.0.1/?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                matrix.Fixture(url)


class NetworkEvidenceTest(unittest.TestCase):
    def test_native_destination_and_scope_are_required(self):
        with tempfile.TemporaryDirectory() as root:
            data = pathlib.Path(root).resolve()
            report = native_report("a", "123")
            run_id = report["attempt"]["local_run_id"]
            with sqlite3.connect(data / "agentprov.db") as db:
                db.execute("CREATE TABLE events (id TEXT,cgroup_id TEXT,payload TEXT,run_id TEXT,source TEXT,event_type TEXT)")
                def event(raw, cgroup="123", source="agentprov_ebpf"):
                    db.execute("DELETE FROM events")
                    db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)", ("network-a", cgroup, json.dumps({"payload": {"raw": raw}}), run_id, source, "network_connect"))
                    db.commit()

                event({"dst_ip": "127.0.0.1", "port": "18581"})
                self.assertEqual(len(matrix.network_events(data, report, 18581)), 1)
                event({"dst_ip": "127.0.0.1", "port": "18581"}, cgroup="456")
                with self.assertRaisesRegex(RuntimeError, "another scope"):
                    matrix.network_events(data, report, 18581)
                for raw, source in (({"dst_ip": "other", "port": "18581"}, "agentprov_ebpf"),
                                    ({"dst_ip": "127.0.0.1", "port": "18580"}, "agentprov_ebpf"),
                                    ({"dst_ip": "127.0.0.1", "port": "18581"}, "declared")):
                    event(raw, source=source)
                    with self.subTest(raw=raw, source=source), self.assertRaisesRegex(RuntimeError, "missing"):
                        matrix.network_events(data, report, 18581)


if __name__ == "__main__":
    unittest.main()
