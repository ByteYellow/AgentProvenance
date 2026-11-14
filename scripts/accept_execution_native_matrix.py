#!/usr/bin/env python3
"""Exercise concurrent native calls, a lost receipt response and explicit retry.

Use two isolated executor workdirs, native capture, concurrency >= 2 and signed
delivery. The loopback fixture must be reachable from the executor workdirs.
It is a test-only relay, never a replacement execution or production endpoint.
"""

import argparse
import collections
import concurrent.futures
import copy
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import accept_execution_native as native


COMMAND = "python3 analyze.py"
PROMPT = (
    "Run exactly one Bash tool call in the configured remote working directory: "
    "`python3 analyze.py`. Set its timeout to 180000 milliseconds. The script is a "
    "synthetic CSV analysis task and contacts only its local test barrier. "
    "Do not inspect, edit or run any other file or command. After the call, report "
    "its result. If the tool reports a delivery error, report that error and stop; "
    "the operator will recover the same execution. Never retry the tool yourself."
)
TASK = '''import csv, json, pathlib, urllib.request
case = json.loads(pathlib.Path("case.json").read_text())
with pathlib.Path("invocations.log").open("a") as log:
    log.write(case["id"] + "\\n")
with urllib.request.urlopen(case["fixture_url"] + "/barrier/" + case["id"], timeout=100) as response:
    assert json.load(response)["released"]
totals = {}
for row in csv.DictReader(pathlib.Path("input.csv").open()):
    totals[row["team"]] = totals.get(row["team"], 0) + int(row["amount"])
pathlib.Path("totals.json").write_text(json.dumps(totals, sort_keys=True))
print(json.dumps({"case": case["id"], "totals": totals, "invocations": len(pathlib.Path("invocations.log").read_text().splitlines())}, sort_keys=True))
'''


class Fixture:
    def __init__(self, upstream):
        parsed = urllib.parse.urlsplit(upstream)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("test relay requires a loopback HTTP executor")
        self.upstream = upstream.rstrip("/")
        self.condition = threading.Condition()
        self.arrivals = []
        self.released = False
        self.fault = None
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def barrier(self, case, timeout=95):
        if case not in {"a", "b"}:
            raise ValueError("unknown barrier case")
        with self.condition:
            self.arrivals.append({"case": case, "monotonic_ns": time.monotonic_ns()})
            if {row["case"] for row in self.arrivals} == {"a", "b"}:
                self.released = True
                self.condition.notify_all()
            if not self.condition.wait_for(lambda: self.released, timeout):
                raise TimeoutError("both native commands did not reach the barrier")
        return {"released": True}

    def drop_receipt(self, path, response):
        if not path.startswith("/v1/execution-deliveries/") or not path.endswith("/receipt"):
            return False
        delivery = response["delivery"]
        if not delivery.get("receipt"):
            raise RuntimeError("upstream did not persist the receipt")
        with self.condition:
            if self.fault is not None:
                return False
            self.fault = {"path": path, "delivery_id": delivery["manifest"]["id"],
                          "receipt": delivery["receipt"], "manifest_sha256": delivery["manifest_sha256"],
                          "injection": "close_after_upstream_receipt_persisted"}
            return True

    def handler(self):
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path.startswith("/barrier/"):
                    try:
                        body = json.dumps(fixture.barrier(self.path.removeprefix("/barrier/"))).encode()
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    except (ValueError, TimeoutError) as error:
                        self.send_error(409, str(error))
                    return
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                if not self.path.startswith("/v1/"):
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 2 << 20:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if self.command == "POST" else None
                headers = {key: self.headers[key] for key in ("Authorization", "Content-Type") if key in self.headers}
                request = urllib.request.Request(fixture.upstream + self.path, data=body, method=self.command, headers=headers)
                try:
                    response = fixture.opener.open(request, timeout=120)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    receipt = self.command == "POST" and self.path.endswith("/receipt") and response.status == 200
                    raw = response.read(256 << 10) if receipt else None
                    if receipt and fixture.drop_receipt(self.path, json.loads(raw)):
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    self.send_response(response.status)
                    for key in ("Content-Type", "Content-Length"):
                        if response.headers.get(key):
                            self.send_header(key, response.headers[key])
                    self.end_headers()
                    if raw is not None:
                        self.wfile.write(raw)
                    else:
                        shutil.copyfileobj(response, self.wfile, length=64 << 10)

        return Handler


def absolute_route(path):
    value = native.load(path)
    for key in ("token_file", "execution_config", "sign_key_file", "public_key_file"):
        candidate = pathlib.Path(value[key])
        if not candidate.is_absolute():
            candidate = path.resolve().parent / candidate
        value[key] = str(candidate.resolve())
    return value


def launch(args, case, route):
    output = args.output / case
    workdir = output / "workdir"
    workdir.mkdir(parents=True)
    route_path = output / "route.json"
    native.save(route_path, route)
    argv = [str(args.agentprov), "--data-dir", str(output / "data"), "launch", "--sensor", "off", "--no-dashboard", "--json",
            "--sign-key", route["sign_key_file"], "--workdir", str(workdir), "--remote-execution", str(route_path), "--",
            str(args.claude), "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
            "--tools", "Bash", "--allowedTools", "Bash(" + str(args.agentprov) + " internal remote-command *)",
            "--output-format", "stream-json", "--verbose", "--max-budget-usd", "0.25", "--max-turns", "3", "-p", PROMPT]
    env = dict(os.environ, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", CLAUDE_CODE_MAX_OUTPUT_TOKENS="2000", API_TIMEOUT_MS="90000")
    env.pop("CLAUDECODE", None)
    with (output / "launch.stdout").open("w") as out, (output / "launch.stderr").open("w") as err:
        result = subprocess.run(argv, cwd=workdir, env=env, stdout=out, stderr=err, timeout=300)
    native.save(output / "invocation.json", {"exit_code": result.returncode, "command": argv})
    admissions = sorted((output / "data/execution-routes").glob("*/*-admission.json"))
    if len(admissions) != 1:
        raise RuntimeError(f"{case}: expected exactly one native call, got {len(admissions)}")
    hooks = []
    for path in (output / "data/logs").glob("*-hooks.jsonl"):
        hooks.extend(json.loads(line) for line in path.read_text().splitlines() if line)
    if len([hook for hook in hooks if hook.get("hook_event_name") == "PreToolUse"]) != 1:
        raise RuntimeError(case + ": harness issued additional native calls")
    admission_path = admissions[0]
    prefix = str(admission_path).removesuffix("-admission.json")
    collection = native.load(prefix + "-collection.json")
    return {"case": case, "admission": native.load(admission_path), "admission_path": str(admission_path),
            "prepared_path": prefix + ".json", "saved_route": str(admission_path.parent / "route.json"),
            "collection_before": collection, "hooks": hooks}


def validate_overlap(reports, arrivals):
    native.validate_reports(reports, [hook for row in reports for hook in row["native_hooks"]])
    if len(reports) != 2 or len({row["attempt"]["request"]["source"]["session_id"] for row in reports}) != 2:
        raise RuntimeError("expected two independent native sessions")
    for field in ("id", "local_run_id"):
        if len({row["attempt"][field] for row in reports}) != 2:
            raise RuntimeError("concurrent calls share execution identity")
    if any(row["attempt"]["request"]["command"]["argv"][2] != COMMAND for row in reports):
        raise RuntimeError("native commands are not identical")
    if [row["case"] for row in arrivals].count("a") != 1 or [row["case"] for row in arrivals].count("b") != 1:
        raise RuntimeError("initial native tasks did not meet the two-party barrier exactly once")


def validate_receipt_recovery(cases, fault):
    interrupted = [case for case in cases if case["collection_before"]["status"] == "receipt_persisted"]
    if len(interrupted) != 1 or fault is None:
        raise RuntimeError("one actual lost receipt response was not observed")
    before, after = interrupted[0]["collection_before"], interrupted[0]["collection_after"]
    if fault["delivery_id"] != before["delivery_id"] or fault["receipt"] != before["receipt"] or fault["manifest_sha256"] != before["manifest_sha256"]:
        raise RuntimeError("lost response does not match the persisted receiving receipt")
    if after != dict(before, status="acknowledged"):
        raise RuntimeError("recovery changed the signed delivery or receiving receipt")


def artifact_text(data, report, path):
    run_id = report["attempt"]["local_run_id"]
    with sqlite3.connect((data / "agentprov.db").as_uri() + "?mode=ro", uri=True) as db:
        def read(ref):
            row = db.execute("SELECT path FROM provenance_objects WHERE run_id=? AND hash=?", (run_id, ref)).fetchone()
            if row is None:
                raise RuntimeError("signed object is missing")
            raw = pathlib.Path(row[0]).read_bytes()
            if "sha256:" + hashlib.sha256(raw).hexdigest() != ref:
                raise RuntimeError("signed object digest mismatch")
            return json.loads(raw)["payload"]

        checkpoint = read(report["checkpoint_ref"])
        file = next(row for row in checkpoint["result"]["artifact_capture"]["files"] if row["path"] == path)
        manifest = read(file["content_ref"])["text_manifest"]
        body = "".join(read(chunk["ref"])["content"] for chunk in manifest["chunks"])
        if hashlib.sha256(body.encode()).hexdigest() != manifest["sha256"]:
            raise RuntimeError("signed body digest mismatch")
        return body


def network_events(data, report, port):
    run_id = report["attempt"]["local_run_id"]
    expected_cgroup = report["checkpoint"]["scope"]["cgroup_id"]
    found = []
    with sqlite3.connect((data / "agentprov.db").as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("SELECT id,cgroup_id,payload FROM events WHERE run_id=? AND source='agentprov_ebpf' AND event_type='network_connect'", (run_id,))
        for event_id, cgroup, payload in rows:
            raw = (json.loads(payload).get("payload") or {}).get("raw") or {}
            if raw.get("dst_ip") != "127.0.0.1" or str(raw.get("port")) != str(port):
                continue
            if str(cgroup) != expected_cgroup:
                raise RuntimeError("barrier connection belongs to another scope")
            found.append({"run_id": run_id, "event_id": event_id, "cgroup_id": cgroup, "port": port})
    if not found:
        raise RuntimeError("native barrier connection is missing")
    return found


def wait(api, attempt):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        report = api.call("GET", "/v1/executions/" + attempt["id"])
        state = report["attempt"]["state"]
        if state["execution"] in {"failed", "unknown", "cancelled"}:
            raise RuntimeError("execution did not succeed: " + state["execution"])
        if state["execution"] == "succeeded" and state["capture"] in {"sealed", "incomplete"}:
            return report
        time.sleep(0.1)
    raise TimeoutError("execution/capture did not settle")


def verify(args):
    result = native.load(args.output / "result.json")
    if collections.Counter(row["case"] for row in result["barrier"]) != {"a": 2, "b": 1}:
        raise RuntimeError("barrier saw additional or missing command executions")
    checks = {}
    for case in result["cases"]:
        output = args.output / case["case"]
        checks[case["case"]] = native.verify_saved(args.agentprov, output)
        if artifact_text(output / "data", case["report"], "invocations.log") != case["case"] + "\n":
            raise RuntimeError("initial command side effect is duplicated or mixed")
        checks[case["case"]]["native_network_events"] = network_events(output / "data", case["report"], result["fixture_port"])
    if artifact_text(args.output / "a/data", result["retry"]["report"], "invocations.log") != "a\na\n":
        raise RuntimeError("explicit retry did not produce exactly one additional side effect")
    checks["a"]["native_network_events"].extend(network_events(args.output / "a/data", result["retry"]["report"], result["fixture_port"]))
    native.save(args.output / "saved-evidence.json", checks)
    return checks


def execute(args):
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    routes = [absolute_route(path) for path in (args.route_a, args.route_b)]
    if routes[0]["url"] != routes[1]["url"] or routes[0]["workdir"] == routes[1]["workdir"] or any(not route.get("file_diff") for route in routes):
        raise ValueError("routes require one executor, different workdirs and file_diff=true")
    fixture = Fixture(routes[0]["url"])
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.fixture_port), fixture.handler())
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        for route in routes:
            route["url"] = "http://127.0.0.1:" + str(server.server_port)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(launch, args, case, route) for case, route in zip(("a", "b"), routes)]
            cases = [future.result() for future in futures]
        api = native.API(args.route_a)
        reports = []
        for case in cases:
            admission = case["admission"]
            attempt = admission["attempt"]
            replay = api.call("POST", "/v1/executions", attempt["request"])
            if not replay["reused"] or replay["attempt"]["id"] != attempt["id"]:
                raise RuntimeError("transport replay repeated execution")
            command = [str(args.agentprov), "internal", "remote-command", "--route", case["saved_route"],
                       "--request", case["prepared_path"], "--native-command", COMMAND]
            case["recovered_stdout"] = native.run(command)
            case["collection_after"] = native.load(case["prepared_path"].removesuffix(".json") + "-collection.json")
            case["report"] = api.call("GET", "/v1/executions/" + attempt["id"])
            case["report"]["native_hooks"] = case["hooks"]
            reports.append(case["report"])
            native.save(args.output / case["case"] / "result.json", {"reports": [case["report"]]})
        validate_overlap(reports, fixture.arrivals)
        validate_receipt_recovery(cases, fixture.fault)
        native.save(args.output / "initial.json", {"cases": cases, "fault": fixture.fault, "barrier": fixture.arrivals})

        previous = cases[0]["admission"]["attempt"]
        request = copy.deepcopy(previous["request"])
        request.update(operation_id="operator-reexecute-" + previous["id"], previous_attempt_id=previous["id"])
        retry = api.call("POST", "/v1/executions", request)
        repeated = api.call("POST", "/v1/executions", request)
        if retry["reused"] or not repeated["reused"] or repeated["attempt"]["id"] != retry["attempt"]["id"] or retry["attempt"]["id"] == previous["id"]:
            raise RuntimeError("explicit reexecution is not independently idempotent")
        wait(api, retry["attempt"])
        path = args.output / "a/retry-admission.json"
        native.save(path, retry)
        route = routes[0]
        collected = json.loads(native.run([
            str(args.agentprov), "--data-dir", str(args.output / "a/data"), "--daemon-url", route["url"],
            "forensics", "collect-execution", str(path), "--execution-config", route["execution_config"],
            "--receiver", route["receiver_id"], "--sign-key", route["sign_key_file"], "--pub-key", route["public_key_file"],
            "--operation", "operator-result-" + request["operation_id"],
        ], env=dict(os.environ, AGENTPROV_DAEMON_TOKEN=api.token)))
        retry_report = api.call("GET", "/v1/executions/" + retry["attempt"]["id"])
        if retry_report["attempt"]["request"] != request:
            raise RuntimeError("explicit retry changed the original source or command")
        native.validate_reports([retry_report], cases[0]["hooks"])
        if retry_report["checkpoint"]["scope"]["cgroup_id"] in {row["checkpoint"]["scope"]["cgroup_id"] for row in reports}:
            raise RuntimeError("explicit retry reused the original kernel scope")
        for case in cases:
            source = case["admission"]["attempt"]["request"]["source"]
            query = urllib.parse.urlencode({"run": source["run_id"], "harness": source["harness"],
                                           "session": source["session_id"], "tool_call": source["tool_call_id"], "limit": 100})
            page = api.call("GET", "/v1/executions?" + query)
            expected = {case["admission"]["attempt"]["id"]}
            if case["case"] == "a":
                expected.add(retry["attempt"]["id"])
            if page.get("has_more") or {row["id"] for row in page["attempts"]} != expected:
                raise RuntimeError("source query mixed sessions or unexpected executions")
            case["source_query"] = page
        native.save(args.output / "a/result.json", {"reports": [reports[0], retry_report]})
        native.save(args.output / "result.json", {"cases": cases, "fault": fixture.fault, "barrier": fixture.arrivals, "fixture_port": server.server_port,
            "retry": {"admission": retry, "collection": collected, "report": retry_report}})
        verify(args)
    finally:
        native.save(args.output / "fixture.json", {"fault": fixture.fault, "barrier": fixture.arrivals})
        server.shutdown()
        thread.join()
        server.server_close()
    print(json.dumps({"status": "passed", "native_sessions": 2, "execution_attempts": 3, "output": str(args.output)}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    prepare = sub.add_parser("prepare", help="Create a fresh executor task workdir")
    prepare.add_argument("--workdir", type=pathlib.Path, required=True)
    prepare.add_argument("--case", choices=["a", "b"], required=True)
    prepare.add_argument("--fixture-url", required=True)
    for phase in ("run", "verify"):
        command = sub.add_parser(phase)
        for name in ("agentprov", "output", "route-a", "route-b"):
            command.add_argument("--" + name, type=pathlib.Path, required=True)
        if phase == "run":
            command.add_argument("--claude", type=pathlib.Path, required=True)
            command.add_argument("--fixture-port", type=int, required=True)
    args = parser.parse_args()
    if args.phase == "prepare":
        args.workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
        (args.workdir / "analyze.py").write_text(TASK)
        (args.workdir / "input.csv").write_text("team,amount\nalpha,10\nbeta,20\nalpha,30\n")
        native.save(args.workdir / "case.json", {"id": args.case, "fixture_url": args.fixture_url.rstrip("/")})
        return
    args.agentprov, args.output = args.agentprov.resolve(), args.output.resolve()
    if args.phase == "run":
        args.claude = args.claude.resolve()
        execute(args)
    else:
        for path in (args.route_a, args.route_b):
            try:
                native.API(path).call("GET", "/v1/ready")
            except urllib.error.HTTPError:
                raise RuntimeError("executor still responds; stop it before offline verification")
            except (urllib.error.URLError, TimeoutError):
                continue
            raise RuntimeError("executor still responds; stop it before offline verification")
        native.save(args.output / "offline.json", verify(args))
        print(json.dumps({"status": "passed", "output": str(args.output / "offline.json")}))


if __name__ == "__main__":
    main()
