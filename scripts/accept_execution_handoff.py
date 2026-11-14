#!/usr/bin/env python3
"""Exercise an isolated, opt-in execution daemon through its public HTTP API."""

import argparse
import concurrent.futures
import datetime
import json
import pathlib
import time
import urllib.parse
import urllib.request
import uuid


TASK = """import csv, io, json, pathlib, time
rows = list(csv.DictReader(io.StringIO('team,amount\\nalpha,10\\nbeta,20\\nalpha,30\\n')))
totals = {}
for row in rows:
    totals[row['team']] = totals.get(row['team'], 0) + int(row['amount'])
pathlib.Path('totals.json').write_text(json.dumps(totals, sort_keys=True))
time.sleep(1)
print(json.dumps({'rows': len(rows), 'totals': totals, 'artifact': 'totals.json'}, sort_keys=True))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--token-file", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--require-sealed", action="store_true", help="Require native scope capture to seal for completed and stopped tasks")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.require_sealed and not config.get("capture"):
        parser.error("--require-sealed requires native capture configuration")
    token = args.token_file.read_text().strip()
    if not token:
        raise RuntimeError("empty authentication token")

    def api(method, path, body=None):
        raw = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(args.url.rstrip("/") + path, data=raw, method=method)
        req.add_header("Authorization", "Bearer " + token)
        if raw is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    def wait(attempt, state):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = api("GET", "/v1/executions/" + attempt["id"])
            if result["attempt"]["state"]["execution"] == state:
                capture = result["attempt"]["state"]["capture"]
                if state == "running" or not config.get("capture") or capture in {"sealed", "incomplete"}:
                    return result
            if result["attempt"]["state"]["execution"] in {"failed", "unknown"}:
                raise RuntimeError(json.dumps(result))
            time.sleep(0.05)
        raise RuntimeError("execution did not reach " + state)

    nonce = uuid.uuid4().hex
    deadline = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
    requests = []
    for index in range(2):
        requests.append({
            "schema_version": "agentprovenance.execution_handoff/v1",
            "source": {"producer_id": config["caller"]["producer_id"], "namespace": config["caller"]["namespace"],
                       "run_id": "acceptance-" + nonce, "harness": "http-acceptance-fixture",
                       "session_id": "session-" + str(index), "tool_call_id": "analysis"},
            "target": config["target"], "dispatch_id": nonce + "-" + str(index),
            "operation_id": nonce + "-submit-" + str(index), "valid_until": deadline,
            "command": {"argv": ["python3", "-c", TASK], "capture_preset": "detailed", "post_root_grace_ms": 25},
        })
    submitted = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(api, "POST", "/v1/executions", r) for r in requests]
            failures = []
            for future in futures:
                try:
                    submitted.append(future.result()["attempt"])
                except Exception as error:
                    failures.append(error)
            if failures:
                raise RuntimeError("execution admission failed") from failures[0]
        reports = [wait(a, "succeeded") for a in submitted]
        scopes = [r["checkpoint"]["scope"] for r in reports]
        if len({s["run_id"] for s in scopes}) != 2 or len({s["tool_call_id"] for s in scopes}) != 2:
            raise RuntimeError("concurrent calls shared local identity")
        if all(s["scope_kind"] == "cgroup" for s in scopes) and len({s["cgroup_id"] for s in scopes}) != 2:
            raise RuntimeError("concurrent calls shared a kernel scope")
        native_file_events = []
        for request, report in zip(requests, reports):
            if report["checkpoint"]["source"] != request["source"]:
                raise RuntimeError("source attribution changed")
            if "totals.json" not in report["checkpoint"]["result"]["changed_files"]:
                raise RuntimeError("analysis artifact was not captured")
            if config.get("capture"):
                capture = report["checkpoint"].get("capture_report", {})
                if not capture.get("start") or not capture.get("end"):
                    raise RuntimeError("native capture lacks live start/end boundaries")
                if capture["state"] != report["attempt"]["state"]["capture"]:
                    raise RuntimeError("native capture report disagrees with attempt")
                if capture.get("schema_version") == "agentprovenance.execution_native_capture/v2":
                    progress = capture.get("scope_progress", {})
                    if not capture.get("scope_prefix") or not capture.get("shared_prefix") or not progress:
                        raise RuntimeError("native capture lacks scope or shared accounting")
                    if progress["events"] != sum(progress[key] for key in ("ingested", "dropped", "failed", "pending")):
                        raise RuntimeError("native scope accounting is inconsistent")
                if args.require_sealed and capture["state"] != "sealed":
                    raise RuntimeError("task capture did not seal: " + json.dumps(capture))
                scope = report["checkpoint"]["scope"]
                cursor = ""
                found = []
                while True:
                    query = urllib.parse.urlencode({"run": scope["run_id"], "type": "file_write", "limit": 100, "cursor": cursor})
                    page = api("GET", "/v1/telemetry/events?" + query)
                    for event in page["events"]:
                        payload = json.loads(event["payload"])
                        raw = payload.get("payload", {}).get("raw", {})
                        if event["source"] == "agentprov_ebpf" and event["cgroup_id"] == scope["cgroup_id"] and pathlib.PurePosixPath(raw.get("path", "")).name == "totals.json":
                            found.append({"event_id": event["id"], "run_id": event["run_id"], "cgroup_id": event["cgroup_id"], "path": raw["path"]})
                    if not page["has_more"]:
                        break
                    if not page.get("next_cursor") or page["next_cursor"] == cursor:
                        raise RuntimeError("native file evidence pagination did not advance")
                    cursor = page["next_cursor"]
                if not found:
                    raise RuntimeError("task artifact lacks a native file-write event in its own scope")
                native_file_events.extend(found)
        replay = api("POST", "/v1/executions", requests[0])
        if not replay["reused"] or replay["attempt"]["id"] != submitted[0]["id"]:
            raise RuntimeError("transport retry repeated execution")
        retry_request = dict(requests[0], operation_id=nonce + "-retry", previous_attempt_id=submitted[0]["id"],
                             command={"argv": ["sleep", "60"], "disable_snapshot": True, "post_root_grace_ms": 25})
        retry = api("POST", "/v1/executions", retry_request)["attempt"]
        submitted.append(retry)
        wait(retry, "running")
        stop = api("POST", "/v1/executions/" + retry["id"] + "/stop", {"operation_id": nonce + "-stop"})
        cancelled = wait(retry, "cancelled")
        if args.require_sealed and cancelled["attempt"]["state"]["capture"] != "sealed":
            raise RuntimeError("stopped task capture did not seal: " + json.dumps(cancelled))
        source = requests[0]["source"]
        query = urllib.parse.urlencode({"run": source["run_id"], "harness": source["harness"],
                                       "session": source["session_id"], "tool_call": source["tool_call_id"], "limit": 100})
        page = api("GET", "/v1/executions?" + query)
        if {a["id"] for a in page["attempts"]} != {submitted[0]["id"], retry["id"]}:
            raise RuntimeError("source query mixed concurrent sessions")
        result = {"fixture": "execution-handoff-http/v1", "target": config["target"],
                  "requests": requests, "completed": reports, "replay": replay, "stop": stop, "cancelled": cancelled,
                  "checks": ["concurrent_analysis", "source_isolation", "artifact_capture", "idempotent_replay", "explicit_retry", "durable_stop"]}
        if config.get("capture"):
            result["checks"].extend(["native_capture_boundaries", "native_artifact_writes"])
            result["native_file_events"] = native_file_events
            if args.require_sealed:
                result["checks"].append("scope_capture_sealed")
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": "passed", "checks": result["checks"], "output": str(args.output)}))
    finally:
        # Only the attempts created by this invocation are eligible for cleanup.
        for attempt in submitted:
            try:
                api("POST", "/v1/executions/" + attempt["id"] + "/stop", {"operation_id": "cleanup-" + attempt["id"]})
            except Exception as error:
                print("Cleanup request failed for " + attempt["id"] + ": " + str(error))


if __name__ == "__main__":
    main()
