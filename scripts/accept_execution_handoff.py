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
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
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
        for request, report in zip(requests, reports):
            if report["checkpoint"]["source"] != request["source"]:
                raise RuntimeError("source attribution changed")
            if "totals.json" not in report["checkpoint"]["result"]["changed_files"]:
                raise RuntimeError("analysis artifact was not captured")
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
        source = requests[0]["source"]
        query = urllib.parse.urlencode({"run": source["run_id"], "harness": source["harness"],
                                       "session": source["session_id"], "tool_call": source["tool_call_id"], "limit": 100})
        page = api("GET", "/v1/executions?" + query)
        if {a["id"] for a in page["attempts"]} != {submitted[0]["id"], retry["id"]}:
            raise RuntimeError("source query mixed concurrent sessions")
        result = {"fixture": "execution-handoff-http/v1", "target": config["target"],
                  "requests": requests, "completed": reports, "replay": replay, "stop": stop, "cancelled": cancelled,
                  "checks": ["concurrent_analysis", "source_isolation", "artifact_capture", "idempotent_replay", "explicit_retry", "durable_stop"]}
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
