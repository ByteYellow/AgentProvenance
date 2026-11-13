#!/usr/bin/env python3
"""Verify an HTTP execution fixture and signed cross-host evidence collection.

Requires an isolated execution daemon with delivery keys already configured.
Uses a real CSV command; native Agent hooks and kernel capture are separate gates.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import time
import urllib.request
import uuid


TASK = """import csv, io, json, pathlib
rows = list(csv.DictReader(io.StringIO('team,amount\\nalpha,10\\nbeta,20\\nalpha,30\\n')))
totals = {}
for row in rows:
    totals[row['team']] = totals.get(row['team'], 0) + int(row['amount'])
pathlib.Path('totals.json').write_text(json.dumps(totals, sort_keys=True))
print(json.dumps({'rows': len(rows), 'totals': totals}, sort_keys=True))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("url", "receiver"):
        parser.add_argument("--" + name, required=True)
    for name in ("config", "token-file", "agentprov", "sign-key", "pub-key", "data-dir", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    token = args.token_file.read_text().strip()
    if not token:
        raise RuntimeError("empty authentication token")
    env = dict(os.environ, AGENTPROV_DAEMON_TOKEN=token)
    env.pop("AGENTPROV_DAEMON_URL", None)

    def api(method, path, body=None):
        raw = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(args.url.rstrip("/") + path, data=raw, method=method)
        request.add_header("Authorization", "Bearer " + token)
        if raw is not None:
            request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)

    nonce = uuid.uuid4().hex
    request = {
        "schema_version": "agentprovenance.execution_handoff/v1",
        "source": {"producer_id": config["caller"]["producer_id"], "namespace": config["caller"]["namespace"],
                   "run_id": "delivery-" + nonce, "harness": "http-delivery-fixture",
                   "session_id": "session-" + nonce, "tool_call_id": "analyze-csv"},
        "target": config["target"], "dispatch_id": nonce, "operation_id": "submit-" + nonce,
        "valid_until": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat(),
        "command": {"argv": ["python3", "-c", TASK], "capture_preset": "detailed", "post_root_grace_ms": 25},
    }
    admission = api("POST", "/v1/executions", request)
    attempt_id = admission["attempt"]["id"]
    try:
        deadline = time.monotonic() + 30
        while True:
            report = api("GET", "/v1/executions/" + attempt_id)
            state = report["attempt"]["state"]["execution"]
            if state == "succeeded":
                break
            if state in {"failed", "unknown", "cancelled"} or time.monotonic() > deadline:
                raise RuntimeError("execution did not succeed: " + state)
            time.sleep(0.05)
        admission_path = args.output.with_suffix(".admission.json")
        admission_path.write_text(json.dumps(admission) + "\n")
        collect = [str(args.agentprov), "--data-dir", str(args.data_dir), "--daemon-url", args.url,
                   "forensics", "collect-execution", str(admission_path), "--execution-config", str(args.config),
                   "--receiver", args.receiver, "--sign-key", str(args.sign_key), "--pub-key", str(args.pub_key),
                   "--operation", "collect-" + nonce]
        received = []
        for _ in range(2):
            result = subprocess.run(collect, env=env, capture_output=True, text=True, timeout=200)
            if result.returncode != 0:
                raise RuntimeError("collection failed: " + result.stderr)
            received.append(json.loads(result.stdout))
        if received[0] != received[1] or received[0]["status"] != "acknowledged":
            raise RuntimeError("retry changed the saved delivery or receipt")
        after = api("GET", "/v1/executions/" + attempt_id)
        if after["attempt"]["state"]["delivery"] != "acknowledged":
            raise RuntimeError("server did not persist acknowledgment")
        if after["attempt"]["state"]["capture"] != report["attempt"]["state"]["capture"]:
            raise RuntimeError("delivery changed capture status")
        delivery = api("GET", "/v1/execution-deliveries/" + received[0]["delivery_id"])
        run_id = admission["attempt"]["local_run_id"]
        verify = subprocess.run([str(args.agentprov), "--data-dir", str(args.data_dir), "graph", "verify", "--run", run_id, "--json"],
                                env=env, capture_output=True, text=True, timeout=60)
        if verify.returncode != 0:
            raise RuntimeError("received graph verification failed: " + verify.stdout + verify.stderr)
        with sqlite3.connect((args.data_dir / "agentprov.db").resolve().as_uri() + "?mode=ro", uri=True) as db:
            def read_object(ref):
                row = db.execute("SELECT path FROM provenance_objects WHERE hash=? AND run_id=?", (ref, run_id)).fetchone()
                if row is None:
                    raise RuntimeError("received object is missing")
                raw = pathlib.Path(row[0]).read_bytes()
                if "sha256:" + hashlib.sha256(raw).hexdigest() != ref:
                    raise RuntimeError("received object digest mismatch")
                return json.loads(raw)["payload"]

            files = report["checkpoint"]["result"]["artifact_capture"]["files"]
            artifact = next(item for item in files if item["path"] == "totals.json")
            manifest = read_object(artifact["content_ref"])["text_manifest"]
            content = "".join(read_object(chunk["ref"])["content"] for chunk in manifest["chunks"])
            if hashlib.sha256(content.encode()).hexdigest() != manifest["sha256"] or json.loads(content) != {"alpha": 40, "beta": 20}:
                raise RuntimeError("received artifact content mismatch")
        result = {"fixture": "execution-delivery-http/v1", "request": request, "admission": admission,
                  "execution": report, "collection": received[0], "delivery": delivery,
                  "verification": json.loads(verify.stdout), "artifact": json.loads(content),
                  "collector_sha256": hashlib.sha256(args.agentprov.read_bytes()).hexdigest(),
                  "checks": ["real_csv_command", "signed_transfer", "persisted_receipt", "idempotent_retry",
                             "independent_capture_state", "received_graph", "received_artifact_body"]}
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": "passed", "checks": result["checks"], "output": str(args.output)}))
    finally:
        api("POST", "/v1/executions/" + attempt_id + "/stop", {"operation_id": "cleanup-" + nonce})


if __name__ == "__main__":
    main()
