#!/usr/bin/env python3
"""Exercise real daemon health responses against faults in an isolated store."""
import argparse
import json
from pathlib import Path
import platform
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentprov", default="agentprov")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    checks = {}
    with tempfile.TemporaryDirectory(prefix="agentprov-readiness-") as directory:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"

        def request(path):
            try:
                response = urllib.request.urlopen(base + path, timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, json.loads(response.read())

        with open(Path(directory) / "daemon.log", "w+") as log:
            process = subprocess.Popen([
                args.agentprov, "--data-dir", directory, "daemon", "serve",
                "--listen", f"127.0.0.1:{port}", "--auth-token", "fixture-only",
                "--sample-interval", "0", "--evidence-interval", "0",
                "--spool-interval", "0", "--gc-interval", "0",
            ], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    try:
                        code, body = request("/v1/ready")
                        if code == 200 and body["ready"]:
                            break
                    except (urllib.error.URLError, TimeoutError):
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError("daemon did not become ready")
                    time.sleep(0.1)
                checks["ready_without_auth"] = body["status"] == "ok"
                checks["live_without_auth"] = request("/v1/live")[0] == 200
                checks["api_still_requires_auth"] = request("/v1/runs")[0] == 401
                with sqlite3.connect(Path(directory) / "agentprov.db") as db:
                    version = db.execute("SELECT MAX(version) FROM schema_versions").fetchone()[0]
                    db.execute("UPDATE schema_versions SET version=version+1000")
                    db.commit()
                    code, body = request("/v1/ready")
                    checks["future_schema_unavailable"] = code == 503 and not body["ready"] and "schema" in body["checks"]
                    checks["live_during_schema_fault"] = request("/v1/live")[0] == 200
                    db.execute("UPDATE schema_versions SET version=version-1000")
                    db.execute("ALTER TABLE cpu_samples RENAME TO hidden_cpu_samples")
                    db.commit()
                    code, body = request("/v1/health")
                    checks["missing_table_unavailable"] = code == 503 and not body["ready"] and "storage" in body["checks"]
                    checks["unknown_queue_is_null"] = body["queued_spool"] is None
                    checks["live_during_storage_fault"] = request("/v1/live")[0] == 200
                    db.execute("ALTER TABLE hidden_cpu_samples RENAME TO cpu_samples")
                    db.commit()
                    checks["recovers_after_storage_restored"] = request("/v1/ready")[0] == 200
                    db.execute("INSERT INTO telemetry_native_counters(name,value) VALUES ('kernel_dropped_events',5)")
                    db.commit()
                    code, body = request("/v1/health")
                    checks["historical_loss_keeps_query_available"] = code == 200 and body["ready"]
                    checks["historical_loss_explicit"] = body["status"] == "degraded" and body["coverage_status"] == "gaps_recorded"
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    report = {"schema_version": "agentprovenance.daemon_readiness_acceptance/v1",
              "kernel": platform.release(), "architecture": platform.machine(),
              "database_schema": version, "checks": checks, "passed": all(checks.values())}
    output = Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit("FAIL: " + ", ".join(k for k, v in checks.items() if not v))


if __name__ == "__main__":
    main()
