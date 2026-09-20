#!/usr/bin/env python3
"""Opt-in K3s gate: short Pods finish before binding, collector crashes, then recovers.

Uses an isolated store and uniquely labelled Pods. It deliberately does not wait
for informer bindings before starting any workload. Run as root on a test node.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import subprocess
import tempfile
import time
import uuid


def wait_for(operation, predicate, description, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        result = operation()
        if predicate(result):
            return result
        if time.monotonic() >= deadline:
            raise RuntimeError(description + ": " + str(result))
        time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentprov", default="/usr/local/bin/agentprov")
    parser.add_argument("--image", default="docker.io/rancher/mirrored-library-busybox:1.37.0")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on a K3s test node")
    suffix = uuid.uuid4().hex[:10]
    kube = ["k3s", "kubectl", "-n", "default"]
    pods = []
    processes = []
    checks = {}
    completed = False
    report = {"schema_version": "agentprovenance.node_capture_acceptance/v1",
              "kernel": platform.release(), "architecture": platform.machine(), "checks": checks}
    report_path = Path(args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="agentprov-node-capture-") as directory:
        root = Path(directory)
        data = root / "store"
        cli = [str(Path(args.agentprov).resolve()), "--data-dir", str(data)]

        def query(*command):
            return json.loads(subprocess.check_output(cli + list(command) + ["--json"], text=True))

        def launch_sensor(number):
            err_path = root / f"sensor-{number}.err"
            with (root / f"sensor-{number}.out").open("w") as out, err_path.open("w") as err:
                process = subprocess.Popen(cli + ["sensor", "stream", "--no-policy", "--auto-tls=false",
                    "--batch-events", "64", "--flush-interval", "200ms", "--pending-ttl", "2m"],
                    stdout=out, stderr=err)
            processes.append(process)
            wait_for(lambda: (process.poll(), err_path.read_text()),
                     lambda value: "ready probes-attached" in value[1] or value[0] is not None,
                     "collector never became ready", 30)
            if process.poll() is not None:
                raise RuntimeError("collector failed: " + err_path.read_text())
            return process

        def durable_markers():
            found = set()
            with sqlite3.connect(data / "agentprov.db", timeout=10) as db:
                paths = db.execute("SELECT spool_path FROM telemetry_spool_batches WHERE format='native' AND status IN ('queued','processing')").fetchall()
            for (path,) in paths:
                if not path or not Path(path).exists():
                    continue
                for line in Path(path).read_text().splitlines():
                    event = json.loads(line)
                    if event.get("EventType") != "file_write" or not event.get("ContainerID"):
                        continue
                    payload = json.loads(event["Payload"])
                    if payload.get("path", "").lstrip("/") in expected_markers:
                        found.add(payload["path"].lstrip("/"))
            return sorted(found)

        try:
            collector = launch_sensor(1)
            expected_markers = {f"late-{suffix}-{index}.env" for index in range(2)}
            for index in range(2):
                pod = f"agentprov-late-{suffix}-{index}"
                run = "run-" + pod
                marker = f"late-{suffix}-{index}.env"
                pods.append(pod)
                manifest = {
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": pod, "labels": {"agentprov.io/late-test": suffix},
                                 "annotations": {"agentprov.io/run": run}},
                    "spec": {"restartPolicy": "Never", "containers": [{
                        "name": "instant", "image": args.image, "imagePullPolicy": "IfNotPresent",
                        "command": ["sh", "-ec", f"cd /; printf acceptance > {marker}; cat {marker} >/dev/null; /bin/true"]}]},
                }
                subprocess.run(kube + ["apply", "-f", "-"], input=json.dumps(manifest), text=True,
                               check=True, stdout=subprocess.DEVNULL)
            for pod in pods:
                wait_for(lambda: json.loads(subprocess.check_output(kube + ["get", "pod", pod, "-o", "json"], text=True)),
                         lambda value: value.get("status", {}).get("phase") == "Succeeded", "short Pod did not finish")
                checks[pod + ":no_early_binding"] = not query("telemetry", "bindings", "--run", "run-" + pod)["bindings"]
            sealed = wait_for(durable_markers, lambda value: set(value) == expected_markers,
                              "target events with container identity were not durably captured")
            before = query("sensor", "status")["capture"]
            checks["both_markers_durable_before_crash"] = len(sealed) == 2
            # A SIGKILL bypasses every orderly shutdown/sealing callback.
            collector.kill()
            collector.wait(timeout=10)
            collector = launch_sensor(2)
            node = json.loads(subprocess.check_output(kube + ["get", "pod", pods[0], "-o", "json"], text=True))["spec"]["nodeName"]
            with (root / "watch.out").open("w") as out, (root / "watch.err").open("w") as err:
                watcher = subprocess.Popen(cli + ["sandbox", "watch", "--node", node,
                    "--kubeconfig", "/etc/rancher/k3s/k3s.yaml", "--selector", "agentprov.io/late-test=" + suffix,
                    "--report-interval", "1s"], stdout=out, stderr=err)
            processes.append(watcher)
            runs = []
            for index, pod in enumerate(pods):
                run = "run-" + pod
                marker = f"late-{suffix}-{index}.env"
                bindings = wait_for(lambda: query("telemetry", "bindings", "--run", run)["bindings"] or [],
                    lambda rows: bool(rows) and all(row["ended_at"] for row in rows), "missing terminated container binding")
                events = wait_for(lambda: query("telemetry", "list", "--run", run, "--limit", "1000")["events"] or [],
                    lambda rows: any(row["source"] == "agentprov_ebpf" and row["event_type"] == "file_write" and marker in row["payload"] for row in rows),
                    "early file write was not recovered after collector restart")
                native = [row for row in events if row["source"] == "agentprov_ebpf"]
                checks[pod + ":late_attribution"] = bool(native)
                checks[pod + ":closed_interval"] = all(row["ended_at"] for row in bindings)
                checks[pod + ":no_cross_run"] = all(f"late-{suffix}-{1-index}.env" not in row["payload"] for row in native)
                subprocess.run(cli + ["graph", "materialize", "--run", run], check=True, stdout=subprocess.DEVNULL)
                verified = query("graph", "verify", "--run", run)
                checks[pod + ":verified"] = verified.get("valid", verified.get("status") == "ok")
                runs.append({"run_id": run, "native_events": len(native), "bindings": bindings, "verification": verified})
            # Crash again after attribution: already committed batches must not
            # reinsert events when the collector recovers a second time.
            def native_ids():
                with sqlite3.connect(data / "agentprov.db", timeout=10) as db:
                    return sorted(row[0] for row in db.execute(
                        "SELECT id FROM events WHERE source='agentprov_ebpf' AND run_id IN (?,?)",
                        tuple("run-" + pod for pod in pods)))
            time.sleep(2)
            committed_ids = native_ids()
            collector.kill()
            collector.wait(timeout=10)
            collector = launch_sensor(3)
            time.sleep(3)
            checks["no_duplicate_events_after_second_restart"] = native_ids() == committed_ids
            checks["collector_still_running"] = collector.poll() is None
            report.update(runs=runs, before_crash=before, after_recovery=query("sensor", "status"))
            completed = True
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            subprocess.run(kube + ["delete", "pod"] + pods + ["--ignore-not-found", "--wait=false"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            report["passed"] = completed and bool(checks) and all(checks.values())
            report["diagnostics"] = {path.name: path.read_text()[-16000:] for path in root.glob("*.err")}
            report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit("FAIL: " + ", ".join(name for name, value in checks.items() if not value))


if __name__ == "__main__":
    main()
