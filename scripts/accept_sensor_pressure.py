#!/usr/bin/env python3
"""Bounded x86 sensor pressure acceptance; run as root on an idle test node.

Compares exact attempts/results, kernel loss reporting, immediate shutdown drain,
and resident memory. The optional baseline is measured without pass assertions.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time


def measure(sensor, fixture, label, rounds, pause_us, ring_mib=None):
    with tempfile.TemporaryDirectory(prefix="agentprov-pressure-") as tmp:
        root = Path(tmp)
        records = root / "events.jsonl"
        diagnostics = root / "sensor.log"
        peak = [0]
        stop = threading.Event()
        args = [sensor, "--auto-tls=false", "--apparmor-state=false", "--seccomp-state=false"]
        if ring_mib:
            args += ["--ring-buffer-mib", str(ring_mib)]
        with records.open("w") as out, diagnostics.open("w") as err:
            process = subprocess.Popen(args, stdout=out, stderr=err)
            def sample():
                while not stop.wait(.02):
                    try:
                        for line in Path(f"/proc/{process.pid}/status").read_text().splitlines():
                            if line.startswith("VmRSS:"):
                                peak[0] = max(peak[0], int(line.split()[1]))
                    except FileNotFoundError:
                        return
            monitor = threading.Thread(target=sample, daemon=True)
            monitor.start()
            try:
                deadline = time.monotonic() + 30
                while "agentprov-sensor: ready" not in diagnostics.read_text():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(diagnostics.read_text())
                    time.sleep(.02)
                started = time.monotonic()
                subprocess.run([fixture, str(rounds), str(pause_us)], check=True, timeout=60)
                workload_seconds = time.monotonic() - started
                # Stop immediately: accepted records must survive normal shutdown.
                process.terminate()
                process.wait(timeout=60)
                elapsed = time.monotonic() - started
                if process.returncode:
                    raise RuntimeError(diagnostics.read_text())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                stop.set()
                monitor.join()
        counts = {"file_open": 0, "syscall_result": 0, "process_exit": 0}
        drops = 0
        with records.open() as data:
            for line in data:
                event = json.loads(line)
                if event.get("resource") == "sensor_ringbuf":
                    drops += event.get("dropped_delta", 0)
                if event.get("comm") != "sensor-pressure":
                    continue
                kind = event.get("event_type")
                if kind in counts:
                    counts[kind] += 1
        expected = rounds * 4
        return {"label": label, "expected_opens": expected, "counts": counts,
                "kernel_drops": drops, "workload_seconds": round(workload_seconds, 4),
                "total_and_drain_seconds": round(elapsed, 4), "peak_rss_kib": peak[0],
                "passed": counts["file_open"] == expected and counts["syscall_result"] == expected
                          and counts["process_exit"] == 5 and drops == 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on a test node")
    report = {"schema_version": "agentprovenance.sensor_pressure/v1", "runs": []}
    with tempfile.TemporaryDirectory(prefix="agentprov-load-bin-") as tmp:
        fixture = str(Path(tmp) / "sensor-pressure")
        source = Path(__file__).resolve().parents[1] / "internal/sensor/testdata/sensor_pressure.c"
        subprocess.run(["cc", "-O2", str(source), "-o", fixture], check=True)
        for name, rounds, pause in [("burst", 10000, 0), ("paced", 40000, 10000)]:
            if args.baseline:
                report["runs"].append(measure(args.baseline, fixture, "baseline-" + name, rounds, pause))
            report["runs"].append(measure(args.sensor, fixture, "candidate-" + name, rounds, pause))
        # Force overload with 1 MiB to check the bounded failure path, not a
        # zero-loss claim for a workload beyond the configured buffer budget.
        overload = measure(args.sensor, fixture, "overload-1MiB", 10000, 0, 1)
        overload["passed"] = overload["kernel_drops"] > 0 and overload["counts"]["file_open"] < overload["expected_opens"]
        report["runs"].append(overload)
    report["passed"] = all(r["passed"] for r in report["runs"] if not r["label"].startswith("baseline-"))
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
