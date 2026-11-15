#!/usr/bin/env python3
"""Bounded Linux sensor pressure acceptance; run as root on an idle test node.

Compares exact attempts/results, kernel loss reporting, immediate shutdown drain,
and resident memory. The optional baseline is measured without pass assertions.
"""
import argparse
from collections import Counter
from contextlib import nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import tempfile
import threading
import time


MINIMAL_FLAGS = ["--auto-tls=false", "--apparmor-state=false", "--seccomp-state=false"]
DEFAULT_FLAGS = ["--auto-tls=true", "--apparmor-state=true", "--seccomp-state=true"]


def fixture_run(fixture, rounds, pause_us):
    started = time.monotonic()
    process = subprocess.Popen([str(fixture), str(rounds), str(pause_us)], start_new_session=True)
    expired = threading.Event()
    def expire():
        expired.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    timer = threading.Timer(60, expire)
    timer.start()
    try:
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        elapsed = time.monotonic() - started
        if expired.is_set():
            raise RuntimeError("workload exceeded 60 seconds")
        code = process.returncode
        if code:
            raise RuntimeError(f"workload exited with {code}")
    finally:
        timer.cancel()
        timer.join()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    return {"workload_seconds": elapsed,
            "workload_cpu_seconds": usage.ru_utime + usage.ru_stime}


def inspect_records(records):
    counts = {"file_open": 0, "syscall_result": 0, "process_exit": 0}
    drops, states = Counter(), Counter()
    digest = hashlib.sha256()
    size = fixture_bytes = 0
    with records.open("rb") as data:
        for raw in data:
            digest.update(raw)
            size += len(raw)
            event = json.loads(raw)
            if not isinstance(event, dict):
                raise ValueError("sensor record must be an object")
            if event.get("event_type") == "resource_pressure":
                drops[event.get("resource", "unknown")] += event.get("dropped_delta", 0)
            if event.get("event_type") == "access_control_state":
                for field in ("identity", "apparmor", "seccomp"):
                    states[field + ":" + event.get("state", {}).get(field, {}).get("status", "unknown")] += 1
            if event.get("comm") == "sensor-pressure":
                fixture_bytes += len(raw)
                kind = event.get("event_type")
                if kind in counts:
                    counts[kind] += 1
    return {"counts": counts, "kernel_drops": drops.get("sensor_ringbuf", 0),
            "resource_drops": dict(drops), "node_access_state_status_counts": dict(states),
            "output_bytes": size, "fixture_output_bytes": fixture_bytes, "output_sha256": digest.hexdigest()}


def capability_snapshots(log):
    ready = last = None
    for line in log.splitlines():
        prefix = "agentprov-sensor: capabilities "
        if line.startswith(prefix):
            last = json.loads(line[len(prefix):])
            if not isinstance(last, dict):
                raise ValueError("capability report must be an object")
            if last.get("ready") is True:
                ready = last
    return {"last_ready_capabilities": ready, "last_capabilities": last}


def measure(sensor, fixture, label, rounds, pause_us, ring_mib=None, *, output_dir=None, sensor_flags=None):
    if output_dir is not None:
        Path(output_dir).mkdir(parents=True, exist_ok=False)
    context = (nullcontext(str(output_dir)) if output_dir is not None else
               tempfile.TemporaryDirectory(prefix="agentprov-pressure-"))
    with context as tmp:
        root = Path(tmp)
        records = root / "events.jsonl"
        diagnostics = root / "sensor.log"
        peak = [None]
        stop = threading.Event()
        args = [str(sensor), *(MINIMAL_FLAGS if sensor_flags is None else sensor_flags)]
        if ring_mib:
            args += ["--ring-buffer-mib", str(ring_mib)]
        env = {key: value for key, value in os.environ.items() if key not in (
            "AGENTPROV_SSL_LIB", "AGENTPROV_GO_TLS_BIN", "AGENTPROV_LIBC_LIB", "AGENTPROV_AUTO_TLS")}
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        launched = time.monotonic()
        result = {"label": label, "expected_opens": rounds * 4, "sensor_flags": args[1:], "passed": False}
        with records.open("w") as out, diagnostics.open("w") as err:
            process = subprocess.Popen(args, stdout=out, stderr=err, env=env)
            def sample():
                while not stop.wait(.02):
                    try:
                        for line in Path(f"/proc/{process.pid}/status").read_text().splitlines():
                            if line.startswith("VmRSS:"):
                                peak[0] = max(peak[0] or 0, int(line.split()[1]))
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
                result["startup_seconds"] = time.monotonic() - launched
                started = time.monotonic()
                result.update(fixture_run(fixture, rounds, pause_us))
                # Stop immediately: accepted records must survive normal shutdown.
                drain_started = time.monotonic()
                process.terminate()
                process.wait(timeout=60)
                result["drain_seconds"] = time.monotonic() - drain_started
                result["total_and_drain_seconds"] = time.monotonic() - started
                if process.returncode:
                    raise RuntimeError(diagnostics.read_text())
            except Exception as error:
                result["error"] = f"{type(error).__name__}: {error}"
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                stop.set()
                monitor.join()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        result["sensor_cpu_seconds"] = (after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
                                         - result.get("workload_cpu_seconds", 0))
        result["sensor_exit_code"] = process.returncode
        result["peak_rss_kib"] = peak[0]
        try:
            result.update(inspect_records(records))
        except (ValueError, TypeError) as error:
            result["error"] = f"invalid sensor JSONL: {error}"
        try:
            result.update(capability_snapshots(diagnostics.read_text()))
        except ValueError as error:
            result["error"] = f"invalid capability report: {error}"
        expected = rounds * 4
        counts = result.get("counts", {})
        result["passed"] = (not result.get("error") and counts.get("file_open") == expected
                            and counts.get("syscall_result") == expected and counts.get("process_exit") == 5
                            and result.get("kernel_drops") == 0)
        if output_dir is not None:
            with records.open("rb") as source, gzip.open(root / "events.jsonl.gz", "wb", compresslevel=1) as target:
                shutil.copyfileobj(source, target)
            result["compressed_output_bytes"] = (root / "events.jsonl.gz").stat().st_size
            records.unlink()
        return result


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
        overload["passed"] = (not overload.get("error") and overload.get("kernel_drops", 0) > 0
                              and overload.get("counts", {}).get("file_open", overload["expected_opens"])
                              < overload["expected_opens"])
        report["runs"].append(overload)
    report["passed"] = all(r["passed"] for r in report["runs"] if not r["label"].startswith("baseline-"))
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
