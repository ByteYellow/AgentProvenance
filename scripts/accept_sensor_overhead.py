#!/usr/bin/env python3
"""Measure native Sensor cost on an otherwise idle, dedicated Linux test host."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import uuid

from accept_sensor_pressure import DEFAULT_FLAGS, MINIMAL_FLAGS, fixture_run, measure


SCHEMA = "agentprovenance.sensor_overhead/v1"
BUDGET_SCHEMA = "agentprovenance.sensor_overhead_budget/v1"
WORKLOADS = {"burst": (10000, 0), "paced": (40000, 10000)}
PROFILES = {"off": None, "minimal": MINIMAL_FLAGS, "default": DEFAULT_FLAGS}
REPEATS = 3
METRICS = ("workload_seconds", "sensor_cpu_seconds", "peak_rss_kib", "fixture_output_bytes")
# Fixed timer allowances are declared before any baseline or candidate is run.
ALLOWANCES = {"workload_seconds": 0.02, "sensor_cpu_seconds": 0.02,
              "peak_rss_kib": 0, "fixture_output_bytes": 0}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(data)
    return value.hexdigest()


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def environment():
    memory = next(line for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemTotal:"))
    return {"hostname": platform.node(), "system": platform.system(),
            "architecture": platform.machine(), "kernel": platform.release(),
            "cpu_count": os.cpu_count(), "memory_kib": int(memory.split()[1]),
            "python": platform.python_version()}


def numeric(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def capture_passes(result):
    last = result.get("last_capabilities") or {}
    tls_drops = last.get("tls_discovery", {}).get("event_discovery", {}).get("queue_drops", 0)
    return (result["passed"] and result["peak_rss_kib"] is not None
            and result.get("last_ready_capabilities") is not None
            and tls_drops == 0 and all(v == 0 for v in result.get("resource_drops", {}).values()))


def summaries(runs):
    result = {}
    for workload in WORKLOADS:
        off = [r for r in runs if r["workload"] == workload and r["profile"] == "off"]
        require(len(off) == REPEATS, f"missing off samples for {workload}")
        reference = statistics.median(r["workload_seconds"] for r in off)
        require(reference > 0, "off duration must be positive")
        for profile in PROFILES:
            selected = [r for r in runs if r["workload"] == workload and r["profile"] == profile]
            require(len(selected) == REPEATS and {r["repeat"] for r in selected} == {1, 2, 3},
                    f"expected three distinct repeats for {profile}/{workload}")
            require(all(r["passed"] for r in selected), f"failed run in {profile}/{workload}")
            fields = ("workload_seconds", "workload_cpu_seconds")
            if profile != "off":
                fields += ("sensor_cpu_seconds", "peak_rss_kib", "fixture_output_bytes",
                           "output_bytes", "compressed_output_bytes", "startup_seconds", "drain_seconds")
            values = {}
            for field in fields:
                samples = [r.get(field) for r in selected]
                require(all(numeric(v) for v in samples), f"missing/invalid {profile}/{workload}/{field}")
                values[field] = statistics.median(samples)
            values["relative_to_off"] = values["workload_seconds"] / reference
            result[profile + "/" + workload] = values
    return result


def identity(report):
    return {name: report[name] for name in ("environment", "workloads", "profiles", "repeats", "measurement_sha256",
                                          "fixture_source_sha256", "fixture_binary_sha256", "compiler")}


def validate_report(report):
    require(report.get("schema_version") == SCHEMA and report.get("passed") is True, "baseline must have passed")
    require(report["repeats"] == REPEATS and report["profiles"] == PROFILES
            and report["workloads"] == {name: list(value) for name, value in WORKLOADS.items()}, "unexpected profile")
    require(len(report["runs"]) == len(PROFILES) * len(WORKLOADS) * REPEATS, "unexpected sample count")
    return summaries(report["runs"])


def freeze(report, allowed):
    require(numeric(allowed) and allowed <= 1, "allowed regression must be between 0 and 1")
    summary = validate_report(report)
    limits = {}
    for case, values in summary.items():
        fields = ("workload_seconds",) if case.startswith("off/") else METRICS
        limits[case] = {field: {"baseline_median": values[field],
                               "maximum": values[field] * (1 + allowed) + ALLOWANCES[field]}
                        for field in fields}
    return {"schema_version": BUDGET_SCHEMA, "frozen_at": datetime.now(timezone.utc).isoformat(),
            "baseline_run_id": report["run_id"], "baseline_sensor_sha256": report["sensor_sha256"],
            "identity": identity(report), "allowed_regression": allowed,
            "fixed_allowances": ALLOWANCES, "limits": limits}


def check(report, budget):
    require(budget.get("schema_version") == BUDGET_SCHEMA, "invalid budget schema")
    require(identity(report) == budget.get("identity"), "environment/workload/instrument identity differs from baseline")
    require(report["run_id"] != budget["baseline_run_id"], "candidate must be a fresh measurement")
    summary = summaries(report["runs"])
    require(set(budget["limits"]) == set(summary), "budget is missing cases")
    checks = []
    for case, values in summary.items():
        fields = ("workload_seconds",) if case.startswith("off/") else METRICS
        require(set(budget["limits"][case]) == set(fields), "budget is missing metrics")
        for field in fields:
            limit = budget["limits"][case][field]["maximum"]
            require(numeric(limit), "invalid budget limit")
            checks.append({"case": case, "metric": field, "actual": values[field], "maximum": limit,
                           "passed": values[field] <= limit})
    return checks


def run(args):
    require(sys.platform == "linux" and os.geteuid() == 0, "run as root on a dedicated Linux test host")
    sensor = Path(args.sensor).resolve(strict=True)
    require(os.access(sensor, os.X_OK), "Sensor must be executable")
    if args.source_commit:
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_commit), "source commit must be a full SHA")
    budget = json.loads(Path(args.budget).read_text()) if args.budget else None
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[1]
    source = repo / "internal/sensor/testdata/sensor_pressure.c"
    fixture = root / "sensor-pressure"
    report = {"schema_version": SCHEMA, "run_id": uuid.uuid4().hex,
              "started_at": datetime.now(timezone.utc).isoformat(), "passed": False, "runs": [],
              "source_commit": args.source_commit, "sensor_sha256": digest(sensor),
              "environment": environment(), "workloads": {name: list(v) for name, v in WORKLOADS.items()},
              "profiles": PROFILES, "repeats": REPEATS,
              "measurement_sha256": {name: digest(repo / "scripts" / name) for name in
                                     ("accept_sensor_overhead.py", "accept_sensor_pressure.py")},
              "fixture_source_sha256": digest(source),
              "methods": {"cpu": "waited child user+system seconds; sensor includes startup and drain",
                          "rss": "/proc/PID/status VmRSS polled every 20 ms",
                          "wall": "monotonic clock through wait4; fixture forks four workers",
                          "output": "JSONL to local disk; gzip level 1 after timing; node-wide capture",
                          "off": "no Sensor; capture counts and resource metrics remain unknown"}}
    try:
        report["compiler"] = subprocess.check_output(["cc", "--version"], text=True).splitlines()[0]
        subprocess.run(["cc", "-O2", str(source), "-o", str(fixture)], check=True)
        report["fixture_binary_sha256"] = digest(fixture)
        if budget:
            require(identity(report) == budget.get("identity"), "budget identity mismatch before measurement")
        profiles = list(PROFILES)
        for repeat in range(REPEATS):
            # Rotate order so no profile always benefits from the first warm cache.
            for workload, (rounds, pause) in WORKLOADS.items():
                for profile in profiles[repeat:] + profiles[:repeat]:
                    label = f"{repeat + 1}-{workload}-{profile}"
                    print("measuring " + label, flush=True)
                    if profile == "off":
                        result = {"label": label, "passed": True, "capture": "not_collected",
                                  "counts": None, "kernel_drops": None, "peak_rss_kib": None,
                                  "sensor_cpu_seconds": None, "output_bytes": None}
                        try:
                            result.update(fixture_run(fixture, rounds, pause))
                        except Exception as error:
                            result.update(passed=False, error=str(error))
                    else:
                        result = measure(sensor, fixture, label, rounds, pause, output_dir=root / label,
                                         sensor_flags=PROFILES[profile])
                        result["passed"] = capture_passes(result)
                    result.update(profile=profile, workload=workload, repeat=repeat + 1,
                                  node_load_after=list(os.getloadavg()))
                    report["runs"].append(result)
                    save(root / (label + ".json"), result)
        report["summary"] = summaries(report["runs"])
        if budget:
            report["budget_sha256"] = digest(args.budget)
            report["budget_checks"] = check(report, budget)
        report["passed"] = all(item["passed"] for item in report.get("budget_checks", []))
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    save(root / "report.json", report)
    print(json.dumps({"report": str(root / "report.json"), "passed": report["passed"], "error": report.get("error")}))
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("run")
    command.add_argument("--sensor", required=True)
    command.add_argument("--output", required=True)
    command.add_argument("--source-commit")
    command.add_argument("--budget")
    command = commands.add_parser("freeze")
    command.add_argument("--baseline", required=True)
    command.add_argument("--budget", required=True)
    command.add_argument("--allowed-regression", type=float, default=.25)
    args = parser.parse_args()
    try:
        if args.command == "run":
            return run(args)
        baseline = json.loads(Path(args.baseline).read_text())
        budget = freeze(baseline, args.allowed_regression)
        budget["baseline_report_sha256"] = digest(args.baseline)
        save(args.budget, budget)
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
