#!/usr/bin/env python3
"""Compare retained measurements with an unchanged frozen performance budget.

The optional memory-page rule addresses Linux boot accounting on the same VM
profile. It leaves both input files intact and records the exact difference.
All other environment, instrument and workload checks remain in the original
validator. Metric limits are never adjusted.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import accept_context_cost as context
import accept_sensor_overhead as sensor
import accept_telemetry_100k_pressure as telemetry


def compare_environment(current, baseline, allow_memory_page=False):
    if current == baseline:
        return copy.deepcopy(current), {"exact_match": True}
    memory = [key for key in ("memory_bytes", "memory_kib") if key in current and key in baseline]
    if len(memory) != 1:
        raise ValueError("environment identity differs")
    key = memory[0]
    rest = lambda value: {k: v for k, v in value.items() if k != key}
    if rest(current) != rest(baseline):
        raise ValueError("environment differs beyond physical memory accounting")
    if current.get("system") != "Linux":
        raise ValueError("the one-page rule requires Linux boot accounting")
    before, after = baseline[key], current[key]
    if type(before) is not int or type(after) is not int or min(before, after) <= 0:
        raise ValueError("invalid memory accounting")
    delta = (after - before) * (1024 if key == "memory_kib" else 1)
    if not allow_memory_page or abs(delta) > 4096:
        raise ValueError("physical memory accounting differs; explicit one-page comparison required")
    return copy.deepcopy(baseline), {"exact_match": False, "rule": "linux_boot_memory_at_most_one_4k_page",
        "field": key, "baseline": before, "candidate": after, "difference_bytes": delta,
        "maximum_difference_bytes": 4096, "other_environment_fields_equal": True}


def compare(kind, report, budget, allow_memory_page=False):
    if report.get("passed") is not True:
        raise ValueError("measurement must have passed before budget comparison")
    expected = budget["environment"] if kind == "telemetry" else budget["identity"]["environment"]
    # Only the comparison view uses the audited equivalent environment. Raw
    # observations, their hashes, the frozen budget and every metric stay intact.
    value = copy.deepcopy(report)
    value["environment"], environment = compare_environment(report["environment"], expected, allow_memory_page)
    if kind == "telemetry":
        result = telemetry.check_budget(value, budget)
        checks = [{"metric": name, **item} for name, item in result["checks"].items()]
    else:
        checks = (sensor if kind == "sensor" else context).check(value, budget)
    return {"schema_version": "agentprovenance.frozen_budget_comparison/v1", "kind": kind,
        "passed": all(item["passed"] for item in checks), "environment_comparison": environment,
        "metric_limits_changed": False, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("sensor", "context", "telemetry"))
    for name in ("report", "budget", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--allow-memory-page-variation", action="store_true")
    args = parser.parse_args()
    raw_report, raw_budget = args.report.read_bytes(), args.budget.read_bytes()
    result = compare(args.kind, json.loads(raw_report), json.loads(raw_budget), args.allow_memory_page_variation)
    result.update(report_sha256=hashlib.sha256(raw_report).hexdigest(),
        budget_sha256=hashlib.sha256(raw_budget).hexdigest(),
        comparison_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"passed": result["passed"], "checks": len(result["checks"]), "output": str(args.output)}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
