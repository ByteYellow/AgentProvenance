#!/usr/bin/env python3
"""Measure retained Browser/Notebook imports and signed/offline exports on fixed inputs.

Inputs are existing recorder JSONL files, not newly executed Agent tasks. All
stores, logs, synthetic signing keys and reports stay in a new private directory.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import uuid
import zipfile


SCHEMA = "agentprovenance.context_cost/v1"
BUDGET_SCHEMA = "agentprovenance.context_cost_budget/v1"
PRESETS = ("basic", "detailed", "detailed-no-attachments")
REPEATS = 3
STAGES = ("import", "project", "query", "bundle", "replay", "excluded_replay")
METRICS = ("store_bytes", "attachment_bytes", "bundle_bytes", "replay_bytes",
           "peak_rss_bytes", "cpu_seconds", *(stage + "_seconds" for stage in STAGES))
# Fixed CLI scheduling allowance, declared before baseline/candidate measurements.
TIME_ALLOWANCE = 0.05


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def save(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")


def environment():
    return {"system": platform.system(), "architecture": platform.machine(),
            "kernel": platform.release(), "hostname": platform.node(),
            "cpu_count": os.cpu_count(), "python": platform.python_version(),
            "memory_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")}


def execute(argv, directory, timeout=120):
    """Blocking wait4 avoids timed-wait quantization and keeps per-child rusage."""
    directory.mkdir(mode=0o700)
    save(directory / "command.json", argv)
    expired = threading.Event()
    with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
        start = time.monotonic()
        child = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True,
                                 env={**os.environ, "AGENTPROV_DAEMON_URL": "", "AGENTPROV_LANG": "en"})

        def stop():
            expired.set()
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(timeout, stop)
        timer.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
        except BaseException:
            stop()
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            raise
        finally:
            timer.cancel()
            timer.join()
        child.returncode = os.waitstatus_to_exitcode(status)
        sample = {"wall_seconds": time.monotonic() - start,
                  "cpu_seconds": usage.ru_utime + usage.ru_stime,
                  "peak_rss_bytes": usage.ru_maxrss * (1024 if sys.platform == "linux" else 1),
                  "exit_code": child.returncode, "timed_out": expired.is_set()}
    save(directory / "measurement.json", sample)
    require(not sample["timed_out"] and sample["exit_code"] == 0,
            "CLI failed; inspect " + str(directory))
    return sample


def store_inventory(root):
    files = [{"path": str(path.relative_to(root)), "bytes": path.stat().st_size}
             for path in sorted(root.rglob("*")) if path.is_file()]
    return {"bytes": sum(item["bytes"] for item in files), "files": files}


def native_identity(entries):
    return sorted(json.dumps({name: entry.get(name) for name in
                              ("kind", "tool_call_id", "notebook", "browser")} |
                             {"harness": entry["source"]["harness"],
                              "session": entry["source"].get("session_id")}, sort_keys=True)
                  for entry in entries)


def replay_inventory(path, entries, attachments):
    with zipfile.ZipFile(path) as archive:
        inventory = json.loads(archive.read("export-inventory.json"))
        require(inventory["signed"] is False, "reading copy must remain unsigned")
        require(inventory["contents"]["context_entries"] == entries, "replay lost context records")
        require(inventory["contents"].get("attachment_refs", 0) == attachments, "replay attachment selection mismatch")
        return inventory


def measure(binary, root, harness, captures, preset):
    root.mkdir(mode=0o700)
    commands, durations = [], {stage + "_seconds": 0.0 for stage in STAGES}

    def cli(data, *args, stage=None, structured=True):
        folder = root / ("command-%03d" % (len(commands) + 1))
        sample = execute([str(binary), "--data-dir", str(data), "--lang", "en", *map(str, args)], folder)
        commands.append(sample)
        if stage:
            durations[stage + "_seconds"] += sample["wall_seconds"]
        raw = (folder / "stdout").read_text()
        return json.loads(raw) if structured else raw

    data, restored, run_id = root / "store", root / "restored", "context-cost-" + harness
    flags = ["--capture", preset.split("-")[0]]
    if preset == "detailed-no-attachments":
        flags += ["--capture-attachments=false"]
    for capture in captures:
        args = ("context", "import", "--run", run_id, "--harness", harness, "--file", capture, *flags)
        first = cli(data, *args, stage="import")
        repeated = cli(data, *args)
        require(first["stored"] > 0 and repeated["stored"] == 0
                and repeated["duplicates"] == first["stored"], "import is not idempotent")
    cli(data, "context", "project", "--run", run_id, stage="project")

    def read_entries(store, stage=None):
        result, cursor = [], ""
        while True:
            page = cli(store, "context", "list", "--run", run_id, "--limit", 100, "--cursor", cursor, stage=stage)
            result.extend(page["entries"] or [])
            if not page["has_more"]:
                return result
            require(page["next_cursor"] and page["next_cursor"] != cursor, "context cursor did not advance")
            cursor = page["next_cursor"]

    entries = read_entries(data, "query")
    require(entries, "capture has no imported context")
    attachments = [item for entry in entries for item in entry.get("attachments", [])]
    require(attachments, "capture must contain typed attachments")
    if preset == "detailed":
        require(all(item["state"] == "stored" and item.get("ref") for item in attachments), "expected retained attachments")
    else:
        require(all(item["state"] == "omitted" and item["reason"] == "capture_policy"
                    and not item.get("ref") for item in attachments), "disabled attachment retention saved bytes")
    refs = {item["ref"]: item for item in attachments if item["state"] == "stored"}
    storage = store_inventory(data)
    save(root / "storage.json", storage)
    private, public = root / "signing.key", root / "signing.pub"
    cli(root / "key-store", "forensics", "keygen", "--priv", private, "--pub", public, structured=False)
    bundle = cli(data, "forensics", "export", run_id, "--sign-key", private, "--json", stage="bundle")
    require(bundle["signed"], "Bundle must be signed")
    bundle_path = Path(bundle["path"])
    bundle_bytes, bundle_digest = bundle_path.stat().st_size, digest(bundle_path)
    imported = cli(restored, "forensics", "import", bundle_path, "--pub-key", public, "--json")
    require(imported["attestation_verified"], "import did not verify signature")
    data.rename(root / "store-unavailable")
    require(read_entries(restored) == entries, "signed round trip changed records")
    graph = cli(restored, "graph", "verify", "--run", run_id, "--json")
    require(graph["error_count"] == 0 and graph["warning_count"] == 0, "graph verification failed")
    for ref, item in refs.items():
        value, count, offset = hashlib.sha256(), 0, 0
        while True:
            page = cli(restored, "context", "attachment", "--run", run_id, "--ref", ref, "--offset", offset, "--limit", 7193)
            chunk = base64.b64decode(page["data"], validate=True)
            value.update(chunk)
            count += len(chunk)
            if not page["has_more"]:
                break
            require(page["next_offset"] == count and count > offset, "attachment cursor mismatch")
            offset = count
        require(value.hexdigest() == item["sha256"] and count == item["bytes"], "attachment bytes changed")
    whole = root / "whole.zip"
    cli(restored, "dashboard", "export", "--run", run_id, "--output", whole, stage="replay", structured=False)
    replay_inventory(whole, len(entries), len(refs))
    archives = {"whole": {"bytes": whole.stat().st_size, "sha256": digest(whole)}}
    if refs:
        excluded = root / "excluded.zip"
        flags = [flag for ref in refs for flag in ("--exclude-attachment", ref)]
        cli(restored, "dashboard", "export", "--run", run_id, "--output", excluded, *flags, stage="excluded_replay", structured=False)
        replay_inventory(excluded, len(entries), 0)
        archives["excluded"] = {"bytes": excluded.stat().st_size, "sha256": digest(excluded)}
    metrics = {**durations, "store_bytes": storage["bytes"], "attachment_bytes": sum(item["bytes"] for item in refs.values()),
               "bundle_bytes": bundle_bytes, "replay_bytes": archives["whole"]["bytes"],
               "cpu_seconds": sum(item["cpu_seconds"] for item in commands),
               "peak_rss_bytes": max(item["peak_rss_bytes"] for item in commands)}
    result = {"harness": harness, "preset": preset, "run_id": run_id, "passed": True,
              "entries": len(entries), "attachments": attachments, "metrics": metrics,
              "archives": archives, "bundle_sha256": bundle_digest, "graph": graph,
              "native_identity_sha256": hashlib.sha256(json.dumps(native_identity(entries)).encode()).hexdigest()}
    save(root / "result.json", result)
    return result


def numeric(value):
    return isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def summaries(report):
    require(report["schema_version"] == SCHEMA and report["repeats"] == REPEATS, "invalid report profile")
    require(len(report["samples"]) == REPEATS * len(PRESETS) * 2, "missing samples")
    result = {}
    for harness in ("browser", "jupyter"):
        all_samples = [s for s in report["samples"] if s["harness"] == harness]
        require(len({s["native_identity_sha256"] for s in all_samples}) == 1, "retention changed native associations")
        for preset in PRESETS:
            samples = [s for s in all_samples if s["preset"] == preset]
            require(len(samples) == REPEATS and {s["repeat"] for s in samples} == {1, 2, 3}
                    and all(s["passed"] is True for s in samples), "failed/duplicate repeats")
            fields = METRICS if preset == "detailed" else tuple(f for f in METRICS if f != "excluded_replay_seconds")
            values = {}
            for field in fields:
                numbers = [s["metrics"].get(field) for s in samples]
                require(all(numeric(n) for n in numbers), "invalid metric " + field)
                values[field] = statistics.median(numbers)
            result[harness + "/" + preset] = values
    return result


def identity(report):
    return {key: report[key] for key in ("environment", "inputs", "measurement_sha256", "repeats")}


def freeze(report):
    require(report["passed"] is True, "baseline must have passed")
    values = summaries(report)
    return {"schema_version": BUDGET_SCHEMA, "frozen_at": datetime.now(timezone.utc).isoformat(),
            "baseline_run_id": report["run_id"], "baseline_binary_sha256": report["binary_sha256"],
            "identity": identity(report), "allowed_regression": .25, "time_allowance_seconds": TIME_ALLOWANCE,
            "limits": {case: {field: {"baseline_median": value,
                                      "maximum": value * 1.25 + (TIME_ALLOWANCE if field.endswith("_seconds") else 0)}
                               for field, value in metrics.items()} for case, metrics in values.items()}}


def check(report, budget):
    require(budget["schema_version"] == BUDGET_SCHEMA and identity(report) == budget["identity"], "budget identity mismatch")
    require(report["run_id"] != budget["baseline_run_id"], "candidate must be a fresh measurement")
    summary = summaries(report)
    require(set(summary) == set(budget["limits"]), "budget cases differ")
    checks = []
    for case, metrics in summary.items():
        require(set(metrics) == set(budget["limits"][case]), "budget metrics differ")
        for field, value in metrics.items():
            limit = budget["limits"][case][field]["maximum"]
            require(numeric(limit), "invalid limit")
            checks.append({"case": case, "metric": field, "actual": value, "maximum": limit, "passed": value <= limit})
    return checks


def run(args):
    require(sys.platform in ("darwin", "linux"), "measurement requires macOS or Linux wait4")
    binary = Path(args.agentprov).resolve(strict=True)
    require(os.access(binary, os.X_OK), "CLI must be executable")
    root = Path(args.output).resolve()
    require(shutil.disk_usage(root.parent).free >= 512 * 1024**2, "at least 512 MiB free space required")
    root.mkdir(mode=0o700, exist_ok=False)
    inputs = {"browser": [Path(p).resolve(strict=True) for p in args.browser_input],
              "jupyter": [Path(p).resolve(strict=True) for p in args.notebook_input]}
    report = {"schema_version": SCHEMA, "run_id": uuid.uuid4().hex, "passed": False, "samples": [],
              "started_at": datetime.now(timezone.utc).isoformat(), "source_commit": args.source_commit,
              "binary_sha256": digest(binary), "environment": environment(), "repeats": REPEATS,
              "inputs": {h: [{"sha256": digest(p), "bytes": p.stat().st_size} for p in paths] for h, paths in inputs.items()},
              "measurement_sha256": digest(__file__),
              "methods": {"cpu": "sum of child user+system time, including validation commands",
                          "rss": "maximum per-child wait4 peak, not the sum of simultaneous processes",
                          "wall": "monotonic through blocking wait4; measured stages exclude verification commands",
                          "storage": "logical files after import/project/query and before Bundle export",
                          "inputs": "fixed historical recorder captures; no Agent, browser, kernel or Sensor started"}}
    try:
        if args.source_commit:
            require(re.fullmatch(r"[0-9a-f]{40}", args.source_commit), "source revision must be a full SHA")
        execute([str(binary), "--version"], root / "version")
        report["binary_version"] = (root / "version/stdout").read_text().strip()
        require(not args.source_commit or args.source_commit in report["binary_version"], "binary source differs")
        budget = json.loads(Path(args.budget).read_text()) if args.budget else None
        if budget:
            require(identity(report) == budget["identity"], "budget identity mismatch before measurement")
        copied = {}
        for harness, paths in inputs.items():
            folder = root / "inputs" / harness
            folder.mkdir(parents=True, mode=0o700)
            copied[harness] = []
            for index, path in enumerate(paths):
                target = folder / f"{index}.jsonl"
                shutil.copyfile(path, target)
                require(digest(target) == report["inputs"][harness][index]["sha256"], "input changed during copy")
                copied[harness].append(target)
        for repeat in range(REPEATS):
            for harness, captures in copied.items():
                for preset in PRESETS[repeat:] + PRESETS[:repeat]:
                    label = f"{repeat + 1}-{harness}-{preset}"
                    print("measuring " + label, flush=True)
                    sample = measure(binary, root / label, harness, captures, preset)
                    sample["repeat"] = repeat + 1
                    report["samples"].append(sample)
        report["summary"] = summaries(report)
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
    command.add_argument("--agentprov", required=True)
    command.add_argument("--browser-input", action="append", required=True)
    command.add_argument("--notebook-input", action="append", required=True)
    command.add_argument("--output", required=True)
    command.add_argument("--source-commit")
    command.add_argument("--budget")
    command = commands.add_parser("freeze")
    command.add_argument("--baseline", required=True)
    command.add_argument("--budget", required=True)
    args = parser.parse_args()
    try:
        if args.command == "run":
            return run(args)
        report = json.loads(Path(args.baseline).read_text())
        budget = freeze(report)
        budget["baseline_report_sha256"] = digest(args.baseline)
        save(args.budget, budget)
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
