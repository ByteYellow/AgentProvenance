#!/usr/bin/env python3
"""Authenticated telemetry pressure measurement and frozen regression budgets."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RUN = "run-100k-pressure"
PAGE = f"/v1/telemetry/events?run={RUN}&limit=5"
HEALTH = f"/v1/telemetry/producer-health?run={RUN}"
SCHEMA = "agentprovenance.telemetry_pressure_report/v2"
BUDGET_SCHEMA = "agentprovenance.telemetry_pressure_budget/v1"
FLAGS = ["--sample-interval", "0", "--spool-interval", "0", "--spool-limit", "1",
         "--spool-max-queued", "2", "--spool-drop-policy", "reject",
         "--evidence-interval", "0", "--gc-interval", "0"]
METRICS = ("drain_ms", "daemon_peak_rss_bytes", "stopped_store_bytes",
           "health_after_p95_ms", "query_after_p95_ms")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def percentiles(samples):
    require(all(math.isfinite(x) and x >= 0 for x in samples), "invalid latency")
    ordered = sorted(samples)
    if not ordered:
        return {"samples": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None}
    return {"samples": len(ordered), "p50_ms": statistics.median(ordered),
            "p95_ms": ordered[math.ceil(.95 * len(ordered)) - 1],
            "p99_ms": ordered[math.ceil(.99 * len(ordered)) - 1], "max_ms": ordered[-1]}


def cpu_seconds(stat, ticks):
    fields = stat.rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / ticks


def validate_page(page, expected_total=None):
    require(page.get("schema_version") == "agentprovenance.telemetry_events/v1", "page schema")
    count = page.get("event_count")
    require(isinstance(count, int) and 0 <= count <= 5, "page is not bounded")
    require(len(page.get("events") or []) == count, "page count differs from records")
    if expected_total is not None:
        require(page.get("total_count") == expected_total, "unexpected telemetry total")
        require(count == min(5, expected_total), "unexpected page length")
        if expected_total > 5:
            require(page.get("has_more") is True and bool(page.get("next_cursor")), "missing next page")
        require(str(page.get("result_set_id", "")).startswith("sha256:"), "missing result identity")
        require(str(page.get("page_hash", "")).startswith("sha256:"), "missing page digest")


class Client:
    def __init__(self, url, token):
        self.url, self.token = url, token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, body=None, timeout=30):
        raw = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.url + path, data=raw, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        started = time.monotonic()
        with self.opener.open(request, timeout=timeout) as response:
            require(response.status == 200, "unexpected HTTP status")
            content = response.read(8 * 1024 * 1024 + 1)
        require(len(content) <= 8 * 1024 * 1024, "benchmark response exceeds 8 MiB")
        value = json.loads(content)
        require(isinstance(value, dict) and not value.get("error"), "API error response")
        return value, (time.monotonic() - started) * 1000


def generate(path, count):
    with path.open("x", encoding="utf-8") as stream:
        for index in range(count):
            row = {"time": "2026-01-01T00:00:00Z", "rule": "Terminal shell in container",
                   "priority": "Notice", "output_fields": {
                       "evt.type": "execve", "proc.pid": 1000 + index, "proc.ppid": 1,
                       "container.id": "container-pressure", "proc.cmdline": "true"}}
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")


def storage(root):
    # The input fixture is not stored evidence. Include spool files and SQLite WAL.
    sizes = {}
    for path in root.rglob("*"):
        if path.is_file() and "ingest" not in path.relative_to(root).parts:
            sizes[str(path.relative_to(root))] = path.stat().st_size
    return {"logical_bytes": sum(sizes.values()), "files": sizes}


def environment():
    return {"system": platform.system(), "machine": platform.machine(),
            "kernel": platform.release(), "cpu_count": os.cpu_count(),
            "memory_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"),
            "python": platform.python_version()}


def measure(binary, root, count, listen, source_commit, after_samples=30):
    data = root / "store"
    (data / "ingest").mkdir(parents=True)
    fixture = data / "ingest/falco-100k.jsonl"
    generate(fixture, count)
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    if source_commit:
        require(source_commit in version, "binary version does not contain requested source commit")
    profile = {"name": "falco-execve-no-policy/v1", "events": count,
               "input_sha256": digest(fixture), "daemon_flags": FLAGS,
               "page_limit": 5, "during_probe_limit": 10, "after_samples": after_samples}
    report = {"schema_version": SCHEMA, "generated_at": datetime.now(timezone.utc).isoformat(),
              "environment": environment(), "profile": profile,
              "source_commit": source_commit, "binary_sha256": digest(binary),
              "binary_version": version, "script_sha256": digest(__file__),
              "input_bytes": fixture.stat().st_size, "passed": False}
    if listen.endswith(":0"):
        host = listen.rsplit(":", 1)[0]
        with socket.socket() as sock:
            sock.bind((host, 0))
            listen = f"{host}:{sock.getsockname()[1]}"
    stop, peak, cpu_peak, monitor_errors = threading.Event(), [0], [None], []
    samples = {phase: {"health": [], "query": []} for phase in ("during", "after")}
    with (root / "daemon.log").open("x") as log:
        process = subprocess.Popen([str(binary), "--data-dir", str(data), "daemon", "serve",
                                    "--listen", listen, *FLAGS], stdout=log, stderr=log)

        def sample_memory():
            previous = None
            ticks = os.sysconf("SC_CLK_TCK")
            while not stop.wait(.1):
                try:
                    if platform.system() == "Linux":
                        status = Path(f"/proc/{process.pid}/status").read_text()
                        values = [int(row.split()[1]) * 1024 for row in status.splitlines()
                                  if row.startswith("VmRSS:")]
                        if values:
                            peak[0] = max(peak[0], values[0])
                        current = (time.monotonic(), cpu_seconds(
                            Path(f"/proc/{process.pid}/stat").read_text(), ticks))
                        if previous:
                            cpu = (current[1] - previous[1]) / (current[0] - previous[0]) * 100
                            cpu_peak[0] = max(cpu_peak[0] or 0, cpu)
                        previous = current
                    else:
                        raw = subprocess.check_output(["ps", "-o", "rss=,pcpu=", "-p", str(process.pid)], text=True)
                        rss, cpu = raw.split()
                        peak[0] = max(peak[0], int(rss) * 1024)
                        cpu_peak[0] = max(cpu_peak[0] or 0, float(cpu))
                except (OSError, ValueError, subprocess.CalledProcessError) as error:
                    if process.poll() is None:
                        monitor_errors.append(type(error).__name__)
                    return

        monitor = threading.Thread(target=sample_memory, daemon=True)
        monitor.start()
        try:
            client = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                require(process.poll() is None, "daemon exited before readiness; inspect daemon.log")
                token_path = data / "auth-token"
                if token_path.exists():
                    token = token_path.read_text().strip()
                    if token:
                        client = Client("http://" + listen, token)
                        try:
                            health, _ = client.request("/v1/health")
                            if health.get("status") == "ok":
                                break
                        except OSError:
                            pass
                time.sleep(.05)
            else:
                raise ValueError("daemon readiness timeout")
            queued, enqueue_ms = client.request("/v1/telemetry/ingest-falco", {
                "file": str(fixture), "run_id": RUN, "queued": True, "no_policy": True})
            require(queued.get("schema_version") == "agentprovenance.daemon_falco_spool/v1"
                    and queued.get("spool_batch", {}).get("status") == "queued", "batch was not queued")
            report["enqueue_ms"] = enqueue_ms
            report["queued_storage"] = storage(data)
            report["queued_snapshot"], _ = client.request(HEALTH)
            page, _ = client.request(PAGE)
            require(page.get("event_count") == 0, "events visible before explicit drain")

            def probe(phase):
                health, elapsed = client.request("/v1/health")
                require(health.get("status") == "ok", "unhealthy daemon during measurement")
                samples[phase]["health"].append(elapsed)
                page, elapsed = client.request(PAGE)
                validate_page(page, count if phase == "after" else None)
                samples[phase]["query"].append(elapsed)

            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(client.request, "/v1/telemetry/spool/process", {"limit": 1}, 1800)
                while not future.done():
                    if len(samples["during"]["health"]) < 10:
                        probe("during")
                    time.sleep(1)
                envelope, report["drain_ms"] = future.result()
            require(envelope.get("schema_version") == "agentprovenance.telemetry_spool_process/v1",
                    "drain schema")
            result = envelope.get("result", {})
            require(result.get("processed") == 1 and result.get("failed") == 0, "drain failed")
            batches = result.get("batches", [])
            require(len(batches) == 1 and batches[0].get("ingested_count") == count and
                    batches[0].get("failed_count") == 0, "unexpected ingested count")
            if count > 1000:
                require(batches[0].get("row_results_truncated") is True, "unbounded row results")
            report["process_result"] = {key: value for key, value in batches[0].items()
                                        if key not in ("row_results", "events")}
            for _ in range(after_samples):
                probe("after")
            producer, _ = client.request(HEALTH)
            spool = producer.get("spool", {})
            require(spool.get("failed_batches") == 0 and spool.get("failed_events") == 0
                    and spool.get("ingested_events") == count and spool.get("queued_batches") == 0,
                    "producer reports missing, failed or pending events")
            report["producer_health"] = producer
            report["drained_storage"] = storage(data)
            report["passed"] = True
        except Exception as error:
            report["error"] = f"{type(error).__name__}: {error}"
        finally:
            stop.set()
            monitor.join()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    report["error"] = "daemon did not stop within 30 seconds"
            report["daemon_exit_code"] = process.returncode
    report["stopped_storage"] = storage(data)
    report["latency_samples_ms"] = samples
    report["latency"] = {phase: {name: percentiles(values) for name, values in rows.items()}
                         for phase, rows in samples.items()}
    report["metrics"] = {
        "drain_ms": report.get("drain_ms"), "daemon_peak_rss_bytes": peak[0],
        "stopped_store_bytes": report["stopped_storage"]["logical_bytes"],
        "health_after_p95_ms": report["latency"]["after"]["health"]["p95_ms"],
        "query_after_p95_ms": report["latency"]["after"]["query"]["p95_ms"]}
    if report.get("drain_ms"):
        report["ingest_events_per_second"] = count * 1000 / report["drain_ms"]
    report["monitor_errors"] = monitor_errors
    report["daemon_peak_cpu_percent"] = cpu_peak[0]
    report["cpu_measurement"] = ("proc_stat_interval_100ms" if platform.system() == "Linux"
                                 else "ps_lifetime_average_polled_100ms")
    report["passed"] = bool(report["passed"] and not report.get("error") and
                            not monitor_errors and peak[0] > 0 and process.returncode == 0)
    return report


def validate_report(report):
    require(report.get("schema_version") == SCHEMA and report.get("passed") is True,
            "a passing v2 measurement is required")
    for key in ("environment", "profile", "binary_sha256", "script_sha256"):
        require(bool(report.get(key)), "missing measurement identity: " + key)
    for name in METRICS:
        value = report.get("metrics", {}).get(name)
        require(isinstance(value, (int, float)) and not isinstance(value, bool) and
                math.isfinite(value) and value > 0, "missing or invalid metric: " + name)


def freeze(paths, regression):
    require(len(paths) >= 3, "freeze requires at least three independent baseline runs")
    require(math.isfinite(regression) and 0 <= regression <= 1, "invalid allowed regression")
    reports = [json.loads(Path(path).read_text()) for path in paths]
    hashes = [digest(path) for path in paths]
    require(len(set(hashes)) == len(hashes), "baseline runs must be distinct")
    first = reports[0]
    for report in reports:
        validate_report(report)
        for field in ("environment", "profile", "binary_sha256", "script_sha256"):
            require(report[field] == first[field], "baseline mismatch: " + field)
    medians = {name: statistics.median(report["metrics"][name] for report in reports) for name in METRICS}
    # A small fixed latency allowance avoids treating sub-millisecond timer noise
    # as a regression. The allowance is persisted before the candidate is run.
    limits = {name: value * (1 + regression) + (1 if name.endswith("_ms") and name != "drain_ms" else 0)
              for name, value in medians.items()}
    return {"schema_version": BUDGET_SCHEMA, "generated_at": datetime.now(timezone.utc).isoformat(),
            "baseline_sha256": hashes, "baseline_binary_sha256": first["binary_sha256"],
            "environment": first["environment"], "profile": first["profile"],
            "script_sha256": first["script_sha256"], "allowed_regression": regression,
            "query_timer_allowance_ms": 1, "baseline_medians": medians, "maximums": limits}


def check_budget(report, budget):
    validate_report(report)
    require(budget.get("schema_version") == BUDGET_SCHEMA, "budget schema")
    for field in ("environment", "profile", "script_sha256"):
        require(report[field] == budget.get(field), "candidate mismatch: " + field)
    checks = {}
    for name in METRICS:
        maximum = budget.get("maximums", {}).get(name)
        require(isinstance(maximum, (int, float)) and math.isfinite(maximum) and maximum > 0,
                "invalid budget metric: " + name)
        value = report["metrics"][name]
        checks[name] = {"actual": value, "maximum": maximum, "passed": value <= maximum}
    return {"passed": all(item["passed"] for item in checks.values()), "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--agentprov", type=Path)
    run.add_argument("--output", type=Path)
    run.add_argument("--report", type=Path)
    run.add_argument("--events", type=int, default=100000)
    run.add_argument("--listen", default="127.0.0.1:0")
    run.add_argument("--source-commit", default="")
    run.add_argument("--budget", type=Path)
    baseline = commands.add_parser("freeze")
    baseline.add_argument("--baseline", type=Path, action="append", required=True)
    baseline.add_argument("--budget", type=Path, required=True)
    baseline.add_argument("--allowed-regression", type=float, default=.25)
    args = parser.parse_args()
    if args.command == "freeze":
        write_json(args.budget, freeze(args.baseline, args.allowed_regression))
        print(f"Frozen budget: {args.budget}")
        return
    require(args.events >= 10, "use at least ten events for bounded pagination")
    require(args.listen.startswith("127.0.0.1:"), "measurement requires an IPv4 loopback listener")
    if args.output:
        root = args.output.resolve()
        root.mkdir(parents=True, exist_ok=False)
    else:
        root = Path(tempfile.mkdtemp(prefix="agentprov-pressure-"))
    report_path = args.report or root / "report.json"
    require(not report_path.exists(), "report already exists")
    binary = args.agentprov.resolve() if args.agentprov else root / "agentprov"
    if not args.agentprov:
        subprocess.run(["go", "build", "-o", str(binary), "./cmd/agentprov"], cwd=ROOT, check=True)
    report = measure(binary, root, args.events, args.listen, args.source_commit)
    if args.budget and report["passed"]:
        try:
            report["budget_result"] = check_budget(report, json.loads(args.budget.read_text()))
            report["budget_sha256"] = digest(args.budget)
            report["passed"] = report["budget_result"]["passed"]
        except ValueError as error:
            report["passed"], report["error"] = False, str(error)
    write_json(report_path, report)
    print(json.dumps({"passed": report["passed"], "report": str(report_path),
                      "metrics": report["metrics"], "error": report.get("error")}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
