#!/usr/bin/env python3
"""Q-01 controlled soak against an explicitly supplied, isolated loopback daemon.

Example (existing operator-owned daemon; no provisioning or restart):
  python3 scripts/accept_execution_soak.py --url http://127.0.0.1:8787 \
    --config operator.json --token-file daemon.token --daemon-pid 1234 \
    --agentprov ./agentprov --output ./soak-smoke --duration-seconds 60

For the handoff run, explicitly set --duration-seconds 86400. samples.jsonl is
bounded by both records and bytes; reaching either limit ends the run early.
Only this invocation's admitted attempt can receive a stop request. A lost
admission response is not retried as a new operation. Recovery observations are
passive: this script never restarts services, injects faults, or changes policy.
CPU is process CPU-seconds / wall-seconds * 100 (may exceed 100 on many cores).
Resource and latency trends require operator review; duration alone never
automatically passes Q-01. Short runs retain a PENDING 24-hour gate.
"""

import argparse
import contextlib
import datetime
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import re
import signal
import statistics
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


SCHEMA = "agentprovenance.execution_handoff/v1"
DAY = 86400
MAX_RESPONSE = 256 * 1024
QUEUES = ("queued_evidence", "queued_gc", "queued_spool", "queued_spool_bytes", "failed_spool")
NATIVE_GAUGES = ("queued_batches", "queued_bytes", "pending_events", "cleanup_pending_batches")
LOSS_COUNTERS = (
    "dropped_queue_full", "dropped_oversize", "expired_uncorrelated", "kernel_dropped_events",
    "tls_truncated_messages", "tls_reassembly_dropped_streams", "tls_reassembly_dropped_bytes",
    "dropped_partial_recovery", "dropped_partial_shutdown", "invalid",
)
COUNTERS = ("captured", "ingested", "read") + LOSS_COUNTERS


def sha256(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def loopback_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or parsed.username is not None or
            parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("require a loopback HTTP(S) origin without credentials, path or query")
    host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
    try:
        address = ipaddress.ip_address(host)
        port = parsed.port
    except ValueError:
        raise ValueError("require a literal loopback address or localhost") from None
    if not address.is_loopback or port is None:
        raise ValueError("require a loopback address and explicit port")
    authority = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
    return f"{parsed.scheme}://{authority}"


class APIError(RuntimeError):
    """Codes only: response bodies, tokens and filesystem paths stay out of logs."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


@contextlib.contextmanager
def request_deadline(seconds):
    # POSIX wall deadline covers slow headers/bodies as well as connect timeout.
    def expire(signum, frame):
        raise APIError("request_deadline")
    handler = signal.signal(signal.SIGALRM, expire)
    previous = signal.setitimer(signal.ITIMER_REAL, seconds)
    started = time.monotonic()
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, handler)
        if previous[0]:
            signal.setitimer(signal.ITIMER_REAL, max(.001, previous[0] - (time.monotonic() - started)), previous[1])


class API:
    def __init__(self, url, token):
        self.url = loopback_url(url)
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, body=None, timeout=2):
        if timeout <= 0:
            raise APIError("deadline")
        with request_deadline(timeout):
            return self._call(method, path, body, timeout)

    def _call(self, method, path, body, timeout):
        request = urllib.request.Request(self.url + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        deadline = time.monotonic() + timeout
        try:
            try:
                response = self.opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as error:
                if error.code != 503 or path != "/v1/health":
                    error.close()
                    raise APIError(f"http_{error.code}") from None
                response = error
            with response:
                chunks, size = [], 0
                while True:
                    if time.monotonic() >= deadline:
                        raise APIError("response_deadline")
                    chunk = response.read1(min(16384, MAX_RESPONSE + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        raise APIError("response_too_large")
                value = json.loads(b"".join(chunks))
                if not isinstance(value, dict):
                    raise APIError("response_not_object")
                return response.status, value
        except APIError:
            raise
        except (OSError, ValueError, urllib.error.URLError):
            raise APIError("request_failed") from None


def number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def health_projection(value):
    if value.get("schema_version") != "agentprovenance.daemon_health/v1":
        raise APIError("health_schema_mismatch")
    native = value.get("native_capture") or {}
    counters = native.get("counters")
    return {
        "ready": value.get("ready") is True,
        "status": value.get("status") if value.get("status") in {"ok", "degraded", "unavailable"} else "unknown",
        "coverage_status": value.get("coverage_status") if value.get("coverage_status") in {
            "unknown", "not_observed", "no_recorded_gaps", "pending", "gaps_recorded"} else "unknown",
        "queues": {key: number(value.get(key)) for key in QUEUES},
        "native": {key: number(native.get(key)) for key in NATIVE_GAUGES},
        # The daemon's valid counters map is sparse. A missing map is unknown.
        "counters": {key: number(counters.get(key, 0)) if isinstance(counters, dict) else None for key in COUNTERS},
        "native_error_present": bool(native.get("last_error")),
    }


def counter_delta(previous, current):
    delta, resets = {}, []
    for key, value in current.items():
        old = previous.get(key) if previous else None
        if value is None or old is None:
            delta[key] = None
        elif value < old:
            delta[key] = None
            resets.append(key)
        else:
            delta[key] = value - old
    return delta, resets


def proc_stat(text, pid):
    closing = text.rfind(")")
    if closing < 0 or int(text.split("(", 1)[0]) != pid:
        raise ValueError("invalid proc stat")
    fields = text[closing + 2:].split()
    return {"start_ticks": int(fields[19]), "cpu_ticks": int(fields[11]) + int(fields[12]),
            "rss_pages": int(fields[21])}


def read_process(pid, root=pathlib.Path("/proc")):
    try:
        directory = root / str(pid)
        boot = (root / "sys/kernel/random/boot_id").read_text().strip()
        first = proc_stat((directory / "stat").read_text(), pid)
        namespace = os.readlink(directory / "ns/pid")
        second = proc_stat((directory / "stat").read_text(), pid)
        if first["start_ticks"] != second["start_ticks"]:
            return {"status": "identity_raced"}
        return {"status": "ok", "identity": {"boot_id": boot, "pid": pid,
                "start_ticks": second["start_ticks"], "pid_namespace": namespace},
                "cpu_seconds": second["cpu_ticks"] / os.sysconf("SC_CLK_TCK"),
                "rss_bytes": second["rss_pages"] * os.sysconf("SC_PAGE_SIZE")}
    except (OSError, ValueError, IndexError):
        return {"status": "unavailable", "pid": pid, "cpu_seconds": None, "rss_bytes": None}


def process_sample(current, previous, pinned, elapsed):
    if current.get("status") != "ok":
        return current
    if pinned is not None and current["identity"] != pinned:
        return {"status": "identity_changed", "identity": current["identity"],
                "cpu_percent": None, "rss_bytes": None}
    result = dict(current, cpu_percent=None)
    if previous and previous.get("identity") == current["identity"] and elapsed > 0:
        delta = current["cpu_seconds"] - previous["cpu_seconds"]
        if delta >= 0:
            result["cpu_percent"] = 100 * delta / elapsed
    return result


def trend(points):
    values = [(t, value) for t, value in points if number(value) is not None]
    if not values:
        return {"count": 0, "status": "unavailable"}
    xs, ys = zip(*values)
    mean_x, mean_y = statistics.mean(xs), statistics.mean(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    ordered = sorted(ys)
    middle = max(1, len(ys) // 2)
    return {"count": len(ys), "first": ys[0], "last": ys[-1], "min": min(ys), "max": max(ys),
            "mean": mean_y, "p95": ordered[math.ceil(len(ys) * .95) - 1],
            "first_half_mean": statistics.mean(ys[:middle]), "last_half_mean": statistics.mean(ys[middle:] or ys[-1:]),
            "slope_per_hour": 3600 * sum((x - mean_x) * (y - mean_y) for x, y in values) / denominator if denominator else None}


def recovery_intervals(samples, field, end):
    intervals, start = [], None
    for sample in samples:
        healthy = sample[field]
        if not healthy and start is None:
            start = sample["elapsed_seconds"]
        elif healthy and start is not None:
            intervals.append({"start_seconds": start, "end_seconds": sample["elapsed_seconds"],
                              "duration_seconds": sample["elapsed_seconds"] - start, "recovered": True})
            start = None
    if start is not None:
        intervals.append({"start_seconds": start, "end_seconds": None, "duration_seconds": end - start, "recovered": False})
    return {"status": "observed" if intervals else "not_observed", "intervals": intervals,
            "duration_trend": trend([(item["start_seconds"], item["duration_seconds"]) for item in intervals if item["recovered"]])}


class JSONL:
    def __init__(self, path, max_records, max_bytes):
        self.stream = path.open("xb")
        self.max_records, self.max_bytes = max_records, max_bytes
        self.records, self.bytes = 0, 0

    def write(self, value):
        raw = (json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if self.records >= self.max_records or self.bytes + len(raw) > self.max_bytes:
            raise APIError("jsonl_limit")
        self.stream.write(raw)
        self.stream.flush()
        self.records += 1
        self.bytes += len(raw)


def request_for(config, nonce, index, validity_seconds):
    operation = f"soak-{nonce}-{index}"
    # Same admission contract as accept_execution_handoff.py, with no file writes.
    return {"schema_version": SCHEMA,
            "source": {"producer_id": config["caller"]["producer_id"], "namespace": config["caller"]["namespace"],
                       "run_id": "soak-" + nonce, "harness": "http-soak-fixture", "session_id": operation, "tool_call_id": operation},
            "target": config["target"], "dispatch_id": operation, "operation_id": operation,
            "valid_until": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=validity_seconds)).isoformat(),
            "command": {"argv": ["/bin/echo", operation], "disable_snapshot": True,
                        "capture_preset": "basic", "post_root_grace_ms": 25, "tool_results": False}}


def validate_readiness(value, config):
    caller = config["caller"]
    if (value.get("schema_version") != SCHEMA or value.get("target") != config["target"] or
            value.get("principal_id") != caller["principal_id"] or
            value.get("source_producer_id") != caller["producer_id"] or value.get("source_namespace") != caller["namespace"]):
        raise APIError("operator_identity_mismatch")
    if not value.get("worker_running"):
        raise APIError("execution_worker_unavailable")
    if config.get("capture") and not (value.get("native_capture") and value.get("capture_ready")):
        raise APIError("native_capture_unavailable")


def owned_attempt(value, request, expected_id=None):
    attempt = value.get("attempt") or {}
    identity = attempt.get("id", "")
    actual = attempt.get("request") or {}
    if (not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity) or (expected_id and identity != expected_id) or
            any(actual.get(key) != request[key] for key in ("source", "target", "dispatch_id", "operation_id")) or
            (actual.get("command") or {}).get("argv") != request["command"]["argv"]):
        raise APIError("attempt_identity_mismatch")
    return attempt


def completion(value, request, attempt_id, native):
    attempt = owned_attempt(value, request, attempt_id)
    state = attempt.get("state") or {}
    execution = state.get("execution")
    if execution in {"accepted", "starting", "running"}:
        return None
    if execution != "succeeded":
        raise APIError("execution_not_succeeded")
    if native and state.get("capture") not in {"sealed", "incomplete"}:
        return None
    checkpoint = value.get("checkpoint") or {}
    if (not value.get("checkpoint_ref") or not attempt.get("request_hash") or
            checkpoint.get("request_hash") != attempt["request_hash"] or checkpoint.get("attempt_id") != attempt_id or
            checkpoint.get("source") != request["source"] or checkpoint.get("target") != request["target"]):
        raise APIError("checkpoint_identity_mismatch")
    capture = checkpoint.get("capture_report") or {}
    progress = capture.get("scope_progress") or {}
    if native:
        keys = ("events", "ingested", "dropped", "failed", "pending")
        if (capture.get("state") != "sealed" or state.get("capture") != "sealed" or
                not capture.get("start") or not capture.get("end") or progress.get("state") != "settled" or
                any(number(progress.get(key)) is None for key in keys) or
                progress["events"] != sum(progress[key] for key in keys[1:]) or
                any(progress.get(key, 0) for key in ("dropped", "failed", "pending", "sampling_gaps")) or capture.get("error")):
            raise APIError("capture_not_lossless_settled")
    return {"execution": "succeeded", "capture": state.get("capture"), "checkpoint_consistency": "matched",
            "scope_progress": {key: number(progress.get(key)) for key in ("events", "ingested", "dropped", "failed", "pending", "sampling_gaps")}}


def provenance(binary):
    root = pathlib.Path(__file__).resolve().parent.parent
    def git(*args):
        try:
            return subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True,
                                  timeout=2, check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
    dirty = git("status", "--porcelain", "--untracked-files=no")
    return {"source_sha": git("rev-parse", "HEAD"), "tracked_worktree_dirty": None if dirty is None else bool(dirty),
            "script_sha256": sha256(__file__), "handoff_script_sha256": sha256(root / "scripts/accept_execution_handoff.py"),
            "binary_sha256": sha256(binary)}


def run(args):
    # Validate operator inputs before opening the endpoint or creating artifacts.
    api = API(args.url, args.token_file.read_text().strip())
    if not api.token or "\n" in api.token or "\r" in api.token:
        raise ValueError("token file must contain one nonempty bearer credential")
    config = json.loads(args.config.read_text())
    for section, keys in (("caller", ("producer_id", "namespace", "principal_id")), ("target", ("producer_id", "instance_id", "generation"))):
        if not isinstance(config.get(section), dict) or any(not isinstance(config[section].get(key), str) or not config[section][key] for key in keys):
            raise ValueError("operator config requires caller and target identities")
    metadata = provenance(args.agentprov)
    metadata["config_sha256"] = sha256(args.config)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    log = JSONL(args.output / "samples.jsonl", args.max_records, args.max_log_bytes)
    started_at, started = utc_now(), time.monotonic()
    deadline = started + args.duration_seconds
    reserve = min(2.0, args.duration_seconds / 5)
    work_deadline = deadline
    samples, operations, active = [], [], None
    processes = {"daemon": args.daemon_pid}
    if args.sensor_pid:
        processes["sensor"] = args.sensor_pid
    pins, previous_proc, previous_time, previous_counters = {}, {}, {}, None
    stop_reason, failures, interrupted = "duration", [], False
    nonce = uuid.uuid4().hex
    next_sample = next_submit = next_poll = started
    readiness, uncertain_admission = None, None
    old_handlers = {}

    def interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, interrupt)

    def call(method, path, body=None, cleanup=False):
        remaining = (deadline if cleanup else work_deadline) - time.monotonic()
        return api.call(method, path, body, timeout=min(args.request_timeout, remaining))

    try:
        _, readiness = call("GET", "/v1/execution-readiness")
        validate_readiness(readiness, config)
        for label, pid in processes.items():
            initial = read_process(pid)
            if initial["status"] == "ok":
                pins[label] = initial["identity"]
                try:
                    executable_hash = sha256(pathlib.Path("/proc") / str(pid) / "exe")
                    after = read_process(pid)
                    if after.get("identity") != pins[label]:
                        raise APIError("process_identity_raced")
                    metadata[label + "_executable_sha256"] = executable_hash
                    if label == "daemon" and executable_hash != metadata["binary_sha256"]:
                        raise APIError("daemon_binary_mismatch")
                except OSError:
                    metadata[label + "_executable_sha256"] = None
        while time.monotonic() < work_deadline and not interrupted:
            now = time.monotonic()
            if now >= next_sample:
                elapsed = now - started
                sample = {"kind": "sample", "at": utc_now(), "elapsed_seconds": elapsed, "scope": "daemon-wide"}
                try:
                    before = time.monotonic()
                    status, raw = call("GET", "/v1/health")
                    health = health_projection(raw)
                    sample.update(health=health, health_http_status=status, health_latency_ms=(time.monotonic() - before) * 1000)
                    delta, resets = counter_delta(previous_counters, health["counters"])
                    sample.update(counter_delta=delta, counter_resets=resets)
                    previous_counters = health["counters"]
                    sample["available"] = status == 200 and health["ready"]
                    backlog = list(health["queues"].values()) + list(health["native"].values())
                    sample["backlog_clear"] = sample["available"] and all(value == 0 for value in backlog)
                except APIError as error:
                    sample.update(error=str(error), available=False, backlog_clear=False)
                sample["processes"] = {}
                for label, pid in processes.items():
                    current = read_process(pid)
                    sampled_at = time.monotonic()
                    if current["status"] == "ok" and label not in pins:
                        pins[label] = current["identity"]
                    sample["processes"][label] = process_sample(current, previous_proc.get(label), pins.get(label), sampled_at - previous_time.get(label, sampled_at))
                    if sample["processes"][label]["status"] == "ok":
                        previous_proc[label], previous_time[label] = current, sampled_at
                log.write(sample)
                samples.append(sample)
                next_sample = time.monotonic() + args.sample_interval
            now = time.monotonic()
            if active and now >= next_poll:
                _, report = call("GET", "/v1/executions/" + active["id"])
                done = completion(report, active["request"], active["id"], bool(config.get("capture")))
                if done:
                    operation = {"kind": "operation", "operation_id": active["request"]["operation_id"],
                                 "attempt_id": active["id"], "elapsed_seconds": now - started,
                                 "admission_latency_ms": active["admission_latency_ms"],
                                 "completion_observed_latency_ms": (time.monotonic() - active["started"]) * 1000, **done}
                    log.write(operation)
                    operations.append(operation)
                    active = None
                elif now - active["started"] >= args.operation_timeout:
                    raise APIError("owned_operation_timeout")
                next_poll = time.monotonic() + .25
            now = time.monotonic()
            if active is None and now >= next_submit and work_deadline - now > args.operation_timeout + reserve:
                request = request_for(config, nonce, len(operations), min(args.operation_timeout, work_deadline - now))
                uncertain_admission = {"operation_id": request["operation_id"], "valid_until": request["valid_until"], "status": "admission_unconfirmed"}
                _, admission = call("POST", "/v1/executions", request)
                attempt = owned_attempt(admission, request)
                active = {"id": attempt["id"], "request": request, "started": now,
                          "admission_latency_ms": (time.monotonic() - now) * 1000}
                uncertain_admission = None
                next_submit, next_poll = time.monotonic() + args.operation_interval, time.monotonic()
            wake = min(next_sample, next_poll if active else max(next_submit, now + .1), work_deadline)
            time.sleep(max(0, min(.25, wake - time.monotonic())))
        if interrupted:
            stop_reason = "interrupted"
        elif active:
            stop_reason = "unfinished_operation"
    except APIError as error:
        stop_reason = str(error)
        failures.append(stop_reason)
    finally:
        measurement_duration = min(time.monotonic(), deadline) - started
        cleanup = {"status": "not_needed"}
        if active:
            try:
                call("POST", "/v1/executions/" + active["id"] + "/stop",
                     {"operation_id": "soak-cleanup-" + nonce}, cleanup=True)
                cleanup = {"status": "stop_requested", "attempt_id": active["id"]}
            except APIError as error:
                cleanup = {"status": "unconfirmed", "attempt_id": active["id"], "error": str(error)}
        log.stream.close()
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    elapsed = time.monotonic() - started
    observed = samples[-1]["elapsed_seconds"] - samples[0]["elapsed_seconds"] if len(samples) > 1 else 0
    missing_process = sum(any(p["status"] != "ok" for p in sample["processes"].values()) for sample in samples)
    reset_count = sum(len(sample.get("counter_resets", [])) for sample in samples)
    loss_points = {key: [s["counter_delta"][key] for s in samples if s.get("counter_delta", {}).get(key) is not None] for key in LOSS_COUNTERS}
    loss_deltas = {key: sum(values) if values else None for key, values in loss_points.items()}
    metrics = {}
    for key in QUEUES:
        metrics[key] = trend([(s["elapsed_seconds"], s.get("health", {}).get("queues", {}).get(key)) for s in samples])
    for key in NATIVE_GAUGES:
        metrics["native_" + key] = trend([(s["elapsed_seconds"], s.get("health", {}).get("native", {}).get(key)) for s in samples])
    for label in processes:
        for key in ("cpu_percent", "rss_bytes"):
            metrics[label + "_" + key] = trend([(s["elapsed_seconds"], s["processes"][label].get(key)) for s in samples])
    for key in ("admission_latency_ms", "completion_observed_latency_ms"):
        metrics[key] = trend([(op["elapsed_seconds"], op[key]) for op in operations])
    metrics["health_latency_ms"] = trend([(s["elapsed_seconds"], s.get("health_latency_ms")) for s in samples])
    status = "completed" if stop_reason == "duration" and operations else "incomplete"
    report = {"schema_version": "agentprovenance.execution_soak/v1", "status": status,
              "started_at": started_at, "ended_at": utc_now(), "requested_duration_seconds": args.duration_seconds,
              "actual_duration_seconds": elapsed, "observed_sample_span_seconds": observed,
              "measurement_duration_seconds": measurement_duration,
              "stop_reason": stop_reason, "errors": failures, "source": metadata, "process_identities": pins,
              "sample_count": len(samples), "operation_count": len(operations), "cleanup": cleanup,
              "jsonl": {"records": log.records, "bytes": log.bytes, "max_records": args.max_records, "max_bytes": args.max_log_bytes,
                        "sha256": sha256(args.output / "samples.jsonl")},
              "native_capture_requested": bool(config.get("capture")), "loss_counter_increments": loss_deltas,
              "loss_counter_delta_samples": {key: len(values) for key, values in loss_points.items()},
              "uncertain_admission": uncertain_admission,
              "counter_resets": reset_count, "process_unavailable_or_changed_samples": missing_process,
              "metrics": metrics, "sampling_interval_seconds": args.sample_interval, "execution_poll_interval_seconds": .25,
              "availability_recovery": recovery_intervals(samples, "available", elapsed),
              "backlog_recovery": recovery_intervals(samples, "backlog_clear", elapsed),
              "q01_24h": {"status": "PENDING", "duration_met": measurement_duration >= DAY,
                          "reason": "short_run" if measurement_duration < DAY else "operator_trend_recovery_and_integrity_review_required",
                          "integrity_scope": "API checkpoint identity and native scope accounting; not independent signature verification",
                          "fault_injection": "none"}}
    with (args.output / "report.json").open("x") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("status", "actual_duration_seconds", "sample_count", "operation_count", "stop_reason", "q01_24h")}))
    return 0 if status == "completed" else 2


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("config", "token-file", "agentprov", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--daemon-pid", type=int, required=True)
    parser.add_argument("--sensor-pid", type=int)
    parser.add_argument("--duration-seconds", type=float, default=60)
    parser.add_argument("--sample-interval", type=float, default=30)
    parser.add_argument("--operation-interval", type=float, default=60)
    parser.add_argument("--operation-timeout", type=float, default=10)
    parser.add_argument("--request-timeout", type=float, default=2)
    parser.add_argument("--max-records", type=int, default=10000)
    parser.add_argument("--max-log-bytes", type=int, default=32 * 1024 * 1024)
    args = parser.parse_args(argv)
    for key, low, high in (("duration_seconds", 1, DAY), ("sample_interval", .1, 3600),
                           ("operation_interval", .1, 3600), ("operation_timeout", .1, 30), ("request_timeout", .05, 5),
                           ("max_records", 1, 100000), ("max_log_bytes", 128, 128 * 1024 * 1024)):
        if not math.isfinite(getattr(args, key)) or not low <= getattr(args, key) <= high:
            parser.error(f"{key} must be between {low} and {high}")
    if args.daemon_pid <= 0 or (args.sensor_pid is not None and args.sensor_pid <= 0):
        parser.error("process IDs must be positive, explicit operator inputs")
    return args


def main():
    os.umask(0o077)
    try:
        return run(arguments())
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"status": "input_or_io_error", "detail": "check explicit inputs and output permissions; no credentials logged"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
