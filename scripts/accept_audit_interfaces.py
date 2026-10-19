#!/usr/bin/env python3
"""Check audit contracts through real CLI, HTTP, SDK and stdio MCP processes.

Uses synthetic evidence in a temporary store. No kernel probes, policies,
credentials or external services are required.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from agentprov import Client


HOST = "audit-interface-fixture"
BOOT = "01234567-89ab-cdef-0123-456789abcdef"
TARGET = "/tmp/\u539f\u59cb\u8bc1\u636e.txt"
TOKEN = "fixture-only"


def database_digest(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        return hashlib.sha256("\n".join(db.iterdump()).encode()).hexdigest()


def request(base, path, params=None, *, token=TOKEN, locale="en", method="GET"):
    query = urllib.parse.urlencode(params or {})
    url = base + path + ("?" + query if query else "")
    headers = {"Accept-Language": locale}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers, method=method)
    # Test traffic must remain local even when the caller has a proxy configured.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        text = response.read().decode("utf-8")
        body = json.loads(text) if response.headers.get_content_type() == "application/json" else text
        return response.status, body


@contextmanager
def server(binary, directory, env, kind):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        address = f"127.0.0.1:{sock.getsockname()[1]}"
    base = "http://" + address
    args = [binary, "--data-dir", str(directory), kind, "serve"]
    if kind == "daemon":
        args += ["--listen", address, "--auth-token", TOKEN,
                 "--sample-interval", "0", "--evidence-interval", "0",
                 "--spool-interval", "0", "--gc-interval", "0"]
        ready_path = "/v1/ready"
    else:
        args += ["--addr", address]
        ready_path = "/api/runs"
    with (directory / (kind + ".log")).open("w+", encoding="utf-8") as log:
        process = subprocess.Popen(args, stdout=log, stderr=log, env=env)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"{kind} exited: {log.read()}")
                try:
                    if request(base, ready_path)[0] == 200:
                        break
                except (urllib.error.URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{kind} did not become ready")
                time.sleep(0.1)
            yield base
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def seed(cli, directory, run, preset):
    lines = [
        'type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" '
        f'operation="open" profile="fixture" name="{TARGET}" pid=42 '
        'comm="fixture" requested_mask="r" denied_mask="r"',
        'type=SECCOMP msg=audit(1792342593.757:131): pid=42 comm="fixture" '
        'arch=c00000b7 syscall=56 code=0x7ffc0000',
        'type=SECCOMP msg=audit(1792342593.758:132): pid=99 comm="fixture" '
        'arch=c000003e syscall=257 code=0x50000',
    ]
    audit = directory / "synthetic-audit.log"
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
    args = ["telemetry", "ingest-audit", "--run", run, "--file", str(audit),
            "--host-id", HOST, "--boot-id", BOOT, "--capture", preset, "--json"]
    first = json.loads(cli(args).stdout)
    duplicate = json.loads(cli(args).stdout)
    if first["ingested"] != 3 or duplicate["duplicates"] != 3 or duplicate["ingested"] != 0:
        raise AssertionError("audit seed or cross-delivery deduplication failed")
    at = datetime.fromtimestamp(1792342593, timezone.utc) + timedelta(microseconds=757000)
    process = f"{BOOT}:42:1000000000"
    thread = f"{BOOT}:43:1000000000"
    for offset, stage, event_type in [(-5000, "", "execve"),
                                      (100, "attempt", "file_open"),
                                      (200, "result", "syscall_result"),
                                      (5000, "", "process_exit")]:
        payload = {
            "host_id": HOST, "boot_id": BOOT, "process_instance_id": process,
            "process_start_ns": "1000000000", "tid": 43,
            "thread_instance_id": thread, "thread_start_ns": "1000000000",
            "monotonic_ns": str(10000000000 + offset * 1000),
            "realtime_coarse_resolution_ns": 4000000, "comm": "fixture",
            "command": "fixture", "path": TARGET,
        }
        if stage:
            payload.update(operation_id=f"syscall-v1:{thread}:42:1000000000:10000100000",
                           operation="file_open", observation_stage=stage,
                           syscall_start_ns="10000100000", syscall_number=56, sensor_arch="arm64")
        if stage == "result":
            payload.update(syscall_result=-13, syscall_outcome="error")
        if event_type == "process_exit":
            payload["exit_scope"] = "thread_group"
            payload["exit_code"] = 0
        cli(["telemetry", "ingest", "--run", run, "--source", "agentprov_ebpf",
             "--type", event_type, "--pid", "42", "--tgid", "42",
             "--timestamp", (at + timedelta(microseconds=offset)).isoformat(),
             "--payload", json.dumps(payload)])


def exercise(binary, directory, checks):
    env = dict(os.environ, AGENTPROV_DAEMON_URL="", AGENTPROV_DAEMON_TOKEN=TOKEN,
               NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
    os.environ["NO_PROXY"] = env["NO_PROXY"]
    os.environ["no_proxy"] = env["no_proxy"]

    def check(name, passed):
        checks[name] = bool(passed)
        if not passed:
            raise AssertionError(name)

    def cli(args, *, locale="en", input_text=None, success=True):
        proc = subprocess.run([binary, "--data-dir", str(directory), "--lang", locale, *args],
                              input=input_text, capture_output=True, text=True, encoding="utf-8",
                              env=env, timeout=30)
        if success and proc.returncode:
            raise RuntimeError(f"CLI failed: {proc.stderr}")
        return proc

    runs = {preset: f"fixture/audit {preset} & one" for preset in ("basic", "detailed")}
    for preset, run in runs.items():
        seed(cli, directory, run, preset)
        check(preset + ".deduplicated", True)

    with server(binary, directory, env, "daemon") as daemon:
        with server(binary, directory, env, "dashboard") as dashboard:
            before = database_digest(directory / "agentprov.db")
            local = Client(binary=binary, data_dir=directory, env=env, timeout=10)
            # The HTTP method must work without a local CLI executable.
            remote = Client(binary=directory / "absent-binary", daemon_url=daemon, env=env, timeout=10)
            queries, event_queries = [], []
            for preset, run in runs.items():
                cursor, seen = "", []
                for index in range(4):
                    page = local.audit_associations(run, limit=1, cursor=cursor)
                    params = {"run": run, "limit": 1}
                    if cursor:
                        params["cursor"] = cursor
                    queries.append((params, page))
                    key = f"{preset}.page{index + 1}"
                    check(key + ".sdk_http", remote.audit_associations(run, limit=1, cursor=cursor) == page)
                    for locale in ("en", "zh-CN"):
                        for label, base, path in (("daemon", daemon, "/v1/telemetry/audit-associations"),
                                                  ("dashboard", dashboard, "/api/audit/associations")):
                            code, got = request(base, path, params, locale=locale)
                            check(key + f".{label}.{locale}", code == 200 and got == page)
                        args = ["telemetry", "audit-associations", "--run", run, "--limit", "1", "--json"]
                        if cursor:
                            args += ["--cursor", cursor]
                        for label, prefix in (("local_cli", []), ("remote_cli", ["--daemon-url", daemon])):
                            check(key + f".{label}.{locale}",
                                  json.loads(cli(prefix + args, locale=locale).stdout) == page)
                        got = cli(["ai", "call", "get_audit_associations", "--input", json.dumps(params)], locale=locale)
                        check(key + f".ai_call.{locale}", json.loads(got.stdout) == page)
                    seen += page["items"]
                    if not page["has_more"]:
                        break
                    check(key + ".cursor_advances", bool(page.get("next_cursor")) and page["next_cursor"] != cursor)
                    cursor = page["next_cursor"]
                check(preset + ".pages_complete", not page["has_more"] and len(seen) == 3 and len({i["event_id"] for i in seen}) == 3)
                by_decision = {item["decision"]: item for item in seen}
                denied, logged = by_decision["DENIED"], by_decision["LOG"]
                check(preset + ".shared_operation", denied["operation"]["status"] == "inferred"
                      and logged["operation"]["status"] == "inferred"
                      and denied["operations"][0]["id"] == logged["operations"][0]["id"])
                check(preset + ".actual_result", denied["operations"][0]["syscall_result"] == -13
                      and denied["operations"][0]["attempt_record_count"] == 1
                      and denied["operations"][0]["result_record_count"] == 1)
                check(preset + ".unassociated_retained", by_decision["ERRNO"]["process"]["status"] == "unassociated")
                event_id = denied["event_id"]
                exact = local.audit_associations(run, event_id=event_id)
                check(preset + ".exact_event", len(exact["items"]) == 1 and exact["items"][0]["event_id"] == event_id)
                check(preset + ".exact_event_http", remote.audit_associations(run, event_id=event_id) == exact)
                queries.append(({"run": run, "event": event_id}, exact))

                code, records = request(daemon, "/v1/telemetry/events", {"run": run, "type": "access_control", "limit": 10})
                check(preset + ".source_events", code == 200 and len(records["events"]) == 3)
                payload = json.loads(next(e["payload"] for e in records["events"] if e["id"] == event_id))
                while "raw" in payload or "payload" in payload:
                    payload = payload.get("raw", payload.get("payload"))
                check(preset + ".original_target", payload["target"] == TARGET)
                text = payload["raw_record"].get("text", "")
                check(preset + ".raw_retention", TARGET in text if preset == "detailed" else text == "")
                _, translated = request(daemon, "/v1/telemetry/events", {"run": run, "type": "access_control", "limit": 10}, locale="zh-CN")
                check(preset + ".original_language", translated == records)
                event_queries.append(({"run": run, "type": "access_control", "limit": 10}, records))
                for locale in ("en", "zh-CN"):
                    got = cli(["ai", "call", "list_events", "--input", json.dumps(event_queries[-1][0])], locale=locale)
                    check(preset + ".ai_original_language." + locale, json.loads(got.stdout) == records)

            path = "/v1/telemetry/audit-associations"
            run = runs["detailed"]
            for token in ("", "incorrect"):
                code, body = request(daemon, path, {"run": run}, token=token, locale="zh-CN")
                check("auth." + ("missing" if not token else "wrong"), code == 401 and json.dumps(body, ensure_ascii=False).isascii())
            unauthorized = Client(daemon_url=daemon, env={"AGENTPROV_DAEMON_TOKEN": ""}, timeout=10)
            try:
                unauthorized.audit_associations(run)
            except RuntimeError as error:
                check("sdk.auth_failure", "status=401" in str(error) and str(error).isascii())
            else:
                check("sdk.auth_failure", False)
            bad_queries = [({}, "missing_run"), ({"run": run, "limit": "1.5"}, "fractional_limit"),
                           ({"run": run, "session": "other"}, "unknown_filter"),
                           ([("run", run), ("run", run)], "repeated_run"),
                           ({"run": run, "cursor": queries[0][1]["next_cursor"]}, "cross_run_cursor")]
            for params, name in bad_queries:
                code, body = request(daemon, path, params, locale="zh-CN")
                check("http.reject." + name, code == 400 and body["error"].startswith("invalid audit association query") and body["error"].isascii())
            check("http.reject_write", request(daemon, path, {"run": run}, method="POST")[0] == 405)
            for label, client in (("local", local), ("http", remote)):
                try:
                    client.audit_associations(run, cursor="invalid")
                except RuntimeError as error:
                    check("sdk.invalid_cursor." + label, "invalid audit association query" in str(error) and str(error).isascii())
                else:
                    check("sdk.invalid_cursor." + label, False)

            for locale in ("en", "zh-CN"):
                invalid = cli(["telemetry", "audit-associations", "--run", run, "--cursor", "invalid", "--json"], locale=locale, success=False)
                check("cli.error_english." + locale, invalid.returncode != 0 and not invalid.stdout
                      and "invalid audit association query" in invalid.stderr and invalid.stderr.isascii())
                for name, args, message in (
                    ("import", ["telemetry", "ingest-audit", "--run", run, "--json"], "required flag"),
                    ("follow", ["telemetry", "follow-audit", "--run", run, "--once", "--json"], "required flag"),
                    ("ai_input", ["ai", "call", "get_audit_associations", "--input", "{"], "invalid --input JSON"),
                    ("ai_provider", ["ai", "tools", "--provider", "invalid"], "unknown provider"),
                ):
                    bad = cli(args, locale=locale, success=False)
                    check(f"cli.error_english.{name}.{locale}", bad.returncode != 0 and not bad.stdout
                          and message in bad.stderr and bad.stderr.isascii())
                messages = [
                    {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                ]
                for i, (params, _) in enumerate(queries, 2):
                    messages.append({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "get_audit_associations", "arguments": params}})
                for i, (params, _) in enumerate(event_queries, 1000):
                    messages.append({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "list_events", "arguments": params}})
                messages.append({"jsonrpc": "2.0", "id": 999, "method": "tools/call", "params": {"name": "get_audit_associations", "arguments": {"run": run, "limit": 0}}})
                wire = cli(["ai", "mcp"], locale=locale, input_text="".join(json.dumps(m) + "\n" for m in messages))
                replies = [json.loads(line) for line in wire.stdout.splitlines()]
                check("mcp.clean_wire." + locale, len(replies) == len(messages) - 1 and len({r["id"] for r in replies}) == len(replies))
                by_id = {reply["id"]: reply for reply in replies}
                tool = next(t for t in by_id[1]["result"]["tools"] if t["name"] == "get_audit_associations")
                check("mcp.read_only." + locale, tool["annotations"]["readOnlyHint"] is True)
                for i, (_, expected) in enumerate(queries, 2):
                    result = by_id[i]["result"]
                    check(f"mcp.page{i}.{locale}", not result["isError"] and result["structuredContent"] == expected
                          and json.loads(result["content"][0]["text"]) == expected)
                for i, (_, expected) in enumerate(event_queries, 1000):
                    result = by_id[i]["result"]
                    check(f"mcp.original_language{i}.{locale}", not result["isError"] and result["structuredContent"] == expected
                          and json.loads(result["content"][0]["text"]) == expected)
                error = by_id[999]["result"]
                check("mcp.error_english." + locale, error["isError"] and error["structuredContent"]["error"].isascii()
                      and json.loads(error["content"][0]["text"]) == error["structuredContent"])
            check("all_reads_preserve_store", database_digest(directory / "agentprov.db") == before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentprov", default="agentprov")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    binary = shutil.which(args.agentprov)
    if not binary:
        parser.error("agentprov binary not found")
    binary = str(Path(binary).resolve())
    report = {"schema_version": "agentprovenance.audit_interface_acceptance/v1",
              "fixture": "synthetic", "architecture": platform.machine(),
              "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "checks": {}, "passed": False}
    try:
        with tempfile.TemporaryDirectory(prefix="agentprov-audit-api-") as directory:
            exercise(binary, Path(directory), report["checks"])
        report["passed"] = all(report["checks"].values())
    except Exception as error:
        report["error"] = str(error)
    output = Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
