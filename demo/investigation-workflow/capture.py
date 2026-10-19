#!/usr/bin/env python3
"""Capture two real DeepSeek runs in an isolated Linux demonstration workspace."""
import argparse
import base64
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time


HERE = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, capture_output=True, **kwargs)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def journal_cursor():
    last = run(["journalctl", "-k", "-n", "1", "-o", "json", "--no-pager"]).stdout
    return json.loads(last.strip().splitlines()[-1])["__CURSOR"]


def audit_records(cursor, diagnostics):
    time.sleep(1)
    journal = run(["journalctl", "-k", f"--after-cursor={cursor}", "-o", "json", "--no-pager"]).stdout
    pids = {str(item["pid"]) for item in diagnostics}
    records = []
    for line in journal.splitlines():
        record = json.loads(line)
        message = record.get("MESSAGE", "")
        match = re.search(r"\bpid=(\d+)\b", message)
        if match and match[1] in pids and ("apparmor=" in message or "type=1326" in message or "SECCOMP" in message):
            records.append(record)
    return records


def contains_credential(raw, key):
    if key.encode() in raw:
        return True
    bundle = json.loads(raw)
    return any(key.encode() in base64.b64decode(row["content_b64"])
               for table in ("object_blobs", "snapshot_files")
               for row in bundle.get(table, []) if row.get("content_b64"))


def export_capture(cli, run_id, private, public, stage, key):
    exported = json.loads(run(cli + ["forensics", "export", run_id, "--sign-key",
                                    str(private / "sign.key"), "--json"]).stdout)
    raw = Path(exported["path"]).read_bytes()
    if contains_credential(raw, key):
        raise RuntimeError("Credential scan failed; public bundle was not copied")
    output = public / f"{stage}.forensics.json.gz"
    output.write_bytes(gzip.compress(raw, mtime=0))
    attestation = public / f"{stage}.forensics.dsse.json"
    shutil.copy2(exported["attestation_path"], attestation)
    with tempfile.TemporaryDirectory(prefix="agentprov-demo-replay-") as fresh:
        replay = [cli[0], "--data-dir", fresh]
        run(replay + ["forensics", "import", str(output), "--pub-key",
                      str(public / "demo-signing.pub"), "--json"])
        run(replay + ["graph", "verify", "--run", run_id, "--json"])
    return output


class Rates(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/rates.json":
            self.send_error(404)
            return
        body = b'{"base":"USD","rate":"1.00","source":"local-demo"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def capture(args):
    if os.geteuid() != 0:
        raise SystemExit("Run inside a disposable Linux VM as root.")
    account = pwd.getpwnam(args.user)
    home = Path(account.pw_dir)
    base = args.output.resolve()
    base.mkdir(mode=0o755)
    work = base / "workspace"
    shutil.copytree(HERE / "workspace", work, ignore=shutil.ignore_patterns("__pycache__"))
    for item in [work, *work.rglob("*")]:
        os.chown(item, account.pw_uid, account.pw_gid)
    private = base / "private"
    private.mkdir(mode=0o700)
    public = base / "public"
    public.mkdir()
    guard = base / "guard-probe"
    run(["cc", "-static", "-O2", "-Wall", "-Werror", str(HERE / "guard-probe.c"), "-o", str(guard)])
    profile_name = "agentprov-demo-" + hashlib.sha256(str(base).encode()).hexdigest()[:12]
    profile = private / "apparmor.profile"
    profile.write_text(
        f'profile {profile_name} "{guard}" flags=(attach_disconnected) {{\n'
        '  file,\n  network,\n  signal,\n'
        f'  audit deny "{work / "vault/release_secret.txt"}" r,\n}}\n'
    )
    binary = str(args.binary.resolve())
    cli = [binary, "--data-dir", str(private / "store")]
    run(cli + ["forensics", "keygen", "--priv", str(private / "sign.key"), "--pub", str(public / "demo-signing.pub")])
    env = dict(os.environ, HOME=str(home), DSH_HOME=str(args.dsh_home),
               DSH_TELEMETRY_DISABLED="1", AGENTPROV_SSL_LIB=str(args.tls_library),
               AGENTPROV_LIBC_LIB=args.libc_library, AGENTPROV_TLS_CAPTURE_BODY="1",
               DEMO_GUARD_PROBE=str(guard),
               PATH=f"{home}/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Rates)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env["DEMO_RATE_PORT"] = str(server.server_port)
    # Credentials remain outside the recorded workspace; only an exact-match scan
    # uses their values, and neither the values nor this private file are exported.
    key = run(["/bin/bash", "-c", 'set -a; . "$1"; printf %s "${DEEPSEEK_API_KEY:-$ANTHROPIC_AUTH_TOKEN}"',
               "read-demo-key", str(args.env_file)], env=env).stdout
    if not key:
        raise SystemExit("The environment file must set DEEPSEEK_API_KEY or ANTHROPIC_AUTH_TOKEN.")
    manifest = {
        "schema_version": "agentprovenance.investigation_demo/v1",
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": os.uname().machine,
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        "harness": "deepseek",
        "capture": "detailed",
        "tls_body": True,
        "workload": "local reporting pipeline, public canary, loopback rate service",
        "runs": [],
    }
    root_session = None
    loaded = False
    try:
        run(["apparmor_parser", "-r", str(profile)])
        loaded = True
        cursor = journal_cursor()
        checks = [json.loads(run(["runuser", "-u", args.user, "--", str(guard), *arguments]).stdout)
                  for arguments in (["read", str(work / "vault/release_secret.txt")],
                                    ["connect", "127.0.0.1", str(server.server_port)])]
        if [item["errno"] for item in checks] != [13, 1] or len(audit_records(cursor, checks)) < 3:
            raise RuntimeError("AppArmor/seccomp preflight failed before the model was started")
        print(json.dumps({"stage": "preflight", "status": "passed"}), flush=True)
        for stage in ("before", "after"):
            case = private / stage
            case.mkdir()
            cursor = journal_cursor()
            (case / "journal-cursor.txt").write_text(cursor)
            task = (HERE / f"task-{stage}.txt").read_text()
            command = cli + ["launch", "--capture", "detailed", "--no-dashboard", "--json",
                             "--sensor", "auto", "--file-diff", "--sign-key", str(private / "sign.key"),
                             "--context-harness", "deepseek", "--context-dir", str(args.dsh_home / "sessions"),
                             "--workdir", str(work)]
            if root_session:
                command += ["--context-session", root_session]
            command += ["--", "/usr/sbin/runuser", "-u", args.user, "--", "/bin/bash", "-c",
                        'set -a; . "$1"; export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-$ANTHROPIC_AUTH_TOKEN}"; '
                        'exec "$HOME/.local/bin/dsh" headless --json ${3:+--session-id "$3"} "$2"',
                        "capture-task", str(args.env_file), task, root_session or ""]
            started = time.monotonic()
            print(json.dumps({"stage": stage, "status": "capturing"}), flush=True)
            with (case / "launch.json").open("w") as out, (case / "launch.log").open("w") as err:
                proc = subprocess.Popen(command, env=env, stdout=out, stderr=err, start_new_session=True)
                try:
                    status = proc.wait(timeout=900)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGINT)
                    try:
                        proc.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                    raise
            if status:
                raise RuntimeError(f"{stage} launch exited {status}; inspect its private log")
            launch = json.loads((case / "launch.json").read_text())
            run_id = launch["run_id"]
            sources = {c["source"]["id"]: c["source"]
                       for c in launch["agent_context"]["coverage"]
                       if c["source"]["harness"] == "deepseek" and c["source"].get("channel") == "transcript"}
            roots = {s["session_id"] for s in sources.values() if not s.get("parent_session_id")}
            if len(roots) != 1:
                raise RuntimeError(f"Expected one native root session, got {len(roots)}")
            actual_root = roots.pop()
            if root_session and root_session != actual_root:
                raise RuntimeError("The second run did not resume the original session")
            root_session = actual_root
            children = {s["session_id"] for s in sources.values() if s.get("parent_session_id")}
            if not children:
                raise RuntimeError("The harness did not capture a real subagent session")
            report = json.loads((work / "output/report.json").read_text())
            diagnostics = json.loads((work / "output/diagnostics.json").read_text())
            if report["total"] != "42.00":
                raise RuntimeError("Unexpected report total")
            if stage == "before" and [item["errno"] for item in diagnostics] != [13, 1]:
                raise RuntimeError("Expected real AppArmor EACCES and seccomp EPERM results")
            if stage == "after" and diagnostics:
                raise RuntimeError("The repaired run still invoked optional diagnostics")
            save(case / "diagnostics.json", diagnostics)
            save(case / "report.json", report)
            shutil.copy2(work / "settings.json", case / "settings.json")
            records = audit_records(cursor, diagnostics)
            audit_file = case / "audit.jsonl"
            audit_file.write_text("".join(json.dumps(r) + "\n" for r in records))
            if stage == "before" and len(records) < 3:
                raise RuntimeError(f"Expected three kernel audit records, got {len(records)}")
            if records:
                imported = run(cli + ["telemetry", "ingest-audit", "--run", run_id, "--file", str(audit_file), "--json"])
                save(case / "audit-import.json", json.loads(imported.stdout))
            run(cli + ["graph", "materialize", "--run", run_id])
            verified = run(cli + ["graph", "verify", "--run", run_id, "--json"])
            save(case / "verify.json", json.loads(verified.stdout))
            if key in json.dumps(launch):
                raise RuntimeError("Credential scan failed; public bundle was not copied")
            output_bundle = export_capture(cli, run_id, private, public, stage, key)
            result = {"stage": stage, "run_id": run_id, "session_id": root_session,
                      "child_sessions": sorted(children), "audit_records": len(records),
                      "messages": launch["agent_context"]["messages"],
                      "tool_calls": launch["agent_context"]["tool_calls"],
                      "report_total": report["total"], "diagnostics": diagnostics,
                      "duration_seconds": round(time.monotonic() - started, 2),
                      "bundle": output_bundle.name, "bundle_bytes": output_bundle.stat().st_size,
                      "bundle_sha256": hashlib.sha256(output_bundle.read_bytes()).hexdigest()}
            manifest["runs"].append(result)
            save(public / "capture-manifest.json", manifest)
            print(json.dumps(result), flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        if loaded:
            run(["apparmor_parser", "-R", str(profile)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new directory outside the source checkout")
    parser.add_argument("--user", default="agentprov")
    parser.add_argument("--dsh-home", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--tls-library", type=Path, required=True)
    parser.add_argument("--libc-library", required=True)
    capture(parser.parse_args())
