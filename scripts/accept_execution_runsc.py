#!/usr/bin/env python3
"""Exercise pinned runsc command capture and recovery through the public API.

Run as root with a trusted CLI/runsc and disposable rootfs containing /bin/sh,
/bin/true and /bin/sleep. The output and all ancestors must be root-owned and
not writable by other users. Private fixture keys stay in this output directory.
"""

import argparse
import copy
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

from accept_seccheck import digest, write_json
from accept_seccheck_faults import latest_status, require_preserved_records, wait_for


def require(value, message):
    if not value:
        raise RuntimeError(message)


class Scenario:
    def __init__(self, args, name):
        self.args, self.name = args, name
        self.root = args.output / name
        self.root.mkdir(mode=0o700)
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.receiver = self.root / "receiver"
        self.store = self.root / "executor"
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.socket = self.root / "events.sock"
        self.status = self.root / "receiver.jsonl"
        self.container = "ap-r02-" + name
        self.target = {"producer_id": "runsc-acceptance", "instance_id": args.output.name + "-" + name, "generation": "generation-1"}
        self.scope = {"run_id": "receiver-" + name, "socket_path": str(self.socket), "registration": {
            "namespace": self.target["producer_id"], "instance_id": self.target["instance_id"], "generation": self.target["generation"],
            "sandbox_id": self.container, "container_id": self.container, "peer_uid": 0}}
        self.processes = []
        self.runtime = self.collector = self.daemon = None
        self.receiver_epoch = self.daemon_epoch = 0
        self.token = uuid.uuid4().hex + uuid.uuid4().hex
        self.env = dict(os.environ)
        self.env.pop("AGENTPROV_DAEMON_URL", None)
        self.env["AGENTPROV_DAEMON_TOKEN"] = self.token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.url = "http://127.0.0.1:" + str(reservation.getsockname()[1])
        self.config_path = self.root / "execution.json"
        self.reports = {}

    def command(self, argv, timeout=60):
        result = subprocess.run([str(x) for x in argv], env=self.env, capture_output=True, text=True, timeout=timeout)
        require(result.returncode == 0, "command failed: " + result.stderr[-1500:].replace(self.token, "[redacted]"))
        return result.stdout

    def cli(self, *args):
        return self.command([self.args.cli, *args])

    def launch(self, argv, log):
        with log.open("w") as stream:
            p = subprocess.Popen([str(x) for x in argv], env=self.env, stdout=stream, stderr=subprocess.STDOUT)
        self.processes.append(p)
        return p

    def start_receiver(self):
        self.receiver_epoch += 1
        if self.status.exists():
            self.status.rename(self.root / ("receiver-" + str(self.receiver_epoch - 1) + ".jsonl"))
        with self.status.open("w") as out, (self.root / ("receiver-" + str(self.receiver_epoch) + ".stderr")).open("w") as err:
            self.collector = subprocess.Popen([str(self.args.cli), "--data-dir", str(self.receiver), "telemetry", "receive-seccheck",
                "--config", str(self.root / "registration.json"), "--json", "--status-interval", "100ms", "--batch-events", "16"],
                env=self.env, stdout=out, stderr=err)
        self.processes.append(self.collector)
        wait_for(lambda: latest_status(self.status).get("state") == "listening", "receiver listening")

    def start(self):
        trace = json.loads(self.cli("--data-dir", self.receiver, "telemetry", "seccheck-config", "--socket", self.socket))
        write_json(self.root / "trace.json", trace)
        write_json(self.root / "registration.json", {"schema_version": "agentprovenance.seccheck_collection/v1",
            "runtime_release": "release-20261109.0", "targets": [self.scope]})
        write_json(self.root / "config.json", {"ociVersion": "1.0.2", "root": {"path": str(self.args.rootfs), "readonly": True},
            "process": {"terminal": False, "user": {"uid": 0, "gid": 0}, "args": ["/bin/sleep", "600"], "env": ["PATH=/bin:/usr/bin"], "cwd": "/"},
            "mounts": [{"destination": "/proc", "source": "proc", "type": "proc"},
                {"destination": "/control", "source": str(self.control), "type": "bind", "options": ["bind", "rw"]}],
            "linux": {"namespaces": [{"type": n} for n in ("pid", "mount", "network", "ipc", "uts")]}})
        self.start_receiver()
        self.runtime = self.launch([self.args.runsc, "--root=" + str(self.state), "--platform=systrap", "--network=none",
            "run", "--bundle=" + str(self.root), self.container], self.root / "runsc.log")
        def running():
            p = subprocess.run([str(self.args.runsc), "--root=" + str(self.state), "state", self.container], capture_output=True, timeout=5)
            return p.returncode == 0 and json.loads(p.stdout).get("status") == "running"
        wait_for(running, "OCI running", timeout=30)
        # Use the explicit trace lifecycle: the trace-create client exits
        # before commands start, leaving no initial-launch FD held by runsc run.
        self.reconnect()
        metadata = list(self.state.glob(self.container + "_sandbox:*.state"))
        require(len(metadata) == 1, "ambiguous runtime lifecycle")
        created = json.loads(metadata[0].read_text())["createdAt"]
        for who in ("executor", "reader"):
            self.cli("forensics", "keygen", "--priv", self.root / (who + ".key"), "--pub", self.root / (who + ".pub"))
        self.config = {"target": self.target, "caller": {"principal_id": "fixture", "producer_id": "caller", "namespace": "fixture"},
            "concurrency": 1, "backend": {"mode": "runsc", "runsc": {"binary": str(self.args.runsc), "root": str(self.state),
                "container_id": self.container, "state_created": created, "runtime_release": "release-20261109.0", "workdir": "/", "allow_uncorrelated": True},
                "seccheck": {"target": self.scope, "status_file": str(self.status), "data_dir": str(self.receiver)}},
            "delivery": {"receiver_id": "reader", "sign_key_file": str(self.root / "executor.key"), "receiver_public_key_file": str(self.root / "reader.pub")}}
        write_json(self.config_path, self.config)
        wait_for(lambda: latest_status(self.status).get("targets", [{}])[0].get("state") == "connected", "receiver connected")
        self.start_daemon()

    def start_daemon(self):
        self.daemon_epoch += 1
        self.daemon = self.launch([self.args.cli, "--data-dir", self.store, "daemon", "serve", "--listen", self.url.removeprefix("http://"),
            "--execution-config", self.config_path, "--record-allow-shell", "--record-timeout", "15s", "--sample-interval", "0", "--gc-interval", "0"],
            self.root / ("daemon-" + str(self.daemon_epoch) + ".log"))
        def ready():
            require(self.daemon.poll() is None, "executor exited during startup")
            try:
                return self.api("GET", "/v1/ready").get("ready")
            except OSError:
                return False
        wait_for(ready, "executor ready", timeout=30)

    def api(self, method, path, body=None, url=None):
        req = urllib.request.Request((url or self.url) + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with self.opener.open(req, timeout=10) as response:
            return json.load(response)

    def request(self, name, command):
        return {"schema_version": "agentprovenance.execution_handoff/v1", "source": {"producer_id": "caller", "namespace": "fixture",
                "run_id": self.name, "harness": "runsc-http-fixture", "session_id": name, "tool_call_id": "tool"},
            "target": self.target, "dispatch_id": name, "operation_id": name + "-submit",
            "valid_until": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat(),
            "command": {"argv": ["/bin/sh", "-c", command], "disable_snapshot": True, "capture_preset": "detailed"}}

    def submit(self, request):
        result = self.api("POST", "/v1/executions", request)
        write_json(self.root / (request["operation_id"] + "-admission.json"), result)
        return result

    def wait(self, admission, name, running=False):
        attempt = admission["attempt"]["id"]
        def completed():
            report = self.api("GET", "/v1/executions/" + attempt)
            self.reports[name] = report
            write_json(self.root / (name + "-report.json"), report)
            state = report["attempt"]["state"]
            if running:
                return report if state["execution"] == "running" else None
            return report if state["execution"] in {"succeeded", "failed", "unknown", "cancelled"} and state["capture"] in {"sealed", "incomplete"} else None
        return wait_for(completed, name + " completion", timeout=50)

    def events(self):
        with sqlite3.connect((self.receiver / "agentprov.db").as_uri() + "?mode=ro", uri=True) as db:
            return dict(db.execute("SELECT id,payload FROM events WHERE source='gvisor_seccheck'"))

    def reconnect(self):
        self.command([self.args.runsc, "--root=" + str(self.state), "trace", "create", "--force", "--config=" + str(self.root / "trace.json"), self.container])
        wait_for(lambda: latest_status(self.status).get("targets", [{}])[0].get("state") == "connected", "new trace connection")

    def close(self):
        if self.runtime is not None:
            result = subprocess.run([str(self.args.runsc), "--root=" + str(self.state), "delete", "--force", self.container], capture_output=True, timeout=15)
            (self.root / "runtime-cleanup.log").write_bytes(result.stdout + result.stderr)
            require(result.returncode == 0, "owned runtime cleanup failed")
        for proc in reversed(self.processes):
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                    raise RuntimeError("owned process required forced cleanup")


def sealed(report, outcome="succeeded"):
    require(report["attempt"]["state"]["execution"] == outcome and report["attempt"]["state"]["capture"] == "sealed", "unexpected command outcome or capture state")
    capture = report["checkpoint"]["runtime_report"]["capture"]
    require(capture["state"] == "sealed" and capture.get("command") and capture.get("evidence_ref") and not capture["gaps"], "missing persisted command boundary")
    return capture


def baseline(s):
    request = s.request("once", "printf x >> /control/invocations; /bin/true")
    # A real loopback relay discards the HTTP reply after durable admission.
    saved = []
    class DropReply(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            require(self.path == "/v1/executions", "unexpected relay path")
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            saved.append(s.api("POST", self.path, body))
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
    relay = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DropReply)
    thread = threading.Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            s.api("POST", "/v1/executions", request, url="http://127.0.0.1:" + str(relay.server_port))
        except (OSError, ConnectionError):
            pass
        else:
            raise RuntimeError("admission response loss was not injected")
    finally:
        relay.shutdown(); relay.server_close(); thread.join(timeout=5)
    require(len(saved) == 1, "relay did not persist exactly one admission")
    admission = saved[0]
    write_json(s.root / "lost-reply-admission.json", admission)
    first = s.wait(admission, "once")
    sealed(first)
    for _ in range(3):
        duplicate = s.submit(request)
        require(duplicate["reused"] and duplicate["attempt"]["id"] == admission["attempt"]["id"], "transport retry reexecuted")
        require(s.wait(duplicate, "once")["checkpoint_ref"] == first["checkpoint_ref"], "query changed checkpoint")
    require((s.control / "invocations").read_text() == "x", "query/retry changed execution count")
    wrong = copy.deepcopy(request); wrong["target"]["generation"] = "wrong-generation"
    try:
        s.submit(wrong)
    except urllib.error.HTTPError as error:
        require(error.code == 403, "wrong generation response")
    else:
        raise RuntimeError("wrong generation accepted")
    retry = dict(request, operation_id="once-explicit-retry", previous_attempt_id=admission["attempt"]["id"])
    second = s.submit(retry)
    sealed(s.wait(second, "explicit-retry"))
    require(second["attempt"]["id"] != admission["attempt"]["id"] and (s.control / "invocations").read_text() == "xx", "explicit retry did not create one new attempt")
    failed = s.wait(s.submit(s.request("exit-seven", "exit 7")), "exit-seven")
    require(sealed(failed, "failed")["command"]["root_wait_status"] == 7 << 8, "native nonzero exit lost")
    collect = ["--data-dir", s.root / "reader", "--daemon-url", s.url, "forensics", "collect-execution", s.root / "lost-reply-admission.json",
        "--execution-config", s.config_path, "--receiver", "reader", "--sign-key", s.root / "reader.key", "--pub-key", s.root / "executor.pub", "--operation", "deliver-once"]
    receipt = json.loads(s.cli(*collect))
    require(receipt["status"] == "acknowledged" and json.loads(s.cli(*collect)) == receipt, "signed receipt retry changed")
    write_json(s.root / "delivery.json", receipt)
    with sqlite3.connect((s.root / "reader/agentprov.db").as_uri() + "?mode=ro", uri=True) as db:
        ref = first["checkpoint"]["runtime_report"]["capture"]["evidence_ref"]
        row = db.execute("SELECT path FROM provenance_objects WHERE run_id=? AND hash=?", (first["attempt"]["local_run_id"], ref)).fetchone()
        require(row is not None, "signed delivery omitted command evidence")
        raw = Path(row[0]).read_bytes()
        require("sha256:" + hashlib.sha256(raw).hexdigest() == ref, "command evidence digest changed")
        evidence = json.loads(raw)["payload"]
        require(evidence["events"] and evidence["boundary_events"] and all(e["run_id"] == s.scope["run_id"] for e in evidence["events"]), "native command source identity changed")
    s.daemon.send_signal(signal.SIGTERM); require(s.daemon.wait(timeout=30) == 0, "clean executor restart failed")
    s.start_daemon()
    require(json.loads(s.cli(*collect)) == receipt and (s.control / "invocations").read_text() == "xx", "restart changed delivery or replayed workload")
    return ["lost_admission_reply", "duplicate_submission", "query_no_reexecution", "explicit_retry", "wrong_generation", "native_nonzero_exit", "signed_command_evidence", "receipt_restart"]


def fault(s, mode):
    work = "/bin/sleep 60" if mode == "cancel" else "/bin/sleep 8"
    if mode.startswith("receiver-"):
        work = "while [ ! -e /control/release ]; do /bin/sleep .1; done"
    request = s.request(mode, "printf x >> /control/invocations; touch /control/entered; " + work + "; printf done > /control/finished")
    admission = s.submit(request)
    s.wait(admission, mode + "-running", running=True)
    wait_for(lambda: (s.control / "entered").exists(), "workload dispatched")
    before = s.events()
    if mode == "executor-restart":
        s.daemon.kill(); require(s.daemon.wait(timeout=10) == -signal.SIGKILL, "executor kill failed")
        s.start_daemon()
    elif mode == "cancel":
        s.api("POST", "/v1/executions/" + admission["attempt"]["id"] + "/stop", {"operation_id": mode + "-stop"})
    elif mode == "receiver-restart":
        s.collector.kill(); require(s.collector.wait(timeout=10) == -signal.SIGKILL, "receiver kill failed")
        s.start_receiver(); s.reconnect()
    elif mode == "receiver-reconnect":
        # The receiver permits one producer per scope. Close the old trace
        # before replacing it; force-create connects its new sink first.
        s.command([s.args.runsc, "--root=" + str(s.state), "trace", "delete", "--name=Default", s.container])
        wait_for(lambda: latest_status(s.status).get("targets", [{}])[0].get("state") == "disconnected", "old trace disconnected")
        s.reconnect()
    if mode.startswith("receiver-"):
        (s.control / "release").touch()
    report = s.wait(admission, mode)
    if mode in {"executor-restart", "cancel"}:
        require(report["attempt"]["state"] == {"execution": "unknown", "capture": "incomplete", "delivery": "pending"}, "interrupted workload lost unknown state")
        fenced = s.wait(s.submit(s.request("fenced", "printf wrong >> /control/invocations")), "fenced")
        require(fenced["attempt"]["state"]["execution"] == "failed", "unknown attempt did not fence generation")
    else:
        require(report["attempt"]["state"]["capture"] == "incomplete", "receiver discontinuity sealed old command")
        require(report["checkpoint"]["runtime_report"]["capture"]["gaps"], "receiver discontinuity has no gap")
        sealed(s.wait(s.submit(s.request("after-reconnect", "/bin/true")), "after-reconnect"))
    for _ in range(2):
        replay = s.submit(request)
        require(replay["reused"] and replay["attempt"]["id"] == admission["attempt"]["id"], "fault recovery reexecuted command")
    require((s.control / "invocations").read_text() == "x", "fault/query reexecuted workload")
    require_preserved_records(before, s.events())
    return [mode, "query_no_reexecution", "committed_events_preserved"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "runsc", "rootfs", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--fixture-source-sha", required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    os.umask(0o077)
    for name in ("cli", "runsc", "rootfs", "output"):
        setattr(args, name, getattr(args, name).absolute())
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in (args.cli, args.runsc, args.output):
        for component in (path, *path.parents):
            stat = component.lstat()
            require(not component.is_symlink() and stat.st_uid == 0 and not stat.st_mode & 0o022, "fixture requires trusted root-owned paths")
    version = subprocess.check_output([str(args.cli), "--version"], text=True, timeout=15).strip()
    require(args.source_sha + ";" in version, "CLI source differs from specified acceptance source")
    report = {"schema_version": "agentprovenance.runsc_execution_acceptance/v1", "status": "FAIL", "cli_source_sha": args.source_sha,
        "fixture_source_sha": args.fixture_source_sha, "fixture_sha256": digest(Path(__file__)), "command": sys.argv,
        "cli_version": version, "python_version": platform.python_version(), "cli_sha256": digest(args.cli),
        "runsc_sha256": digest(args.runsc), "kernel": platform.release(), "architecture": platform.machine(), "checks": {}}
    started = time.monotonic()
    try:
        for name in ("baseline", "receiver-reconnect", "receiver-restart", "executor-restart", "cancel"):
            s = Scenario(args, name)
            try:
                s.start()
                checks = baseline(s) if name == "baseline" else fault(s, name)
                report["checks"][name] = {"status": "PASS", "checks": checks, "target": s.target}
            finally:
                s.close()
        report["status"] = "PASS"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        write_json(args.output / "result.json", report)
        print(json.dumps({"status": report["status"], "output": str(args.output / "result.json")}))


if __name__ == "__main__":
    main()
