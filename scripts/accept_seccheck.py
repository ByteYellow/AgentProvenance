#!/usr/bin/env python3
"""Exercise the public SecCheck CLI with two isolated, pinned runsc workloads."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run_json(cli, store, *args):
    result = subprocess.run([str(cli), "--data-dir", str(store), *args],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stderr}")
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "runsc", "rootfs", "workload", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("isolated runsc acceptance requires root")
    for name in ("cli", "runsc", "rootfs", "workload", "output"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    version = subprocess.check_output([str(args.runsc), "--version"], text=True, timeout=10)
    if "runsc version release-20261109.0" not in version.splitlines():
        raise RuntimeError(f"unexpected runtime: {version}")
    store = args.output / "store"
    status_path = args.output / "collector.jsonl"
    started, cleanup, collector = [], [], None
    with tempfile.TemporaryDirectory(prefix="ap-scc-") as sockets:
        try:
            targets = []
            for index in range(2):
                name = f"seccheck-cli-{index}"
                bundle = args.output / name
                bundle.mkdir()
                socket = str(Path(sockets) / f"{index}.sock")
                targets.append({"run_id": "seccheck-cli", "socket_path": socket,
                                "registration": {"namespace": "acceptance", "instance_id": "linux-node",
                                                 "generation": args.output.name, "sandbox_id": name,
                                                 "container_id": name, "peer_uid": os.geteuid()}})
                trace = run_json(args.cli, store, "telemetry", "seccheck-config", "--socket", socket)
                write_json(bundle / "trace.json", trace)
                write_json(bundle / "config.json", {
                    "ociVersion": "1.0.2", "hostname": "seccheck",
                    "process": {"user": {"uid": 0, "gid": 0}, "terminal": False,
                                "args": ["/acceptance", "-test.run=^TestSecCheckLiveWorkload$", "-test.v"],
                                "env": ["PATH=/bin:/usr/bin", "AGENTPROV_SECCHECK_CHILD=1"],
                                "cwd": "/", "noNewPrivileges": True},
                    "root": {"path": str(args.rootfs), "readonly": True},
                    "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                               {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
                               {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
                                "options": ["nosuid", "nodev", "size=16m"]},
                               {"destination": "/acceptance", "type": "bind", "source": str(args.workload),
                                "options": ["bind", "ro"]}],
                    "linux": {"namespaces": [{"type": n} for n in ("pid", "network", "ipc", "uts", "mount")]}})
                cleanup.append((bundle, name))
            write_json(args.output / "registration.json", {"schema_version": "agentprovenance.seccheck_collection/v1",
                       "runtime_release": "release-20261109.0", "targets": targets})
            with status_path.open("w") as stdout, (args.output / "collector.stderr").open("w") as stderr:
                collector = subprocess.Popen([str(args.cli), "--data-dir", str(store), "telemetry", "receive-seccheck",
                    "--config", str(args.output / "registration.json"), "--json", "--status-interval", "100ms"],
                    stdout=stdout, stderr=stderr)

                def wait_status(predicate):
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        # Only complete JSONL records are visible during writing.
                        lines = status_path.read_text().split("\n")[:-1]
                        if lines and predicate(json.loads(lines[-1])):
                            return
                        if collector.poll() is not None:
                            raise RuntimeError(f"collector stopped: {collector.returncode}")
                        time.sleep(0.05)
                    raise RuntimeError("collector status deadline exceeded")

                wait_status(lambda s: s["state"] == "listening")
                for bundle, name in cleanup:
                    log = (bundle / "workload.log").open("w")
                    proc = subprocess.Popen([str(args.runsc), "--root=" + str(bundle / "state"), "--platform=systrap",
                        "--network=none", "--pod-init-config=" + str(bundle / "trace.json"), "run",
                        "--bundle=" + str(bundle), name], stdout=log, stderr=subprocess.STDOUT)
                    started.append((proc, log, bundle))
                for proc, log, bundle in started:
                    code = proc.wait(timeout=60)
                    log.close()
                    if code or "SECCHECK_OK" not in (bundle / "workload.log").read_text():
                        raise RuntimeError(f"workload failed: {bundle}, exit={code}")
                wait_status(lambda s: all(t["state"] == "disconnected" for t in s["targets"]))
                collector.send_signal(signal.SIGTERM)
                if collector.wait(timeout=45):
                    raise RuntimeError("collector did not drain successfully")
            status = json.loads(status_path.read_text().splitlines()[-1])
            assert status["state"] == "stopped" and status["node_spool"]["pending_events"] == 0
            assert status["node_spool"]["queued_bytes"] == 0
            assert all(t["accepted_records"] > 20 and t["reported_dropped_events"] == 0 for t in status["targets"])
            health = run_json(args.cli, store, "telemetry", "producer-health", "--run", "seccheck-cli", "--json")
            verify = run_json(args.cli, store, "graph", "verify", "--run", "seccheck-cli", "--json")
            assert verify["error_count"] == 0 and verify["warning_count"] == 0
            with sqlite3.connect(f"file:{store / 'agentprov.db'}?mode=ro", uri=True) as db:
                rows = db.execute("SELECT pid,container_id,tool_call_id,session_id,payload FROM events WHERE source='gvisor_seccheck'").fetchall()
            roots, outcomes, ready = set(), {}, 0
            for pid, scope, call, session, payload in rows:
                assert not call and not session
                if pid == 1:
                    roots.add(scope)
                body = json.loads(payload)
                sentry = body["sentry"]
                name = sentry["registration"]["sandbox_id"]
                outcomes.setdefault(name, set()).add((body["operation"], body.get("syscall_outcome")))
                if sentry.get("reason") == "receiver_ready":
                    ready += 1
                    assert sentry["capabilities"]["model_intent"] == "none"
            expected = {("file_open", "success"), ("file_open", "failure"), ("network_connect", "success"),
                        ("network_connect", "failure"), ("network_connect", "pending")}
            assert len(roots) == 2 and ready == 2 and len(outcomes) == 2
            for observed in outcomes.values():
                assert expected <= observed, (expected - observed)
            assert health["events"]["by_source"]["gvisor_seccheck"] == len(rows)
            assert not health["coverage"]["complete"]
            write_json(args.output / "result.json", {"runtime": version, "platform": list(os.uname()),
                "binary_sha256": {name: digest(getattr(args, name)) for name in ("cli", "runsc", "workload")},
                "events": len(rows), "status": status, "health": health, "verify": verify})
        finally:
            for proc, log, _ in started:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=10)
                log.close()
            if collector and collector.poll() is None:
                collector.send_signal(signal.SIGTERM)
                try:
                    collector.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    collector.kill()
                    collector.wait(timeout=10)
            cleanup_errors = []
            for bundle, name in cleanup:
                result = subprocess.run([str(args.runsc), "--root=" + str(bundle / "state"), "delete", "--force", name], capture_output=True, timeout=10)
                (bundle / "cleanup.log").write_bytes(result.stdout + result.stderr)
                if result.returncode and any(item[2] == bundle for item in started):
                    cleanup_errors.append(f"runtime cleanup failed: {bundle}")
                mount = bundle / "state" / "null-netns"
                if mount.exists() and subprocess.run(["mountpoint", "-q", str(mount)]).returncode == 0:
                    if subprocess.run(["umount", str(mount)], timeout=10).returncode:
                        cleanup_errors.append(f"namespace cleanup failed: {mount}")
            if cleanup_errors:
                raise RuntimeError("; ".join(cleanup_errors))
    print(json.dumps({"status": "passed", "events": len(rows), "output": str(args.output)}))


if __name__ == "__main__":
    main()
