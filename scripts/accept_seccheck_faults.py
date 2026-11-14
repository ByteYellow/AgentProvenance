#!/usr/bin/env python3
"""Exercise live Sentry loss, persisted backlog recovery and trace reconnection."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time

from accept_seccheck import digest, run_json, write_json


def wait_for(check, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.05)
    raise RuntimeError(f"deadline: {description}")


def latest_status(path):
    lines = path.read_text().split("\n")[:-1]
    return json.loads(lines[-1]) if lines else {}


def spool_inventory(directory):
    records = {}
    for path in sorted(directory.glob("*.jsonl")):
        with path.open() as source:
            for line in source:
                record = json.loads(line)
                identity = record["RawEventID"]
                if identity in records and record != records[identity]:
                    raise RuntimeError(f"conflicting pending observation: {identity}")
                records[identity] = record
    return records


def require_preserved_records(before, after):
    if not before:
        raise RuntimeError("preservation check requires committed observations")
    if any(after.get(key) != value for key, value in before.items()):
        raise RuntimeError("previously committed evidence changed or disappeared")


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
    control = args.output / "control"
    control.mkdir()
    bundle = args.output / "sandbox"
    bundle.mkdir()
    state = bundle / "state"
    name = "seccheck-faults"
    collectors, runtime = [], None
    with tempfile.TemporaryDirectory(prefix="ap-scf-") as sockets:
        try:
            endpoint = str(Path(sockets) / "events.sock")
            trace = run_json(args.cli, store, "telemetry", "seccheck-config", "--socket", endpoint)
            write_json(bundle / "trace.json", trace)
            registration = {"namespace": "acceptance", "instance_id": "linux-node", "generation": args.output.name,
                            "sandbox_id": name, "container_id": name, "peer_uid": os.geteuid()}
            write_json(args.output / "registration.json", {"schema_version": "agentprovenance.seccheck_collection/v1",
                "runtime_release": "release-20261109.0", "targets": [{"run_id": name,
                    "socket_path": endpoint, "registration": registration}]})
            write_json(bundle / "config.json", {
                "ociVersion": "1.0.2", "hostname": "seccheck-faults",
                "process": {"user": {"uid": 0, "gid": 0}, "terminal": False,
                    "args": ["/acceptance", "-test.run=^TestSecCheckLiveFaultWorkload$", "-test.v"],
                    "env": ["PATH=/bin:/usr/bin", "AGENTPROV_SECCHECK_CHILD=1"], "cwd": "/", "noNewPrivileges": True},
                "root": {"path": str(args.rootfs), "readonly": True},
                "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
                    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "size=16m"]},
                    {"destination": "/acceptance", "type": "bind", "source": str(args.workload), "options": ["bind", "ro"]},
                    {"destination": "/control", "type": "bind", "source": str(control), "options": ["bind", "rw"]}],
                "linux": {"namespaces": [{"type": n} for n in ("pid", "network", "ipc", "uts", "mount")]}})

            def start_collector(index):
                path = args.output / f"collector-{index}.jsonl"
                with path.open("w") as out, (args.output / f"collector-{index}.stderr").open("w") as err:
                    proc = subprocess.Popen([str(args.cli), "--data-dir", str(store), "telemetry", "receive-seccheck",
                        "--config", str(args.output / "registration.json"), "--json", "--status-interval", "100ms",
                        "--batch-events", "8"], stdout=out, stderr=err)
                collectors.append(proc)

                def ready():
                    if proc.poll() is not None:
                        raise RuntimeError(f"collector {index} stopped before listening: {proc.returncode}")
                    return latest_status(path).get("state") == "listening"

                wait_for(ready, f"collector {index} listening")
                return proc, path

            def phase(phase_name):
                (control / phase_name).touch()
                wait_for(lambda: (control / (phase_name + ".done")).exists(), phase_name)

            first, first_status = start_collector(1)
            with (bundle / "workload.log").open("w") as log:
                runtime = subprocess.Popen([str(args.runsc), "--root=" + str(state), "--platform=systrap", "--network=none",
                    "--pod-init-config=" + str(bundle / "trace.json"), "run", "--bundle=" + str(bundle), name],
                    stdout=log, stderr=subprocess.STDOUT)
            wait_for(lambda: (control / "ready.done").exists(), "workload ready")
            wait_for(lambda: latest_status(first_status).get("targets", [{}])[0].get("state") == "connected", "first connection")
            first.send_signal(signal.SIGSTOP)
            wait_for(lambda: "State:\tT" in Path(f"/proc/{first.pid}/status").read_text(), "collector stopped")
            phase("burst")
            first.send_signal(signal.SIGCONT)
            phase("after-burst")
            loss = wait_for(lambda: latest_status(first_status).get("targets", [{}])[0].get("reported_dropped_events", 0), "Sentry reports actual loss")
            write_json(args.output / "congestion.json", latest_status(first_status))

            def committed_marker():
                with sqlite3.connect(f"file:{store / 'agentprov.db'}?mode=ro", uri=True) as db:
                    observations = dict(db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'"))
                if any(json.loads(value).get("path", "").startswith("/tmp/seccheck-after-burst-") for value in observations.values()):
                    return observations
                return None

            baseline = wait_for(committed_marker, "pre-fault evidence committed")
            write_json(args.output / "committed-before-fault.json", baseline)

            # Hold semantic insertion, not socket acceptance, to leave real fsynced backlog.
            with sqlite3.connect(store / "agentprov.db", timeout=15) as db:
                db.execute("CREATE TRIGGER acceptance_hold BEFORE INSERT ON events WHEN NEW.source='gvisor_seccheck' BEGIN SELECT RAISE(ABORT,'acceptance ingestion hold'); END")
            phase("queued")
            wait_for(lambda: latest_status(first_status).get("node_spool", {}).get("pending_events", 0) > 0
                     and "acceptance ingestion hold" in latest_status(first_status).get("last_worker_error", ""), "durable failed batch")
            first.kill()
            assert first.wait(timeout=10) == -signal.SIGKILL
            shutil.copytree(store / "spool", args.output / "crash-spool")
            pending = spool_inventory(args.output / "crash-spool")
            assert pending, "no fsynced pending observations"
            write_json(args.output / "pending-identities.json", sorted(pending))
            phase("disconnected")
            with sqlite3.connect(store / "agentprov.db", timeout=15) as db:
                before = dict(db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'"))
                db.execute("DROP TRIGGER acceptance_hold")
            require_preserved_records(baseline, before)
            second, second_status = start_collector(2)
            command = [str(args.runsc), "--root=" + str(state), "trace", "create", "--force", "--config=" + str(bundle / "trace.json"), name]
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            (args.output / "reconnect.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f"reconnect failed: {result.returncode}")
            wait_for(lambda: latest_status(second_status).get("targets", [{}])[0].get("state") == "connected", "reconnected producer")
            phase("reconnected")
            (control / "finish").touch()
            assert runtime.wait(timeout=15) == 0
            assert "SECCHECK_FAULT_OK" in (bundle / "workload.log").read_text()
            wait_for(lambda: latest_status(second_status).get("targets", [{}])[0].get("state") == "disconnected", "final disconnect")
            second.send_signal(signal.SIGTERM)
            assert second.wait(timeout=45) == 0
            final = latest_status(second_status)
            assert final["state"] == "stopped" and final["node_spool"]["pending_events"] == 0
            assert final["node_spool"]["queued_bytes"] == 0
            health = run_json(args.cli, store, "telemetry", "producer-health", "--run", name, "--json")
            verify = run_json(args.cli, store, "graph", "verify", "--run", name, "--json")
            assert health["coverage"]["has_sensor_drops"] and not health["coverage"]["complete"]
            assert verify["error_count"] == 0 and verify["warning_count"] == 0
            with sqlite3.connect(f"file:{store / 'agentprov.db'}?mode=ro", uri=True) as db:
                rows = db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'").fetchall()
            saved = dict(rows)
            assert len(saved) == len(rows) and pending.keys() <= saved.keys()
            require_preserved_records(before, saved)
            for identity, record in pending.items():
                body = json.loads(saved[identity])
                assert all(body.get(key) == value for key, value in json.loads(record["Payload"]).items())
            bodies = [json.loads(value) for value in saved.values()]
            connections = {b["sentry"]["connection_id"] for b in bodies if b["sentry"].get("reason") == "connected"}
            assert len(connections) == 2
            root_lifetimes = {}
            for body in bodies:
                sentry = body["sentry"]
                context = sentry.get("context", {})
                if context.get("group_id") == 1 and context.get("group_start_ns", 0) > 0:
                    root_lifetimes.setdefault(sentry["connection_id"], set()).add(context["group_start_ns"])
            assert connections <= root_lifetimes.keys()
            assert len(set().union(*(root_lifetimes[key] for key in connections))) == 1
            assert any(b["sentry"].get("reason") == "stale_endpoint_recovered" for b in bodies)
            assert health["seccheck_node_capture"]["counters"]["stale_endpoint_recovered"] == 1
            assert "sentry_node_receiver_restart_gap" in health["coverage"]["issues"]
            assert any(b.get("path", "").startswith("/tmp/seccheck-reconnected-") for b in bodies)
            assert all(b["sentry"]["registration"] == registration for b in bodies)
            public_key = args.output / "acceptance.pub"
            with tempfile.TemporaryDirectory(prefix="ap-scf-key-") as keys:
                private_key = Path(keys) / "acceptance.key"
                subprocess.run([str(args.cli), "forensics", "keygen", "--priv", str(private_key),
                    "--pub", str(public_key)], capture_output=True, check=True, timeout=10)
                exported = run_json(args.cli, store, "forensics", "export", name,
                    "--sign-key", str(private_key), "--json")
            assert exported["signed"]
            receiver_store = args.output / "receiver-store"
            imported = run_json(args.cli, receiver_store, "forensics", "import", exported["path"],
                "--pub-key", str(public_key), "--json")
            assert imported["attestation_verified"]
            with sqlite3.connect(f"file:{receiver_store / 'agentprov.db'}?mode=ro", uri=True) as db:
                imported_rows = dict(db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'"))
            assert imported_rows == saved
            imported_verify = run_json(args.cli, receiver_store, "graph", "verify", "--run", name, "--json")
            assert imported_verify["error_count"] == 0 and imported_verify["warning_count"] == 0
            write_json(args.output / "result.json", {"runtime": version, "platform": list(os.uname()),
                "binary_sha256": {key: digest(getattr(args, key)) for key in ("cli", "runsc", "workload")},
                "observed_loss": loss, "recovered_observations": len(pending), "preserved_observations": len(before),
                "events": len(rows), "connections": sorted(connections), "status": final, "health": health, "verify": verify,
                "bundle": exported, "import": imported, "import_verify": imported_verify})
        finally:
            for proc in collectors:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGCONT)
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.wait(timeout=40)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=10)
            cleanup = subprocess.run([str(args.runsc), "--root=" + str(state), "delete", "--force", name], capture_output=True, timeout=15)
            (args.output / "cleanup.log").write_bytes(cleanup.stdout + cleanup.stderr)
            if runtime is not None:
                if runtime.poll() is None:
                    runtime.kill()
                runtime.wait(timeout=10)
            mount = state / "null-netns"
            if mount.exists() and subprocess.run(["mountpoint", "-q", str(mount)]).returncode == 0:
                subprocess.run(["umount", str(mount)], check=True, timeout=10)
            if runtime is not None and cleanup.returncode:
                raise RuntimeError(f"runtime cleanup failed: {cleanup.returncode}")
    print(json.dumps({"status": "passed", "loss": loss, "recovered": len(pending), "output": str(args.output)}))


if __name__ == "__main__":
    main()
