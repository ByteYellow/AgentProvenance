#!/usr/bin/env python3
"""Verify the installed in-guest service, scoped collection and bundle replay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentprov", default="/usr/local/bin/agentprov")
    parser.add_argument("--data-dir", default="/var/lib/agentprov")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run inside the guest as root")
    virtualization = subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip()
    if virtualization not in {"kvm", "qemu"}:
        raise SystemExit(f"expected QEMU/KVM guest, got {virtualization}")
    subprocess.run(["systemctl", "is-active", "--quiet", "agentprov-sensor.service"], check=True)
    invocation = subprocess.check_output(["systemctl", "show", "agentprov-sensor.service", "--property=InvocationID", "--value"], text=True).strip()
    deadline = time.monotonic() + 15
    while True:
        journal = subprocess.check_output(["journalctl", "_SYSTEMD_INVOCATION_ID=" + invocation, "--no-pager", "-o", "cat"], text=True)
        if "ready probes-attached" in journal:
            break
        if time.monotonic() > deadline:
            raise RuntimeError("guest collector is active but has not attached its probes")
        time.sleep(0.1)
    run = "run-kvm-" + uuid.uuid4().hex[:12]
    base = [args.agentprov, "--data-dir", args.data_dir]
    report_path = Path(args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    def query(*command):
        return json.loads(subprocess.check_output(base + list(command) + ["--json"], text=True))

    with tempfile.TemporaryDirectory(prefix="agentprov-kvm-") as directory:
        workspace = Path(directory) / "workspace"
        workspace.mkdir()
        subprocess.run(base + ["record", "--run", run, "--workdir", str(workspace), "--", "sh", "-c",
            "set -e; id >/dev/null; printf 'kvm-evidence\\n' > artifact.txt; "
            "python3 -c 'import socket; s=socket.socket(); s.connect_ex((\"127.0.0.1\",9)); s.close()'; sleep 1"], check=True)
        # The service ingests asynchronously. Wait for the actual fixture facts,
        # rather than equating service liveness with a completed evidence view.
        deadline = time.monotonic() + 15
        while True:
            events = query("telemetry", "list", "--run", run, "--limit", "10000").get("events", [])
            native = [row for row in events if row.get("source") == "agentprov_ebpf"]
            types = {row["event_type"] for row in native}
            if {"execve", "file_write", "network_connect"}.issubset(types):
                break
            if time.monotonic() > deadline:
                raise RuntimeError(f"guest service did not ingest fixture facts: {types}")
            time.sleep(0.2)
        bindings = query("telemetry", "bindings", "--run", run)["bindings"]
        cgroups = sorted({str(row.get("cgroup_id", "")) for row in bindings if str(row.get("cgroup_id", "")).isdigit()})
        if not cgroups or cgroups == ["0"]:
            raise RuntimeError("record did not create a kernel cgroup scope")
        subprocess.run(base + ["graph", "materialize", "--run", run], check=True, stdout=subprocess.DEVNULL)
        verification = query("graph", "verify", "--run", run)
        exported = query("forensics", "export", run)
        bundle = Path(exported["path"])
        bundle_out = report_path.with_suffix(".forensics.json")
        shutil.copyfile(bundle, bundle_out)
        replay = [args.agentprov, "--data-dir", str(Path(directory) / "replay")]
        imported = json.loads(subprocess.check_output(replay + ["forensics", "import", str(bundle_out), "--json"], text=True))
        replay_verification = json.loads(subprocess.check_output(replay + ["graph", "verify", "--run", run, "--json"], text=True))
        report = {
            "schema_version": "agentprovenance.kvm_guest_acceptance/v1",
            "architecture": platform.machine(), "kernel": platform.release(),
            "virtualization": virtualization,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "run_id": run, "native_events": len(native), "event_types": sorted(types),
            "cgroups": cgroups, "verification": verification,
            "replay_verification": replay_verification,
            "bundle_sha256": hashlib.sha256(bundle_out.read_bytes()).hexdigest(),
            "imported_run": imported.get("run_id"), "passed": True,
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
