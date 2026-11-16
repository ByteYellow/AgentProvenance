"""Optional Guest workspace composition using the existing W-01 MCP fixture."""
import json
from contextlib import closing
from pathlib import Path
import re
import shutil
import sqlite3
import sys

from common import Blocked, clean_env, command, digest, load, redact, require, save
from reader import verify_reader


WORKSPACE_INPUTS = ("scripts/accept_workspace.py", "python/agentprov/__init__.py",
                    "python/agentprov/workspace_mcp.py", "python/agentprov_eval/__init__.py")


def option_issues(mode, lock, verifier):
    if not mode:
        return []
    issues = []
    if not verifier:
        issues.append("workspace requires --verifier and lock.verifier")
    settings = lock.get("workspace", {})
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.+-]*)", settings.get("mcp_version") or ""):
        issues.append("workspace.mcp_version")
    if mode == "harness":
        harness = settings.get("harness", {})
        if not isinstance(harness.get("path"), str) or not Path(harness["path"]).is_absolute():
            issues.append("workspace.harness.path (existing authenticated Guest entrypoint)")
        if not re.fullmatch(r"[a-f0-9]{64}", harness.get("sha256") or ""):
            issues.append("workspace.harness.sha256")
    return issues


def inspect_workspace(data, config, native=False):
    """Check content-addressed workspace receipts and their actual record scope."""
    with closing(sqlite3.connect((Path(data) / "agentprov.db").as_uri() + "?mode=ro", uri=True)) as db:
        objects = db.execute("SELECT hash,object_type,path FROM provenance_objects WHERE run_id=? "
                             "AND object_type IN ('workspace_operation','workspace_manifest') ORDER BY hash LIMIT 1025",
                             (config["run_id"],)).fetchall()
        require(0 < len(objects) <= 1024, "workspace evidence objects missing or exceed fixture bound")
        operations, executions = set(), []
        for ref, kind, path in objects:
            require("sha256:" + digest(path) == ref, "workspace evidence hash mismatch")
            payload = load(path)["payload"]
            binding = payload["binding"]
            require(binding.get("target") == config["target"], "workspace evidence target/generation mismatch")
            require(binding.get("mode") == "remote-authoritative" and
                    binding.get("root") == config["root"] and binding.get("workspace_id") == config["workspace_id"],
                    "workspace evidence binding mismatch")
            if kind == "workspace_operation":
                receipt = payload["receipt"]
                operations.add(receipt.get("operation"))
                if receipt.get("operation") == "execute":
                    require(receipt.get("exit_code") == 0 and receipt.get("input_manifest_ref") and
                            receipt.get("output_manifest_ref"), "workspace execution lost revision evidence")
                    executions.append(receipt)
        require({"read", "edit", "write", "execute"} <= operations, "workspace Read/Edit/Write/Bash evidence missing")
        require(len(executions) == 1, "workspace Bash was omitted or replayed")
        receipt = executions[0]
        record = receipt["record"]
        row = db.execute("SELECT a.tool_call_id,a.workspace_path FROM fork_attempts a JOIN rollouts r ON r.id=a.rollout_id "
                         "WHERE a.id=? AND a.snapshot_id=? AND r.run_id=?",
                         (record["attempt_id"], record["base_snapshot_id"], config["run_id"])).fetchone()
        require(row and row[1] == config["root"] and record["run_id"] == config["run_id"], "workspace record belongs to another run/root")
        scopes = db.execute("SELECT cgroup_id FROM execution_context_bindings WHERE run_id=? AND attempt_id=? AND tool_call_id=? "
                            "AND binding_source='zero_sdk_record' AND cgroup_id!=''",
                            (config["run_id"], record["attempt_id"], row[0])).fetchall()
        require(len(scopes) == 1, "workspace record has no unique execution scope")
        cgroup = scopes[0][0]
        # Scope-only correlation deliberately omits a tool ID. Keep that fidelity
        # and join the signed record attempt plus its owned kernel cgroup.
        events = db.execute("SELECT id,raw_event_id,cgroup_id,correlation_method,tool_call_id,event_type FROM events "
                            "WHERE run_id=? AND json_extract(payload,'$.attempt_id')=? AND source='agentprov_ebpf' ORDER BY id LIMIT 4097",
                            (config["run_id"], record["attempt_id"])).fetchall()
        require(len(events) <= 4096, "workspace native event evidence exceeds fixture bound")
        if native:
            require(str(cgroup).isdigit() and int(cgroup) > 0, "workspace record requires a native cgroup")
            require(bool(events) and all(e[1] and e[2] == cgroup and
                    e[3].startswith(("cgroup_time_window:", "kernel_process_instance:")) for e in events) and
                    {"execve", "file_open"} <= {e[5] for e in events},
                    "workspace native events do not match its record cgroup")
        return {"object_refs": [r[0] for r in objects], "record": record, "cgroup_id": cgroup,
                "input_manifest_ref": receipt["input_manifest_ref"], "output_manifest_ref": receipt["output_manifest_ref"],
                "input_revision": receipt["input_revision"], "output_revision": receipt["output_revision"],
                "association": "owned_record_cgroup", "native_events": [dict(zip(
                    ("id", "raw_event_id", "cgroup_id", "correlation_method", "tool_call_id", "event_type"), e)) for e in events]}


def deliver_workspace(binary, verifier, config, output, sign_key, public_key, source, native=False):
    output.mkdir(mode=0o700)
    env = clean_env()
    def cli(*args):
        return json.loads(command([binary, *args], timeout=90, env=env))
    evidence = inspect_workspace(Path(config["data_dir"]), config, native)
    exported = cli("--data-dir", config["data_dir"], "forensics", "export", config["run_id"], "--sign-key", sign_key, "--json")
    require(exported.get("signed") is True, "workspace bundle was not signed")
    bundle = output / "bundle.json"
    shutil.copyfile(exported["path"], bundle)
    shutil.copyfile(exported["attestation_path"], output / "bundle.dsse.json")
    shutil.copyfile(public_key, output / "executor.pub")
    require(digest(bundle) == exported["sha256"], "workspace exported bundle changed")
    imported = cli("--data-dir", output / "offline", "forensics", "import", bundle, "--pub-key", output / "executor.pub", "--json")
    require(imported.get("attestation_verified") is True, "workspace signed import failed")
    verification = cli("--data-dir", output / "offline", "graph", "verify", "--run", config["run_id"], "--json")
    require(inspect_workspace(output / "offline", config, native) == evidence, "signed workspace import lost binding/native evidence")
    reader = verify_reader(binary, verifier, output / "offline", config["run_id"], output / "reader", source=source)
    return {"status": "PASS", "bundle_sha256": digest(bundle), "attestation_sha256": digest(output / "bundle.dsse.json"),
            "evidence": evidence, "verification": verification, "reader": reader}


def run_case(binary, verifier, fixture, package, control, output, config, lock, source, mode, native=True):
    """native=False is only for local CLI/MCP contract testing, never a matrix PASS."""
    require(mode in {"contract", "harness"}, "unsupported workspace case")
    require(not option_issues(mode, lock, verifier), "workspace pins/configuration incomplete")
    target_file = control / "workspace-target.json"
    require(load(target_file) == config["target"], "workspace operator Target differs from execution generation")
    argv = [sys.executable, fixture, "--agentprov", binary, "--python-package", package,
            "--output", output, "--target-file", target_file]
    if native:
        argv += ["--sensor", "--sensor-placement", "guest_kernel"]
    if mode == "harness":
        entry = Path(lock["workspace"]["harness"]["path"])
        require(digest(entry) == lock["workspace"]["harness"]["sha256"], "Guest Harness entrypoint differs from lock")
        argv += ["--claude", entry]
    report = {"status": "FAIL", "mode": mode, "workspace_mode": "remote-authoritative",
              "target": config["target"], "native": native, "phases": {}, "harness": "PENDING", "source": source,
              "binary_sha256": digest(binary), "verifier_sha256": digest(verifier),
              "fixture_sha256": {str(path): digest(path) for path in (
                  Path(__file__), Path(fixture), Path(package) / "agentprov/__init__.py",
                  Path(package) / "agentprov/workspace_mcp.py", Path(package) / "agentprov_eval/__init__.py")}}
    try:
        command(argv, timeout=400 if mode == "harness" else 150, env=clean_env(), allowed=(0, 2))
        result = load(output / "report.json")
        if result.get("status") == "blocked":
            report["failure_code"] = result.get("failure_code", "workspace_prerequisite_unavailable")
            raise Blocked("workspace prerequisites blocked: " + report["failure_code"])
        require(result.get("status") == "passed", "workspace fixture failed")
        require(result.get("binary_sha256") == digest(binary), "workspace fixture executable hash mismatch")
        require(result.get("sensor") == ("on" if native else "off"), "workspace fixture Sensor mode mismatch")
        require(result.get("mcp_version") == lock["workspace"]["mcp_version"], "workspace MCP version differs from lock")
        for phase in (("contract", "harness") if mode == "harness" else ("contract",)):
            require(result.get(phase, {}).get("status") == "passed", "workspace " + phase + " did not pass")
            workspace = load(output / phase / "operator/workspace.json")
            require(workspace["target"] == config["target"] and workspace["run_id"] == result[phase]["run_id"],
                    "workspace fixture used another target/run")
            if native:
                validate_sensor(result[phase].get("sensor", {}), workspace, config, lock)
            report["phases"][phase] = deliver_workspace(binary, verifier, workspace, output / (phase + "-delivery"),
                control / "executor.key", control / "executor.pub", source, native)
        require(load(target_file) == config["target"], "workspace fixture changed the operator Target")
        report.update(status="PASS", harness="PASS" if mode == "harness" else "PENDING",
                      matrix_status="PASS" if native and mode == "harness" else "PENDING", fixture_report_sha256=digest(output / "report.json"))
        return report
    except Blocked as error:
        report["status"], report["error"] = "BLOCKED", redact(str(error))
        raise
    except Exception as error:
        report["error"] = redact(str(error))
        raise
    finally:
        if output.is_dir():
            for log in output.rglob("*"):
                if log.is_file() and log.suffix in {".stdout", ".stderr"}:
                    log.write_text(redact(log.read_text(errors="replace")))
            save(output / "kata-workspace.json", report)


def validate_sensor(sensor, workspace, execution, lock):
    require(sensor.get("status") == "passed" and sensor.get("drain") == "collector_stopped_store_empty",
            "workspace Sensor readiness/drain did not pass")
    require(sensor.get("target") == execution["target"] and sensor.get("run_id") == workspace["run_id"],
            "workspace Sensor report belongs to another target/run")
    ready, final = sensor["ready"], sensor["final"]
    require(ready.get("collector_running") is True and final.get("collector_running") is False and
            ready["capabilities"].get("ready") is True and final["capabilities"].get("status") == "stopped" and
            bool(ready["capabilities"].get("collector_id")) and
            ready["capabilities"]["collector_id"] == final["capabilities"].get("collector_id"),
            "workspace Sensor lifetime mismatch")
    for snapshot in (ready, final):
        producer = snapshot["capabilities"]["producer"]
        for key, expected in (("version", lock["sensor"]["version"]), ("commit", lock["sensor"]["source_sha"]),
                              ("placement", "guest_kernel"), ("boot_id", execution["backend"]["guest"]["guest_boot_id"])):
            require(producer.get(key) == expected, "workspace Sensor producer " + key + " mismatch")
