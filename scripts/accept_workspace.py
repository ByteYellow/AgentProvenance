#!/usr/bin/env python3
"""Accept W-01 through actual stdio MCP, optionally with a real Claude Harness.

Run this on the machine hosting the entire Harness and workspace. The default
fixture uses no provider credentials, HTTP server, sensor, or privileged setup.
--claude opts into a bounded real Harness run using the operator's existing
provider setup; credentials are never read, printed, or copied by this script.
--sensor opts into Linux kernel capture in each fixture's own store. It requires
BPF/perf permissions and a writable cgroup v2 /sys/fs/cgroup/agentprov subtree.
Exit 2 means a missing environment prerequisite; exit 1 means failed acceptance.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from urllib.parse import quote


MCP_SERVER = "agentprov_workspace"
TOOLS = {"workspace_inspect", "workspace_read", "workspace_edit", "workspace_write", "workspace_bash"}
PROMPT = r"""Use only the workspace MCP tools for this small task. First inspect the binding,
then read input.txt. Replace value=1 with value=2 using workspace_edit and the revision/digest
returned by that read. Use workspace_write to create note.txt with the decoded content below,
using the current revision or expected_digest='absent'.
note.txt content (JSON string): "agent-note\n"
The JSON escape \n represents an actual LF (0x0A) byte; the quotes are JSON delimiters.
Pass that decoded string as the tool's content: exactly 11 UTF-8 bytes, including the final LF.
Then call workspace_bash with the current
observed revision and command: cat input.txt note.txt > result.txt; printf WORKSPACE_HARNESS_OK
Read result.txt and verify the exact decoded content below:
result.txt content (JSON string): "value=2\nagent-note\n"
The file must contain exactly 19 UTF-8 bytes, with one LF after each line, including the final line.
Do not install packages,
use background commands, or use any other tools. On CAS conflict reread and decide a new edit;
on unknown/recovery inspect rather than replaying Bash. Finish with the verified result name."""


class AcceptanceFailure(AssertionError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class AcceptanceBlocked(AcceptanceFailure):
    pass


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def load_target(path):
    if path is None:
        return None
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022 or before.st_uid not in (0, os.geteuid()):
            raise AcceptanceFailure("unsafe_target_file", "Target must be operator-owned and not group/world-writable")
        raw = stream.read(16385)
        after = os.fstat(stream.fileno())
    if len(raw) > 16384 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise AcceptanceFailure("invalid_target_file", "Target exceeded its limit or changed while being read")
    target = json.loads(raw)
    if (not isinstance(target, dict) or set(target) != {"producer_id", "instance_id", "generation"} or
            any(not isinstance(v, str) or not v or len(v.encode()) > 256 or
                any(c.isspace() or ord(c) < 32 for c in v) for v in target.values())):
        raise AcceptanceFailure("invalid_target_file", "Target must contain producer_id, instance_id and generation")
    return target


def layout(base, label, target=None):
    base.mkdir(mode=0o700)
    work, operator = base / "work", base / "operator"
    work.mkdir()
    operator.mkdir(mode=0o700)
    (work / "input.txt").write_text("value=1\n", encoding="utf-8")
    target = dict(target) if target is not None else {
        "producer_id": "workspace-acceptance", "instance_id": platform.node() or "local",
        "generation": "fixture-" + uuid.uuid4().hex}
    config = {"schema": "agentprovenance.workspace_cli/v1", "workspace_id": label,
              "run_id": "run-w01-" + uuid.uuid4().hex, "root": str(work),
              "state_dir": str(operator / "state"), "data_dir": str(operator / "data"),
              "target": target, "target_file": str(operator / "current-target.json"),
              "allowed_operations": ["read", "write", "edit", "execute"], "bash_timeout_seconds": 30}
    write_json(operator / "current-target.json", target)
    path = operator / "workspace.json"
    write_json(path, config)
    return path, config


def connect(config):
    return sqlite3.connect("file:" + quote(str(Path(config["data_dir"]) / "agentprov.db")) + "?mode=ro", uri=True)


def verify_sensor_records(config):
    with connect(config) as db:
        attempts = db.execute("""SELECT a.id,a.tool_call_id,a.snapshot_id FROM fork_attempts a
            JOIN tool_calls t ON t.id=a.tool_call_id AND t.attempt_id=a.id
            WHERE t.run_id=? AND a.workspace_path=? AND a.exit_code=0""",
            (config["run_id"], config["root"])).fetchall()
        if len(attempts) != 1:
            raise AcceptanceFailure("sensor_record_mismatch", "Expected exactly one successful workspace record")
        attempt, tool, snapshot = attempts[0]
        bindings = db.execute("""SELECT id,cgroup_id FROM execution_context_bindings
            WHERE run_id=? AND attempt_id=? AND tool_call_id=? AND binding_source='zero_sdk_record' AND cgroup_id!=''""",
            (config["run_id"], attempt, tool)).fetchall()
        if len(bindings) != 1 or not bindings[0][1].isdecimal() or int(bindings[0][1]) <= 0:
            raise AcceptanceBlocked("sensor_cgroup_unavailable", "Record needs an owned kernel cgroup, not a logical scope")
        binding, cgroup = bindings[0]
        # Native correlation deliberately retains scope-only attribution. Link
        # through record's owned cgroup/attempt, not a fabricated event tool ID.
        events = db.execute("""SELECT id,raw_event_id,event_type,correlation_method,cgroup_id,tool_call_id FROM events
            WHERE run_id=? AND cgroup_id=? AND source='agentprov_ebpf'
            AND json_extract(payload,'$.attempt_id')=? AND raw_event_id!=''
            ORDER BY id LIMIT 4097""", (config["run_id"], cgroup, attempt)).fetchall()
        if len(events) > 4096:
            raise AcceptanceFailure("sensor_evidence_limit", "Fixture native event evidence exceeded its bound")
        events = [row for row in events if row[3].startswith(("kernel_process_instance:", "cgroup_time_window:"))]
        kinds = {row[2] for row in events}
        if not {"execve", "file_open"} <= kinds:
            raise AcceptanceFailure("sensor_record_events_missing", "Missing native exec/file observations in the actual record scope")
        receipts = []
        objects = db.execute("SELECT hash,path FROM provenance_objects WHERE run_id=? AND object_type='workspace_operation' LIMIT 1025",
                             (config["run_id"],)).fetchall()
        if len(objects) > 1024:
            raise AcceptanceFailure("sensor_evidence_limit", "Fixture workspace evidence exceeded its bound")
        for digest, path in objects:
            with open(path, "rb") as stream:
                raw = stream.read((4 << 20) + 1)
            if len(raw) > 4 << 20 or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
                raise AcceptanceFailure("sensor_workspace_evidence_invalid", "Workspace evidence hash or size is invalid")
            obj = json.loads(raw)
            payload = obj.get("payload", {})
            receipt = payload.get("receipt", {})
            record = receipt.get("record") or {}
            if record.get("attempt_id") != attempt:
                continue
            workspace = payload.get("binding", {})
            if (obj.get("run_id") != config["run_id"] or record.get("run_id") != config["run_id"] or
                    record.get("base_snapshot_id") != snapshot or workspace.get("target") != config["target"] or
                    workspace.get("root") != config["root"] or workspace.get("workspace_id") != config["workspace_id"] or
                    not receipt.get("input_manifest_ref") or not receipt.get("output_manifest_ref")):
                raise AcceptanceFailure("sensor_workspace_binding_mismatch", "Record receipt does not match the configured workspace Target")
            receipts.append(digest)
        if not receipts:
            raise AcceptanceFailure("sensor_workspace_receipt_missing", "No workspace evidence refers to the captured record")
    return {"run_id": config["run_id"], "target": config["target"], "attempt_id": attempt,
            "tool_call_id": tool, "binding_id": binding, "cgroup_id": cgroup, "workspace_receipts": receipts,
            "association": "owned_record_cgroup", "native_events": [
                {"id": row[0], "raw_event_id": row[1], "event_type": row[2], "correlation_method": row[3],
                 "cgroup_id": row[4], "tool_call_id": row[5]} for row in events]}


class SensorCapture:
    """Own one collector lifetime, outside the workspace's per-operation lock."""

    def __init__(self, base, binary, config, options=None):
        self.base, self.binary, self.config, self.options = base, binary, config, options
        self.enabled = options is not None and options.sensor
        self.process = None
        self.stdout = self.stderr = None
        self.report = {"status": "off"}

    def status(self):
        result = subprocess.run([str(self.binary), "--data-dir", self.config["data_dir"], "sensor", "status", "--json"],
                                env=self.environment, capture_output=True, timeout=5)
        if result.returncode:
            raise AcceptanceFailure("sensor_status_failed", "sensor status failed; inspect the private collector logs")
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or not isinstance(value.get("capture"), dict):
            raise AcceptanceFailure("sensor_status_invalid", "sensor status returned an invalid response")
        return value

    def log_tail(self):
        with (self.base / "sensor.stderr").open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - (64 << 10)))
            return stream.read().decode("utf-8", errors="replace")

    def start(self):
        if platform.system() != "Linux":
            raise AcceptanceBlocked("sensor_requires_linux", "Sensor acceptance requires Linux")
        cgroup = Path("/sys/fs/cgroup/agentprov")
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file() or not os.access(cgroup if cgroup.exists() else cgroup.parent, os.W_OK):
            raise AcceptanceBlocked("sensor_cgroup_unavailable", "Delegate a writable cgroup v2 /sys/fs/cgroup/agentprov subtree")
        self.environment = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR") if k in os.environ}
        self.environment.update(AGENTPROV_LANG="en", AGENTPROV_DAEMON_URL="")
        # Record publishes its cgroup binding before exec. Expire unowned node
        # traffic promptly; this fixture does not exercise late binding recovery.
        argv = [str(self.binary), "--data-dir", self.config["data_dir"], "sensor", "stream",
                "--placement", self.options.sensor_placement, "--no-policy", "--auto-tls=false",
                "--apparmor-state=false", "--seccomp-state=false", "--ring-buffer-mib", "4",
                "--flush-interval", "100ms", "--pending-ttl", "1ms", "--max-queued-bytes", "16777216",
                "--max-queued-batches", "128"]
        self.report.update(status="starting", command=argv)
        self.stdout = (self.base / "sensor.stdout").open("xb")
        self.stderr = (self.base / "sensor.stderr").open("xb")
        self.process = subprocess.Popen(argv, env=self.environment, stdout=self.stdout, stderr=self.stderr)
        deadline = time.monotonic() + self.options.sensor_ready_timeout
        while time.monotonic() < deadline:
            log = self.log_tail()
            if self.process.poll() is not None:
                if any(reason in log.lower() for reason in ("operation not permitted", "permission denied", "not supported", "no btf")):
                    raise AcceptanceBlocked("sensor_prerequisite_unavailable", "Sensor permissions or kernel prerequisites are missing; inspect sensor.stderr")
                raise AcceptanceFailure("sensor_start_failed", "Sensor exited before readiness; inspect sensor.stderr")
            if "agentprov sensor stream: ready probes-attached" in log:
                ready = self.status()
                caps = ready.get("capabilities") or {}
                required = [p for p in caps.get("probes", []) if p.get("required")]
                if (ready.get("collector_running") is True and ready.get("capabilities_historical") is False and
                        caps.get("ready") is True and caps.get("collector_id") and required and
                        all(p.get("status") == "attached" for p in required)):
                    if caps.get("producer", {}).get("placement") != self.options.sensor_placement:
                        raise AcceptanceFailure("sensor_placement_mismatch", "Sensor reported a different observation placement")
                    self.report.update(status="ready", ready=ready)
                    write_json(self.base / "sensor-ready.json", ready)
                    return
            time.sleep(0.1)
        raise AcceptanceFailure("sensor_ready_timeout", "Sensor did not become ready within the deadline")

    def stop(self, validate):
        if self.process is None:
            return
        exited_early = self.process.poll() is not None
        if not exited_early:
            self.process.terminate()
        try:
            code = self.process.wait(timeout=self.options.sensor_drain_timeout)
        except subprocess.TimeoutExpired as error:
            self.process.kill()
            self.process.wait(timeout=5)
            raise AcceptanceFailure("sensor_drain_timeout", "Collector exceeded stop/drain deadline; forced termination") from error
        self.report["returncode"] = code
        final = self.status()
        self.report["final"] = final
        write_json(self.base / "sensor-final.json", final)
        if not validate:
            return
        if exited_early or code:
            raise AcceptanceFailure("sensor_stopped_unexpectedly", "Collector exited before the task finished or failed during shutdown")
        if final.get("collector_running") is not False or final.get("capabilities_historical") is not True:
            raise AcceptanceFailure("sensor_still_running", "Collector lock is still held after shutdown")
        caps = final.get("capabilities") or {}
        if caps.get("collector_id") != self.report["ready"]["capabilities"]["collector_id"] or caps.get("status") != "stopped":
            raise AcceptanceFailure("sensor_lifetime_mismatch", "Final capability report is not this stopped collector")
        capture = final["capture"]
        if any(capture.get(key) != 0 for key in ("queued_batches", "queued_bytes", "pending_events", "cleanup_pending_batches")) or capture.get("last_error"):
            raise AcceptanceFailure("sensor_drain_incomplete", "Pending capture or spool cleanup remains after shutdown")
        counters = capture.get("counters", {})
        loss = {k: v for k, v in counters.items() if v and (k.startswith("dropped_") or k in ("invalid", "failed", "kernel_dropped_events"))}
        if loss:
            self.report["loss"] = loss
            raise AcceptanceFailure("sensor_capture_loss", "Collector reported dropped or invalid capture")
        self.report["evidence"] = verify_sensor_records(self.config)
        self.report.update(status="passed", drain="collector_stopped_store_empty")

    def finish(self, error):
        try:
            self.stop(validate=error is None)
        except BaseException as cleanup:
            if error is None:
                error = cleanup
            else:
                self.report["cleanup_failure"] = getattr(cleanup, "code", type(cleanup).__name__)
        finally:
            for stream in (self.stdout, self.stderr):
                if stream is not None:
                    stream.close()
        if error is not None:
            self.report.update(status="blocked" if isinstance(error, AcceptanceBlocked) else "failed",
                               failure_code=getattr(error, "code", type(error).__name__))
            error.sensor = self.report
        write_json(self.base / "sensor.json", self.report)
        return error

    def __enter__(self):
        if self.enabled:
            self.report = {"status": "starting", "run_id": self.config["run_id"], "target": self.config["target"],
                           "data_dir": self.config["data_dir"], "placement": self.options.sensor_placement,
                           "report_path": str(self.base / "sensor.json")}
            try:
                self.start()
            except BaseException as error:
                self.finish(error)
                raise
        return self

    def __exit__(self, kind, error, traceback):
        if self.enabled:
            result = self.finish(error)
            if error is None and result is not None:
                raise result
        return False


def verify_refs(config, results):
    refs = set()
    with connect(config) as db:
        for item in results:
            result = item["result"]
            if result.get("run_id", config["run_id"]) != config["run_id"]:
                raise AssertionError("result belongs to a different run")
            view = result.get("view") or {}
            binding, receipt = view.get("binding", {}), view.get("last_receipt", {})
            for ref in (binding.get("manifest_ref"), binding.get("evidence_ref"), result.get("operation_ref"),
                        result.get("content_evidence", {}).get("ref"), receipt.get("input_manifest_ref"),
                        receipt.get("output_manifest_ref"), receipt.get("stdout", {}).get("ref"), receipt.get("stderr", {}).get("ref")):
                if ref:
                    refs.add(ref)
            if result.get("operation_ref") and (result["operation_ref"] != receipt.get("ref") or
                                                  result["tool_call_id"] != receipt.get("tool_call_id")):
                raise AssertionError("tool borrowed a previous receipt")
        for ref in refs:
            row = db.execute("SELECT run_id,path FROM provenance_objects WHERE hash=?", (ref,)).fetchone()
            if row is None or row[0] != config["run_id"]:
                raise AssertionError("missing or wrong-run evidence reference")
            if "sha256:" + hashlib.sha256(Path(row[1]).read_bytes()).hexdigest() != ref:
                raise AssertionError("evidence object hash mismatch")
        attempts = db.execute("SELECT id,tool_call_id,snapshot_id,workspace_path FROM fork_attempts").fetchall()
        contexts = db.execute("SELECT COUNT(*) FROM agent_context_entries WHERE run_id=? AND kind='tool_result'", (config["run_id"],)).fetchone()[0]
    return {"verified_refs": sorted(refs), "record_attempts": len(attempts), "context_results": contexts}


async def contract_acceptance(base, binary, package, options=None, target=None):
    path, config = layout(base, "contract", target)
    with SensorCapture(base, binary, config, options) as sensor:
        result = await contract_tools(base, binary, package, path, config)
    result.update(config_path=str(path), target=config["target"])
    if sensor.enabled:
        result["sensor"] = sensor.report
    return result


async def contract_tools(base, binary, package, path, config):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    environment = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "LANG") if k in os.environ}
    environment["PYTHONPATH"] = str(package)
    parameters = StdioServerParameters(command=sys.executable, args=["-m", "agentprov.workspace_mcp", "--agentprov", str(binary), "--config", str(path)], env=environment)
    results = []

    async def call(client, name, expected_error=None, **arguments):
        response = await client.call_tool(name, arguments)
        value = response.structured_content
        if response.is_error or not isinstance(value, dict):
            raise AssertionError("MCP transport/tool failure")
        results.append({"tool": name, "arguments": arguments, "result": value})
        with (base / "results.jsonl").open("a", encoding="utf-8") as progress:
            progress.write(json.dumps(results[-1]) + "\n")
        if expected_error:
            if value.get("ok") or value.get("error", {}).get("code") != expected_error:
                raise AssertionError("expected structured " + expected_error)
        elif not value.get("ok"):
            raise AssertionError("workspace tool failed: " + value.get("error", {}).get("code", "unknown"))
        return value

    with (base / "mcp.stderr").open("w") as log:
        async with stdio_client(parameters, errlog=log) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                inventory = await client.list_tools()
                if {tool.name for tool in inventory.tools} != TOOLS:
                    raise AssertionError("unexpected workspace tool inventory")
                initial = await call(client, "workspace_inspect")
                if initial["view"]["binding"]["revision"] != 1:
                    raise AssertionError("unexpected initial revision")
                read_file = await call(client, "workspace_read", path="input.txt")
                if read_file["content"] != "value=1\n":
                    raise AssertionError("wrong authoritative input")
                edited = await call(client, "workspace_edit", path="input.txt", old_text="1", new_text="2", count=1,
                                    expected_revision=1, expected_digest=read_file["sha256"])
                await call(client, "workspace_write", path="input.txt", content="stale overwrite", expected_revision=1, expected_error="conflict")
                for _ in range(3):
                    inspected = await call(client, "workspace_inspect")
                    if inspected["view"]["binding"]["revision"] != edited["view"]["binding"]["revision"]:
                        raise AssertionError("query or conflict changed the file revision")
                written = await call(client, "workspace_write", path="note.txt", content="controlled-write\n", expected_digest="absent")
                executed = await call(client, "workspace_bash", expected_revision=written["view"]["binding"]["revision"],
                                      command="cat input.txt note.txt > result.txt; printf WORKSPACE_OK")
                receipt = executed["view"]["last_receipt"]
                if executed.get("stdout") != "WORKSPACE_OK" or receipt["input_manifest_ref"] != written["view"]["binding"]["manifest_ref"] or receipt["exit_code"] != 0:
                    raise AssertionError("Bash did not consume the current observed revision")
                record_ref = receipt["record"]
                with connect(config) as db:
                    attempt = db.execute("SELECT tool_call_id,snapshot_id,workspace_path FROM fork_attempts WHERE id=?", (record_ref["attempt_id"],)).fetchone()
                    snapshot_path = db.execute("SELECT path FROM snapshots WHERE id=?", (record_ref["base_snapshot_id"],)).fetchone()[0]
                if attempt != (executed["record_tool_call_id"], record_ref["base_snapshot_id"], config["root"]):
                    raise AssertionError("record reference did not identify the actual runner")
                if (Path(snapshot_path) / "input.txt").read_text() != "value=2\n":
                    raise AssertionError("record baseline used stale input")
                result = await call(client, "workspace_read", path="result.txt")
                if result["content"] != "value=2\ncontrolled-write\n":
                    raise AssertionError("unexpected result bytes")
                settled_revision = result["view"]["binding"]["revision"]
        # A new bridge reads the same durable state. Query never reruns Bash.
        async with stdio_client(parameters, errlog=log) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                restarted = await call(client, "workspace_inspect")
                if restarted["view"]["binding"]["revision"] != settled_revision:
                    raise AssertionError("bridge restart lost revision")
                concurrent = await asyncio.gather(*[
                    client.call_tool("workspace_write", {"path": "input.txt", "content": "winner-" + str(i), "expected_revision": settled_revision}) for i in range(2)])
                values = [x.structured_content for x in concurrent]
                if sum(x.get("ok") is True for x in values) != 1 or sum(x.get("error", {}).get("code") == "conflict" for x in values) != 1:
                    raise AssertionError("concurrent CAS did not choose one winner")
                for value in values:
                    results.append({"tool": "workspace_write", "arguments": {"expected_revision": settled_revision}, "result": value})
                await call(client, "workspace_read", path="../operator/workspace.json", expected_error="unsafe_path")
                link = Path(config["root"]) / "escape"
                link.symlink_to(path)
                try:
                    await call(client, "workspace_read", path="escape", expected_error="unsafe_path")
                finally:
                    link.unlink()
                target_path = Path(config["target_file"])
                replacement = target_path.with_suffix(".new")
                write_json(replacement, {**config["target"], "generation": "fixture-recreated"})
                replacement.replace(target_path)
                await call(client, "workspace_bash", command="touch must-not-run", expected_revision=settled_revision + 1, expected_error="stale_target")
    if (Path(config["root"]) / "must-not-run").exists():
        raise AssertionError("stale generation executed")
    evidence = verify_refs(config, results)
    if evidence["record_attempts"] != 1:
        raise AssertionError("query, restart, conflict, or stale generation reran Bash")
    write_json(base / "results.json", results)
    return {"status": "passed", "run_id": config["run_id"], "checks": ["read_edit_write_bash_same_bytes", "record_snapshot", "cas_conflict_reread", "concurrent_cas",
            "restart_query_no_replay", "path_symlink_rejection", "stale_generation", "current_run_evidence", "trusted_context"], **evidence}


def verify_harness_run(base, config, returncode):
    if returncode:
        raise AcceptanceFailure("harness_process_failed", "Claude process failed; inspect the private Harness logs")
    calls = []
    initializations, completions = [], []
    for line in (base / "claude.stdout").read_text().splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if item.get("type") == "system" and item.get("subtype") == "init":
            initializations.append(item)
        if item.get("type") == "result":
            completions.append(item)
        message = item.get("message")
        if item.get("type") != "assistant" or not isinstance(message, dict):
            continue
        content = message.get("content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append({"id": block.get("id"), "name": block.get("name")})
    allowed = {"mcp__" + MCP_SERVER + "__" + name for name in TOOLS}
    if not initializations:
        raise AcceptanceFailure("missing_init_inventory", "Claude stream contains no initialization inventory")
    for initialization in initializations:
        servers = initialization.get("mcp_servers")
        if not isinstance(servers, list) or not any(isinstance(server, dict) and server.get("name") == MCP_SERVER and
                                                   server.get("status") == "connected" for server in servers):
            raise AcceptanceFailure("mcp_not_connected", "Claude did not initialize the configured workspace MCP server")
        tools = initialization.get("tools")
        if not isinstance(tools, list) or not allowed <= {tool for tool in tools if isinstance(tool, str)}:
            raise AcceptanceFailure("missing_controlled_tools", "Claude initialization is missing controlled workspace tools")
    if not calls:
        raise AcceptanceFailure("no_tool_calls", "Claude emitted no actual tool_use calls; prose/XML is not a tool call")
    if any(not isinstance(call["name"], str) or call["name"] not in allowed for call in calls):
        raise AcceptanceFailure("uncontrolled_tool", "Claude used a tool outside the controlled workspace inventory")
    if not {"mcp__" + MCP_SERVER + "__workspace_" + name for name in ("read", "edit", "write", "bash")} <= {call["name"] for call in calls}:
        raise AcceptanceFailure("missing_required_tool_calls", "Claude did not exercise Read/Edit/Write/Bash")
    artifact = Path(config["root"]) / "result.txt"
    if not artifact.is_file() or artifact.is_symlink():
        raise AcceptanceFailure("missing_artifact", "Harness did not produce the required regular result.txt")
    if artifact.read_bytes() != b"value=2\nagent-note\n":
        raise AcceptanceFailure("artifact_mismatch", "Harness artifact bytes do not match the requested task")
    if not completions or completions[-1].get("subtype") != "success" or completions[-1].get("is_error"):
        raise AcceptanceFailure("harness_result_failed", "Claude did not finish the task successfully")
    with connect(config) as db:
        attempts = db.execute("SELECT COUNT(*) FROM fork_attempts").fetchone()[0]
        result_entries = db.execute("SELECT COUNT(*) FROM agent_context_entries WHERE kind='tool_result'").fetchone()[0]
    if attempts != 1 or result_entries < 5:
        raise AcceptanceFailure("incomplete_evidence", "Harness tool/record evidence is incomplete or Bash replayed")
    return {"status": "passed", "run_id": config["run_id"], "controlled_calls": calls,
            "init_inventory": "verified", "connected_server": MCP_SERVER,
            "record_attempts": attempts, "context_results": result_entries, "artifact_sha256": hashlib.sha256((Path(config["root"]) / "result.txt").read_bytes()).hexdigest()}


def harness_acceptance(base, binary, package, claude, options=None, target=None):
    config_path, config = layout(base, "harness", target)
    with SensorCapture(base, binary, config, options) as sensor:
        result = harness_tools(base, binary, package, claude, config_path, config)
    result.update(config_path=str(config_path), target=config["target"])
    if sensor.enabled:
        result["sensor"] = sensor.report
    return result


def harness_tools(base, binary, package, claude, config_path, config):
    mcp_config = {"mcpServers": {MCP_SERVER: {"command": sys.executable,
                  "args": ["-m", "agentprov.workspace_mcp", "--agentprov", str(binary), "--config", str(config_path)],
                  "env": {"PYTHONPATH": str(package)}}}}
    write_json(base / "mcp.json", mcp_config)
    environment = dict(os.environ, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", API_TIMEOUT_MS="90000")
    environment.pop("CLAUDECODE", None)
    argv = [str(claude), "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", str(base / "mcp.json"),
            "--tools", "", "--allowedTools", ",".join("mcp__" + MCP_SERVER + "__" + name for name in sorted(TOOLS)),
            "--output-format", "stream-json", "--verbose", "--max-budget-usd", "0.50", "--max-turns", "12", "-p", PROMPT]
    # Native files remain private; public reporting contains only fixture facts.
    with (base / "claude.stdout").open("w") as stdout, (base / "claude.stderr").open("w") as stderr:
        try:
            finished = subprocess.run(argv, cwd=config["root"], env=environment, stdout=stdout, stderr=stderr, timeout=300)
        except subprocess.TimeoutExpired as error:
            raise AcceptanceFailure("harness_timeout", "Claude exceeded the bounded task lifetime") from error
    return verify_harness_run(base, config, finished.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--agentprov", required=True, type=Path)
    parser.add_argument("--claude", type=Path, help="opt in to the real Harness using existing operator credentials")
    parser.add_argument("--python-package", type=Path, default=Path(__file__).resolve().parent.parent / "python")
    parser.add_argument("--target-file", type=Path, help="operator-owned Target JSON; copied, never modified")
    parser.add_argument("--sensor", action="store_true", help="opt in to Linux sensor stream/status and same-record native evidence checks")
    parser.add_argument("--sensor-placement", choices=("local_kernel", "host_kernel", "guest_kernel"), default="local_kernel")
    parser.add_argument("--sensor-ready-timeout", type=int, default=30, help="readiness deadline in seconds (1..120)")
    parser.add_argument("--sensor-drain-timeout", type=int, default=30, help="stop/drain deadline in seconds (1..120)")
    args = parser.parse_args()
    if not all(1 <= value <= 120 for value in (args.sensor_ready_timeout, args.sensor_drain_timeout)):
        parser.error("sensor timeouts must be between 1 and 120 seconds")
    out = args.output.resolve()
    out.mkdir(mode=0o700)
    binary, package = args.agentprov.resolve(strict=True), args.python_package.resolve(strict=True)
    report = {"platform": platform.platform(), "architecture": platform.machine(), "sensor": "on" if args.sensor else "off",
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "harness": {"status": "not_requested"}}
    phase = "contract"
    def interrupted(signum, frame):
        raise AcceptanceFailure("acceptance_interrupted", "Acceptance interrupted; owned collector will be stopped")
    previous_sigterm = signal.signal(signal.SIGTERM, interrupted)
    try:
        try:
            report["mcp_version"] = importlib.metadata.version("mcp")
        except importlib.metadata.PackageNotFoundError as error:
            raise AcceptanceBlocked("mcp_dependency_missing", "Use a Python environment with the existing MCP dependency") from error
        target = load_target(args.target_file)
        report["contract"] = asyncio.run(contract_acceptance(out / "contract", binary, package, args, target))
        if args.claude:
            phase = "harness"
            report["harness"] = harness_acceptance(out / "harness", binary, package, args.claude.absolute(), args, target)
    except BaseException as error:
        report["status"] = "blocked" if isinstance(error, AcceptanceBlocked) else "failed"
        report["failure_type"] = type(error).__name__
        report["failure_code"] = getattr(error, "code", "acceptance_error")
        report["failure_phase"] = phase
        report[phase] = {"status": report["status"], "failure_code": report["failure_code"]}
        if hasattr(error, "sensor"):
            report[phase]["sensor"] = error.sensor
        write_json(out / "report.json", report)
        print(json.dumps({"status": report["status"], "failure_type": type(error).__name__, "failure_code": report["failure_code"],
                          "failure_phase": phase, "report": str(out / "report.json")}))
        raise SystemExit(2 if isinstance(error, AcceptanceBlocked) else 1)
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
    report["status"] = "passed"
    write_json(out / "report.json", report)
    print(json.dumps({"status": "passed", "architecture": report["architecture"], "contract": report["contract"]["status"],
                      "harness": report["harness"]["status"], "record_attempts": report["contract"]["record_attempts"], "report": str(out / "report.json")}))


if __name__ == "__main__":
    main()
