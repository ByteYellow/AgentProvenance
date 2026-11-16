#!/usr/bin/env python3
"""Accept W-01 through actual stdio MCP, optionally with a real Claude Harness.

Run this on the machine hosting the entire Harness and workspace. The default
fixture uses no provider credentials, HTTP server, sensor, or privileged setup.
--claude opts into a bounded real Harness run using the operator's existing
provider setup; credentials are never read, printed, or copied by this script.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import uuid
from urllib.parse import quote


MCP_SERVER = "agentprov_workspace"
TOOLS = {"workspace_inspect", "workspace_read", "workspace_edit", "workspace_write", "workspace_bash"}
PROMPT = """Use only the workspace MCP tools for this small task. First inspect the binding,
then read input.txt. Replace value=1 with value=2 using workspace_edit and the revision/digest
returned by that read. Use workspace_write to create note.txt containing exactly agent-note\n,
with the current revision or expected_digest='absent'. Then call workspace_bash with the current
observed revision and command: cat input.txt note.txt > result.txt; printf WORKSPACE_HARNESS_OK
Read result.txt to verify its exact content is value=2\nagent-note\n. Do not install packages,
use background commands, or use any other tools. On CAS conflict reread and decide a new edit;
on unknown/recovery inspect rather than replaying Bash. Finish with the verified result name."""


class AcceptanceFailure(AssertionError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def layout(base, label):
    base.mkdir(mode=0o700)
    work, operator = base / "work", base / "operator"
    work.mkdir()
    operator.mkdir(mode=0o700)
    (work / "input.txt").write_text("value=1\n", encoding="utf-8")
    target = {"producer_id": "workspace-acceptance", "instance_id": platform.node() or "local",
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


async def contract_acceptance(base, binary, package):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    path, config = layout(base, "contract")
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


def harness_acceptance(base, binary, package, claude):
    config_path, config = layout(base, "harness")
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
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(mode=0o700)
    binary, package = args.agentprov.resolve(strict=True), args.python_package.resolve(strict=True)
    report = {"platform": platform.platform(), "architecture": platform.machine(), "sensor": "off",
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "mcp_version": importlib.metadata.version("mcp"),
              "harness": {"status": "not_requested"}}
    phase = "contract"
    try:
        report["contract"] = asyncio.run(contract_acceptance(out / "contract", binary, package))
        if args.claude:
            phase = "harness"
            report["harness"] = harness_acceptance(out / "harness", binary, package, args.claude.absolute())
    except BaseException as error:
        report["status"] = "failed"
        report["failure_type"] = type(error).__name__
        report["failure_code"] = getattr(error, "code", "acceptance_error")
        report["failure_phase"] = phase
        report[phase] = {"status": "failed", "failure_code": report["failure_code"]}
        write_json(out / "report.json", report)
        print(json.dumps({"status": "failed", "failure_type": type(error).__name__, "failure_code": report["failure_code"],
                          "failure_phase": phase, "report": str(out / "report.json")}))
        raise SystemExit(1)
    report["status"] = "passed"
    write_json(out / "report.json", report)
    print(json.dumps({"status": "passed", "architecture": report["architecture"], "contract": report["contract"]["status"],
                      "harness": report["harness"]["status"], "record_attempts": report["contract"]["record_attempts"], "report": str(out / "report.json")}))


if __name__ == "__main__":
    main()
