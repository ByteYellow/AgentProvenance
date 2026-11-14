#!/usr/bin/env python3
"""Run a real Claude Code task through the recorded Notebook MCP entry.

Uses the user's existing Claude provider configuration. Requires the optional
Notebook dependencies. Logs and fixture signing keys stay in a new private
output directory; inspect it before sharing. No provider key is printed.
"""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import uuid


PROMPT = """Use only the notebook tools to analyze input.csv in the notebook working directory.
Make exactly two notebook_execute calls. In the first, load the CSV with csv.DictReader,
compute integer totals by category, and keep a variable named totals in the kernel.
In the second, check totals == {'alpha': 40, 'beta': 20}, write result.json with json.dumps(totals,
sort_keys=True), and print VERIFIED_TOTALS. Do not restart the kernel. Do not install packages.
Then briefly report the totals and output filename. If a call times out, query its message_id;
do not reexecute it. This is a small local fixture, not a repository task."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--agentprov", required=True, type=pathlib.Path)
    parser.add_argument("--claude", required=True, type=pathlib.Path)
    parser.add_argument("--capture", choices=("basic", "detailed"), default="detailed")
    args = parser.parse_args()
    # Preserve the CLI entry name: launch selects its harness from argv[0].
    out, binary, claude = args.output.absolute(), args.agentprov.resolve(), args.claude.absolute()
    out.mkdir(mode=0o700)
    work = out / "work"
    work.mkdir()
    (work / "input.csv").write_text("category,value\nalpha,10\nbeta,20\nalpha,30\n")
    package = pathlib.Path(__file__).resolve().parent.parent / "python"
    if not (package / "agentprov/notebook_mcp.py").exists():
        package = pathlib.Path(os.environ["PYTHONPATH"].split(os.pathsep)[0]).resolve()
    config = {"mcpServers": {"notebook": {"command": sys.executable,
        "args": ["-m", "agentprov.notebook_mcp", "--workdir", str(work), "--capture-dir", str(out / "captures"),
                 "--producer-id", "notebook-entry", "--namespace", "agent-acceptance", "--instance-id", "local",
                 "--generation", str(uuid.uuid4()), "--notebook-id", "csv-analysis"],
        "env": {"PYTHONPATH": str(package)}}}}
    (out / "mcp.json").write_text(json.dumps(config, indent=2) + "\n")
    data, received = out / "data", out / "received"
    environment = dict(os.environ, AGENTPROV_DAEMON_URL="", AGENTPROV_LANG="en",
                       CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", API_TIMEOUT_MS="90000")
    environment.pop("CLAUDECODE", None)

    def cli(home, *argv, structured=True):
        result = subprocess.run([str(binary), "--data-dir", str(home), "--lang", "en", *map(str, argv)],
                                env=environment, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(f"CLI failed: {argv}\n{result.stderr}")
        return json.loads(result.stdout) if structured else result.stdout

    invocation = [str(binary), "--data-dir", str(data), "launch", "--sensor", "off", "--no-dashboard",
                  "--json", "--file-diff", "--capture", args.capture, "--workdir", str(work), "--", str(claude),
                  "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", str(out / "mcp.json"),
                  "--tools", "", "--allowedTools", "mcp__notebook__notebook_execute,mcp__notebook__notebook_result",
                  "--output-format", "stream-json", "--verbose", "--max-budget-usd", "0.50", "--max-turns", "8", "-p", PROMPT]
    with (out / "launch.stdout").open("w") as stdout, (out / "launch.stderr").open("w") as stderr:
        completed = subprocess.run(invocation, cwd=work, env=environment, stdout=stdout, stderr=stderr, timeout=300)
    if completed.returncode:
        raise AssertionError("native Agent launch failed; see private launch logs")
    launch = json.loads((out / "launch.stdout").read_text())
    run = launch["run_id"]
    if json.loads((work / "result.json").read_text()) != {"alpha": 40, "beta": 20}:
        raise AssertionError("Agent did not produce the expected artifact")
    capture_files = sorted((out / "captures").glob("*.jsonl"))
    if len(capture_files) != 1:
        raise AssertionError("Agent unexpectedly restarted or never opened the kernel")
    for capture in capture_files:
        imported = cli(data, "context", "import", "--run", run, "--harness", "jupyter", "--file", capture)
        if imported["stored"] == 0:
            raise AssertionError("native Notebook evidence missing")
    cli(data, "context", "project", "--run", run)
    entries = cli(data, "context", "list", "--run", run, "--limit", "200")
    if entries.get("has_more"):
        raise AssertionError("fixture unexpectedly exceeds one context page")
    native = [e for e in entries["entries"] if e["source"]["harness"] == "jupyter" and e["kind"] == "tool_call"]
    callers = [e for e in entries["entries"] if e.get("notebook_request")]
    call_ids = {(e["source"]["harness"], e["source"]["session_id"], e.get("agent_id", ""), e["tool_call_id"]) for e in callers}
    if len(native) != 2 or len(call_ids) != 2:
        raise AssertionError(f"expected two native Agent/Notebook calls, got {len(call_ids)}/{len(native)}")
    if args.capture == "basic" and any(e["content"]["state"] != "omitted" for e in callers):
        raise AssertionError("basic capture retained MCP result bodies")
    matches = []
    for caller in callers:
        ref = caller["notebook_request"]
        targets = [e for e in native if e["source"]["notebook"] == ref["scope"] and
                   e["notebook"]["message_session"] == ref["message_session"] and e["notebook"]["message_id"] == ref["message_id"]]
        if len(targets) != 1:
            raise AssertionError("Agent result does not uniquely identify a captured request")
        forward = cli(data, "context", "links", "--run", run, "--entry", caller["id"])
        reverse = cli(data, "context", "links", "--run", run, "--entry", targets[0]["id"])
        if sum(x["relation"] == "context_notebook_request" for x in forward["links"]) != 1 or sum(x["relation"] == "context_notebook_caller" for x in reverse["links"]) != 1:
            raise AssertionError("bidirectional native links missing")
        matches.append({"caller": caller["id"], "tool_call_id": caller["tool_call_id"], "request": targets[0]["id"],
                        "native_reference": ref, "forward": forward, "reverse": reverse})
    private, public = out / "fixture.key", out / "fixture.pub"
    cli(data, "forensics", "keygen", "--priv", private, "--pub", public, structured=False)
    bundle = cli(data, "forensics", "export", run, "--sign-key", private, "--json")
    if not bundle["signed"]:
        raise AssertionError("bundle was not signed")
    cli(received, "forensics", "import", bundle["path"], "--pub-key", public, "--json")
    data.rename(out / "data-unavailable")
    work.rename(out / "work-unavailable")
    for key in ("path", "attestation_path"):
        if bundle.get(key):
            bundle[key] = str(out / "data-unavailable" / pathlib.Path(bundle[key]).relative_to(data))
    restored = cli(received, "context", "list", "--run", run, "--limit", "200")
    if restored["entries"] != entries["entries"]:
        raise AssertionError("signed import changed the native evidence")
    for match in matches:
        if cli(received, "context", "links", "--run", run, "--entry", match["caller"]) != match["forward"]:
            raise AssertionError("signed import lost native links")
    verified = cli(received, "graph", "verify", "--run", run, "--json")
    if verified["error_count"] or verified["warning_count"]:
        raise AssertionError("signed graph verification failed")
    cli(received, "dashboard", "export", "--run", run, "--output", out / "replay.zip", structured=False)
    cli(received, "dashboard", "export", "--run", run, "--exclude-record", "entry/" + native[0]["id"],
        "--output", out / "replay-selected.zip", structured=False)
    report = {"run_id": run, "platform": platform.platform(), "capture": args.capture,
              "agent_calls": len(call_ids), "caller_observations": len(callers), "notebook_requests": len(native),
              "matches": matches, "graph": verified, "bundle": bundle,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "claude_version": subprocess.check_output([str(claude), "--version"], text=True).strip(),
              "source_capture": "native_claude_hooks_and_jupyter", "runtime_capture": "disabled"}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"run_id": run, "agent_calls": len(call_ids), "notebook_requests": len(native), "graph_errors": verified["error_count"]}))


if __name__ == "__main__":
    main()
