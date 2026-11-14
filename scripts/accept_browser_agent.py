#!/usr/bin/env python3
"""Run a real Claude Code task through the recorded Browser MCP entry.

Uses existing Claude provider settings. Owns a loopback page and a fresh browser;
private logs, captures and fixture signing keys remain in a new output directory.
"""

import argparse
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import uuid

from accept_browser import Handler


PAGE = b'''<!doctype html><title>Regional totals</title><h1>Regional totals</h1>
<table><tr><th>region</th><th>total</th></tr><tr><td>alpha</td><td>40</td></tr>
<tr><td>beta</td><td>20</td></tr></table><a id="download" href="/report.csv" download>Download report</a>'''
CSV = b"region,total\nalpha,40\nbeta,20\n"


class AgentHandler(Handler):
    def do_GET(self):
        if self.path == "/task":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)
        else:
            super().do_GET()


def accept(args, out, origin):
    # Preserve the CLI entry name: launch selects its harness from argv[0].
    binary, claude = args.agentprov.resolve(), args.claude.absolute()
    work = out / "work"
    work.mkdir()
    package = Path(__file__).resolve().parent.parent / "python"
    config = {"mcpServers": {"browser": {"command": sys.executable,
        "args": ["-m", "agentprov.browser_mcp", "--capture-dir", str(out / "captures"),
                 "--producer-id", "browser-entry", "--namespace", "agent-acceptance", "--instance-id", "local",
                 "--generation", str(uuid.uuid4())], "env": {"PYTHONPATH": str(package)}}}}
    (out / "mcp.json").write_text(json.dumps(config, indent=2) + "\n")
    prompt = f"""Use only the browser tools to inspect {origin}/task. First list browser_pages to get the default page_id.
Make exactly four browser_execute calls: navigate to that URL, read_text, click the #download link, and screenshot.
Read the regional totals from the page and briefly report them with the downloaded filename. Do not create pages,
install packages, or use another tool. If waiting times out, query browser_result with the returned operation_id;
do not resend the operation. This is a small local browsing fixture."""
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
                  "--json", "--capture", args.capture, "--workdir", str(work), "--", str(claude),
                  "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", str(out / "mcp.json"),
                  "--tools", "", "--allowedTools", "mcp__browser__browser_pages,mcp__browser__browser_execute,mcp__browser__browser_result",
                  "--output-format", "stream-json", "--verbose", "--max-budget-usd", "0.50", "--max-turns", "10", "-p", prompt]
    with (out / "launch.stdout").open("w") as stdout, (out / "launch.stderr").open("w") as stderr:
        completed = subprocess.run(invocation, cwd=work, env=environment, stdout=stdout, stderr=stderr, timeout=300)
    if completed.returncode:
        raise AssertionError("native Agent launch failed; see private launch logs")
    run = json.loads((out / "launch.stdout").read_text())["run_id"]
    capture = out / "captures/browser.jsonl"
    rows = [json.loads(line) for line in capture.read_text().splitlines()]
    if any(r.get("kind") == "gap" for r in rows):
        raise AssertionError("browser producer reported a capture gap")
    if not any(r.get("kind") == "download_finished" and r.get("payload", {}).get("sha256") == hashlib.sha256(CSV).hexdigest() for r in rows):
        raise AssertionError("Agent did not download the expected report")
    if not any(r.get("kind") == "action_end" and "alpha" in r.get("payload", {}).get("text", "") and "40" in r["payload"]["text"] for r in rows):
        raise AssertionError("Agent did not read the real page")
    imported = cli(data, "context", "import", "--run", run, "--harness", "browser", "--file", capture)
    repeated = cli(data, "context", "import", "--run", run, "--harness", "browser", "--file", capture)
    if not imported["stored"] or repeated["stored"] or repeated["duplicates"] != imported["stored"]:
        raise AssertionError("native Browser import is not idempotent")
    cli(data, "context", "project", "--run", run)

    def entries(store):
        values, cursor = [], ""
        while True:
            page = cli(store, "context", "list", "--run", run, "--limit", "100", "--cursor", cursor)
            values.extend(page["entries"])
            if not page["has_more"]:
                return values
            if cursor == page["next_cursor"]:
                raise AssertionError("entry paging stalled")
            cursor = page["next_cursor"]

    original = entries(data)
    native = [e for e in original if e["source"]["harness"] == "browser" and e["kind"] == "tool_call"]
    callers = [e for e in original if e.get("browser_operation")]
    call_ids = {(e["source"]["harness"], e["source"]["session_id"], e.get("agent_id", ""), e["tool_call_id"]) for e in callers}
    if len(native) != 4 or len(call_ids) != 4 or {e["browser"]["operation"] for e in native} != {"navigate", "read_text", "click", "screenshot"}:
        raise AssertionError(f"expected four native Agent/Browser calls, got {len(call_ids)}/{len(native)}")
    if args.capture == "basic" and any(e["content"]["state"] != "omitted" for e in callers):
        raise AssertionError("basic retained MCP output bodies")
    matches = []
    for caller in callers:
        ref = caller["browser_operation"]
        targets = [e for e in native if e["source"]["browser"] == ref["scope"] and all(
            e["browser"][k] == ref[k] for k in ("target_id", "operation_id", "operation"))]
        if len(targets) != 1:
            raise AssertionError("Agent result does not uniquely identify a captured operation")
        forward = cli(data, "context", "links", "--run", run, "--entry", caller["id"])
        reverse = cli(data, "context", "links", "--run", run, "--entry", targets[0]["id"])
        if sum(x["relation"] == "context_browser_operation" for x in forward["links"]) != 1 or sum(x["relation"] == "context_browser_caller" for x in reverse["links"]) != 1:
            raise AssertionError("native directional links missing")
        matches.append({"caller": caller["id"], "tool_call_id": caller["tool_call_id"], "operation": targets[0]["id"],
                        "native_reference": ref, "forward": forward, "reverse": reverse})
    private, public = out / "fixture.key", out / "fixture.pub"
    cli(data, "forensics", "keygen", "--priv", private, "--pub", public, structured=False)
    bundle = cli(data, "forensics", "export", run, "--sign-key", private, "--json")
    imported = cli(received, "forensics", "import", bundle["path"], "--pub-key", public, "--json")
    if not bundle["signed"] or not imported["attestation_verified"]:
        raise AssertionError("signed round trip did not verify")
    data.rename(out / "data-unavailable")
    work.rename(out / "work-unavailable")
    for key in ("path", "attestation_path"):
        if bundle.get(key):
            bundle[key] = str(out / "data-unavailable" / Path(bundle[key]).relative_to(data))
    if entries(received) != original:
        raise AssertionError("signed import changed native records")
    for match in matches:
        if cli(received, "context", "links", "--run", run, "--entry", match["caller"]) != match["forward"]:
            raise AssertionError("signed import lost native links")
    graph = cli(received, "graph", "verify", "--run", run, "--json")
    if graph["error_count"] or graph["warning_count"]:
        raise AssertionError("signed graph verification failed")
    attachments = [a for e in original for a in e.get("attachments", [])]
    if len(attachments) != 2 or {a["source_media_type"] for a in attachments} != {"image/png", "application/har+json"}:
        raise AssertionError("screenshot or HAR reference missing")
    if args.capture == "basic" and any(a["state"] != "omitted" for a in attachments):
        raise AssertionError("basic retained Browser attachments")
    cli(received, "dashboard", "export", "--run", run, "--output", out / "replay.zip", structured=False)
    cli(received, "dashboard", "export", "--run", run, "--exclude-record", "entry/" + native[0]["id"],
        "--output", out / "replay-selected.zip", structured=False)
    report = {"run_id": run, "platform": platform.platform(), "capture": args.capture, "entries": len(original),
              "agent_calls": len(call_ids), "caller_observations": len(callers), "browser_operations": len(native),
              "matches": matches, "attachments": attachments, "graph": graph, "bundle": bundle,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "claude_version": subprocess.check_output([str(claude), "--version"], text=True).strip(),
              "source_capture": "native_claude_hooks_and_chromium", "native_sensor": "disabled",
              "process_sampling": "launch"}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"run_id": run, "agent_calls": len(call_ids), "browser_operations": len(native), "graph_errors": graph["error_count"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--agentprov", required=True, type=Path)
    parser.add_argument("--claude", required=True, type=Path)
    parser.add_argument("--capture", choices=("basic", "detailed"), default="detailed")
    args = parser.parse_args()
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    server = ThreadingHTTPServer(("127.0.0.1", 0), AgentHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        accept(args, out, "http://127.0.0.1:" + str(server.server_port))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == "__main__":
    main()
