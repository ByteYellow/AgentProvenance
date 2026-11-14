#!/usr/bin/env python3
"""Run a real Claude Bash task through a configured remote execution route.

Provision input.csv in the executor workdir with team/amount rows alpha/10,
beta/20, alpha/30. Enable native capture and file_diff on an isolated executor.
The caller needs Claude Code 2.1.295+, configured provider access, and Python 3.
Use verify after stopping the executor to check the saved evidence independently.
"""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import sqlite3
import subprocess
import urllib.error
import urllib.request


EXPECTED = {"alpha": 40, "beta": 20}
PROMPT = (
    "Use only Bash in the configured remote working directory. Read input.csv, "
    "compute amount totals grouped by team using Python, and write totals.json. "
    "Then use a separate Bash call to read totals.json and verify the result. "
    "Report the totals. Do not create agents, install software, use network, "
    "or read any other files. This is a synthetic data analysis task."
)


def load(path):
    return json.loads(pathlib.Path(path).read_text())


def save(path, value):
    pathlib.Path(path).write_text(json.dumps(value, indent=2) + "\n")


def run(argv, **kwargs):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout.strip()


class API:
    def __init__(self, route_path):
        path = pathlib.Path(route_path).resolve()
        self.route = load(path)
        token = pathlib.Path(self.route["token_file"])
        if not token.is_absolute():
            token = path.parent / token
        self.token = token.read_text().strip()
        self.url = self.route["url"].rstrip("/")

    def call(self, method, path, body=None):
        headers = {"Authorization": "Bearer " + self.token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.url + path, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode(),
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)


def validate_reports(reports, hooks):
    identities = set()
    for report in reports:
        attempt = report["attempt"]
        source = attempt["request"]["source"]
        identity = (source["session_id"], source["tool_call_id"])
        matching = [row for row in hooks if row.get("hook_event_name") == "PreToolUse"
                    and row.get("session_id") == identity[0] and row.get("tool_use_id") == identity[1]]
        if len(matching) != 1 or identity in identities:
            raise RuntimeError("native hook identity is missing, duplicated or shared")
        command = attempt["request"]["command"]["argv"]
        if len(command) != 3 or matching[0].get("tool_name") != "Bash" or matching[0].get("tool_input", {}).get("command") != command[2]:
            raise RuntimeError("native Bash command differs from admitted command")
        identities.add(identity)
        if attempt["state"]["execution"] != "succeeded" or attempt["state"]["delivery"] != "acknowledged":
            raise RuntimeError("native execution or signed delivery did not finish")
        capture = report["checkpoint"]["capture_report"]
        progress = capture["scope_progress"]
        if progress["state"] != "settled" or progress["pending"] or capture.get("error"):
            raise RuntimeError("owned capture interval did not settle")
        if progress.get("sampling_gaps", 0) and (
            capture["state"] != "incomplete" or "scope_state_sampling_gap" not in capture["issues"]
        ):
            raise RuntimeError("sampling gaps disappeared from the report")
    cgroups = [report["checkpoint"]["scope"]["cgroup_id"] for report in reports]
    if len(set(cgroups)) != len(cgroups) or any(not value.isdecimal() for value in cgroups):
        raise RuntimeError("independent calls lack distinct native cgroup identities")


def verify_saved(cli, output):
    result = load(output / "result.json")
    data = output / "data"
    artifact_refs, file_events, verified = [], [], []
    with sqlite3.connect((data / "agentprov.db").as_uri() + "?mode=ro", uri=True) as db:
        def object_payload(run_id, ref):
            row = db.execute("SELECT path FROM provenance_objects WHERE run_id=? AND hash=?", (run_id, ref)).fetchone()
            if row is None:
                raise RuntimeError("received evidence object is missing")
            raw = pathlib.Path(row[0]).read_bytes()
            if "sha256:" + hashlib.sha256(raw).hexdigest() != ref:
                raise RuntimeError("received evidence digest mismatch")
            return json.loads(raw)["payload"]

        for report in result["reports"]:
            attempt = report["attempt"]
            run_id = attempt["local_run_id"]
            checkpoint = object_payload(run_id, report["checkpoint_ref"])
            if checkpoint["capture_report"] != report["checkpoint"]["capture_report"]:
                raise RuntimeError("signed capture report differs from the execution API")
            verification = json.loads(run([str(cli), "--data-dir", str(data), "graph", "verify", "--run", run_id, "--json"]))
            verified.append(verification)
            events = db.execute("SELECT id,cgroup_id,payload FROM events WHERE run_id=? AND source='agentprov_ebpf' AND event_type='file_write'", (run_id,)).fetchall()
            for event_id, cgroup, payload in events:
                event = json.loads(payload)
                raw = (event.get("payload") or {}).get("raw") or {}
                path = raw.get("path") or ""
                if pathlib.PurePosixPath(path).name == "totals.json":
                    if str(cgroup) != checkpoint["scope"]["cgroup_id"]:
                        raise RuntimeError("native artifact event belongs to another scope")
                    file_events.append({"run_id": run_id, "event_id": event_id, "cgroup_id": cgroup})
            capture = (checkpoint.get("result") or {}).get("artifact_capture") or {}
            for artifact in capture.get("files") or []:
                if artifact["path"] != "totals.json":
                    continue
                manifest = object_payload(run_id, artifact["content_ref"])["text_manifest"]
                body = "".join(object_payload(run_id, chunk["ref"])["content"] for chunk in manifest["chunks"])
                if hashlib.sha256(body.encode()).hexdigest() != manifest["sha256"] or json.loads(body) != EXPECTED:
                    raise RuntimeError("signed artifact body does not match expected totals")
                artifact_refs.append({"run_id": run_id, "content_ref": artifact["content_ref"], "sha256": manifest["sha256"]})
    if not artifact_refs or not file_events:
        raise RuntimeError("signed output body or native output write is missing")
    return {"status": "passed", "verification": verified, "artifacts": artifact_refs, "native_file_events": file_events}


def execute(args):
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    workdir = output / "workdir"
    workdir.mkdir()
    cli = args.agentprov.resolve()
    api = API(args.route)
    if not api.route.get("file_diff"):
        raise RuntimeError("acceptance requires file_diff=true in the isolated task route")
    argv = [str(cli), "--data-dir", str(output / "data"), "launch", "--sensor", "off", "--no-dashboard", "--json",
            "--workdir", str(workdir), "--remote-execution", str(args.route.resolve()), "--",
            str(args.claude.resolve()), "--setting-sources", "user", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
            "--tools", "Bash", "--allowedTools", "Bash(" + str(cli) + " internal remote-command *)",
            "--output-format", "stream-json", "--verbose", "--max-budget-usd", "0.25", "--max-turns", "8", "-p", PROMPT]
    env = dict(os.environ, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", CLAUDE_CODE_MAX_OUTPUT_TOKENS="2000", API_TIMEOUT_MS="90000")
    env.pop("CLAUDECODE", None)
    with (output / "launch.stdout").open("w") as out, (output / "launch.stderr").open("w") as err:
        completed = subprocess.run(argv, cwd=workdir, env=env, stdout=out, stderr=err, timeout=300)
    save(output / "invocation.json", {"exit_code": completed.returncode, "caller_platform": platform.platform(),
                                     "binary_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
                                     "claude_version": run([str(args.claude.resolve()), "--version"])})
    if completed.returncode:
        raise RuntimeError("native launch failed; see retained launch.stdout and launch.stderr")
    admissions = sorted((output / "data/execution-routes").glob("*/*-admission.json"))
    if len(admissions) < 2:
        raise RuntimeError("expected separate analysis and verification native tool calls")
    hooks = []
    for path in (output / "data/logs").glob("*-hooks.jsonl"):
        hooks.extend(json.loads(line) for line in path.read_text().splitlines() if line)
    reports = []
    for path in admissions:
        admission = load(path)
        attempt = admission["attempt"]
        # Replay the exact request. A fresh operation would be a new execution.
        replay = api.call("POST", "/v1/executions", attempt["request"])
        if replay["attempt"]["id"] != attempt["id"] or replay["attempt"]["local_run_id"] != attempt["local_run_id"]:
            raise RuntimeError("transport replay created another execution")
        reports.append(api.call("GET", "/v1/executions/" + attempt["id"]))
    validate_reports(reports, hooks)
    if (workdir / "totals.json").exists():
        raise RuntimeError("remote artifact unexpectedly appeared in the caller workspace")
    save(output / "result.json", {"status": "passed", "reports": reports, "native_hook_events": len(hooks),
                                  "checks": ["native_session_and_tool", "independent_cgroups", "settled_capture",
                                             "transport_replay", "signed_delivery", "caller_workspace_separation"]})
    save(output / "saved-evidence.json", verify_saved(cli, output))
    print(json.dumps({"status": "passed", "attempts": len(reports), "output": str(output)}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["run", "verify"])
    parser.add_argument("--agentprov", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--claude", type=pathlib.Path)
    parser.add_argument("--route", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.phase == "run":
        if args.claude is None:
            parser.error("run requires --claude")
        execute(args)
    else:
        api = API(args.route)
        try:
            api.call("GET", "/v1/ready")
        except urllib.error.HTTPError:
            raise RuntimeError("executor endpoint still responds; stop it before offline verification")
        except (urllib.error.URLError, TimeoutError):
            pass
        else:
            raise RuntimeError("executor is still running; stop it before offline verification")
        output = args.output.resolve()
        result = verify_saved(args.agentprov.resolve(), output)
        result["executor_unavailable"] = True
        save(output / "offline.json", result)
        print(json.dumps({"status": "passed", "output": str(output / "offline.json")}))


if __name__ == "__main__":
    main()
