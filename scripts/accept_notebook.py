#!/usr/bin/env python3
"""Exercise native Jupyter requests, late output, two clients and a kernel restart.

Run in a dedicated Python environment with jupyter-client==8.6.3 and
ipykernel==6.29.5. PYTHONPATH must include this repository's python directory.
Creates only a new output directory and owns/stops its kernel.
"""

import argparse
import json
import os
import pathlib
import queue
import subprocess
import time

import ipykernel
import jupyter_client
from jupyter_client import KernelManager
from jupyter_client.session import Session

from agentprov.notebook import Recorder


def request(client, recorder, code):
    msg = client.session.msg("execute_request", content={"code": code, "silent": False,
        "store_history": True, "user_expressions": {}, "allow_stdin": False, "stop_on_error": True})
    client.shell_channel.send(msg)
    recorder.record("shell", "send", msg)
    return {"session": msg["header"]["session"], "msg_id": msg["header"]["msg_id"]}


def collect(observer, clients, recorder, requests, required_text=()):
    replies, idle, messages = {}, set(), []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for client in clients:
            try:
                msg = client.get_shell_msg(timeout=0.01)
            except queue.Empty:
                continue
            recorder.record("shell", "receive", msg)
            messages.append(msg)
            if msg["header"]["msg_type"] == "execute_reply":
                replies[msg["parent_header"]["msg_id"]] = msg["content"]["status"]
        try:
            msg = observer.get_iopub_msg(timeout=0.02)
        except queue.Empty:
            msg = None
        if msg is not None:
            recorder.record("iopub", "receive", msg)
            messages.append(msg)
            if msg["header"]["msg_type"] == "status" and msg["content"].get("execution_state") == "idle":
                idle.add(msg["parent_header"].get("msg_id"))
        texts = "".join(m["content"].get("text", "") for m in messages)
        if all(r["msg_id"] in replies and r["msg_id"] in idle for r in requests) and all(x in texts for x in required_text):
            if any(replies[r["msg_id"]] != "ok" for r in requests):
                raise AssertionError("native kernel returned a failed execution")
            return messages
    raise TimeoutError("native replies, idle, or expected output missing")


def verify_store(binary, out, capture):
    environment = {**os.environ, "AGENTPROV_DAEMON_URL": "", "AGENTPROV_LANG": "en"}
    root = out / "cli"
    root.mkdir(mode=0o700)
    results, identities = {}, {}

    def command(data, *args, structured=True):
        completed = subprocess.run([binary, "--data-dir", str(data), "--lang", "en", *map(str, args)],
                                   capture_output=True, text=True, timeout=60, env=environment)
        if completed.returncode:
            raise AssertionError(f"CLI failed ({completed.returncode}): {args}\n{completed.stderr}")
        return json.loads(completed.stdout) if structured else completed.stdout

    private, public = root / "signing.key", root / "signing.pub"
    command(root / "key-store", "forensics", "keygen", "--priv", private, "--pub", public, structured=False)
    for preset in ("basic", "detailed"):
        data, replay, run = root / preset, root / (preset + "-replay"), "notebook-" + preset
        for filename in ("first.jsonl", "restarted.jsonl"):
            args = ("context", "import", "--run", run, "--harness", "jupyter", "--file", out / filename, "--capture", preset)
            imported = command(data, *args)
            repeated = command(data, *args)
            if imported["stored"] == 0 or repeated["stored"] != 0 or repeated["duplicates"] != imported["stored"]:
                raise AssertionError("native capture import was not idempotent")
        command(data, "context", "project", "--run", run)
        page = command(data, "context", "list", "--run", run, "--limit", "200")
        if page.get("has_more"):
            raise AssertionError("fixture unexpectedly exceeds a context page")
        entries = page["entries"]
        calls = [e for e in entries if e["kind"] == "tool_call"]
        if len(calls) != 3 or len({e["source"]["session_id"] for e in calls}) != 2:
            raise AssertionError("native requests or kernel lifetimes were merged")
        by_native = {(e["notebook"]["message_session"], e["notebook"]["message_id"]): e for e in calls}
        requests = [*capture["requests"], capture["restarted_request"]]
        if set(by_native) != {(r["session"], r["msg_id"]) for r in requests}:
            raise AssertionError("import changed native request identities")
        parents = []
        late = []
        replies = []
        for entry in entries:
            if entry["kind"] != "tool_result":
                continue
            native = entry["notebook"]
            parent = by_native[(native["parent_session"], native["parent_message_id"])]
            if entry["tool_call_id"] != parent["tool_call_id"]:
                raise AssertionError("output associated with another native request")
            links = command(data, "context", "links", "--run", run, "--entry", entry["id"])
            if len(links["links"]) != 1:
                raise AssertionError("output graph reference is missing")
            parents.append((native["message_id"], entry["tool_call_id"]))
            if native["message_type"] == "execute_reply":
                replies.append(entry)
            if native["message_id"] in capture["late_output_ids"]:
                late.append(entry)
            state = entry["content"]["state"]
            if state != ("omitted" if preset == "basic" else "stored"):
                raise AssertionError("capture preset changed output retention")
        if len(replies) != 3 or any(e["status"] != "returned" for e in replies):
            raise AssertionError("native execution outcomes changed")
        first_request = capture["requests"][0]
        first_call = by_native[(first_request["session"], first_request["msg_id"])]
        if not late or any(e["tool_call_id"] != first_call["tool_call_id"] for e in late):
            raise AssertionError("late background output lost its original request")
        identities[preset] = sorted(parents)
        bundle = command(data, "forensics", "export", run, "--sign-key", private, "--json")
        if not bundle["signed"]:
            raise AssertionError("bundle was not signed")
        command(data, "forensics", "verify-attestation", bundle["path"], bundle["attestation_path"],
                "--pub-key", public, structured=False)
        command(replay, "forensics", "import", bundle["path"], "--pub-key", public, "--json")
        data.rename(data.with_name(data.name + "-unavailable"))
        restored = command(replay, "context", "list", "--run", run, "--limit", "200")
        if restored["entries"] != entries:
            raise AssertionError("signed round trip changed native context")
        if preset == "detailed":
            for entry in late:
                text = command(replay, "context", "content", "--run", run, "--ref", entry["content"]["ref"])
                if "LATE_A" not in text["content"]:
                    raise AssertionError("late output body unavailable after source-store removal")
        graph = command(replay, "graph", "verify", "--run", run, "--json")
        if graph["error_count"] or graph["warning_count"]:
            raise AssertionError("replayed graph verification failed")
        results[preset] = {"entries": len(entries), "requests": len(calls), "native_parent_outputs": len(parents),
                           "late_outputs": len(late), "bundle_sha256": bundle["sha256"], "graph": graph}
    if identities["basic"] != identities["detailed"]:
        raise AssertionError("capture preset changed native parent relationships")
    (out / "cli-results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--agentprov", help="also verify import, graph projection and signed round trip using this binary")
    args = parser.parse_args()
    out = pathlib.Path(args.output).resolve()
    out.mkdir(mode=0o700)
    manager = KernelManager(kernel_name="python3", connection_file=str(out / "connection.json"))
    clients = []
    manager.start_kernel(cwd=str(out))
    result = {"client_version": jupyter_client.__version__, "kernel_version": ipykernel.__version__}
    try:
        def new_client():
            session = Session(key=manager.session.key, signature_scheme=manager.session.signature_scheme)
            client = manager.client(session=session)
            client.start_channels()
            clients.append(client)
            client.wait_for_ready(timeout=30)
            return client

        a, b = new_client(), new_client()
        if a.session.session == b.session.session:
            raise AssertionError("expected independent frontend sessions")
        info = a.kernel_info(reply=True, timeout=15)
        scope = {"producer_id": "notebook-acceptance", "namespace": "local-fixture", "instance_id": "lab",
                 "generation": "fixture-1", "notebook_id": "csv-analysis", "kernel_id": manager.kernel_id,
                 "kernel_session_id": info["header"]["session"]}
        with Recorder(out / "first.jsonl", scope, client_version=jupyter_client.__version__) as recorder:
            ra = request(a, recorder, "import threading, time\nfrom pathlib import Path\n"
                "def later():\n    while not Path('release').exists(): time.sleep(0.01)\n    print('LATE_A')\n"
                "threading.Thread(target=later, daemon=True).start()\nprint('EARLY_A')")
            first = collect(a, [a], recorder, [ra], ["EARLY_A"])
            rb = request(b, recorder, "from pathlib import Path\nPath('release').write_text('go')\nprint('CLIENT_B')")
            second = collect(a, [a, b], recorder, [rb], ["CLIENT_B", "LATE_A"])
            late = [m for m in second if "LATE_A" in m["content"].get("text", "")]
            if not late or any(m["parent_header"].get("msg_id") != ra["msg_id"] or
                               m["parent_header"].get("session") != ra["session"] for m in late):
                raise AssertionError("tested kernel did not preserve native late-output parent")
            result.update(first_scope=scope, requests=[ra, rb], first_messages=len(first) + len(second),
                          late_output_ids=[m["header"]["msg_id"] for m in late])
        for client in clients:
            client.stop_channels()
        clients.clear()
        manager.restart_kernel(now=True)
        c = new_client()
        info = c.kernel_info(reply=True, timeout=15)
        scope = {**scope, "kernel_session_id": info["header"]["session"]}
        if scope["kernel_session_id"] == result["first_scope"]["kernel_session_id"]:
            raise AssertionError("native kernel restart reused its session")
        with Recorder(out / "restarted.jsonl", scope, client_version=jupyter_client.__version__) as recorder:
            rc = request(c, recorder, "import csv, io, json\nfrom pathlib import Path\n"
                "rows=list(csv.DictReader(io.StringIO('item,value\\na,7\\nb,11\\n')))\n"
                "total=sum(int(r['value']) for r in rows)\nPath('result.json').write_text(json.dumps({'total':total}))\nprint('TOTAL', total)")
            after = collect(c, [c], recorder, [rc], ["TOTAL 18"])
            if json.loads((out / "result.json").read_text()) != {"total": 18}:
                raise AssertionError("data-analysis artifact differs")
            result.update(restarted_scope=scope, restarted_request=rc, restarted_messages=len(after))
        (out / "result-manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    finally:
        for client in clients:
            client.stop_channels()
        manager.shutdown_kernel(now=True)
        manager.cleanup_resources()
    if args.agentprov:
        verify_store(str(pathlib.Path(args.agentprov).resolve()), out, result)


if __name__ == "__main__":
    main()
