#!/usr/bin/env python3
"""Owned Chromium contexts, durable receipts and real Linux Sensor custody.

Run as root on the Linux host with --browser-user selecting an unprivileged
operator account. All changes stay in a new output directory and an owned record
cgroup. This fixture never changes the host's sandbox policy or installs software.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

from accept_browser import Handler


def save(path, value):
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


class SlowHandler(Handler):
    posts = 0

    def do_POST(self):
        type(self).posts += 1
        super().do_POST()

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(2)
        try:
            super().do_GET()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def browser_case(args):
    from agentprov.browser_custody import NativeCustody
    from agentprov.browser_mcp import BrowserRuntime
    output = args.output
    placement = {"producer_id": "browser-native-acceptance", "namespace": "owned",
                 "instance_id": "local-fixture", "generation": "generation-1"}
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = "http://127.0.0.1:" + str(server.server_port)
    runtimes, records = [], []

    async def create(label, generation):
        p = dict(placement, generation=generation)
        runtime = BrowserRuntime(output / ("capture-" + label), p,
                                 custody=NativeCustody(output / "operator", output / "data", args.run))
        runtimes.append(runtime)
        await runtime.start()
        return runtime

    try:
        a, b = await create("a", "generation-1"), await create("b", "generation-1")
        pages = [(a, a.browser.first_page), (a, (await a.new_page())["page_id"]), (b, b.browser.first_page)]
        results = await asyncio.gather(*(r.execute(p, "navigate", origin + "/redirect") for r, p in pages))
        records.extend(results)
        for runtime, page in pages:
            await runtime.browser.pages[page].wait_for_function("window.workerReady === true", timeout=20000)
        records.extend(await asyncio.gather(*(r.execute(p, "click", "#run") for r, p in pages)))
        for runtime, page in pages:
            await runtime.browser.pages[page].wait_for_function("window.backgroundDone === true", timeout=20000)
        records.append(await a.execute(pages[0][1], "read_text"))
        records.append(await a.execute(pages[0][1], "click", "#download"))
        for _ in range(100):
            if any(json.loads(line).get("kind") == "download_finished" for line in a.browser.path.read_text().splitlines()):
                break
            await asyncio.sleep(.1)
        else:
            raise AssertionError("native download completion missing")
        try:
            await a.execute(b.browser.first_page, "read_text")
        except ValueError:
            pass
        else:
            raise AssertionError("cross-context page accepted")
        settled = results[0]["browser_operation"]["operation_id"]
        slow = await a.execute(a.browser.first_page, "navigate", origin + "/slow", timeout_seconds=.1)
        assert slow["waiting_state"] == "pending"
        slow_id = slow["browser_operation"]["operation_id"]
        await a.close()
        await b.close()
        before = SlowHandler.posts
        reopened = await create("a", "generation-2")
        for _ in range(3):
            assert reopened.result(settled)["execution_status"] == "ok"
            assert reopened.result(slow_id)["execution_status"] == "unknown"
        assert SlowHandler.posts == before, "query replayed browser activity"
        records.append(await reopened.execute(reopened.browser.first_page, "navigate", origin + "/redirect"))
        await reopened.close()
        report = {"status": "passed", "run_id": args.run,
                  "cases": ["parallel_contexts", "parallel_tabs", "redirect", "iframe", "worker", "background",
                            "download", "wrong_context_rejected", "pending_receipt", "restart_query_without_reexecute"],
                  "results": records, "pending_operation": slow_id, "post_requests_before_query": before,
                  "post_requests_after_query": SlowHandler.posts,
                  "custody_reports": [str(r.custody.output / "report.json") for r in runtimes]}
        for runtime in runtimes:
            custody = json.loads((runtime.custody.output / "report.json").read_text())
            assert custody["native"] == "supported", "missing live native process identity"
        save(output / "browser-result.json", report)
    finally:
        for runtime in reversed(runtimes):
            await runtime.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def acceptance(args):
    if os.geteuid() != 0:
        raise RuntimeError("native Browser fixture requires root for Sensor and cgroup setup")
    user = pwd.getpwnam(args.browser_user)
    if user.pw_uid == 0:
        raise RuntimeError("Chromium must run as an unprivileged operator")
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    os.chown(output, user.pw_uid, user.pw_gid)
    work = output / "work"
    work.mkdir()
    os.chown(work, user.pw_uid, user.pw_gid)
    data = output / "data"
    binary = args.agentprov.resolve(strict=True)
    env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR") if k in os.environ}
    env.update(AGENTPROV_DAEMON_URL="", AGENTPROV_LANG="en")
    report = {"status": "failed", "run_id": args.run, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    stdout = (output / "sensor.stdout").open("x")
    stderr = (output / "sensor.stderr").open("x")
    collector = subprocess.Popen([str(binary), "--data-dir", str(data), "sensor", "stream", "--no-policy",
        "--placement", "guest_kernel", "--auto-tls=false", "--apparmor-state=false", "--seccomp-state=false",
        "--ring-buffer-mib", "8", "--flush-interval", "100ms", "--pending-ttl", "1ms"],
        stdout=stdout, stderr=stderr, env=env)
    try:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if collector.poll() is not None:
                raise RuntimeError("collector exited before readiness")
            if "agentprov sensor stream: ready probes-attached" in (output / "sensor.stderr").read_text():
                break
            time.sleep(.1)
        else:
            raise RuntimeError("collector readiness timeout")
        report["sensor_ready"] = json.loads(subprocess.check_output([str(binary), "--data-dir", str(data), "sensor", "status", "--json"], env=env))
        for path in [data, *data.rglob("*")]:
            os.chown(path, user.pw_uid, user.pw_gid, follow_symlinks=False)
        child = ["runuser", "-u", args.browser_user, "--", "env", "PYTHONPATH=" + str(args.python_package.resolve()),
                 "PLAYWRIGHT_BROWSERS_PATH=" + str(args.browsers.resolve()), sys.executable, str(Path(__file__).resolve()),
                 "--worker", "--output", str(output), "--run", args.run]
        with (output / "record.json").open("x") as out, (output / "record.stderr").open("x") as err:
            result = subprocess.run([str(binary), "--data-dir", str(data), "record", "--run", args.run,
                                     "--workdir", str(work), "--json", "--", *child], env=env, stdout=out, stderr=err, timeout=240)
        report["record_exit"] = result.returncode
        record = json.loads((output / "record.json").read_text())
        if result.returncode or record.get("exit_code") != 0:
            raise RuntimeError("Browser record failed; inspect private record.stderr")
        report["browser"] = json.loads((output / "browser-result.json").read_text())
        report["status"] = "passed"
    except BaseException as error:
        report["error_type"] = type(error).__name__
        raise
    finally:
        collector.terminate()
        try:
            collector.wait(timeout=45)
        except subprocess.TimeoutExpired:
            collector.kill()
            collector.wait(timeout=5)
            report["status"], report["drain"] = "failed", "timeout"
        stdout.close()
        stderr.close()
        final = json.loads(subprocess.check_output([str(binary), "--data-dir", str(data), "sensor", "status", "--json"], env=env))
        report["sensor_final"], report["collector_exit"] = final, collector.returncode
        capture = final["capture"]
        losses = {k: v for k, v in capture["counters"].items() if v and (k.startswith("dropped_") or k in ("invalid", "failed", "kernel_dropped_events"))}
        if collector.returncode or losses or any(capture[k] for k in ("queued_batches", "queued_bytes", "pending_events", "cleanup_pending_batches")):
            report["status"], report["losses"] = "failed", losses
        save(output / "report.json", report)
        for path in [data, *data.rglob("*")]:
            os.chown(path, user.pw_uid, user.pw_gid, follow_symlinks=False)
    if report["status"] != "passed":
        raise RuntimeError("native Browser acceptance failed")
    print(json.dumps({"status": report["status"], "report": str(output / "report.json")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run", default="browser-native-acceptance")
    parser.add_argument("--agentprov", type=Path)
    parser.add_argument("--browser-user")
    parser.add_argument("--browsers", type=Path)
    parser.add_argument("--python-package", type=Path, default=Path(__file__).resolve().parents[1] / "python")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.worker:
        asyncio.run(browser_case(args))
    else:
        if not all((args.agentprov, args.browser_user, args.browsers)):
            parser.error("--agentprov, --browser-user and --browsers are required")
        acceptance(args)


if __name__ == "__main__":
    main()
