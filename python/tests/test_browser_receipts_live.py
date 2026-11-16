"""Opt-in B-01 acceptance through real stdio MCP and owned Chromium.

Install python/browser-requirements.txt and Playwright Chromium first. Then run:
PYTHONPATH=python python3 python/tests/test_browser_receipts_live.py --output DIR

Uses only a loopback HTTP fixture. Kills its own first bridge process after a
durable admission, then queries both operations in a new bridge generation.
"""

import argparse
import asyncio
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import threading
import unittest


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path in ("/complete", "/pending"):
            with self.server.count_lock:
                self.server.counts[self.path] += 1
            self.server.seen[self.path].set()
        if self.path == "/pending":
            self.server.release.wait(60)
        data = b'<html><body><button id="once" onclick="location.href=\'/complete\'">Submit once</button></body></html>'
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


async def live_acceptance(directory, channel=None, *, custody_dir=None, native_data_dir=None, run_id=None):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700)
    capture = directory / "capture"
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    server.count_lock = threading.Lock()
    server.counts = {"/complete": 0, "/pending": 0}
    server.seen = {path: threading.Event() for path in server.counts}
    server.release = threading.Event()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = "http://127.0.0.1:" + str(server.server_port)
    observations = []
    report = {"passed": False, "transport": "real stdio MCP and owned Chromium", "sensor": "off"}
    if custody_dir:
        assert native_data_dir and run_id and channel is None
        custody_dir = Path(custody_dir)
        report["sensor"] = "native_owned_launcher"

    @contextlib.asynccontextmanager
    async def bridge(generation):
        pid_file = directory / (generation + ".pid")
        arguments = [str(Path(__file__).resolve()), "--bridge-worker", "--pid-file", str(pid_file),
                     "--capture-dir", str(capture), "--producer-id", "b01-live", "--namespace", "acceptance",
                     "--instance-id", "owned", "--generation", generation, "--no-screenshots", "--no-har"]
        if channel:
            arguments += ["--channel", channel]
        if custody_dir:
            arguments += ["--custody-dir", str(custody_dir), "--native-data-dir", str(native_data_dir), "--run", run_id]
        parameters = StdioServerParameters(command=sys.executable, args=arguments, env=dict(os.environ))
        with (directory / (generation + ".log")).open("w") as log:
            async with stdio_client(parameters, errlog=log) as (read, write):
                async with ClientSession(read, write) as client:
                    try:
                        await client.initialize()
                    except BaseException as error:
                        # This fixture uses synthetic loopback pages and no
                        # credentials. Preserve the child startup cause instead
                        # of reporting only an MCP "Connection closed" wrapper.
                        log.flush()
                        detail = (directory / (generation + ".log")).read_bytes()[-4096:].decode("utf-8", "replace")
                        error.add_note("Browser fixture " + generation + " startup diagnostics:\n" + detail)
                        raise
                    yield client, int(pid_file.read_text())

    async def call(client, tool, **arguments):
        answer = await client.call_tool(tool, arguments)
        if answer.is_error or not isinstance(answer.structured_content, dict):
            raise AssertionError("MCP fixture call failed: " + tool)
        value = answer.structured_content
        observations.append({"tool": tool, "result": value})
        return value

    def action_count():
        return sum(json.loads(line).get("kind") == "action_start"
                   for path in capture.glob("browser*.jsonl") for line in path.read_text().splitlines())

    async def wait_native(client, page, generation):
        if not custody_dir:
            return
        for _ in range(40):
            if any(json.loads(p.read_text())["scope"]["generation"] == generation
                   for p in custody_dir.glob("*/launch-witness.json")):
                return
            await asyncio.sleep(.25)
            await call(client, "browser_execute", page_id=page, action="read_text")
        raise AssertionError("native launch evidence missing: " + generation)

    try:
        killed = False
        try:
            async with bridge("first") as (client, pid):
                inventory = await client.list_tools()
                assert {tool.name for tool in inventory.tools} == {
                    "browser_pages", "browser_new_page", "browser_execute", "browser_result"}
                page = (await call(client, "browser_pages"))["default_page_id"]
                navigation = await call(client, "browser_execute", page_id=page, action="navigate", value=origin)
                assert navigation["execution_status"] == "ok"
                completed = await call(client, "browser_execute", page_id=page, action="click", value="#once")
                assert completed["execution_status"] == "ok"
                assert await asyncio.to_thread(server.seen["/complete"].wait, 5)
                await wait_native(client, page, "first")
                pending = await call(client, "browser_execute", page_id=page, action="navigate",
                                     value=origin + "/pending", timeout_seconds=.1)
                assert pending["execution_status"] == "unknown" and pending["waiting_state"] == "pending"
                assert await asyncio.to_thread(server.seen["/pending"].wait, 5)
                assert pending["browser_receipt"]["source_refs"]["accept"]
                os.kill(pid, signal.SIGKILL)
                killed = True
        except Exception:
            if not killed:
                raise
        finally:
            server.release.set()
        before = action_count()
        async with bridge("second") as (client, _):
            pages = await call(client, "browser_pages")
            assert pages["scope"]["generation"] == "second"
            for original, status in ((completed, "ok"), (pending, "unknown")):
                operation_id = original["browser_operation"]["operation_id"]
                for _ in range(3):
                    restored = await call(client, "browser_result", operation_id=operation_id)
                    assert restored["execution_status"] == status
                    assert restored["waiting_state"] == "settled"
                    assert restored["browser_operation"] == original["browser_operation"]
                    assert restored["browser_receipt"]["bridge_identity"]["authentication"] == "unverified"
            assert action_count() == before
            assert server.counts == {"/complete": 1, "/pending": 1}
            new = await call(client, "browser_execute", page_id=pages["default_page_id"], action="navigate", value=origin)
            assert new["execution_status"] == "ok"
            assert new["browser_operation"]["scope"]["generation"] == "second"
            await wait_native(client, pages["default_page_id"], "second")
        if custody_dir:
            launches = [json.loads(p.read_text()) for p in custody_dir.glob("*/launch-witness.json")]
            assert len(launches) == 2
            assert {p["scope"]["generation"] for p in launches} == {"first", "second"}
            assert len({p["process_instance_id"] for p in launches}) == 2
            sealed = [json.loads(p.read_text()) for p in custody_dir.glob("*/report.json")]
            assert len(sealed) == 1 and sealed[0]["scope"]["generation"] == "second"
            assert sealed[0]["native"] == "supported"
            manifests = [json.loads(p.read_text()) for p in capture.glob("owned-*.json")]
            assert len(manifests) == 1 and manifests[0]["placement"]["generation"] == "second"
            report["custody"] = {"observed_launches": launches, "sealed_generations": ["second"],
                                 "interrupted_generation": "first", "interrupted_capture": "unsealed"}
        report.update(passed=True, original_actions=before, actions_after_queries=before,
                      total_actions=action_count(), side_effect_counts=dict(server.counts),
                      completed_status="ok", interrupted_status="unknown", old_generation="first", new_generation="second")
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        worker.join()
        report["observations"] = observations
        (directory / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


class LiveReceiptTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(os.environ.get("AGENTPROV_BROWSER_LIVE_OUTPUT"), "opt-in Chromium/MCP acceptance")
    async def test_live_bridge_restart(self):
        report = await live_acceptance(os.environ["AGENTPROV_BROWSER_LIVE_OUTPUT"])
        self.assertTrue(report["passed"])


if __name__ == "__main__":
    if "--bridge-worker" in sys.argv:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--bridge-worker", action="store_true")
        parser.add_argument("--pid-file", required=True)
        arguments, remaining = parser.parse_known_args()
        Path(arguments.pid_file).write_text(str(os.getpid()))
        sys.argv = [sys.argv[0], *remaining]
        from agentprov.browser_mcp import main
        main()
    elif "--output" in sys.argv:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--output", required=True)
        parser.add_argument("--channel")
        arguments = parser.parse_args()
        if any(importlib.util.find_spec(name) is None for name in ("playwright", "websockets", "mcp")):
            parser.error("install python/browser-requirements.txt and Playwright Chromium first")
        result = asyncio.run(live_acceptance(arguments.output, arguments.channel))
        print(json.dumps({k: v for k, v in result.items() if k != "observations"}, indent=2))
    else:
        unittest.main()
