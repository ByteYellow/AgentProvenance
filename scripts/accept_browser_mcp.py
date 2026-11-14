#!/usr/bin/env python3
"""Exercise the recorded Browser entry through an actual stdio MCP client.

Requires python/browser-requirements.txt and its Chromium build. Uses an owned
browser and a loopback fixture; no model key or external website is required.
"""

import argparse
import asyncio
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import time

from accept_browser import Handler, SECRET


class MCPHandler(Handler):
    slow_requests = 0

    def do_GET(self):
        if self.path == "/slow":
            type(self).slow_requests += 1
            time.sleep(.7)
        super().do_GET()


async def accept(out, origin):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "agentprov.browser_mcp",
        "--capture-dir", str(out / "captures"), "--producer-id", "mcp-fixture", "--namespace", "acceptance",
        "--instance-id", "local", "--generation", "first"], env=dict(os.environ))
    results = []
    with (out / "server.log").open("w") as log:
        async with stdio_client(params, errlog=log) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                inventory = await client.list_tools()
                if {t.name for t in inventory.tools} != {"browser_pages", "browser_new_page", "browser_execute", "browser_result"}:
                    raise AssertionError("unexpected tool inventory")
                if any(t.output_schema is None for t in inventory.tools):
                    raise AssertionError("structured tool result schema missing")

                async def call(name, **arguments):
                    result = await client.call_tool(name, arguments)
                    if result.is_error or not isinstance(result.structured_content, dict):
                        raise AssertionError(str(result.content))
                    value = result.structured_content
                    results.append({"tool": name, "arguments": arguments, "result": value})
                    return value

                pages = await call("browser_pages")
                a, b = pages["default_page_id"], (await call("browser_new_page"))["page_id"]
                first, second = await asyncio.gather(
                    call("browser_execute", page_id=a, action="navigate", value=origin + "/redirect"),
                    call("browser_execute", page_id=b, action="navigate", value=origin + "/redirect"))
                if first["execution_status"] != "ok" or second["execution_status"] != "ok":
                    raise AssertionError("parallel page navigation failed")
                text = await call("browser_execute", page_id=a, action="read_text")
                if "BROWSER_EVIDENCE_OK" not in text["output"].get("text", ""):
                    raise AssertionError("real page text missing")
                image = await call("browser_execute", page_id=a, action="screenshot")
                if image["execution_status"] != "ok" or image["output"].get("bytes", 0) <= 0:
                    raise AssertionError("real screenshot missing")
                await call("browser_execute", page_id=a, action="click", value="#run")
                slow = await call("browser_execute", page_id=b, action="navigate", value=origin + "/slow", timeout_seconds=.1)
                if slow["execution_status"] != "unknown" or slow["waiting_state"] != "pending":
                    raise AssertionError("waiting timeout became a terminal operation")
                operation = slow["browser_operation"]["operation_id"]
                for _ in range(100):
                    settled = await call("browser_result", operation_id=operation)
                    if settled["waiting_state"] == "settled":
                        break
                    await asyncio.sleep(.1)
                if settled["execution_status"] != "ok" or MCPHandler.slow_requests != 1:
                    raise AssertionError("poll repeated or lost the original navigation")
    rows = [json.loads(line) for line in (out / "captures/browser.jsonl").read_text().splitlines()]
    operations = [r for r in rows if r.get("kind") == "action_start"]
    refs = [r["result"]["browser_operation"] for r in results if r["tool"] == "browser_execute"]
    if len(refs) != 6 or {r["operation_id"] for r in refs} != {r["operation_id"] for r in operations}:
        raise AssertionError("captured operation IDs differ from MCP references")
    for ref in refs:
        target = [r for r in operations if r["operation_id"] == ref["operation_id"]]
        if len(target) != 1 or target[0]["target_id"] != ref["target_id"] or target[0]["operation"] != ref["operation"]:
            raise AssertionError("MCP reference changed native page or operation")
        if any(rows[0][k] != v for k, v in ref["scope"].items()):
            raise AssertionError("MCP reference changed native browser context")
    requests = [r for r in rows if r.get("kind") == "request"]
    if any(r.get("operation_id") for r in requests):
        raise AssertionError("background request borrowed a tool operation")
    if any(r.get("kind") == "gap" for r in rows) or not any(r.get("kind") == "har" for r in rows):
        raise AssertionError("capture incomplete or close archive missing")
    if SECRET in (out / "captures/browser.jsonl").read_text():
        raise AssertionError("private transport data reached capture")
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"operations": len(operations), "requests": len(requests), "pages": [a, b],
                      "timeout_poll_without_retry": True, "har": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    out = Path(parser.parse_args().output).absolute()
    out.mkdir(mode=0o700)
    server = ThreadingHTTPServer(("127.0.0.1", 0), MCPHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        asyncio.run(accept(out, "http://127.0.0.1:" + str(server.server_port)))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == "__main__":
    main()
