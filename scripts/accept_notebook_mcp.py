#!/usr/bin/env python3
"""Exercise the optional Notebook MCP entry through the official stdio client.

Install python/notebook-requirements.txt and set PYTHONPATH=python. The fixture
owns a new output directory and its kernel; it does not call a language model.
"""

import argparse
import asyncio
import json
import os
import pathlib
import sys


async def accept(out):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    out.mkdir(mode=0o700)
    work = out / "work"
    work.mkdir()
    (work / "input.csv").write_text("category,value\nalpha,10\nbeta,20\nalpha,30\n")
    params = StdioServerParameters(command=sys.executable, args=["-m", "agentprov.notebook_mcp",
        "--workdir", str(work), "--capture-dir", str(out / "captures"),
        "--producer-id", "mcp-fixture", "--namespace", "acceptance", "--instance-id", "local",
        "--generation", "first", "--notebook-id", "analysis"],
        env={**os.environ, "NOTEBOOK_SECRET_CANARY": "not-for-the-kernel"})
    results = []
    with (out / "server.log").open("w") as log:
        async with stdio_client(params, errlog=log) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = await client.list_tools()
                if {t.name for t in tools.tools} != {"notebook_execute", "notebook_result", "notebook_restart"}:
                    raise AssertionError("unexpected tool inventory")
                if any(t.output_schema is None for t in tools.tools):
                    raise AssertionError("structured tool output schema missing")

                async def call(name, **arguments):
                    result = await client.call_tool(name, arguments)
                    if result.is_error:
                        raise AssertionError(str(result.content))
                    value = result.structured_content
                    if not isinstance(value, dict):
                        raise AssertionError("native structured result missing")
                    results.append({"tool": name, "arguments": arguments, "result": value})
                    return value

                first = await call("notebook_execute", code="""import csv, json, os, threading, time
from pathlib import Path
assert 'NOTEBOOK_SECRET_CANARY' not in os.environ
rows = list(csv.DictReader(open('input.csv')))
totals = {}
for row in rows:
    totals[row['category']] = totals.get(row['category'], 0) + int(row['value'])
def later():
    time.sleep(1)
    print('LATE_ORIGINAL_REQUEST', flush=True)
threading.Thread(target=later, daemon=True).start()
print(totals)
""")
                second = await call("notebook_execute", code="Path('result.json').write_text(json.dumps(totals, sort_keys=True)); print('FILE_WRITTEN')")
                if first["execution_status"] != "ok" or second["execution_status"] != "ok":
                    raise AssertionError("native task failed")
                timeout = await call("notebook_execute", timeout_seconds=0.1,
                                     code="with open('counter', 'a') as f: f.write('once\\n')\ntime.sleep(0.7)\nprint('FINISHED_ONCE')")
                if timeout["execution_status"] != "unknown":
                    raise AssertionError("timeout fabricated a terminal outcome")
                await asyncio.sleep(1.2)
                late = await call("notebook_result", message_id=first["notebook_request"]["message_id"])
                completed = await call("notebook_result", message_id=timeout["notebook_request"]["message_id"])
                if not any("LATE_ORIGINAL_REQUEST" in x["text"] for x in late["outputs"]):
                    raise AssertionError("background output lost its native request")
                if completed["execution_status"] != "ok" or (work / "counter").read_text() != "once\n":
                    raise AssertionError("request lookup repeated or lost the original execution")
                restarted = await call("notebook_restart")
                after = await call("notebook_execute", code="assert 'totals' not in globals(); print('FRESH_KERNEL')")
                if restarted["scope"]["kernel_session_id"] == first["notebook_request"]["scope"]["kernel_session_id"] or after["execution_status"] != "ok":
                    raise AssertionError("kernel restart reused state or identity")
    if json.loads((work / "result.json").read_text()) != {"alpha": 40, "beta": 20}:
        raise AssertionError("output artifact has wrong totals")
    captures = sorted((out / "captures").glob("*.jsonl"))
    if len(captures) != 2:
        raise AssertionError("expected two kernel captures")
    messages = [json.loads(line) for p in captures for line in p.read_text().splitlines()]
    sent = [v["message"]["header"]["msg_id"] for v in messages if v.get("direction") == "send"]
    expected = [r["result"]["notebook_request"]["message_id"] for r in results if r["tool"] == "notebook_execute"]
    if sorted(sent) != sorted(expected) or len(set(sent)) != 4:
        raise AssertionError("native captures differ from tool references")
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"requests": len(sent), "kernels": len(captures), "totals": {"alpha": 40, "beta": 20},
                      "late_output": True, "timeout_poll_without_retry": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    asyncio.run(accept(pathlib.Path(args.output).absolute()))


if __name__ == "__main__":
    main()
