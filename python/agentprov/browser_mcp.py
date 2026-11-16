"""Optional stdio MCP entry for one owned, recorded Chromium context."""

import argparse
import asyncio
import contextlib
import os
from pathlib import Path
import uuid
from typing import Any

from agentprov.browser import Browser, safe_url
from agentprov.browser_receipts import MAX_LOGS, MAX_OUTPUT_BYTES, ReceiptStore, private_directory


RESULT_SCHEMA = "agentprovenance.browser_tool_result/v1"
MAX_OPERATIONS = 1024
MAX_PENDING = 32


class BrowserRuntime:
    def __init__(self, capture_dir, placement, *, screenshots=True, har=True, channel=None):
        self.capture_dir = Path(capture_dir).absolute()
        self.browser = Browser(self.capture_dir / "browser.jsonl", placement,
                               screenshots=screenshots, har=har, channel=channel)
        self.receipts = ReceiptStore(self.capture_dir, placement)
        self.requests = {}
        self.closed = False
        self.lock_file = None

    async def start(self):
        if self.closed or self.lock_file is not None:
            raise RuntimeError("browser runtime already started or closed")
        private_directory(self.capture_dir, create=True)
        # One live owner per journal directory. Readers never take this lock;
        # a crashed writer releases it without a stale PID/lease recovery path.
        import fcntl
        fd = os.open(self.capture_dir / ".bridge.lock", os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.lock_file = os.fdopen(fd, "wb")
        try:
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.receipts.refresh()
            if self.receipts.gap or len(self.receipts.logs) >= MAX_LOGS:
                raise RuntimeError("browser receipt history unavailable")
            if self.browser.path.exists():
                self.browser.path = self.capture_dir / ("browser-" + str(uuid.uuid4()) + ".jsonl")
            await self.browser.start()
        except BaseException:
            await self.close()
            raise

    def pages(self):
        return {"scope": dict(self.browser.capture.scope), "page_ids": list(self.browser.pages),
                "default_page_id": self.browser.first_page}

    async def new_page(self):
        if self.closed:
            raise RuntimeError("browser is closed")
        page = await self.browser.new_page()
        return {"scope": dict(self.browser.capture.scope), "page_id": page}

    async def execute(self, page_id, action, value="", timeout_seconds=30):
        if page_id not in self.browser.pages or action not in ("navigate", "click", "read_text", "screenshot"):
            raise ValueError("unknown browser page or action")
        if not isinstance(value, str) or len(value.encode("utf-8")) > 16384 or (action == "navigate" and not safe_url(value)):
            raise ValueError("invalid browser action value")
        if not 0.1 <= timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be between 0.1 and 60")
        if self.closed or self.browser.failure or self.browser.capture is None or self.browser.capture.stopped:
            raise RuntimeError("browser capture is not ready")
        if len(self.requests) >= MAX_OPERATIONS or sum(not r["task"].done() for r in self.requests.values()) >= MAX_PENDING:
            raise RuntimeError("browser operation budget exceeded")
        operation_id = str(uuid.uuid4())
        request = {"reference": {"scope": dict(self.browser.capture.scope), "target_id": page_id,
                                  "operation_id": operation_id, "operation": action},
                   "status": "unknown", "output": {}, "output_truncated": False}
        # Admission must reach stable storage before scheduling any browser work.
        self.receipts.accept(self.browser.capture, page_id, action, value, operation_id)
        task = asyncio.create_task(self._execute(request, value))
        request["task"] = task
        self.requests[operation_id] = request
        # Waiting and execution have separate lifetimes. Poll the returned ID;
        # a timeout or caller cancellation never repeats the browser action.
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout_seconds)
        except TimeoutError:
            pass
        return self._result(request, "execute")

    async def _execute(self, request, value):
        ref = request["reference"]
        try:
            await self.browser.operation(ref["target_id"], ref["operation"], value, operation_id=ref["operation_id"])
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            result = self.receipts.result(ref["operation_id"])
            request["status"], request["output"] = result["execution_status"], result["output"]
            request["output_truncated"] = result["output_truncated"]

    def _result(self, request, operation):
        pending = not request["task"].done()
        result = self.receipts.result(request["reference"]["operation_id"], pending=pending)
        if self.browser.failure or self.browser.capture.stopped:
            result["capture_status"], result["capture_reason"] = "partial", self.browser.failure or "capture_stopped"
        return {"schema_version": RESULT_SCHEMA, "operation": operation, **result,
                "waiting_state": "pending" if pending else "settled"}

    def result(self, operation_id):
        if operation_id not in self.requests:
            return {"schema_version": RESULT_SCHEMA, "operation": "read", **self.receipts.result(operation_id),
                    "waiting_state": "settled"}
        return self._result(self.requests[operation_id], "read")

    async def close(self):
        self.closed = True
        tasks = [r["task"] for r in self.requests.values()]
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await self.browser.close()
        finally:
            if self.lock_file:
                self.lock_file.close()
                self.lock_file = None


def main():
    from mcp.server.mcpserver import Context, MCPServer

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", required=True, help="private capture journal directory; reuse to recover receipts")
    for name in ("producer-id", "namespace", "instance-id", "generation"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--no-screenshots", action="store_true")
    parser.add_argument("--no-har", action="store_true")
    parser.add_argument("--channel", default=None)
    args = parser.parse_args()
    placement = {key: getattr(args, key) for key in ("producer_id", "namespace", "instance_id", "generation")}

    @contextlib.asynccontextmanager
    async def lifespan(_server):
        runtime = BrowserRuntime(args.capture_dir, placement, screenshots=not args.no_screenshots, har=not args.no_har, channel=args.channel)
        try:
            await runtime.start()
            yield runtime
        finally:
            await runtime.close()

    server = MCPServer("AgentProvenance Browser", lifespan=lifespan)

    @server.tool(structured_output=True)
    async def browser_pages(ctx: Context) -> dict[str, Any]:
        """List the owned context's native page IDs and its default page."""
        return ctx.request_context.lifespan_context.pages()

    @server.tool(structured_output=True)
    async def browser_new_page(ctx: Context) -> dict[str, Any]:
        """Create a new blank page in the recorded context."""
        return await ctx.request_context.lifespan_context.new_page()

    @server.tool(structured_output=True)
    async def browser_execute(page_id: str, action: str, ctx: Context, value: str = "", timeout_seconds: float = 30) -> dict[str, Any]:
        """Run navigate (URL), click (selector), read_text or screenshot once. On unknown status, poll browser_result; do not resend."""
        return await ctx.request_context.lifespan_context.execute(page_id, action, value, timeout_seconds)

    @server.tool(structured_output=True)
    async def browser_result(operation_id: str, ctx: Context) -> dict[str, Any]:
        """Read an existing operation without repeating its browser action."""
        return ctx.request_context.lifespan_context.result(operation_id)

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
