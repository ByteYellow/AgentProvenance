"""Optional stdio MCP tools backed by one owned, recorded Jupyter kernel."""

import argparse
import asyncio
import contextlib
import hashlib
import os
import pathlib
import queue
import tempfile
import uuid
from typing import Any

from agentprov.notebook import Recorder


RESULT_SCHEMA = "agentprovenance.notebook_tool_result/v1"
MAX_REQUESTS = 1024
MAX_CODE_BYTES = 256 << 10
MAX_OUTPUT_BYTES = 32 << 10


class NotebookRuntime:
    """Execute once, keep native references, and observe output between tool calls.

    This process is a tool executor, not an isolation boundary. Run it inside
    the selected sandbox. The kernel gets a minimal environment, not MCP/API
    credentials inherited by the tool server.
    """

    def __init__(self, workdir, capture_dir, placement, *, manager_factory=None):
        self.workdir = pathlib.Path(workdir).resolve(strict=True)
        if not self.workdir.is_dir():
            raise ValueError("workdir must be a directory")
        if set(placement) != {"producer_id", "namespace", "instance_id", "generation", "notebook_id"}:
            raise ValueError("invalid notebook placement fields")
        if any(not isinstance(v, str) or not v or v.strip() != v or len(v.encode("utf-8")) > 512
               or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in v) for v in placement.values()):
            raise ValueError("invalid notebook placement identity")
        self.placement = dict(placement)
        self.capture_dir = pathlib.Path(capture_dir).absolute()
        self.manager_factory = manager_factory
        self.manager = self.client = self.recorder = self.resources = None
        self.tasks, self.requests = [], {}
        self.lock = asyncio.Lock()
        self.capture_error = ""
        self.remaining_bytes, self.remaining_messages = 128 << 20, 24998
        self.closed = False
        self.stopping = False

    async def start(self):
        self.capture_dir.mkdir(mode=0o700)
        await self._start_kernel()

    async def _start_kernel(self):
        import jupyter_client
        from jupyter_client import AsyncKernelManager

        if self.remaining_bytes < 8192 or self.remaining_messages < 1:
            raise RuntimeError("notebook capture budget exhausted")
        self.stopping = False
        self.resources = tempfile.TemporaryDirectory(prefix="agentprov-notebook-")
        root = pathlib.Path(self.resources.name)
        self.manager = (self.manager_factory or AsyncKernelManager)(
            kernel_name="python3", connection_file=str(root / "connection.json"))
        environment = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
        environment.update(HOME=str(root), TMPDIR=str(root), IPYTHONDIR=str(root / "ipython"))
        try:
            await self.manager.start_kernel(cwd=str(self.workdir), env=environment)
            self.client = self.manager.client()
            self.client.start_channels()
            await self.client.wait_for_ready(timeout=30)
            info = await self.client.kernel_info(reply=True, timeout=15)
            self.scope = {**self.placement, "kernel_id": self.manager.kernel_id,
                          "kernel_session_id": info["header"]["session"]}
            self.recorder = Recorder(self.capture_dir / (str(uuid.uuid4()) + ".jsonl"), self.scope,
                                     client_version=jupyter_client.__version__,
                                     max_bytes=self.remaining_bytes, max_messages=self.remaining_messages)
            self.tasks = [asyncio.create_task(self._receive(channel)) for channel in ("shell", "iopub")]
        except BaseException:
            await self._stop_kernel()
            raise

    async def _receive(self, channel):
        try:
            while True:
                try:
                    message = await getattr(self.client, "get_" + channel + "_msg")(timeout=0.2)
                except queue.Empty:
                    if not await self.manager.is_alive():
                        if not self.stopping:
                            self._fail_capture("kernel_stopped")
                        return
                    continue
                self.recorder.record(channel, "receive", message)
                parent = message.get("parent_header", {})
                request = self.requests.get(parent.get("msg_id"))
                if request is None or request["reference"]["scope"] != self.scope or parent.get("session") != request["reference"]["message_session"]:
                    continue
                self._observe(request, channel, message)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._fail_capture("channel_recording_failed")

    def _fail_capture(self, reason):
        self.capture_error = reason
        for request in self.requests.values():
            if request["reference"]["scope"] == self.scope:
                request["capture_error"] = reason
                request["changed"].set()

    @staticmethod
    def _observe(request, channel, message):
        kind, content = message["header"]["msg_type"], message.get("content", {})
        if channel == "shell" and kind == "execute_reply":
            status = content.get("status")
            request["status"] = status if status in ("ok", "error", "aborted") else "unknown"
            request["reply"] = True
        if channel == "iopub" and kind == "status" and content.get("execution_state") == "idle":
            request["idle"] = True
        text = ""
        if channel == "iopub":
            if kind == "stream":
                text = content.get("text", "")
            elif kind == "error":
                text = str(content.get("ename", "")) + ": " + str(content.get("evalue", ""))
            elif kind in ("execute_result", "display_data", "update_display_data"):
                text = content.get("data", {}).get("text/plain", "")
        if isinstance(text, str) and text:
            raw = text.encode("utf-8")
            remaining = MAX_OUTPUT_BYTES - request["output_bytes"]
            kept = raw[:remaining].decode("utf-8", errors="ignore")
            if kept and len(request["outputs"]) < 128:
                request["outputs"].append({"message_id": message["header"]["msg_id"],
                                           "type": kind, "text": kept})
                request["output_bytes"] += len(kept.encode("utf-8"))
            if len(raw) > remaining or len(request["outputs"]) >= 128:
                request["output_truncated"] = True
        request["changed"].set()

    async def execute(self, code, timeout_seconds=30):
        if not isinstance(code, str) or not code.strip() or len(code.encode("utf-8")) > MAX_CODE_BYTES:
            raise ValueError("code must contain 1 to 262144 UTF-8 bytes")
        if not 0.1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 0.1 and 120")
        async with self.lock:
            if self.closed or self.client is None or self.capture_error:
                raise RuntimeError("notebook capture is not ready")
            if len(self.requests) >= MAX_REQUESTS:
                raise RuntimeError("notebook request budget exceeded; start a new session")
            message = self.client.session.msg("execute_request", content={
                "code": code, "silent": False, "store_history": True,
                "user_expressions": {}, "allow_stdin": False, "stop_on_error": True})
            header = message["header"]
            request = {"reference": {"scope": dict(self.scope), "message_session": header["session"],
                                      "message_id": header["msg_id"]},
                       "status": "unknown", "reply": False, "idle": False, "outputs": [],
                       "capture_error": "",
                       "output_bytes": 0, "output_truncated": False, "changed": asyncio.Event(),
                       "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest()}
            self.requests[header["msg_id"]] = request
            try:
                self.client.shell_channel.send(message)
                self.recorder.record("shell", "send", message)
            except Exception:
                self._fail_capture("request_send_or_record_failed")
        # Timeout/cancellation never resends or implicitly interrupts a request.
        try:
            async with asyncio.timeout(timeout_seconds):
                while not (request["reply"] and request["idle"]) and not request["capture_error"]:
                    await request["changed"].wait()
                    request["changed"].clear()
        except TimeoutError:
            pass
        return self._result(request, "execute")

    def result(self, message_id):
        if message_id not in self.requests:
            raise ValueError("unknown notebook request")
        return self._result(self.requests[message_id], "read")

    def _result(self, request, operation):
        return {"schema_version": RESULT_SCHEMA, "operation": operation,
                "notebook_request": request["reference"], "code_sha256": request["code_sha256"],
                "execution_status": request["status"],
                "capture_status": "partial" if request["capture_error"] else "ok",
                "capture_reason": request["capture_error"],
                "output_state": "idle_observed" if request["idle"] else "pending",
                "outputs": list(request["outputs"]), "output_truncated": request["output_truncated"]}

    async def restart(self):
        async with self.lock:
            if self.closed:
                raise RuntimeError("notebook is closed")
            await self._stop_kernel()
            self.capture_error = ""
            await self._start_kernel()
            return {"scope": self.scope, "status": "ready"}

    async def _stop_kernel(self):
        self.stopping = True
        for request in self.requests.values():
            if not request["reply"]:
                request["capture_error"] = request["capture_error"] or "kernel_stopped_before_reply"
                request["changed"].set()
        try:
            if self.manager is not None and self.manager.has_kernel:
                await self.manager.shutdown_kernel(now=True)
        finally:
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks = []
            if self.client is not None:
                self.client.stop_channels()
            if self.recorder is not None:
                self.remaining_bytes -= self.recorder.size
                self.remaining_messages -= self.recorder.count
                self.recorder.close()
            if self.resources is not None:
                self.resources.cleanup()
            self.client = self.manager = self.recorder = self.resources = None

    async def close(self):
        async with self.lock:
            self.closed = True
            await self._stop_kernel()


def main():
    from mcp.server.mcpserver import Context, MCPServer

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--capture-dir", required=True, help="new private directory outside the task workspace")
    for name in ("producer-id", "namespace", "instance-id", "generation", "notebook-id"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    placement = {key: getattr(args, key) for key in ("producer_id", "namespace", "instance_id", "generation", "notebook_id")}

    @contextlib.asynccontextmanager
    async def lifespan(_server):
        runtime = NotebookRuntime(args.workdir, args.capture_dir, placement)
        try:
            await runtime.start()
            yield runtime
        finally:
            await runtime.close()

    server = MCPServer("AgentProvenance Notebook", lifespan=lifespan)

    @server.tool(structured_output=True)
    async def notebook_execute(code: str, ctx: Context, timeout_seconds: float = 30) -> dict[str, Any]:
        """Execute Python once in the persistent kernel. On unknown status, use notebook_result; do not resend."""
        return await ctx.request_context.lifespan_context.execute(code, timeout_seconds)

    @server.tool(structured_output=True)
    async def notebook_result(message_id: str, ctx: Context) -> dict[str, Any]:
        """Read one existing request and available late output without executing code."""
        return ctx.request_context.lifespan_context.result(message_id)

    @server.tool(structured_output=True)
    async def notebook_restart(ctx: Context) -> dict[str, Any]:
        """Explicitly stop the current kernel and start an empty one with a new identity. Variables are lost."""
        return await ctx.request_context.lifespan_context.restart()

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
