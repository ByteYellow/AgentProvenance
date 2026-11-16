"""Stdio-only workspace tools backed by the agentprov workspace JSON CLI."""

import argparse
import asyncio
from contextlib import suppress
import json
import os
import pathlib
import shutil
from typing import Any


SCHEMA = "agentprovenance.workspace_tool_result/v1"
CONFIG_SCHEMA = "agentprovenance.workspace_cli/v1"
MAX_REQUEST_BYTES = 40 << 20
MAX_RESPONSE_BYTES = 192 << 20


def failure(code, message, action="inspect"):
    return {"schema": SCHEMA, "ok": False,
            "error": {"code": code, "message": message, "next_action": action}}


class WorkspaceRuntime:
    """One fixed operator binding; each tool is one subprocess, with no retry.

    The Harness loop is outside the core lease. Only its individual Bash callback
    holds the execution lease. Operator configuration and the CLI binary are not
    tool parameters. Provider credentials are not forwarded to the tool CLI.
    """

    def __init__(self, config, agentprov="agentprov", *, invoke=None):
        self.config = str(pathlib.Path(config).absolute())
        with open(self.config, "rb") as source:
            raw = source.read((64 << 10) + 1)
        if len(raw) > 64 << 10:
            raise ValueError("workspace config exceeds limit")
        settings = json.loads(raw)
        if not isinstance(settings, dict) or settings.get("schema") != CONFIG_SCHEMA:
            raise ValueError("unsupported workspace config schema")
        target = settings.get("target")
        if not isinstance(target, dict) or set(target) != {"producer_id", "instance_id", "generation"}:
            raise ValueError("workspace target is required")
        self.identity = {"workspace_id": settings["workspace_id"], "target": dict(target)}
        self.run_id, self.root = settings["run_id"], settings["root"]
        self.timeout = settings.get("bash_timeout_seconds", 60) or 60
        if type(self.timeout) is not int or not 1 <= self.timeout <= 300:
            raise ValueError("invalid Bash timeout")
        if any(not isinstance(x, str) or not x or len(x.encode()) > 256
               or any(c.isspace() or ord(c) < 32 for c in x)
               for x in (self.identity["workspace_id"], self.run_id, *target.values())):
            raise ValueError("invalid workspace identity")
        self.agentprov = shutil.which(str(agentprov)) or str(pathlib.Path(agentprov).absolute())
        self.invoke = invoke or self._invoke

    async def call(self, operation, **arguments):
        common = {"path", "expected_revision", "expected_digest"}
        fields = {"inspect": set(), "read": common,
                  "write": common | {"content"},
                  "edit": common | {"old_text", "new_text", "count"},
                  "bash": {"command", "expected_revision"}}
        if operation not in fields or set(arguments) - fields[operation]:
            return failure("invalid_request", "Unsupported workspace tool arguments.", "correct_request")
        arguments = {k: v for k, v in arguments.items() if v is not None}
        revision = arguments.get("expected_revision")
        if revision is not None and (type(revision) is not int or not 1 <= revision < 2**64):
            return failure("invalid_request", "Expected revision must be a positive integer.", "correct_request")
        if operation in ("write", "edit", "bash") and revision is None and not arguments.get("expected_digest"):
            return failure("invalid_request", "Use the revision or digest from the read that informed this change.", "reread")
        request = {**self.identity, **arguments}
        try:
            encoded = json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            return failure("invalid_request", "Arguments must be valid UTF-8 JSON.", "correct_request")
        if len(encoded) > MAX_REQUEST_BYTES:
            return failure("limit_exceeded", "Workspace request exceeds the transport limit.", "correct_request")
        # In particular, never Inspect/rebase/resend after a CAS conflict.
        result = await self.invoke(operation, encoded)
        if not isinstance(result, dict) or result.get("schema") != SCHEMA or type(result.get("ok")) is not bool:
            return failure("outcome_unknown", "CLI returned an invalid response; inspect before deciding another operation.")
        if result.get("run_id", self.run_id) != self.run_id:
            return failure("outcome_unknown", "CLI result run does not match the configured binding.")
        view = result.get("view")
        if view is not None:
            if not isinstance(view, dict) or not isinstance(view.get("binding"), dict):
                return failure("outcome_unknown", "CLI result binding is malformed.")
            binding = view.get("binding", {})
            if (binding.get("workspace_id") != self.identity["workspace_id"] or
                    binding.get("target") != self.identity["target"] or binding.get("root") != self.root):
                return failure("outcome_unknown", "CLI result target does not match the configured binding.")
            if result.get("operation_ref"):
                receipt = view.get("last_receipt", {})
                if (not isinstance(receipt, dict) or receipt.get("ref") != result["operation_ref"] or
                        receipt.get("tool_call_id") != result.get("tool_call_id")):
                    return failure("outcome_unknown", "CLI operation reference does not match this trusted tool call.")
        if result["ok"] and (view is None or not result.get("tool_call_id") or result.get("run_id") != self.run_id):
            return failure("outcome_unknown", "CLI success is missing its binding or trusted tool identity.")
        return result

    async def _invoke(self, operation, request):
        env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM") if k in os.environ}
        env.update(AGENTPROV_LANG="en", AGENTPROV_DAEMON_URL="")
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                self.agentprov, "workspace", operation, "--config", self.config, "--json",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env)

            async def bounded(stream, limit):
                data = bytearray()
                while True:
                    chunk = await stream.read(65536)
                    if not chunk:
                        return bytes(data)
                    if len(data) + len(chunk) > limit:
                        raise ValueError("CLI transport limit exceeded")
                    data.extend(chunk)

            async def exchange():
                process.stdin.write(request)
                await process.stdin.drain()
                process.stdin.close()
                raw, _ = await asyncio.gather(bounded(process.stdout, MAX_RESPONSE_BYTES), bounded(process.stderr, 64 << 10))
                await process.wait()
                value = json.loads(raw)
                if not isinstance(value, dict) or (process.returncode and value.get("ok") is not False):
                    raise ValueError("inconsistent CLI status")
                return value

            return await asyncio.wait_for(exchange(), timeout=self.timeout + 90)
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, TimeoutError):
            return failure("outcome_unknown", "CLI response was unavailable; inspect before deciding another operation.")
        finally:
            if process is not None and process.returncode is None:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()


def make_server(runtime):
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("AgentProvenance Workspace", instructions=(
        "Use workspace_inspect to discover the current binding, then workspace_read before editing. "
        "Carry the read's revision/digest into write/edit, and the current observed revision into Bash. "
        "On conflict, reread and decide a new change. On unknown/recovery, inspect; do not replay Bash. "
        "All paths are relative to the configured remote-authoritative root. Bash is bounded and foreground-only."))

    @server.tool(structured_output=True)
    async def workspace_inspect() -> dict[str, Any]:
        """Inspect/recover the current binding and observed manifest. Never execute a command."""
        return await runtime.call("inspect")

    @server.tool(structured_output=True)
    async def workspace_read(path: str, expected_revision: int | None = None,
                             expected_digest: str | None = None) -> dict[str, Any]:
        """Read actual UTF-8 bytes, source digest, revision, and stored content evidence."""
        return await runtime.call("read", path=path, expected_revision=expected_revision, expected_digest=expected_digest)

    @server.tool(structured_output=True)
    async def workspace_write(path: str, content: str, expected_revision: int | None = None,
                              expected_digest: str | None = None) -> dict[str, Any]:
        """Write with a prior revision/digest; digest 'absent' means create-only. Never automatically retry."""
        return await runtime.call("write", path=path, content=content, expected_revision=expected_revision, expected_digest=expected_digest)

    @server.tool(structured_output=True)
    async def workspace_edit(path: str, old_text: str, new_text: str, count: int = 1,
                             expected_revision: int | None = None,
                             expected_digest: str | None = None) -> dict[str, Any]:
        """Replace exactly count matches under CAS. On conflict, reread before deciding another edit."""
        return await runtime.call("edit", path=path, old_text=old_text, new_text=new_text, count=count,
                                  expected_revision=expected_revision, expected_digest=expected_digest)

    @server.tool(structured_output=True)
    async def workspace_bash(command: str, expected_revision: int) -> dict[str, Any]:
        """Run one bounded foreground Bash command via record in the authoritative root. Unknown outcomes require inspect, not replay."""
        return await runtime.call("bash", command=command, expected_revision=expected_revision)

    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--agentprov", default="agentprov")
    args = parser.parse_args()
    try:
        runtime = WorkspaceRuntime(args.config, args.agentprov)
    except (OSError, ValueError, KeyError, TypeError):
        parser.error("cannot load workspace operator configuration")
    make_server(runtime).run(transport="stdio")


if __name__ == "__main__":
    main()
