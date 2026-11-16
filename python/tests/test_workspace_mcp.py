import asyncio
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from agentprov.workspace_mcp import CONFIG_SCHEMA, SCHEMA, WorkspaceRuntime, make_server


class WorkspaceMCPTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = pathlib.Path(self.temp.name) / "operator.json"
        self.target = {"producer_id": "producer", "instance_id": "instance", "generation": "g1"}
        self.config.write_text(json.dumps({"schema": CONFIG_SCHEMA, "workspace_id": "work", "run_id": "run",
                                           "root": "/remote/work", "target": self.target}))
        self.calls = []
        self.response = {"schema": SCHEMA, "ok": True, "run_id": "run", "tool_call_id": "trusted-entry",
                         "operation_ref": "receipt", "view": {"binding": {"workspace_id": "work", "target": self.target,
                         "root": "/remote/work", "revision": 2}, "last_receipt": {"ref": "receipt", "tool_call_id": "trusted-entry"}}}

        async def invoke(operation, raw):
            self.calls.append((operation, json.loads(raw)))
            return self.response

        self.runtime = WorkspaceRuntime(self.config, "/operator/agentprov", invoke=invoke)

    async def test_conflict_is_returned_without_refresh_or_retry(self):
        self.response = {"schema": SCHEMA, "ok": False, "error": {"code": "conflict", "next_action": "reread"}}
        result = await self.runtime.call("edit", path="file", old_text="old", new_text="new", count=1, expected_revision=1)
        self.assertEqual(result["error"]["code"], "conflict")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "edit")
        self.assertEqual(self.calls[0][1]["expected_revision"], 1)

    async def test_inspect_is_query_only_and_identity_is_pinned(self):
        for _ in range(3):
            await self.runtime.call("inspect")
        self.assertEqual([x[0] for x in self.calls], ["inspect"] * 3)
        updated = json.loads(self.config.read_text())
        updated["target"]["generation"] = "g2"
        self.config.write_text(json.dumps(updated))
        await self.runtime.call("read", path="file")
        self.assertEqual(self.calls[-1][1]["target"]["generation"], "g1")

    async def test_model_cannot_choose_identity_refs_or_runner(self):
        for field in ("run_id", "tool_call_id", "record", "evidence_ref", "target", "workspace_id", "config", "agentprov"):
            result = await self.runtime.call("read", path="file", **{field: "forged"})
            self.assertEqual(result["error"]["code"], "invalid_request")
        result = await self.runtime.call("inspect", command="touch forbidden")
        self.assertEqual(result["error"]["code"], "invalid_request")
        self.assertEqual(self.calls, [])

    async def test_cas_is_required_and_booleans_are_not_revisions(self):
        for revision in (None, True, -1, 0, 2**64, "1"):
            result = await self.runtime.call("write", path="file", content="new", expected_revision=revision)
            self.assertEqual(result["error"]["code"], "invalid_request")
        self.assertEqual(self.calls, [])
        await self.runtime.call("write", path="new", content="", expected_digest="absent")
        self.assertEqual(self.calls[0][1]["content"], "")

    async def test_wrong_run_target_and_receipt_are_not_trusted(self):
        self.response["run_id"] = "other-run"
        self.assertEqual((await self.runtime.call("read", path="file"))["error"]["code"], "outcome_unknown")
        self.response["run_id"] = "run"
        self.response["view"]["binding"]["target"] = {**self.target, "generation": "other"}
        self.assertEqual((await self.runtime.call("read", path="file"))["error"]["code"], "outcome_unknown")
        self.response["view"]["binding"]["target"] = self.target
        self.response["view"]["last_receipt"]["tool_call_id"] = "another-call"
        self.assertEqual((await self.runtime.call("read", path="file"))["error"]["code"], "outcome_unknown")

    async def test_unknown_outcome_does_not_retry_bash(self):
        self.response = {"schema": SCHEMA, "ok": False, "error": {"code": "recovery_required", "next_action": "inspect"}}
        result = await self.runtime.call("bash", command="printf done", expected_revision=1)
        self.assertEqual(result["error"]["next_action"], "inspect")
        self.assertEqual([x[0] for x in self.calls], ["bash"])

    async def test_malformed_success_is_not_promoted(self):
        valid = self.response
        for response in ({}, [], {"schema": SCHEMA, "ok": "true"}, {"schema": SCHEMA, "ok": True},
                         {**valid, "view": []}, {**valid, "view": {"binding": []}},
                         {**valid, "view": {**valid["view"], "last_receipt": []}}):
            self.response = response
            self.assertEqual((await self.runtime.call("inspect"))["error"]["code"], "outcome_unknown")

    async def test_subprocess_malformed_json_is_unknown_not_retried(self):
        for body in (b"[]", b"not JSON", b'{"ok":true}'):
            process = AsyncMock()
            process.stdin.write = lambda _: None
            process.stdin.close = lambda: None
            process.stdout.read.side_effect = [body, b""]
            process.stderr.read.return_value = b""
            process.returncode = 1
            with patch("asyncio.create_subprocess_exec", return_value=process) as spawn:
                result = await self.runtime._invoke("bash", b"{}")
            self.assertEqual(result["error"]["code"], "outcome_unknown")
            spawn.assert_called_once()

    async def test_process_exit_during_cancellation_is_reaped(self):
        process = AsyncMock()
        process.returncode = None
        process.stdin.write = lambda _: None
        process.stdin.close = lambda: None
        process.stderr.read.return_value = b""

        def already_exited():
            raise ProcessLookupError()

        process.terminate = already_exited
        started = asyncio.Event()

        async def pending_read(_):
            started.set()
            await asyncio.Event().wait()

        process.stdout.read.side_effect = pending_read
        with patch("asyncio.create_subprocess_exec", return_value=process) as spawn:
            task = asyncio.create_task(self.runtime._invoke("bash", b"{}"))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        spawn.assert_called_once()
        process.wait.assert_awaited_once()

    async def test_cancellation_does_not_spawn_a_second_call(self):
        started = asyncio.Event()

        async def invoke(operation, raw):
            self.calls.append((operation, raw))
            started.set()
            await asyncio.Event().wait()

        self.runtime.invoke = invoke
        task = asyncio.create_task(self.runtime.call("bash", command="sleep 10", expected_revision=1))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(self.calls), 1)

    async def test_actual_sdk_inventory_has_only_controlled_tools(self):
        try:
            server = make_server(self.runtime)
        except ImportError:
            self.skipTest("optional existing MCP dependency is not installed")
        tools = await server.list_tools()
        self.assertEqual({t.name for t in tools}, {"workspace_inspect", "workspace_read", "workspace_write", "workspace_edit", "workspace_bash"})
        for tool in tools:
            schema = tool.input_schema
            self.assertFalse(set(schema.get("properties", {})) & {"run_id", "target", "tool_call_id", "evidence_ref", "config"})


class WorkspaceHarnessAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "accept_workspace.py"
        spec = importlib.util.spec_from_file_location("accept_workspace", path)
        cls.acceptance = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.acceptance)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.root = self.base / "work"
        self.root.mkdir()
        self.config = {"root": str(self.root)}
        self.init = {"type": "system", "subtype": "init", "mcp_servers": [{"name": "agentprov_workspace", "status": "connected"}],
                     "tools": sorted("mcp__agentprov_workspace__" + tool for tool in self.acceptance.TOOLS)}
        self.success = {"type": "result", "subtype": "success", "is_error": False}
        self.calls = {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "mcp__agentprov_workspace__workspace_" + name, "id": name}
            for name in ("read", "edit", "write", "bash")]}}

    def check_failure(self, code, events):
        (self.base / "claude.stdout").write_text("\n".join(json.dumps(event) for event in events))
        with self.assertRaises(self.acceptance.AcceptanceFailure) as caught:
            self.acceptance.verify_harness_run(self.base, self.config, 0)
        self.assertEqual(caught.exception.code, code)

    def test_api_success_without_init_inventory_fails(self):
        self.check_failure("missing_init_inventory", [self.success])

    def test_empty_init_inventory_classifies_missing_mcp(self):
        self.init.update(tools=[], mcp_servers=[])
        self.check_failure("mcp_not_connected", [self.init, self.success])

    def test_reserved_server_key_cannot_satisfy_init_inventory(self):
        self.assertEqual(self.acceptance.MCP_SERVER, "agentprov_workspace")
        self.init["mcp_servers"] = [{"name": "workspace", "status": "connected"}]
        self.check_failure("mcp_not_connected", [self.init, self.calls, self.success])

    def test_missing_controlled_tools_is_not_success(self):
        self.init["tools"] = []
        self.check_failure("missing_controlled_tools", [self.init, self.success])

    def test_xml_claim_is_not_a_tool_call(self):
        text = {"type": "assistant", "message": {"content": [{"type": "text", "text": "<mcp__tools__workspace__inspect_binding>done</mcp__tools__workspace__inspect_binding>"}]}}
        self.check_failure("no_tool_calls", [self.init, text, self.success])

    def test_missing_artifact_has_specific_failure(self):
        self.check_failure("missing_artifact", [self.init, self.calls, self.success])

    def test_wrong_artifact_has_specific_failure(self):
        (self.root / "result.txt").write_text("wrong bytes")
        self.check_failure("artifact_mismatch", [self.init, self.calls, self.success])

    def test_builtin_bash_is_uncontrolled(self):
        self.calls["message"]["content"][0]["name"] = "Bash"
        self.check_failure("uncontrolled_tool", [self.init, self.calls, self.success])

    def test_incomplete_tool_sequence_is_not_success(self):
        self.calls["message"]["content"].pop()
        self.check_failure("missing_required_tool_calls", [self.init, self.calls, self.success])


if __name__ == "__main__":
    unittest.main()
