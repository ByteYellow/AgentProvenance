"""Receipt regressions and a subprocess acceptance entry, without Chromium.

PYTHONPATH=python python3 python/tests/test_browser_receipts.py --acceptance-output DIR
"""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentprov.browser import Browser, Capture
from agentprov.browser_mcp import BrowserRuntime
from agentprov.browser_receipts import MAX_OUTPUT_BYTES, ReceiptStore, digest


PLACEMENT = dict(producer_id="receipt-fixture", namespace="acceptance", instance_id="local", generation="first")


class RecordedBrowser(Browser):
    """Exercise real operation/Capture code; replace only the browser transport."""

    async def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.capture = Capture(self.path, {**self.placement, "browser_id": str(self.path.name),
                                          "context_id": self.placement["generation"] + "-context"}, browser_version="fixture")
        self.cdp = SimpleNamespace(closed=False)
        self.first_page = "page"
        self.targets = {"page": "session"}
        self.sessions = {"session": dict(target_id="page", target_type="page", cdp_session_id="session")}
        self.pages = {"page": self}

    def locator(self, selector):
        self.selector = selector
        return self

    async def click(self, **kwargs):
        with (self.path.parent / "action-count.jsonl").open("a") as output:
            output.write(json.dumps({"action": "click"}) + "\n")
            output.flush()
            os.fsync(output.fileno())
        if self.selector == "#interrupt":
            await asyncio.Event().wait()

    async def screenshot(self, **kwargs):
        return b"fixture-image"

    async def close(self):
        if self.capture:
            self.capture.close()


async def acceptance_worker(directory, mode, operation_id):
    placement = {**PLACEMENT, "generation": "second" if mode == "read" else "first"}
    with patch("agentprov.browser_mcp.Browser", RecordedBrowser), patch("importlib.metadata.version", return_value="fixture"):
        runtime = BrowserRuntime(directory, placement)
        if mode == "read":
            try:
                result = runtime.result(operation_id)
                # Start a new generation alongside the recovered query history.
                await runtime.start()
                repeated = [runtime.result(operation_id) for _ in range(3)]
                await runtime.close()
                return {"result": result, "repeated": repeated}
            except (ValueError, FileExistsError) as error:
                return {"query_error": type(error).__name__, "message": str(error)}
        await runtime.start()
        result = await runtime.execute("page", "click", "#interrupt" if mode == "interrupt" else "#once", .1)
        if mode == "interrupt":
            print(json.dumps({"result": result}), flush=True)
            os._exit(0)
        await runtime.close()
        return {"result": result}


def subprocess_acceptance(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if any((directory / mode).exists() for mode in ("complete", "interrupt")):
        raise FileExistsError("use a fresh acceptance output directory")

    def worker(path, mode, operation_id=""):
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", mode,
                                  "--directory", str(path), "--operation-id", operation_id],
                                 capture_output=True, text=True, timeout=15)
        if process.returncode:
            raise AssertionError("acceptance worker failed: " + process.stderr)
        return json.loads(process.stdout)

    reports = []
    for mode, expected in (("complete", "ok"), ("interrupt", "unknown")):
        capture = directory / mode
        original = worker(capture, mode)["result"]
        operation_id = original["browser_operation"]["operation_id"]
        recovered = worker(capture, "read", operation_id)
        count = len((capture / "action-count.jsonl").read_text().splitlines())
        result = recovered.get("result", {})
        passed = (result.get("execution_status") == expected
                  and result.get("browser_operation") == original["browser_operation"]
                  and len(recovered.get("repeated", [])) == 3
                  and all(item["execution_status"] == expected for item in recovered.get("repeated", []))
                  and count == 1)
        reports.append(dict(case=mode, passed=passed, expected_status=expected, action_count=count,
                            original=original, recovered=recovered))
    report = {"transport": "fixture; real Browser.operation and fsynced Capture; separate processes",
              "passed": all(item["passed"] for item in reports), "cases": reports}
    (directory / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


class RestartRegressionTests(unittest.TestCase):
    def test_completed_and_interrupted_queries_survive_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            report = subprocess_acceptance(directory)
            self.assertTrue(report["passed"], json.dumps(report, indent=2))


class ReceiptStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.store = ReceiptStore(self.directory, PLACEMENT)
        self.capture = self.new_capture()

    def new_capture(self, name="browser.jsonl", **placement):
        scope = {**PLACEMENT, **placement, "browser_id": name, "context_id": name + "-context"}
        with patch("importlib.metadata.version", return_value="fixture"):
            capture = Capture(self.directory / name, scope, browser_version="fixture")
        self.addCleanup(capture.close)
        return capture

    def accept(self, operation_id="operation", action="click", value="", capture=None, store=None):
        (store or self.store).accept(capture or self.capture, "page", action, value, operation_id)
        return dict(target_id="page", operation=action, operation_id=operation_id)

    def finish(self, identity, *, capture=None, payload=None):
        capture = capture or self.capture
        capture.event("action_start", **identity, payload={})
        capture.event("action_end", **identity, payload=payload or {})

    def append(self, raw):
        self.capture.file.write(raw)
        self.capture.file.flush()
        os.fsync(self.capture.file.fileno())

    def test_receipt_reuses_durable_events_and_queries_are_read_only(self):
        identity = self.accept()
        self.finish(identity)
        result = self.store.result("operation")
        self.assertEqual(result["execution_status"], "ok")
        receipt = result["browser_receipt"]
        saved_digest = receipt.pop("digest")
        self.assertEqual(digest(receipt), saved_digest)
        raw = (self.directory / "browser.jsonl").read_bytes()
        rows = raw.splitlines(keepends=True)
        for ref in receipt["source_refs"].values():
            line = next(line for line in rows if json.loads(line).get("event_id") == ref["event_id"])
            self.assertEqual(ref["sha256"], hashlib.sha256(line).hexdigest())
        for _ in range(8):
            self.assertEqual(self.store.result("operation")["browser_receipt"]["digest"], saved_digest)
        self.assertEqual((self.directory / "browser.jsonl").read_bytes(), raw)
        result["browser_operation"]["scope"]["generation"] = "mutated"
        self.assertEqual(self.store.result("operation")["browser_operation"]["scope"]["generation"], "first")

    def test_accept_without_result_and_late_completion(self):
        identity = self.accept()
        recovered = ReceiptStore(self.directory, {**PLACEMENT, "generation": "second"})
        missing = recovered.result("operation")
        self.assertEqual(missing["execution_status"], "unknown")
        self.assertIsNone(missing["browser_receipt"]["started_at"])
        self.assertIsNone(missing["browser_receipt"]["ended_at"])
        self.finish(identity)
        result = recovered.result("operation")
        self.assertEqual(result["execution_status"], "ok")
        self.assertEqual(result["browser_operation"]["scope"]["generation"], "first")

    def test_partial_result_is_unknown_until_whole_line_arrives(self):
        identity = self.accept()
        self.capture.event("action_start", **identity, payload={})
        raw = self.capture._encode(dict(type="browser_event", context_id=self.capture.scope["context_id"],
                                       event_id="end-event", kind="action_end", **identity, payload={}))
        self.append(raw[:-7])
        result = self.store.result("operation")
        self.assertEqual(result["execution_status"], "unknown")
        self.assertIn("receipt_log_partial_tail", result["browser_receipt"]["gap_refs"])
        self.append(raw[-7:])
        self.assertEqual(self.store.result("operation")["execution_status"], "ok")

    def test_corrupt_line_quarantines_following_results(self):
        identity = self.accept()
        self.capture.event("action_start", **identity, payload={})
        self.append(b'{"broken":\n')
        self.capture.event("action_end", **identity, payload={})
        result = self.store.result("operation")
        self.assertEqual(result["execution_status"], "unknown")
        self.assertEqual(result["execution_reason"], "receipt_log_corrupt")
        self.assertEqual(result["output"], {})
        with self.assertRaises(RuntimeError):
            self.accept("next")

    def test_duplicate_json_keys_and_invalid_envelopes_fail_closed(self):
        self.accept()
        for raw in (b'{"type":1,"type":2}\n', b'[]\n', b'NaN\n', b'{}\n', b'\xff\n'):
            with self.subTest(raw_type=raw[:1]):
                original = (self.directory / "browser.jsonl").read_bytes()
                self.append(raw)
                reader = ReceiptStore(self.directory, PLACEMENT)
                self.assertEqual(reader.result("operation")["execution_reason"], "receipt_log_corrupt")
                self.capture.file.truncate(len(original))
                self.capture.file.seek(len(original))

    def test_replaced_truncated_or_rewritten_journal_never_uses_cached_success(self):
        self.finish(self.accept())
        self.assertEqual(self.store.result("operation")["execution_status"], "ok")
        self.capture.file.truncate(1)
        self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_log_corrupt")

    def test_same_size_rewrite_invalidates_cache(self):
        self.finish(self.accept())
        self.store.result("operation")
        path = self.directory / "browser.jsonl"
        cached_stat = path.stat()
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"action_end"', b'"action_BAD"'))
        self.assertEqual(len(path.read_bytes()), len(original))
        # A coarse filesystem clock can report identical mtime and ctime for
        # both writes. Cache validity must follow the contents, not that clock.
        with patch("agentprov.browser_receipts.os.fstat", return_value=cached_stat):
            self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_log_corrupt")

    def test_prefix_rewrite_with_valid_append_invalidates_cache(self):
        self.finish(self.accept())
        self.assertEqual(self.store.result("operation")["execution_status"], "ok")
        path = self.directory / "browser.jsonl"
        original = path.read_bytes()
        # Keep the appended row valid, so parsing only the new suffix would
        # silently reuse the success cached from the modified history.
        self.capture.event("page_title", target_id="page", payload={"title": "Next"})
        path.write_bytes(path.read_bytes().replace(b'"action_end"', b'"action_BAD"'))
        self.assertGreater(path.stat().st_size, len(original))
        result = self.store.result("operation")
        self.assertEqual(result["execution_reason"], "receipt_log_corrupt")
        self.assertEqual(result["execution_status"], "unknown")
        self.assertEqual(result["output"], {})

    def test_missing_directory_invalidates_cached_result(self):
        self.finish(self.accept())
        self.store.result("operation")
        destination = self.directory.with_name(self.directory.name + "-moved")
        self.directory.rename(destination)
        try:
            self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_log_missing")
        finally:
            destination.rename(self.directory)

    def test_duplicate_event_id_is_corrupt(self):
        self.finish(self.accept())
        rows = (self.directory / "browser.jsonl").read_bytes().splitlines(keepends=True)
        self.append(rows[-1])
        self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_log_corrupt")

    def test_duplicate_or_mismatched_action_identity_is_unknown(self):
        identity = self.accept()
        self.finish(identity)
        self.capture.event("action_end", **{**identity, "target_id": "different-page"}, payload={})
        self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_identity_conflict")

    def test_result_without_start_is_conflicting_not_success(self):
        identity = self.accept()
        self.capture.event("action_end", **identity, payload={})
        self.assertEqual(self.store.result("operation")["execution_status"], "unknown")

    def test_cross_generation_duplicate_id_is_ambiguous(self):
        self.finish(self.accept())
        other = self.new_capture("browser-second.jsonl", generation="second")
        # Simulate an imported duplicate, bypassing the writer's duplicate guard.
        accept = json.loads((self.directory / "browser.jsonl").read_text().splitlines()[1])
        payload = {**accept["payload"], "capture_epoch": other.scope["browser_id"]}
        other.event("action_accept", target_id="page", operation="click", operation_id="operation", payload=payload)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.store.result("operation")

    def test_foreign_producer_namespace_and_instance_are_not_queryable(self):
        self.finish(self.accept())
        for key in ("producer_id", "namespace", "instance_id"):
            with self.subTest(key=key):
                reader = ReceiptStore(self.directory, {**PLACEMENT, key: "foreign"})
                with self.assertRaisesRegex(ValueError, "unknown"):
                    reader.result("operation")

    def test_new_generation_failure_does_not_relabel_historical_result(self):
        self.finish(self.accept())
        other = self.new_capture("browser-second.jsonl", generation="second")
        other.gap("fixture_failure")
        reader = ReceiptStore(self.directory, {**PLACEMENT, "generation": "second"})
        result = reader.result("operation")
        self.assertEqual(result["execution_status"], "ok")
        self.assertEqual(result["capture_status"], "ok")
        self.assertEqual(result["browser_operation"]["scope"]["generation"], "first")

    def test_input_privacy_projection_and_unverified_identity(self):
        self.finish(self.accept(value="[data-private='fixture-private-marker']"))
        url = "https://user:fixture-private-marker@example.test/path?token=fixture-private-marker#fixture-private-marker"
        self.finish(self.accept("navigation", "navigate", url), payload={"url": "https://example.test/path?__redacted__"})
        raw = (self.directory / "browser.jsonl").read_text()
        self.assertNotIn("fixture-private-marker", raw)
        result = self.store.result("navigation")
        receipt = result["browser_receipt"]
        self.assertEqual(receipt["normalized_input_digest"], digest({"action": "navigate", "url": "https://example.test/path?__redacted__"}))
        self.assertEqual(receipt["input_digest_basis"], "privacy_projected_input/v1")
        self.assertEqual(receipt["bridge_identity"]["authentication"], "unverified")
        self.assertEqual(receipt["bridge_identity"]["transcript_identity"], "source_asserted_only")
        self.assertIsNone(receipt["caller_tool_call_id"])

    def test_forged_authentication_claim_is_not_promoted(self):
        self.finish(self.accept())
        path = self.directory / "browser.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[1]["payload"]["bridge_identity"] = {"authentication": "verified", "transcript_identity": "trusted"}
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        result = ReceiptStore(self.directory, PLACEMENT).result("operation")
        self.assertEqual(result["browser_receipt"]["bridge_identity"]["authentication"], "unverified")

    def test_malformed_or_private_error_output_is_not_returned(self):
        for index, payload in enumerate(({"text": {}}, {"status": True}, {"bytes": -1},
                                         {"sha256": "invalid"}, {"reason": "private exception"})):
            self.finish(self.accept(str(index)), payload=payload)
            result = self.store.result(str(index))
            self.assertEqual(result["execution_status"], "unknown")
            self.assertEqual(result["output"], {})

    def test_recovered_text_is_byte_bounded_at_utf8_boundary(self):
        text = "\u6d4b" * MAX_OUTPUT_BYTES
        self.finish(self.accept(action="read_text"), payload={"text": text})
        result = self.store.result("operation")
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["output"]["text"].encode()), MAX_OUTPUT_BYTES)
        self.assertTrue(text.startswith(result["output"]["text"]))

    def test_history_and_admission_budgets_are_explicit(self):
        self.finish(self.accept())
        self.assertEqual(self.store.result("operation")["execution_status"], "ok")
        with patch("agentprov.browser_receipts.MAX_HISTORY_BYTES", 1):
            self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_history_budget_exceeded")
        self.store = ReceiptStore(self.directory, PLACEMENT)
        with patch("agentprov.browser_receipts.MAX_RECEIPTS", 1):
            with self.assertRaises(RuntimeError):
                self.accept("second")

    def test_short_write_rolls_back_without_committing_a_result(self):
        identity = self.accept()
        self.capture.event("action_start", **identity, payload={})
        original = (self.directory / "browser.jsonl").read_bytes()
        file = self.capture.file
        with patch.object(self.capture, "file", wraps=file) as partial:
            partial.closed = False
            partial.write.side_effect = lambda raw: file.write(raw[:len(raw) // 2])
            with self.assertRaises(OSError):
                self.capture.event("action_end", **identity, payload={})
        self.assertEqual((self.directory / "browser.jsonl").read_bytes(), original)
        self.assertEqual(self.store.result("operation")["execution_status"], "unknown")

    def test_symlink_and_nonprivate_files_are_not_trusted(self):
        self.finish(self.accept())
        self.store.result("operation")
        path = self.directory / "browser.jsonl"
        path.chmod(0o644)
        self.assertEqual(self.store.result("operation")["execution_reason"], "receipt_log_corrupt")
        path.chmod(0o600)
        path.rename(self.directory / "original.jsonl")
        path.symlink_to(self.directory / "original.jsonl")
        with self.assertRaises(ValueError):
            ReceiptStore(self.directory, PLACEMENT).result("operation")

    def test_legacy_events_are_not_upgraded_to_durable_admission(self):
        identity = dict(operation_id="legacy", operation="click", target_id="page")
        self.finish(identity)
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.store.result("legacy")
        with self.assertRaisesRegex(ValueError, "already used"):
            self.accept("legacy")


class ReceiptRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "capture"
        browser_patch = patch("agentprov.browser_mcp.Browser", RecordedBrowser)
        version_patch = patch("importlib.metadata.version", return_value="fixture")
        browser_patch.start()
        version_patch.start()
        self.addCleanup(browser_patch.stop)
        self.addCleanup(version_patch.stop)
        self.runtime = BrowserRuntime(self.directory, PLACEMENT)
        self.addAsyncCleanup(self.runtime.close)
        await self.runtime.start()

    async def test_exclusive_writer_and_readers_with_late_results(self):
        original = await self.runtime.execute("page", "click", "#once")
        operation_id = original["browser_operation"]["operation_id"]
        second = BrowserRuntime(self.directory, {**PLACEMENT, "generation": "second"})
        self.assertEqual(second.result(operation_id)["execution_status"], "ok")
        with self.assertRaises(BlockingIOError):
            await second.start()
        await self.runtime.close()
        third = BrowserRuntime(self.directory, {**PLACEMENT, "generation": "second"})
        self.addAsyncCleanup(third.close)
        await third.start()
        self.assertEqual(third.result(operation_id)["browser_operation"], original["browser_operation"])
        self.assertEqual(third.pages()["scope"]["generation"], "second")

    async def test_cancel_running_and_queued_actions_recovers_unknown(self):
        running, queued = await asyncio.gather(self.runtime.execute("page", "click", "#interrupt", .1),
                                               self.runtime.execute("page", "click", "#once", .1))
        await self.runtime.close()
        reader = BrowserRuntime(self.directory, {**PLACEMENT, "generation": "second"})
        for result in (running, queued):
            operation_id = result["browser_operation"]["operation_id"]
            self.assertEqual(reader.result(operation_id)["execution_status"], "unknown")
            self.assertEqual(reader.result(operation_id)["waiting_state"], "settled")
        self.assertEqual(len((self.directory / "action-count.jsonl").read_text().splitlines()), 1)

    async def test_accept_fsync_failure_prevents_action(self):
        with patch("agentprov.browser.os.fsync", side_effect=OSError("fixture disk failure")):
            with self.assertRaisesRegex(RuntimeError, "admission failed"):
                await self.runtime.execute("page", "click", "#once")
        self.assertFalse((self.directory / "action-count.jsonl").exists())
        self.assertEqual(self.runtime.requests, {})
        with self.assertRaises(RuntimeError):
            await self.runtime.execute("page", "click", "#once")

    async def test_admission_crossing_history_budget_does_not_dispatch(self):
        path = self.directory / "browser.jsonl"
        with patch("agentprov.browser_receipts.MAX_HISTORY_BYTES", path.stat().st_size + 10):
            with self.assertRaisesRegex(RuntimeError, "admission failed"):
                await self.runtime.execute("page", "click", "#once")
        self.assertFalse((self.directory / "action-count.jsonl").exists())
        self.assertEqual(self.runtime.requests, {})
        operation_id = json.loads(path.read_text().splitlines()[1])["operation_id"]
        self.assertEqual(BrowserRuntime(self.directory, PLACEMENT).result(operation_id)["execution_status"], "unknown")

    async def test_result_fsync_failure_does_not_report_success(self):
        sync = os.fsync
        count = 0

        def fail_end(fd):
            nonlocal count
            count += 1
            if count == 4:  # accept, action_start, fixture action counter, action_end
                raise OSError("fixture disk failure")
            sync(fd)

        with patch("agentprov.browser.os.fsync", side_effect=fail_end):
            result = await self.runtime.execute("page", "click", "#once")
        self.assertEqual(result["execution_status"], "unknown")
        reader = BrowserRuntime(self.directory, PLACEMENT)
        recovered = reader.result(result["browser_operation"]["operation_id"])
        self.assertEqual(recovered["execution_status"], "unknown")
        self.assertEqual(len((self.directory / "action-count.jsonl").read_text().splitlines()), 1)

    async def test_start_fsync_failure_preserves_accept_without_dispatch(self):
        sync = os.fsync
        count = 0

        def fail_start(fd):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("fixture disk failure")
            sync(fd)

        with patch("agentprov.browser.os.fsync", side_effect=fail_start):
            result = await self.runtime.execute("page", "click", "#once")
        self.assertEqual(result["execution_status"], "unknown")
        self.assertIsNone(result["browser_receipt"]["started_at"])
        self.assertIn("accept", result["browser_receipt"]["source_refs"])
        self.assertFalse((self.directory / "action-count.jsonl").exists())

    async def test_screenshot_has_one_terminal_action_end_and_recovers_metadata(self):
        result = await self.runtime.execute("page", "screenshot")
        self.assertEqual(result["execution_status"], "ok")
        operation_id = result["browser_operation"]["operation_id"]
        rows = [json.loads(line) for line in (self.directory / "browser.jsonl").read_text().splitlines()]
        self.assertEqual([row["kind"] for row in rows if row.get("operation_id") == operation_id],
                         ["action_accept", "action_start", "screenshot", "action_end"])
        recovered = BrowserRuntime(self.directory, PLACEMENT).result(operation_id)
        self.assertEqual(recovered["output"], result["output"])
        self.assertEqual(recovered["output"]["bytes"], len(b"fixture-image"))

    async def test_disabled_screenshot_policy_is_preserved(self):
        self.runtime.browser.screenshots = False
        result = await self.runtime.execute("page", "screenshot")
        operation_id = result["browser_operation"]["operation_id"]
        recovered = BrowserRuntime(self.directory, PLACEMENT).result(operation_id)
        self.assertEqual(recovered["output"], {"reason": "capture_policy"})
        self.assertEqual(recovered["execution_status"], "ok")

    async def test_operation_id_collision_prevents_dispatch(self):
        first = await self.runtime.execute("page", "click", "#once")
        operation_id = first["browser_operation"]["operation_id"]
        with patch("agentprov.browser_mcp.uuid.uuid4", return_value=operation_id):
            with self.assertRaisesRegex(ValueError, "already used"):
                await self.runtime.execute("page", "click", "#once")
        self.assertEqual(len((self.directory / "action-count.jsonl").read_text().splitlines()), 1)


if __name__ == "__main__":
    if any(flag in sys.argv for flag in ("--worker", "--acceptance-output", "--focused-output")):
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--acceptance-output")
        parser.add_argument("--focused-output")
        parser.add_argument("--worker", choices=("complete", "interrupt", "read"))
        parser.add_argument("--directory")
        parser.add_argument("--operation-id", default="")
        args = parser.parse_args()
        if args.worker:
            print(json.dumps(asyncio.run(acceptance_worker(args.directory, args.worker, args.operation_id))))
        elif args.focused_output:
            output = Path(args.focused_output)
            output.mkdir(mode=0o700, parents=True, exist_ok=True)
            suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_browser*.py")
            with (output / "focused-tests.log").open("w") as stream:
                result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
            summary = {"tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                       "skipped": len(result.skipped), "passed": result.wasSuccessful(), "python": sys.version.split()[0]}
            (output / "focused-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps(summary, indent=2))
            sys.exit(0 if result.wasSuccessful() else 1)
        else:
            report = subprocess_acceptance(args.acceptance_output)
            print(json.dumps({"passed": report["passed"], "cases": [
                {key: case[key] for key in ("case", "passed", "expected_status", "action_count")}
                for case in report["cases"]]}, indent=2))
            sys.exit(0 if report["passed"] else 1)
    else:
        unittest.main()
