import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentprov.browser import Browser, Capture, _CDP, safe_url
from agentprov.browser_har import HARCapture


class HARTests(unittest.TestCase):
    def native(self, session="page", hop=0):
        return dict(target_id=session, target_type="page", cdp_session_id=session, request_id="same",
                    redirect_index=hop, frame_id="frame", loader_id="loader")

    def test_native_hops_and_unknown_timing(self):
        h = HARCapture({})
        for n in (self.native(), self.native("other"), self.native(hop=1)):
            h.request(n, {"url": "https://example.test/path?__redacted__", "method": "GET"}, 10, 1800000000)
        h.response(self.native(), {"status": 302, "mime_type": "text/plain"}, "h2",
                   dict(requestTime=10, sendStart=1, sendEnd=2, receiveHeadersEnd=5))
        h.finish(self.native(), 10.01, "redirected", redirect="https://example.test/next")
        h.finish(self.native("other"), 10.02, "failed")
        entries = h.document()["log"]["entries"]
        self.assertEqual(len(entries), 3)
        self.assertEqual([e["_agentprovenance"]["outcome"] for e in entries], ["redirected", "failed", "pending"])
        self.assertAlmostEqual(entries[0]["_agentprovenance"]["observed_duration_ms"], 10)
        self.assertEqual(entries[0]["timings"]["dns"], -1)
        self.assertEqual(entries[1]["time"], 0)
        self.assertTrue(all(v == -1 for v in entries[1]["timings"].values()))
        self.assertIsNone(entries[2]["_agentprovenance"]["observed_duration_ms"])
        with self.assertRaises(ValueError):
            h.request(self.native(), {"url": "https://example.test/", "method": "GET"}, 10, 1800000000)

    def test_entry_and_byte_limits_are_explicit(self):
        for budget in ({"max_entries": 1}, {"max_bytes": 16384}):
            h = HARCapture({}, **budget)
            for i in range(20):
                h.request(self.native(str(i)), {"url": "https://example.test/" + "x" * 1000, "method": "GET"}, 10, 1800000000)
            document = h.document()
            self.assertEqual(document["log"]["_agentprovenance"]["capture_state"], "incomplete")
            self.assertEqual(document["log"]["_agentprovenance"]["omitted_entries"] + len(h.entries), 20)
            self.assertLess(len(json.dumps(document).encode()), h.max_bytes)

    def test_missing_clock_does_not_invent_start(self):
        h = HARCapture({})
        h.request(self.native(), {"url": "https://example.test/", "method": "GET"}, None, 1800000000)
        self.assertEqual(h.document()["log"]["entries"], [])
        self.assertEqual(h.omitted, 1)


class BrowserTests(unittest.TestCase):
    def test_url_privacy(self):
        self.assertEqual(safe_url("https://user:SECRET@example.test/path?token=SECRET#SECRET"), "https://example.test/path?__redacted__")
        self.assertEqual(safe_url("http://[::1]:8080/data"), "http://[::1]:8080/data")
        for url in ("javascript:alert(1)", "data:text/html,secret", "file:///private", "http://example.test:bad"):
            self.assertEqual(safe_url(url), "")

    def test_capture_bounds_and_exclusive_file(self):
        scope = {k: k for k in ("producer_id", "namespace", "instance_id", "generation", "browser_id", "context_id")}
        with tempfile.TemporaryDirectory() as directory, patch("importlib.metadata.version", return_value="1.65.2"):
            path = Path(directory) / "capture.jsonl"
            c = Capture(path, scope, browser_version="Chromium", max_events=1)
            c.event("closed")
            with self.assertRaises(RuntimeError):
                c.event("closed")
            c.close()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([r["type"] for r in rows], ["browser_session", "browser_event", "browser_event"])
            self.assertEqual(rows[-1]["payload"]["reason"], "capture_budget_exceeded")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                Capture(path, scope, browser_version="Chromium")

    def test_placement_validation(self):
        for value in ({}, {"producer_id": "secret\n"}):
            with self.assertRaises(ValueError):
                Browser("unused.jsonl", value)


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_endpoint_waits_for_complete_port_file(self):
        browser = Browser("unused.jsonl", {k: k for k in ("producer_id", "namespace", "instance_id", "generation")})
        browser.owner = Mock()
        browser.owner.browser.is_connected.return_value = True
        states = [FileNotFoundError(), "", "12345\n", "12345\n/devtools/", "12345\n/devtools/browser/owned-id\n"]
        with patch.object(Path, "read_text", side_effect=states) as read, patch("asyncio.sleep", new_callable=AsyncMock):
            self.assertEqual(await browser._owned_endpoint(Path("profile")), ("12345", "/devtools/browser/owned-id"))
            self.assertEqual(read.call_count, len(states))

    async def test_owned_endpoint_failure_and_cancellation(self):
        browser = Browser("unused.jsonl", {k: k for k in ("producer_id", "namespace", "instance_id", "generation")})
        browser.owner = Mock()
        browser.owner.browser.is_connected.return_value = False
        with self.assertRaisesRegex(RuntimeError, "disconnected"):
            await browser._owned_endpoint(Path("profile"))
        browser.owner.browser.is_connected.return_value = True
        with patch.object(Path, "read_text", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(RuntimeError, "endpoint unavailable"):
                await browser._owned_endpoint(Path("profile"), timeout=0)
            pending = asyncio.create_task(browser._owned_endpoint(Path("profile")))
            await asyncio.sleep(0)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
        with patch.object(Path, "read_text", side_effect=PermissionError("profile permission denied")):
            with self.assertRaises(PermissionError):
                await browser._owned_endpoint(Path("profile"))

    async def test_paused_worker_initialization_does_not_deadlock(self):
        browser = Browser("unused.jsonl", {k: k for k in ("producer_id", "namespace", "instance_id", "generation")})
        browser.context_id = "context"
        resumed = asyncio.Event()
        calls = []

        class Session:
            async def send(self, method, params=None, session=None):
                calls.append(method)
                if method == "Network.enable":
                    await resumed.wait()
                if method == "Runtime.runIfWaitingForDebugger":
                    resumed.set()
                return {}

        browser.cdp = Session()
        await asyncio.wait_for(browser._attach({"sessionId": "worker-session", "targetInfo": {
            "targetId": "worker", "type": "service_worker", "browserContextId": "context"}}), .5)
        self.assertTrue(browser.ready["worker"].is_set())
        self.assertLess(calls.index("Network.enable"), calls.index("Runtime.runIfWaitingForDebugger"))

    async def test_disconnection_rejects_pending_commands(self):
        class Socket:
            def __init__(self):
                self.queue = asyncio.Queue()

            async def send(self, raw):
                self.sent = json.loads(raw)

            def __aiter__(self):
                return self

            async def __anext__(self):
                value = await self.queue.get()
                if value is None:
                    raise StopAsyncIteration
                return value

            async def close(self):
                await self.queue.put(None)

        socket = Socket()
        client = _CDP(socket, lambda _: None)
        command = asyncio.create_task(client.send("Network.enable", session="native-session"))
        await asyncio.sleep(0)
        self.assertEqual(socket.sent["sessionId"], "native-session")
        await client.close()
        with self.assertRaises(RuntimeError):
            await command
        self.assertEqual(client.pending, {})
