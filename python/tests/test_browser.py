import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentprov.browser import Browser, Capture, _CDP, safe_url


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
