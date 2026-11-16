"""Owned Playwright/Chromium entry with bounded, privacy-projected CDP evidence."""

import asyncio
import base64
import datetime
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import tempfile
import uuid
from urllib.parse import urlsplit, urlunsplit

from .browser_har import HARCapture


SCHEMA = "agentprovenance.browser_capture/v1"
PLACEMENT = ("producer_id", "namespace", "instance_id", "generation")


def _id(value):
    return (isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 512
            and value == value.strip()
            and not any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value))


def safe_url(value):
    """Keep the destination/path; discard userinfo, fragment and all query data."""
    try:
        if len(value) > 16384:
            return ""
        u = urlsplit(value)
        if u.scheme not in ("http", "https") or not u.hostname:
            return ""
        host = "[" + u.hostname + "]" if ":" in u.hostname else u.hostname
        if u.port is not None:
            host += ":" + str(u.port)
        return urlunsplit((u.scheme, host, u.path, "__redacted__" if u.query else "", ""))
    except (ValueError, TypeError):
        return ""


class Capture:
    def __init__(self, path, scope, *, browser_version, max_events=24000, max_bytes=128 << 20):
        if set(scope) != set(PLACEMENT + ("browser_id", "context_id")) or not all(map(_id, scope.values())):
            raise ValueError("invalid browser scope")
        if not 1 <= max_events <= 24000 or not 8192 <= max_bytes <= 128 << 20:
            raise ValueError("invalid browser capture budget")
        self.scope, self.count, self.size, self.stopped = dict(scope), 0, 0, False
        self.max_events, self.max_bytes = max_events, max_bytes
        self.file = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb", buffering=0)
        try:
            self._write({"type": "browser_session", **scope, "browser_version": browser_version,
                         "playwright_version": importlib.metadata.version("playwright")})
            if hasattr(os, "O_DIRECTORY"):
                directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except BaseException:
            self.file.close()
            raise

    def _encode(self, value):
        value = {"schema_version": SCHEMA, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), **value}
        return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()

    def _write(self, value):
        raw = self._encode(value)
        offset = self.file.tell()
        try:
            if self.file.write(raw) != len(raw):
                raise OSError("short browser capture write")
            self.file.flush()
            os.fsync(self.file.fileno())
        except OSError:
            # Keep a failed append from masquerading as a committed action_end
            # in a live query. Recovery also rejects incomplete JSONL tails.
            try:
                self.file.truncate(offset)
                self.file.seek(offset)
                os.fsync(self.file.fileno())
            except OSError:
                self.stopped = True
            raise
        self.size += len(raw)

    def event(self, kind, **value):
        if self.stopped or self.file.closed:
            raise RuntimeError("browser capture is closed")
        value = {"type": "browser_event", "event_id": str(uuid.uuid4()), "context_id": self.scope["context_id"],
                 "kind": kind, **value}
        if self.count >= self.max_events or self.size + len(self._encode(value)) + 4096 > self.max_bytes:
            self.gap("capture_budget_exceeded")
            raise RuntimeError("browser capture budget exceeded")
        self._write(value)
        self.count += 1

    def gap(self, reason):
        if self.stopped or self.file.closed:
            return
        self.stopped = True
        self._write({"type": "browser_event", "event_id": str(uuid.uuid4()), "context_id": self.scope["context_id"],
                     "kind": "gap", "payload": {"reason": reason}})

    def close(self):
        self.file.close()


class _CDP:
    """Flat CDP sessions over an owned browser's loopback WebSocket."""
    def __init__(self, ws, callback):
        self.ws, self.callback = ws, callback
        self.sequence, self.pending, self.closed = 0, {}, False
        self.reader = asyncio.create_task(self._read())

    async def _read(self):
        try:
            async for raw in self.ws:
                message = json.loads(raw)
                if "id" in message:
                    pending = self.pending.pop(message["id"], None)
                    if pending is not None and not pending[1].done():
                        method, future = pending
                        if "error" in message:
                            code = message["error"].get("code")
                            future.set_exception(RuntimeError(f"CDP {method} failed (code {code if isinstance(code, int) else 'unknown'})"))
                        else:
                            future.set_result(message.get("result", {}))
                else:
                    self.callback(message)
        finally:
            self.closed = True
            for _, future in self.pending.values():
                if not future.done():
                    future.set_exception(RuntimeError("browser connection closed"))
            self.pending.clear()

    async def send(self, method, params=None, session=None):
        if self.closed or len(self.pending) >= 256:
            raise RuntimeError("browser connection unavailable")
        self.sequence += 1
        key = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[key] = (method, future)
        message = {"id": key, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        try:
            await self.ws.send(json.dumps(message))
            return await asyncio.wait_for(future, 15)
        finally:
            self.pending.pop(key, None)

    async def close(self):
        await self.ws.close()
        await asyncio.gather(self.reader, return_exceptions=True)


class Browser:
    """One isolated context. No existing user profile or remote endpoint is used.

    Operations use Playwright; requests retain native CDP identities. The helper
    does not infer that a click caused every request observed in its time window.
    """
    def __init__(self, path, placement, *, screenshots=True, har=True, channel=None, launcher=None):
        if set(placement) != set(PLACEMENT) or not all(map(_id, placement.values())):
            raise ValueError("invalid browser placement")
        self.path, self.placement, self.screenshots, self.channel = Path(path), dict(placement), screenshots, channel
        self.har_enabled, self.har = har, None
        self.capture = self.cdp = self.owner = self.context = self.playwright = self.temp = None
        self.sessions, self.targets, self.frames, self.requests, self.downloads = {}, {}, {}, {}, {}
        self.pages, self.locks, self.tasks, self.ready = {}, {}, set(), {}
        self.operations = set()
        self.context_id, self.closing, self.failure = "", False, None
        self.failure_error = None
        self.image_count = self.image_bytes = 0
        self.launcher = launcher

    async def __aenter__(self):
        try:
            await self.start()
            return self
        except BaseException:
            await self.close()
            raise

    async def __aexit__(self, *args):
        await self.close()

    async def start(self):
        from playwright.async_api import async_playwright
        from websockets.asyncio.client import connect

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="agentprov-browser-")
        profile = Path(self.temp.name) / "profile"
        self.playwright = await async_playwright().start()
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT")}
        env.update(HOME=self.temp.name, TMPDIR=self.temp.name)
        launch = {}
        if self.launcher:
            if self.channel:
                raise ValueError("native custody currently uses the pinned Playwright Chromium executable")
            launch["executable_path"] = self.launcher.prepare(self, self.playwright.chromium.executable_path)
        self.owner = await self.playwright.chromium.launch_persistent_context(
            str(profile), headless=True, channel=self.channel, env=env, chromium_sandbox=True,
            args=["--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1"], **launch)
        self.context = await self.owner.browser.new_context(viewport={"width": 1280, "height": 720}, accept_downloads=True)
        first = await self.context.new_page()
        probe = await self.context.new_cdp_session(first)
        info = (await probe.send("Target.getTargetInfo"))["targetInfo"]
        await probe.detach()
        self.context_id = info["browserContextId"]
        port, endpoint = (profile / "DevToolsActivePort").read_text().splitlines()[:2]
        if not port.isdecimal() or not endpoint.startswith("/devtools/browser/"):
            raise RuntimeError("owned browser endpoint unavailable")
        ws = await connect("ws://127.0.0.1:" + port + endpoint, proxy=None, max_size=4 << 20, max_queue=32)
        self.capture = Capture(self.path, {**self.placement, "browser_id": endpoint.rsplit("/", 1)[-1],
                                          "context_id": self.context_id}, browser_version=self.owner.browser.version)
        if self.har_enabled:
            self.har = HARCapture(self.capture.scope)
        self.cdp = _CDP(ws, self._event)
        self.cdp.reader.add_done_callback(lambda _: self._fail("browser_connection_closed"))
        self.download_path = Path(self.temp.name) / "downloads"
        self.download_path.mkdir()
        await self.cdp.send("Browser.setDownloadBehavior", {"behavior": "allowAndName", "browserContextId": self.context_id,
                                                           "downloadPath": str(self.download_path), "eventsEnabled": True})
        await self.cdp.send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})
        await self._ready(info["targetId"])
        self.pages[info["targetId"]] = first
        self.first_page = info["targetId"]

    def _spawn(self, coroutine):
        if len(self.tasks) >= 128:
            coroutine.close()
            self._fail("browser_observer_backpressure")
            return
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def done(value):
            self.tasks.discard(value)
            if not value.cancelled() and value.exception() is not None:
                self.failure_error = value.exception()
                self._fail("browser_observer_failed")
        task.add_done_callback(done)

    def _fail(self, reason):
        if not self.closing and self.failure is None:
            self.failure = reason
            if self.capture:
                self.capture.gap(reason)

    def _emit(self, kind, identity=None, **value):
        if self.capture and not self.capture.stopped:
            try:
                self.capture.event(kind, **(identity or {}), **value)
            except (OSError, ValueError, RuntimeError):
                self._fail("browser_capture_write_failed")

    async def _ready(self, target):
        await asyncio.wait_for(self.ready.setdefault(target, asyncio.Event()).wait(), 15)
        if self.failure:
            raise RuntimeError(self.failure) from self.failure_error

    async def _attach(self, params):
        info, sid = params["targetInfo"], params["sessionId"]
        accepted, resumed = False, False
        try:
            if (info.get("browserContextId") != self.context_id or info["type"] not in ("page", "iframe", "worker", "service_worker")
                    or info["targetId"] in self.targets):
                return
            if len(self.sessions) >= 256:
                self._fail("browser_target_limit")
                return
            identity = {"target_id": info["targetId"], "target_type": info["type"], "cdp_session_id": sid}
            self.sessions[sid], self.targets[info["targetId"]] = identity, sid
            accepted = True
            network = {"maxTotalBufferSize": 0, "maxResourceBufferSize": 0, "maxPostDataSize": 0}
            attach = {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True}
            if info["type"] in ("worker", "service_worker"):
                # A paused worker cannot acknowledge Network.enable until it is
                # resumed. Queue enable first, then resume without awaiting it.
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(self.cdp.send("Network.enable", network, sid))
                    tasks.create_task(self.cdp.send("Target.setAutoAttach", attach, sid))
                    tasks.create_task(self.cdp.send("Runtime.runIfWaitingForDebugger", session=sid))
                resumed = True
            else:
                await self.cdp.send("Network.enable", network, sid)
                await self.cdp.send("Target.setAutoAttach", attach, sid)
            if info["type"] in ("page", "iframe"):
                await self.cdp.send("Page.enable", session=sid)
            self._emit("target", identity, payload={"url": safe_url(info.get("url", ""))})
        finally:
            if not resumed:
                await self.cdp.send("Runtime.runIfWaitingForDebugger", session=sid)
            if accepted:
                self.ready.setdefault(info["targetId"], asyncio.Event()).set()

    def _event(self, message):
        method, params, sid = message.get("method"), message.get("params", {}), message.get("sessionId")
        if method == "Target.attachedToTarget":
            self._spawn(self._attach(params))
            return
        if method == "Browser.downloadWillBegin":
            owner = self.frames.get(params["frameId"])
            if owner is not None:
                if len(self.downloads) >= 32:
                    self._fail("browser_download_limit")
                    self._spawn(self.cdp.send("Browser.cancelDownload", {"guid": params["guid"], "browserContextId": self.context_id}))
                    return
                identity = {**owner, "download_id": params["guid"], "frame_id": params["frameId"]}
                self.downloads[params["guid"]] = identity
                self._emit("download", identity, payload={"url": safe_url(params["url"]), "suggested_filename": params.get("suggestedFilename", "")})
            return
        if method == "Browser.downloadProgress":
            identity = self.downloads.get(params["guid"])
            if identity:
                if params.get("receivedBytes", 0) > 8 << 20 or params.get("totalBytes", 0) > 8 << 20:
                    self._spawn(self.cdp.send("Browser.cancelDownload", {"guid": params["guid"], "browserContextId": self.context_id}))
                    self._fail("browser_download_size_limit")
                if params["state"] in ("completed", "canceled"):
                    self._spawn(self._download(identity, params["state"]))
            return
        identity = self.sessions.get(sid)
        if identity is None:
            return
        if method == "Page.frameNavigated":
            frame = params["frame"]
            if frame["id"] not in self.frames and len(self.frames) >= 8192:
                self._fail("browser_frame_limit")
                return
            self.frames[frame["id"]] = identity
            self._emit("frame", {**identity, "frame_id": frame["id"], "loader_id": frame.get("loaderId", "")},
                       payload={"url": safe_url(frame.get("url", ""))})
        if not method or not method.startswith("Network.") or "requestId" not in params:
            return
        key = (sid, params["requestId"])
        previous = self.requests.get(key)
        if method == "Network.requestWillBeSent":
            if previous is None and len(self.requests) >= 4096:
                self._fail("browser_request_limit")
                return
            hop = previous["redirect_index"] + 1 if previous and "redirectResponse" in params else 0
            if previous and "redirectResponse" in params:
                self._response(previous, params["redirectResponse"])
                if self.har:
                    self.har.finish(previous, params.get("timestamp"), "redirected", redirect=safe_url(params["request"]["url"]))
            native = {**identity, "request_id": params["requestId"], "redirect_index": hop,
                      "frame_id": params.get("frameId", ""), "loader_id": params.get("loaderId", ""),
                      "initiator_request_id": params.get("initiator", {}).get("requestId", "")}
            self.requests[key] = native
            request = params["request"]
            payload = {"url": safe_url(request["url"]), "method": request["method"],
                       "resource_type": params.get("type", ""), "initiator_type": params.get("initiator", {}).get("type", "")}
            self._emit("request", native, payload=payload)
            if self.har:
                self.har.request(native, payload, params.get("timestamp"), params.get("wallTime"))
        elif previous and method == "Network.responseReceived":
            self._response(previous, params["response"])
        elif previous and method == "Network.loadingFinished":
            self._emit("request_finished", previous, payload={"encoded_bytes": int(params.get("encodedDataLength", 0))})
            if self.har:
                self.har.finish(previous, params.get("timestamp"), "finished", encoded=int(params.get("encodedDataLength", 0)))
        elif previous and method == "Network.loadingFailed":
            self._emit("request_failed", previous, payload={"error_code": params.get("errorText", "")})
            if self.har:
                self.har.finish(previous, params.get("timestamp"), "failed")

    def _response(self, identity, response):
        payload = {"url": safe_url(response["url"]), "status": int(response["status"]),
                   "mime_type": response.get("mimeType", ""), "from_service_worker": response.get("fromServiceWorker", False)}
        self._emit("response", identity, payload=payload)
        if self.har:
            self.har.response(identity, payload, response.get("protocol", ""), response.get("timing"))

    async def _download(self, identity, state):
        guid = identity["download_id"]
        if str(uuid.UUID(guid)) != guid:
            raise ValueError("invalid download identity")
        payload = {"reason": state}
        if state == "completed":
            with (self.download_path / guid).open("rb") as f:
                data = f.read((8 << 20) + 1)
            if len(data) > 8 << 20:
                raise ValueError("download size limit")
            payload.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self._emit("download_finished", identity, payload=payload)

    async def new_page(self):
        if self.failure or len(self.pages) >= 32:
            raise RuntimeError(self.failure or "browser page limit")
        page = await self.context.new_page()
        probe = await self.context.new_cdp_session(page)
        target = (await probe.send("Target.getTargetInfo"))["targetInfo"]["targetId"]
        await probe.detach()
        await self._ready(target)
        self.pages[target] = page
        return target

    async def operation(self, target, name, value="", *, operation_id=None):
        if self.failure or self.cdp.closed:
            raise RuntimeError(self.failure or "browser connection closed") from self.failure_error
        if target not in self.pages or name not in ("navigate", "click", "read_text", "screenshot"):
            raise ValueError("unknown browser page or operation")
        if not isinstance(value, str) or len(value.encode()) > 16384:
            raise ValueError("browser argument size limit")
        operation_id = operation_id or str(uuid.uuid4())
        if not _id(operation_id):
            raise ValueError("invalid browser operation identity")
        async with self.locks.setdefault(target, asyncio.Lock()):
            if operation_id in self.operations:
                raise ValueError("browser operation identity already used")
            self.operations.add(operation_id)
            identity = {**self.sessions[self.targets[target]], "operation_id": operation_id, "operation": name}
            payload = {"url": safe_url(value)} if name == "navigate" else {}
            self._emit("action_start", identity, payload=payload)
            if self.failure or self.capture.stopped:
                raise RuntimeError("browser capture unavailable before operation")
            page, result, image = self.pages[target], {}, None
            try:
                if name == "navigate":
                    if not safe_url(value):
                        raise ValueError("navigation requires an http or https URL")
                    response = await page.goto(value, wait_until="domcontentloaded", timeout=30000)
                    result = {"url": safe_url(page.url), "status": response.status if response else 0}
                elif name == "click":
                    await page.locator(value).click(timeout=10000)
                elif name == "read_text":
                    result = {"text": await page.locator("body").evaluate("e => e.innerText.slice(0, 16384)", timeout=10000)}
                elif name == "screenshot" and self.screenshots:
                    image = await page.screenshot(type="png", full_page=False, timeout=10000)
                    if len(image) > 8 << 20 or self.image_count >= 64 or self.image_bytes + len(image) > 64 << 20:
                        raise ValueError("browser screenshot budget exceeded")
                    self.image_count += 1
                    self.image_bytes += len(image)
                    result = {"bytes": len(image), "sha256": hashlib.sha256(image).hexdigest()}
                elif name == "screenshot":
                    result = {"reason": "capture_policy"}
            except BaseException:
                self._emit("action_end", identity, status="unknown", payload={"reason": "operation_incomplete"})
                raise
            if image is not None:
                self._emit("screenshot", identity, image=base64.b64encode(image).decode("ascii"), payload=result)
            self._emit("action_end", identity, payload=result)
            if self.failure:
                raise RuntimeError("browser operation completed but capture is incomplete")
            return {"scope": dict(self.capture.scope), "operation_id": identity["operation_id"], "target_id": target, **result}

    async def close(self):
        self.closing = True
        try:
            if self.context:
                await self.context.close()
            if self.tasks:
                await asyncio.wait_for(asyncio.gather(*tuple(self.tasks), return_exceptions=True), 20)
            if self.capture and not self.capture.stopped:
                self._emit("har", har=self.har.document(incomplete=bool(self.failure)) if self.har else None,
                           payload={} if self.har else {"reason": "capture_policy"})
                self._emit("closed", payload={"reason": "context_closed"})
        finally:
            try:
                if self.cdp:
                    await self.cdp.close()
            finally:
                try:
                    if self.owner:
                        await self.owner.close()
                finally:
                    try:
                        if self.playwright:
                            await self.playwright.stop()
                    finally:
                        if self.capture:
                            self.capture.close()
                        if self.temp:
                            self.temp.cleanup()
