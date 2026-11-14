#!/usr/bin/env python3
"""Real Chromium fixture: parallel pages, redirect, iframe, worker and background traffic.

Use a fresh output directory. Only owned browser profiles and a loopback fixture
server are used. Optional CLI checks import both retention presets and signed ZIPs.
"""

import argparse
import asyncio
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading

from agentprov.browser import Browser


SECRET = "BROWSER_PRIVATE_CANARY_27c8"
PAGE = b'''<!doctype html><title>Browser evidence fixture</title>
<h1>BROWSER_EVIDENCE_OK</h1><pre>&lt;script&gt;window.OFFLINE_EXECUTED = true&lt;/script&gt;</pre>
<iframe src="/frame"></iframe><button id="run">Fetch background data</button>
<a id="download" href="/report.csv" download>Download report</a>
<script>
window.workerReady = false;
navigator.serviceWorker.register('/sw.js').then(() => navigator.serviceWorker.ready).then(() => window.workerReady = true);
document.querySelector('#run').onclick = async () => {
  await fetch('/background?token=BROWSER_PRIVATE_CANARY_27c8', {method:'POST',
    headers:{'Authorization':'Bearer BROWSER_PRIVATE_CANARY_27c8'}, body:'BROWSER_PRIVATE_CANARY_27c8'});
  window.backgroundDone = true;
};
</script>'''
WORKER = b'''self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', e => e.waitUntil(fetch('/worker-background?key=BROWSER_PRIVATE_CANARY_27c8').then(() => self.clients.claim())));
self.addEventListener('fetch', e => { if (e.request.url.includes('/background')) e.respondWith(fetch(e.request)); });'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 16384))
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/index?token=" + SECRET)
            self.end_headers()
            return
        body, media = b"ok", "text/plain"
        if path == "/index":
            body, media = PAGE, "text/html"
        elif path == "/sw.js":
            body, media = WORKER, "application/javascript"
        elif path == "/frame":
            body, media = b"<p>frame</p><script>fetch('/iframe-background')</script>", "text/html"
        elif path == "/report.csv":
            body, media = b"region,total\nalpha,40\nbeta,20\n", "text/csv"
        self.send_response(200)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "session=" + SECRET + "; Path=/")
        if path == "/report.csv":
            self.send_header("Content-Disposition", 'attachment; filename="report.csv"')
        self.end_headers()
        self.wfile.write(body)


async def run_browser(out, origin, suffix):
    placement = {"producer_id": "browser-acceptance", "namespace": "local-fixture", "instance_id": "lab", "generation": suffix}
    capture = out / (suffix + ".jsonl")
    async with Browser(capture, placement) as browser:
        a, b = browser.first_page, await browser.new_page()
        results = await asyncio.gather(browser.operation(a, "navigate", origin + "/redirect"),
                                       browser.operation(b, "navigate", origin + "/redirect"))
        for page in (a, b):
            await browser.pages[page].wait_for_function("window.workerReady === true", timeout=20000)
        await asyncio.gather(browser.operation(a, "click", "#run"), browser.operation(b, "click", "#run"))
        for page in (a, b):
            await browser.pages[page].wait_for_function("window.backgroundDone === true", timeout=20000)
        text = await browser.operation(a, "read_text")
        if "BROWSER_EVIDENCE_OK" not in text["text"]:
            raise AssertionError("browser did not read the real page")
        await browser.operation(a, "screenshot")
        await browser.operation(a, "click", "#download")
        for _ in range(100):
            rows = [json.loads(line) for line in capture.read_text().splitlines()]
            if any(r.get("kind") == "download_finished" and
                   r.get("payload", {}).get("sha256") == hashlib.sha256(b"region,total\nalpha,40\nbeta,20\n").hexdigest() for r in rows):
                break
            await asyncio.sleep(.1)
        else:
            raise AssertionError("native download completion missing")
        if browser.failure:
            raise AssertionError(browser.failure)
        scope = dict(browser.capture.scope)
        version = browser.owner.browser.version
    rows = [json.loads(line) for line in capture.read_text().splitlines()]
    if SECRET in capture.read_text():
        raise AssertionError("credentials reached capture file")
    requests = [r for r in rows if r.get("kind") == "request"]
    worker = [r for r in requests if r.get("target_type") == "service_worker"]
    if not worker or not any("/worker-background" in r["payload"]["url"] for r in worker):
        raise AssertionError("service worker native requests missing")
    if not all(any(r["target_id"] == p and "/background" in r["payload"]["url"] for r in requests) for p in (a, b)):
        raise AssertionError("parallel pages lost request identity")
    if not any(r.get("redirect_index") == 1 for r in requests):
        raise AssertionError("redirect hop identity missing")
    if not any("/iframe-background" in r["payload"]["url"] and r.get("frame_id") for r in requests):
        raise AssertionError("iframe native request missing")
    if any(r.get("operation_id") for r in requests):
        raise AssertionError("background request borrowed a tool operation")
    archives = [r["har"] for r in rows if r.get("kind") == "har"]
    if len(archives) != 1 or archives[0]["log"]["_agentprovenance"]["capture_state"] != "closed":
        raise AssertionError("HAR archive missing or incomplete")
    har_entries = archives[0]["log"]["entries"]
    key = lambda r: (r["cdp_session_id"], r["request_id"], r["redirect_index"])
    if {key(e["_agentprovenance"]) for e in har_entries} != {key(r) for r in requests}:
        raise AssertionError("HAR native request set differs from captured requests")
    if not any(e["_agentprovenance"]["outcome"] == "redirected" for e in har_entries):
        raise AssertionError("HAR lost redirect outcome")
    if not any(e["_agentprovenance"]["observed_duration_ms"] is not None and e["_agentprovenance"]["observed_duration_ms"] > 0 for e in har_entries):
        raise AssertionError("HAR native duration unavailable")
    for e in har_entries:
        if e["request"]["headers"] or e["request"]["cookies"] or e["response"]["headers"] or e["response"]["cookies"] or "text" in e["response"]["content"]:
            raise AssertionError("HAR retained private transport data")
    return {"scope": scope, "browser_version": version, "pages": [a, b], "events": len(rows),
            "requests": len(requests), "worker_requests": len(worker), "operations": len([r for r in rows if r.get("kind") == "action_start"])}


def verify_store(binary, out):
    env = {**os.environ, "AGENTPROV_DAEMON_URL": "", "AGENTPROV_LANG": "en"}

    def cli(data, *args, json_result=True):
        result = subprocess.run([binary, "--data-dir", str(data), "--lang", "en", *map(str, args)],
                                env=env, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(f"CLI failed: {args}\n{result.stderr}")
        return json.loads(result.stdout) if json_result else result.stdout

    private, public = out / "signing.key", out / "signing.pub"
    cli(out / "keys", "forensics", "keygen", "--priv", private, "--pub", public, json_result=False)
    results, identities = {}, {}
    for preset in ("basic", "detailed", "detailed-no-attachments"):
        data, restored, run = out / preset, out / (preset + "-restored"), "browser-" + preset
        for capture in (out / "first.jsonl", out / "second.jsonl"):
            flags = ["--capture", preset.split("-")[0]]
            if preset == "detailed-no-attachments":
                flags += ["--capture-attachments=false"]
            imported = cli(data, "context", "import", "--run", run, "--harness", "browser", "--file", capture, *flags)
            repeated = cli(data, "context", "import", "--run", run, "--harness", "browser", "--file", capture, *flags)
            if imported["stored"] == 0 or repeated["stored"] or repeated["duplicates"] != imported["stored"]:
                raise AssertionError("browser import was not idempotent")
        cli(data, "context", "project", "--run", run)

        def entries(store):
            saved, cursor = [], ""
            while True:
                page = cli(store, "context", "list", "--run", run, "--limit", "100", "--cursor", cursor)
                saved.extend(page["entries"])
                if not page["has_more"]:
                    return saved
                if page["next_cursor"] == cursor:
                    raise AssertionError("context paging stalled")
                cursor = page["next_cursor"]

        original = entries(data)
        identities[preset] = [(e["source"]["session_id"], e.get("browser"), e.get("tool_call_id")) for e in original]
        bundle = cli(data, "forensics", "export", run, "--sign-key", private, "--json")
        if not bundle["signed"]:
            raise AssertionError("browser bundle is not signed")
        cli(data, "forensics", "verify-attestation", bundle["path"], bundle["attestation_path"], "--pub-key", public, json_result=False)
        verified = cli(restored, "forensics", "import", bundle["path"], "--pub-key", public, "--json")
        if not verified["attestation_verified"]:
            raise AssertionError("browser import did not verify its signature")
        data.rename(out / (preset + "-unavailable"))
        if entries(restored) != original:
            raise AssertionError("signed browser import changed records")
        graph = cli(restored, "graph", "verify", "--run", run, "--json")
        if graph["error_count"] or graph["warning_count"]:
            raise AssertionError("browser graph verification failed")
        attachments = [a for e in original for a in e.get("attachments", [])]
        if len(attachments) != 4 or sum(a["source_media_type"] == "application/har+json" for a in attachments) != 2:
            raise AssertionError("browser screenshot or HAR references missing")
        if preset == "detailed":
            for item in attachments:
                content, offset = bytearray(), 0
                while True:
                    page = cli(restored, "context", "attachment", "--run", run, "--ref", item["ref"], "--offset", offset, "--limit", "7193")
                    content.extend(base64.b64decode(page["data"], validate=True))
                    if not page["has_more"]:
                        break
                    offset = page["next_offset"]
                if hashlib.sha256(content).hexdigest() != item["sha256"]:
                    raise AssertionError("browser attachment digest mismatch")
                if item["media_type"] == "application/har+json":
                    archive = json.loads(content)
                    if SECRET.encode() in content or not archive["log"]["entries"]:
                        raise AssertionError("stored HAR privacy or content failure")
            cli(restored, "dashboard", "export", "--run", run, "--output", out / "browser-full.zip", json_result=False)
            excluded = [flag for a in attachments for flag in ("--exclude-attachment", a["ref"])]
            cli(restored, "dashboard", "export", "--run", run, *excluded, "--output", out / "browser-excluded.zip", json_result=False)
            images = [flag for a in attachments if a["media_type"] == "image/png" for flag in ("--exclude-attachment", a["ref"])]
            cli(restored, "dashboard", "export", "--run", run, *images, "--output", out / "browser-har-only.zip", json_result=False)
            request = next(e for e in original if e.get("browser", {}).get("kind") == "request")
            cli(restored, "dashboard", "export", "--run", run, "--exclude-record", "entry/" + request["id"],
                "--output", out / "browser-request-excluded.zip", json_result=False)
        elif any(a["state"] != "omitted" or a["reason"] != "capture_policy" for a in attachments):
            raise AssertionError("disabled screenshot retention saved pixels")
        results[preset] = {"run_id": run, "entries": len(original), "attachments": attachments, "graph": graph, "bundle_sha256": bundle["sha256"]}
    if identities["basic"] != identities["detailed"] or identities["basic"] != identities["detailed-no-attachments"]:
        raise AssertionError("retention changed browser associations")
    return results


async def capture(out, origin):
    async with asyncio.TaskGroup() as tasks:
        a = tasks.create_task(run_browser(out, origin, "first"))
        b = tasks.create_task(run_browser(out, origin, "second"))
    first, second = a.result(), b.result()
    if first["scope"]["browser_id"] == second["scope"]["browser_id"] or first["scope"]["context_id"] == second["scope"]["context_id"]:
        raise AssertionError("independent tasks shared native browser identity")
    return {"first": first, "second": second}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--agentprov")
    args = parser.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = capture_result = asyncio.run(capture(out, "http://127.0.0.1:" + str(server.server_port)))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    if args.agentprov:
        (out / "capture.json").write_text(json.dumps(capture_result, indent=2) + "\n")
        result = {"capture": capture_result, "store": verify_store(str(Path(args.agentprov).resolve()), out)}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
