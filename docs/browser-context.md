# Browser context

English | [中文](browser-context.zh-CN.md)

Record one owned Chromium context through the optional Playwright entry. Capture
operations, pages, frames, requests, redirects, service-worker traffic, download
digests, screenshots and privacy-projected HAR; import through the existing context interface and share
through signed Bundles or offline reading copies.

## Install

Use Python 3.12 or newer in a dedicated environment:

```sh
python3 -m venv .venv-browser
.venv-browser/bin/python -m pip install -r python/browser-requirements.txt
.venv-browser/bin/python -m playwright install chromium
```

On Linux, install system dependencies with that environment's
`python -m playwright install-deps chromium`, using your normal package-management
permissions. The requirements pin Playwright 1.65.2 and its browser build; the
capture records the actual browser version.

## Record a task

Set `PYTHONPATH` to the repository's `python` directory. In an async tool handler:

```python
from agentprov.browser import Browser

placement = {
    "producer_id": "node-a", "namespace": "research",
    "instance_id": "sandbox-42", "generation": "launch-1",
}
async with Browser("browser.jsonl", placement) as browser:
    page = browser.first_page
    await browser.operation(page, "navigate", "https://example.com/")
    result = await browser.operation(page, "read_text")
    await browser.operation(page, "screenshot")
```

`new_page()` creates a page; `operation(page, "click", selector)` uses a
Playwright locator. Same-page operations serialize, while different pages can
run concurrently. Results contain scope, page and operation IDs. Incomplete
operations retain `unknown` and are not automatically retried.

The entry owns a fresh browser profile/context, enables Chromium's sandbox, uses
a loopback-only debugging connection and minimal process environment, and cleans
up its profile on exit. Linux must permit that browser to create user namespaces.
On restricted Ubuntu installations, configure a path-specific rule following
the [Chromium guide](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).
Startup fails when sandboxing is unavailable; there is no automatic unsafe fallback.
Apply workload filesystem/network restrictions at the deployment boundary.

## Read and share

```sh
agentprov context import --run research --harness browser --file browser.jsonl --capture detailed
agentprov context project --run research
agentprov context list --run research
agentprov dashboard export --run research --output research.zip
```

`--capture basic` retains identities and operation summaries while omitting
optional source/result bodies, screenshots and HAR. `--capture-attachments=false`
independently disables stored attachments. At the producer, `screenshots=False`
skips acquiring pixels and `har=False` skips building the archive; native network
events remain available. Read either type with `context attachment`; omit selected
bytes from sharing copies with `dashboard export --exclude-attachment REF`.
Excluding a supporting request record also excludes its entire HAR archive from
that reading copy, with reason `har_request_excluded`; the original stays intact.

## HAR network records

On context close, the producer writes a HAR 1.2 archive as an
`application/har+json` attachment. Each request retains its CDP session, target,
request ID and redirect hop in `_agentprovenance`. The importer checks these
against observed requests and projects the archive again before storage. Source
and retained SHA-256 digests remain separate.

Headers, cookies, query values and request/response bodies are omitted. Paths and
methods remain visible. Request outcomes distinguish `finished`, `failed`,
`redirected` and `pending`; a closing context can still contain pending requests.
Unknown phase timings use `-1`. HAR `time` sums the available phases (excluding
SSL already included in connect); `observed_duration_ms` separately records the
native start-to-end interval when available. A zero phase sum with unknown phases
is not a measured zero-duration request.

Archives are bounded to 4,096 entries including redirect hops and 8 MiB. Budget
exhaustion marks the archive `incomplete` and counts omitted entries, while native
event capture continues within its own limits. All attachments share the existing
256-manifest / 64 MiB per-run budget. Reading is paged JSON/base64, never an
executable response or an automatic request to captured URLs.

## Identity and privacy

- Native context, target, CDP session, frame, loader and request IDs remain
  distinct. Redirect hops qualify reused request IDs; generation and placement
  isolate independent executions.
- Requests are independent of tool operations. Worker/background requests keep
  their observed scope, without time-window attribution to a click or syscall.
- Before persistence, omit HTTP headers, cookies and POST bodies, remove URL
  userinfo/fragments and replace all query data. The importer repeats this
  projection. Retained paths and explicitly read page text can contain private
  business data: review them before sharing.
- Screenshots use static PNG attachments with separate source/retained digests.
  Pixels are not automatically redacted. Existing attachment limits, selection
  and offline reading apply; script-like text stays inert.
- Limits: 24,000 events, 128 MiB JSONL, 4,096 request identities, 256 observed
  targets, 32 controlled pages/downloads, and 64 screenshots totalling 64 MiB.
  Downloads are limited to 8 MiB each; records retain native ID, completion and
  digest. Capture failures remain explicit gaps.

## Integration check

```sh
PYTHONPATH=python .venv-browser/bin/python scripts/accept_browser.py \
  --output /tmp/browser-check --agentprov /absolute/path/to/agentprov
```

This controlled workflow runs two independent browsers, each with two concurrent
pages. It checks redirects, iframe/worker/background traffic, download digests,
screenshots, HAR request-set equality, privacy canaries, both retention presets and signed import into a
separate store. It produces full, attachment-excluded, HAR-only and
request-excluded offline ZIPs. No model
API key or system sensor is required.

References: [browser contexts](https://playwright.dev/python/docs/api/class-browsercontext),
[request lifecycle](https://playwright.dev/python/docs/api/class-request),
[Chromium target/session identities](https://chromedevtools.github.io/devtools-protocol/tot/Target/).
