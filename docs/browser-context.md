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

### Connect an Agent through MCP

The optional stdio server owns the same recorded browser. Configure your Agent's
MCP client with absolute paths and a new private capture directory:

```json
{
  "mcpServers": {
    "browser": {
      "command": "/path/to/.venv-browser/bin/python",
      "args": ["-m", "agentprov.browser_mcp", "--capture-dir", "/private/captures/task-1",
        "--producer-id", "node-a", "--namespace", "research",
        "--instance-id", "sandbox-42", "--generation", "launch-1"],
      "env": {"PYTHONPATH": "/path/to/AgentProvenance/python"}
    }
  }
}
```

Use `browser_pages` to find the default page, `browser_new_page` for another
page, and `browser_execute(page_id, action, value)` for one operation. After a
waiting timeout, call `browser_result(operation_id)` instead of repeating the
operation. Waiting, execution and capture have separate status fields. Caller
cancellation stops waiting; server shutdown cancels outstanding tasks and closes
the owned browser. There is no HTTP listener or persistent reconnect protocol.

Record the Agent with `agentprov launch` or its supported hooks/transcript
integration. Import `CAPTURE_DIR/browser.jsonl` into that same Run, then project:

```sh
agentprov context import --run RUN --harness browser --file CAPTURE_DIR/browser.jsonl
agentprov context project --run RUN
agentprov context links --run RUN --entry AGENT_RESULT_ENTRY_ID
```

The versioned tool result retains `browser_operation` before body filtering,
including in basic mode. Its full scope, page, operation ID and action resolve
to one native capture. Both hook and transcript observations retain navigation;
competing claims stay `browser_operation_unresolved`. Links use
`source_asserted_native_identity` and rule `browser-mcp/v1`. Polling results do not
create another execution link, and network traffic keeps its own native scope.
Signed import preserves references. Excluding the supporting operation from an
offline copy removes its navigation link while preserving the caller's reference.

Each server retains at most 1,024 operations with 32 pending, and returns at most
32 KiB of page text per result. `--no-screenshots` and `--no-har` control capture
at the producer. Page text, URLs and tool inputs may contain private data; review
the Agent's saved context as well as Browser attachments before sharing.

### Import a standalone capture

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

Exercise the actual stdio MCP protocol without a model key:

```sh
PYTHONPATH=python .venv-browser/bin/python scripts/accept_browser_mcp.py --output /tmp/browser-mcp-check
```

For a real Agent task, use an existing Claude Code provider configuration:

```sh
PYTHONPATH=python .venv-browser/bin/python scripts/accept_browser_agent.py \
  --output /private/browser-agent-check --agentprov /absolute/path/to/agentprov \
  --claude /absolute/path/to/claude --capture detailed
```

The task reads a local table, downloads its CSV and takes a screenshot. The
fixture verifies native Agent/Browser links, repeat import, signed delivery to a
separate store and full/selected offline ZIPs. Repeat with `--capture basic` for
body-independent association. Provider usage is capped per invocation; logs,
captures and fixture keys remain in the private output directory. System
telemetry is off in this application-entry check.

References: [browser contexts](https://playwright.dev/python/docs/api/class-browsercontext),
[request lifecycle](https://playwright.dev/python/docs/api/class-request),
[Chromium target/session identities](https://chromedevtools.github.io/devtools-protocol/tot/Target/).
