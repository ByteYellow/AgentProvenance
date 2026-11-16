# Browser context

English | [中文](browser-context.zh-CN.md)

Record one owned Chromium context through the optional Playwright entry. Capture
operations, pages, frames, requests, redirects, service-worker traffic, download
digests, screenshots and privacy-projected HAR; import through the existing context interface and share
through signed Bundles or offline reading copies.

## Why record browser context

A research task may open a page, read its text and take a screenshot while the
same browser processes continue serving other pages. System telemetry identifies
those processes and their network or file activity. Page, frame and operation
IDs add the task-level context needed to inspect each action and its saved result.

The Playwright entry records these identities at the browser boundary. For an
"open, read, screenshot" task, follow the Agent tool result to the recorded
operation, page and retained text or image. Requests, redirects and background
workers keep their own references, so their relationship to an operation can be
inspected in the saved records.

Use the Python entry in an existing tool, or the supplied stdio MCP server to
connect an Agent. Add Linux system collection when process/file/network evidence
is needed; choose its location using the [deployment guide](deployment-modes.md#choose-collection-by-kernel-boundary).

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
the owned browser. Reusing the private capture directory after a bridge restart
allows `browser_result` to recover the original receipt without opening a browser
or executing an action. Missing results remain `unknown`; historical receipts
keep their original scope and generation. The current producer/namespace/instance
bounds lookup, and conflicting IDs or damaged journals return explicit gaps.
Admission is durably recorded before dispatch. There is no HTTP listener or
session reconnect protocol.

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

### Receiver-pinned local import

The synchronous local operator path uses the same `context import` command and
evidence store. On Linux or macOS:

```sh
agentprov context import --run RUN --harness browser --capture basic \
  --browser-owned-config /private/receiver/browser-import.json \
  --browser-receipts /private/captures/task-1/receipts.json
```

`receipts.json` is a JSON array of the original `browser_receipt` values from
`browser_execute` or `browser_result`. Source overrides (`--file`, `--session`,
`--agent`, nonzero `--after-line`) are rejected for this path. Ordinary `--file`
imports and transcript `action_result` receipts retain `unverified` source trust.

The receiver operator supplies this configuration **outside the capture directory**:

```json
{
  "directory": "/private/captures/task-1",
  "manifest_name": "browser-owned.json",
  "manifest_sha256": "sha256:<receiver-approved manifest digest>",
  "run_id": "RUN",
  "placement": {
    "producer_id": "node-a", "namespace": "research",
    "instance_id": "sandbox-42", "generation": "launch-1"
  },
  "bridge_id": "research-browser-bridge",
  "bridge_config_digest": "sha256:<receiver-approved bridge configuration digest>"
}
```

Replace digest placeholders with `sha256:` followed by 64 lowercase hexadecimal
characters. The operator obtains the manifest pin and expected placement/bridge
configuration from its trusted launcher or collector channel. The importer never
derives an authority pin from an incoming artifact. A self-supplied manifest,
copied config, transcript trust string, or private file mode is not that channel;
same-UID agents require an independently protected operator boundary.

The pinned manifest seals exact complete JSONL prefixes:

```json
{
  "schema_version": "agentprovenance.browser_owned_capture/v1",
  "run_id": "RUN",
  "placement": {
    "producer_id": "node-a", "namespace": "research",
    "instance_id": "sandbox-42", "generation": "launch-1"
  },
  "bridge_id": "research-browser-bridge",
  "bridge_config_digest": "sha256:<same approved configuration digest>",
  "logs": [{
    "name": "browser.jsonl",
    "scope": {
      "producer_id": "node-a", "namespace": "research",
      "instance_id": "sandbox-42", "generation": "launch-1",
      "browser_id": "<recorded browser id>", "context_id": "<recorded context id>"
    },
    "prefix_bytes": 12345,
    "sha256": "sha256:<digest of those exact prefix bytes>"
  }]
}
```

Use the real prefix length and recorded IDs. The manifest digest covers its exact
file bytes, not reserialized JSON. Paths must be absolute, canonical and free of
symlinks. Capture and receiver directories must be owned by the effective user
and private (normally `0700`); input files must be private regular files with one
hard link (normally `0600`). The loader rejects unsafe files, replacement,
truncation, duplicate JSON fields, corrupt sealed lines and identity conflicts.
Append-only growth beyond the sealed prefix is ignored until the operator pins
a new manifest. Each configuration binds one original generation.

All receipts are validated before a single transaction stores context records
and independent `browser_receipt_binding` objects. The JSON response contains
`verified_receipts`, `imports`, `bindings` and stable `binding_refs`. Each binding
records `basis=local_operator_pinned_capture`, exact run/scope/bridge, manifest
and receipt digests, and verified original source refs. Input/result digests are
recomputed from privacy-projected journal fields; source line hashes include the
newline. The original receipt's `bridge_identity.authentication` stays
`unverified`. Repeated import is idempotent, and verification performs no actions.
Signed bundles preserve the binding as evidence; another receiver must validate
it against its own operator configuration before granting local bridge authority.

The synchronous Go APIs are `LoadBrowserLocalImportConfig`,
`LoadBrowserReceiptList` and `Service.ImportOwnedBrowser(ctx, runID, cfg, receipts)`.
For in-process verification without persistence, use `ImportOwnedBrowserCapture`
then `VerifyReceipt`; its opaque `VerifiedBrowserReceipt` cannot be constructed
by decoding JSON. Limits are 64 logs, 128 MiB per log, 256 MiB total sealed bytes,
and 1,024 receipts / 4 MiB per import. `unknown` stays `unknown`; a navigate
admission without `action_start` lacks the URL projection needed to recompute its
input digest and returns `browser_import_input_projection_unavailable` on this
trusted path. Ordinary recovery still retains that admission. Process/socket/file
attribution uses separately witnessed runtime identities, outside this binding.

### Receiver-owned Browser/runtime custody

On Linux or macOS, `graph lens` and `dashboard export` accept the explicit local
`--browser-custody-config` option. It connects an authenticated Browser context
to an operator-mapped native process lifetime, then retains that process's OS
observations. The relation stays at context/process level: a shared network or
renderer process does not assign its socket/file activity to an individual click.
Existing runtime event/file and connection/stream evidence keeps its own identity.

Prepare the inputs through these separate channels:

1. **Manifest and bridge pins:** use the receiver-approved `browser-import.json`
   from the preceding section. The launcher/collector seals complete log lines
   and supplies its manifest digest, run, placement, bridge ID and launch-config
   digest over the operator-controlled channel. Hashing the exact sealed manifest
   with `shasum -a 256 /operator/sealed/browser-owned.json` checks the producer's
   approved bytes; the receiver compares that result with its external pin.
2. **Scope and receipt selector:** obtain the original receipt from
   `browser_execute` or `browser_result`. Copy its six-field `scope` and `digest`
   into the mapping. `jq '.[0] | {scope, receipt_digest: .digest}' receipts.json`
   shows those selectors. The loader independently re-verifies that receipt
   against the pinned original log; it ignores the receipt's trust claims.
3. **Host and process birth:** the trusted launcher/collector must record which
   process lifetime serves that exact context/generation. Inspect its native
   evidence with `agentprov --data-dir /private/evidence telemetry list --run RUN
   --json --limit 100`, following `next_cursor` when necessary. Use a recorded
   `agentprov_ebpf` event with `runtime_process_identity=agentprov.runtime_process/v3`.
   Copy the exact `host_id`, event `pid`, and `process_instance_id` from its payload
   (or nested `payload`/`raw` envelope), and cross-check the launcher's custody
   record. The instance has the form `boot-UUID:PID:process_start_ns`; its boot and
   start value come from the collector's kernel lifetime identity, not wall-clock
   time, a fresh `ps` result, or CDP IDs. Host and Sentry PIDs are separate domains.

The current Browser entry supplies CDP scope and receipts. The operator's
context-to-process custody record is a separate required input; this feature
does not discover it by process name, URL, proximity, or a guest/host PID guess.

Use this template for `/private/receiver/browser-runtime.json`, replacing every
placeholder with the approved or recorded value:

```json
{
  "schema_version": "agentprovenance.browser_runtime_custody/v1",
  "capture_config": "/private/receiver/browser-import.json",
  "receipts": "/private/captures/task-1/receipts.json",
  "run_id": "RUN",
  "manifest_sha256": "sha256:<same receiver-approved manifest digest>",
  "bridge_id": "research-browser-bridge",
  "bridge_config_digest": "sha256:<same receiver-approved bridge configuration digest>",
  "mappings": [{
    "scope": {
      "producer_id": "node-a", "namespace": "research",
      "instance_id": "sandbox-42", "generation": "launch-1",
      "browser_id": "<recorded browser id>", "context_id": "<recorded context id>"
    },
    "receipt_digest": "sha256:<selected original receipt digest>",
    "role": "browser",
    "host_id": "<native collector host id>",
    "pid": 1234,
    "process_instance_id": "<recorded boot UUID>:1234:<recorded process start ns>"
  }]
}
```

Digest values use 64 lowercase hexadecimal characters after `sha256:`. Replace
the example PID in both fields. Roles are `browser`, `renderer`, or `network`;
conflicting process assignments for the same scope/role are rejected. Both
authority files must be outside the capture and store evidence directories,
including Bundle/artifact storage. Provision them in the receiver's private
directory (`0700`) as private regular files (`0600`), without symlinks or extra
hard links. The config is bounded to 64 KiB and 128 mappings. Receipts and imported
`browser_receipt_binding` JSON describe evidence; only the explicit receiver
configuration authorizes this local calculation.

After the owned import, run the production commands:

```sh
agentprov --data-dir /private/evidence graph lens --run RUN --detail raw --json \
  --browser-custody-config /private/receiver/browser-runtime.json \
  > /private/receiver/browser-lens.json
agentprov --data-dir /private/evidence dashboard export --run RUN \
  --browser-custody-config /private/receiver/browser-runtime.json \
  --output /private/receiver/browser-reader.zip
```

The graph command requires local access; omit `--daemon-url`. Add the usual
`--sign-key` and `--exporter-id` to sign a derived reading copy. This option is not
an HTTP request trust flag. Applications call `browsercustody.Load(ctx, path,
store.ResolvePaths(dataDir))` to obtain an opaque capability, then `Resolve(ctx,
db, run)` for the selected database, or set the local `dashboard.Server.BrowserCustody`
configuration. Decoding JSON cannot construct that capability.

The loader rechecks manifest/bridge/run/scope, receipt and original source refs.
The resolver matches the retained native projections to those verified sources;
basic capture can retain that projection without raw text. Detailed retained raw
text is checked when available. Graph queries and frozen exports use the same
rules. Excluding a supporting record with `--exclude-record entry/ENTRY_ID` drops
its custody mapping; excluding `runtime` removes its OS observations. Missing
sensor identity or missing support remains unresolved. The default command, with
no external custody config, grants no runtime custody from imported objects.

#### Native sensor acceptance

The portable fixture tests build and execute the real CLI with synthetic native
events. Run the opt-in check below on the x86 receiver after importing the actual
owned capture and collecting its native sensor evidence:

```sh
AGENTPROV_BROWSER_CUSTODY_CONFIG=/private/receiver/browser-runtime.json \
AGENTPROV_BROWSER_DATA_DIR=/private/evidence \
go test -p 2 -timeout 20m ./internal/provenance \
  -run '^TestBrowserLayerOperatorIngress$' -count=1 -v
```

Acceptance requires a passing test with **`matched_native_process_observations > 0`**,
the expected run/scope/host/process birth, and the corresponding production CLI
graph and exported reader. A zero match fails this check. With neither environment
variable set, the test explicitly **SKIPs**; ordinary `-run Browser` test success
therefore leaves this sensor-on acceptance pending. Exercise concurrent contexts,
background/cache traffic, process reuse and exclusion cases in that environment
while keeping operation-level causes separate from shared process activity.

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

Verify existing Chrome live artifacts through the actual owned-import CLI:

```sh
python3 scripts/accept_browser_owned_import.py \
  --agentprov /absolute/path/to/agentprov \
  --artifacts /absolute/path/to/chrome-live-artifacts \
  --output /private/browser-owned-import-check --approve-fixture-pin
```

The input directory contains `results.json` with
`observations[].result.browser_receipt` and the original `capture/*.jsonl`.
The script reads those bytes without running a browser, copies private snapshots,
and creates separate receiver configurations with explicitly approved **fixture**
pins. It checks receipt/source/digest preservation, original generations,
idempotence, false pins, artifact self-authorization, forged receipts,
cross-generation rejection, and signed bundle import into a separate store.
`results.json` records `fixture_operator_pin=true`; this is an importer check of
actual Chrome bytes, while production launch authentication uses the receiver's
own external pin. Fixture signing keys stay private in the output directory.

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
Sensor capture is off in this application-entry check; launch's process sampling
remains recorded separately.

References: [browser contexts](https://playwright.dev/python/docs/api/class-browsercontext),
[request lifecycle](https://playwright.dev/python/docs/api/class-request),
[Chromium target/session identities](https://chromedevtools.github.io/devtools-protocol/tot/Target/).
