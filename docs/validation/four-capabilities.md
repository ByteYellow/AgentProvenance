# Portable Evidence Acceptance

English | [中文](../zh-CN/validation/four-capabilities.md)

This guide covers the four-capability source increment on
`feature/v1.0-portable-evidence`: controlled workspaces, evidence delivery,
runtime adapters and layered Browser evidence. It is an acceptance handoff,
not a release announcement. The Dashboard changes remain in local preview.

## Current Scope

| Task | Available implementation | Acceptance remaining |
| --- | --- | --- |
| C-01 | Observation domain, scope, policy subject, capability intervals and runtime identity projections | Check new runtime observations on the selected x86 deployment |
| W-01 | Remote-authoritative workspace, revision/digest conflicts, CLI and stdio MCP | Repeat with the final x86 build and Sensor; combine with Kata |
| E-01/E-02 | Reading, signed selected reader, exact originals, recipient-owned trust and independent verifier | Final-build regression; Dashboard controls await review |
| R-01 | Separate platform, execution and capture contracts; native default retained | New-platform integration matrix |
| R-02 | Guest binding, fixed-container runsc execution, separately scoped SecCheck observations | Real runtime identity probe and failure matrix; per-command Sentry association still needs a shared call/lifetime identity and capture watermark |
| R-03 | Kata/QEMU Guest binding and bounded acceptance fixture | Run on Kubernetes with `kata-qemu-runtime-rs`, pinned artifacts and Guest Sensor permissions |
| B-01 | Persistent Browser acceptance/results, restart queries and receiver-owned receipt verification | Repeat with final build; combine with Sensor-on capture |
| B-02 | Native-ID-based Browser layers, versioned rules and evidence references | Run the controlled Browser scenario matrix on Linux |
| B-03 | Explicit runtime custody and kernel process-lifetime checks | Establish actual launcher custody and validate process/OS relations with Sensor on |
| Q-01 | Regression scripts, independent export checks and bounded soak sampler | 24-hour run, recovery/resource review and two complete Linux cases |

R-02's container evidence and command receipts currently remain separate. The
x86 identity probe gathers the fields needed to close that implementation gap;
its success alone does not finish per-command association. Do not replace this
join with command text, PID alone or a time window.

The local workspace case used an ARM Linux VM, Claude Code 2.1.293 and its
existing DeepSeek provider. It completed Inspect, Read, Edit, Write, Bash and a
final Read through `agentprov_workspace`; one recorded command produced the
expected file. Sensor was off. Its original bundle, exporter signature and
producer signature passed recipient-side verification. Offline Chrome inspected
99 queries, 36 views and 12 saved bodies with no external network request.

The local Browser case uses real Chrome and stdio MCP against a controlled
loopback site. Restart queries preserve completed results and interrupted
`unknown` results without repeating the action. Linux OS attribution is a
separate acceptance row.

## Prepare the Checkout

Fetch the feature branch without merging it into `main`. Keep test artifacts in
a fresh private directory outside the checkout. Record the source revision and
any local changes before building:

```sh
git fetch origin feature/v1.0-portable-evidence
git switch feature/v1.0-portable-evidence
git pull --ff-only origin feature/v1.0-portable-evidence
git status --short
git rev-parse HEAD
go version
uname -a
```

Build the executable and independent verifier from the same revision. Set
`OUT` to a new absolute private directory, then record their hashes:

```sh
mkdir -m 700 "$OUT"
go build -trimpath -o "$OUT/agentprov" ./cmd/agentprov
go build -trimpath -o "$OUT/agentprov-verify" ./cmd/agentprov-verify
sha256sum "$OUT/agentprov" "$OUT/agentprov-verify"
go test ./...
go vet ./...
go test -race -p 2 -timeout 20m ./...
```

Kata's version lock additionally needs embedded `internal/buildinfo.Version`
and `internal/buildinfo.Commit`; follow its build instructions before that run.
Use the optional Python dependencies documented by each integration. The
workspace MCP bridge was tested with MCP 2.3.0. The Browser scripts also require
Playwright and an installed Chrome/Chromium. No API key is needed for the local
Browser fixture or the workspace contract-only test.

## Controlled Workspace

Run these commands **inside the machine that owns the workspace**. The entire
Harness and its stdio bridge run there; files are not synchronized back and forth.

```sh
PYTHONPATH=python python3 -m unittest discover -s python/tests -p test_workspace_mcp.py
python3 scripts/accept_workspace.py --agentprov "$OUT/agentprov" \
  --python-package "$PWD/python" --output "$OUT/workspace-contract"
```

For the real Harness case, use an existing, authenticated Claude Code wrapper:

```sh
python3 scripts/accept_workspace.py --agentprov "$OUT/agentprov" \
  --python-package "$PWD/python" --claude /absolute/claude-wrapper \
  --output "$OUT/workspace-harness"
```

The script verifies the connected MCP inventory and actual `tool_use` records,
not text claiming to have called a tool. Its server key is `agentprov_workspace`.
Keep provider credentials in the existing operator environment. The contract
test checks nine cases, including stale revisions, concurrent edits, restart
queries, path boundaries, generation changes and evidence ownership. See the
[workspace guide](../workspace.md) for configuration and the actual tool contract.

On a Linux host with authorized BPF access and a writable cgroup v2 subtree, add
`--sensor`. The fixture owns one collector per store, checks probe readiness,
stops and drains it, and checks native events against the Bash record's cgroup
and workspace receipt. It creates no sudo policy or system service:

```sh
python3 scripts/accept_workspace.py --agentprov "$OUT/agentprov" \
  --python-package "$PWD/python" --claude /absolute/claude-wrapper \
  --sensor --sensor-placement local_kernel --output "$OUT/workspace-sensor"
```

Kata uses the Guest placement and the operator's existing Target file. Follow
the optional workspace case in the [Kata guide](kata-qemu.md) to include the
same Read/Edit/Write/Bash task and signed delivery in that profile.

## Browser Receipts and Native Relations

```sh
PYTHONPATH=python python3 python/tests/test_browser_receipts_live.py \
  --channel chrome --output "$OUT/browser-live"
python3 scripts/accept_browser_owned_import.py --agentprov "$OUT/agentprov" \
  --artifacts "$OUT/browser-live" --output "$OUT/browser-import" \
  --approve-fixture-pin
go test ./internal/agentcontext ./internal/browserlink ./internal/provenance \
  ./internal/dashboard -run 'TestBrowser' -count=1
```

The pin approval applies only to the synthetic fixture's copied capture. Real
imports use an independently approved receiver configuration outside the capture
directory. It fixes the run, bridge, placement and manifest digest. A receipt or
bundle cannot configure its own trust.

For B-03, retain the complete Browser scope and operator-observed process
lifetime alongside Sensor evidence. Include the host/boot, process birth,
collector scope and supporting event IDs. Report context-to-process and
process-to-effect evidence at their supported granularity. Test concurrent tabs,
redirects, background traffic, downloads, restart and missing evidence. The
[Browser guide](../browser-context.md) describes the available entry points and
remaining Sensor-on checks.

After importing the captured Browser records and native events into the same
store, use the external mapping configuration described in that guide. Execute
the opt-in check explicitly; the general test command skips it when its inputs
are absent:

```sh
AGENTPROV_BROWSER_CUSTODY_CONFIG="$CUSTODY" AGENTPROV_BROWSER_DATA_DIR="$DATA" \
  go test ./internal/provenance -run '^TestBrowserLayerOperatorIngress$' -count=1 -v
"$OUT/agentprov" --data-dir "$DATA" graph lens --run "$RUN" --detail raw \
  --browser-custody-config "$CUSTODY" --json
"$OUT/agentprov" --data-dir "$DATA" dashboard export --run "$RUN" \
  --browser-custody-config "$CUSTODY" --output "$OUT/browser-reader.zip"
```

Require `matched_native_process_observations > 0` in the live check. Inspect the
source references of the process/file/network relations, then repeat with a
selected export that excludes a supporting Browser record. The excluded support
must remove the corresponding runtime mapping from the reader. Configuration
files stay outside the capture and exported package.

## Runtime and Kata

Start with the [runtime adapter guide](../runtime-adapters.md). Its opt-in
`TestRunscLiveExecutionIdentityEvidence` creates an owned container and preserves
precise SecCheck identity fields. Then exercise the configured handoff daemon:
duplicate admission, query without reexecution, wrong generation, receiver
disconnect/restart, executor restart and delivery of both evidence scopes.

Run the [Kata/QEMU acceptance procedure](kata-qemu.md) on a dedicated authorized
namespace. Complete its private lock with measured versions and hashes first.
The fixture checks Guest BTF/probes/cgroups, Pod/container/Guest identities,
concurrent commands, collector recovery, Pod rebuild and offline delivery.
It does not install a runtime or alter cluster policies. Add the independent
verifier option so the same run also checks signed reading copies.

## Independent Delivery and Offline Reading

```sh
python3 scripts/accept_derived_view.py --agentprov "$OUT/agentprov" \
  --verifier "$OUT/agentprov-verify" --out "$OUT/delivery"
```

The fixture covers valid/unknown/wrong-role signers, tampered readers and
originals, selection boundaries and package-local policy replacement. Use the
actual generated ZIPs for the browser test. Set a known saved search phrase for
each custom capture:

```sh
PLAYWRIGHT_CHANNEL=chrome AGENTPROV_REPLAY_SEARCH_QUERY=result.txt \
  node scripts/accept_offline_replay.cjs /absolute/workspace-originals.zip
"$OUT/agentprov-verify" --trust-policy /absolute/recipient-policy.json \
  /absolute/workspace-originals.zip
```

The browser fixture uses offline `file://` access and no source database. It
checks selection, indexed content, graph views, search, Compare and mobile
overflow. The existing reader's unsigned-copy banner remains a known UI item
for signed modes while the UI preview is held. Use the independent verifier's
separate integrity, producer, exporter and trust fields for acceptance.

## Soak and Result Handoff

An ARM Linux smoke used a real isolated daemon for 60 seconds: 30 successful
health samples and six completed commands. RSS increased from 46.5 to 57.9 MiB;
health latency p95 was 33.3 ms. This was an execution-only configuration with
capture disabled. The 24-hour duration and capture recovery rows remain pending.

Use a dedicated, operator-configured loopback daemon with a known PID and an
external token file. First run a short smoke, then the full duration:

```sh
python3 scripts/accept_execution_soak.py --url http://127.0.0.1:8787 \
  --config /absolute/execution.json --token-file /absolute/daemon.token \
  --daemon-pid "$DAEMON_PID" --agentprov "$OUT/agentprov" \
  --output "$OUT/soak-24h" --duration-seconds 86400
```

The sampler records bounded resource, backlog, loss, latency and recovery
observations. It never restarts existing services. Short runs keep the 24-hour
gate pending. Review trends and observed fault recovery before accepting Q-01.
An unavailable metric is preserved as unknown.

Return source SHA, dirty state, binary hashes, platform/runtime lock, commands,
exit codes, reports and an artifact hash list. Keep each skipped row and its
missing condition visible. Preserve earlier reports when rerunning; never reuse
a prior success for a different binary. Share public keys through a trusted
channel, and remove private keys, tokens, provider logs and personal captures
from the handoff. Do not publish a whole private output directory.

The next release step remains maintainer review. This handoff creates no PR,
merge, tag, Release or online deployment.
