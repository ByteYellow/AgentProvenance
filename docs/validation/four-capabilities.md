# Portable Evidence Acceptance

English | [中文](../zh-CN/validation/four-capabilities.md)

This guide covers the four-capability source increment on
`feature/v1.0-portable-evidence`: controlled workspaces, evidence delivery,
runtime adapters and layered Browser evidence. It is an acceptance handoff,
not a release announcement. The Dashboard changes remain in local preview.
The [acceptance results](../benchmarks/v1.0-four-capabilities/README.md) separate
fixed-source reruns from earlier captures and record the remaining environment checks.

## Current Scope

| Task | Implementation | Recorded acceptance |
| --- | --- | --- |
| C-01 | Observation domains, capability intervals and runtime identities | Passed recipient API, command watermark and scope/count checks |
| W-01 | Authoritative workspace, revision conflicts, CLI and stdio MCP | Passed native x86 and Kata real Harness, signed delivery and offline reading |
| E-01/E-02 | Reading, derived and originals; recipient-owned trust and verifier | Four same-source packages and all three delivery modes passed; UI controls await review |
| R-01 | Separate platform, execution and capture contracts | Native/K3s/gVisor/Firecracker evidence retained; new platform bindings passed |
| R-02 | Exact Sentry birth, descendants and durable command boundary | Final five-scenario command and receiver/executor fault matrix passed |
| R-03 | Pinned Kata/QEMU Guest binding and capture | All nine R-03 checks passed, including Pod rebuild and real Workspace Harness |
| B-01 | Persistent accept/result and receiver-owned verification | Final Sensor-on, SIGKILL recovery and query-without-reexecution checks passed |
| B-02 | Native Browser layers, rules and evidence references | Context/tab, redirect, iframe/worker, background and download matrix passed |
| B-03 | Runtime custody and process lifetime binding | Three actual launcher scopes and selected signed-reader checks passed |
| Q-01 | Bounded pressure/resource checks and regression gates | 18 Sensor, 5 ingestion and 68 context budget checks passed; 24-hour soak deferred |

The [x86 completion results](../benchmarks/v1.0-x86-completion/README.md) include
native Workspace and Browser cases and runsc's command/fault matrix. runsc binds
each command before dispatch using its Sentry PID and birth identity, follows
native descendant records, and seals after a private completion marker reaches
the durable receiver store. Receiver discontinuities keep the old command
incomplete; cancellation and executor restart preserve unknown outcomes and
fence that generation. Repeated submission and queries reuse the saved attempt.

The earlier workspace case used an ARM Linux VM, Claude Code 2.1.293 and its
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

The fixture produces two stores: `browser-import/data` holds the first import;
`browser-import/received` holds its signed bundle after recipient-side import.
Export both with distinct output names, using run `browser-owned-acceptance`:

```sh
"$OUT/agentprov" --data-dir "$OUT/browser-import/data" dashboard export \
  --run browser-owned-acceptance --output "$OUT/browser-source-reader.zip"
"$OUT/agentprov" --data-dir "$OUT/browser-import/received" dashboard export \
  --run browser-owned-acceptance --output "$OUT/browser-received-reader.zip"
PLAYWRIGHT_CHANNEL=chrome AGENTPROV_REPLAY_SEARCH_QUERY=/pending \
  node scripts/accept_offline_replay.cjs "$OUT/browser-source-reader.zip"
PLAYWRIGHT_CHANNEL=chrome AGENTPROV_REPLAY_SEARCH_QUERY=/pending \
  node scripts/accept_offline_replay.cjs "$OUT/browser-received-reader.zip"
```

Open each reader offline and compare its saved scopes, receipts and native
references. These fixture stores have Sensor off. The next check uses a separate
store containing actual native Sensor events and the operator's runtime mapping.
The `/pending` search phrase comes from the retained fixture URL, including in
basic mode. Omit `PLAYWRIGHT_CHANNEL` when using Playwright's installed Chromium.

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
