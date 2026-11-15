# v1.0 Candidate Acceptance

English | [中文](README.zh-CN.md)

This directory is the portable acceptance handoff for
`feature/v1.0-portable-evidence`. It contains the current status, repeatable
entry points, reviewed read-only recordings and a machine-readable result index.
It is separate from the published release and the default Demo catalog.

## Revision and Scope

The subsequent [Linux amd64 results](../v1.0-amd64/README.md) cover KVM/K3s,
the Go TLS matrix, delivery recovery, Firecracker boot/retirement, and frozen
performance budgets. The tables below preserve the original Mac handoff state.

| Item | Revision |
| --- | --- |
| Runtime used for the final ARM64 captures and integrated tests | `c22c065f5a91fd275529787558ebe9a82e4a1426` |
| Candidate documentation and packaged Mac reader | `cbd3205af40b9557636271ec3b423c179aaa7cbe` |
| Continuation branch | `feature/v1.0-portable-evidence` |

The second revision changes documentation, embedded documentation routing and a
documentation regression test. It leaves the collection, association, storage
and export implementations from the first revision unchanged. Commits adding
this acceptance directory only package the handoff. Record the actual checkout
SHA and executable hashes when continuing on another machine.

```sh
git fetch origin
git switch feature/v1.0-portable-evidence
git pull --ff-only origin feature/v1.0-portable-evidence
git status --short
git rev-parse HEAD
```

Preserve local changes before switching. Continue on this branch. Main merge,
release/tag creation and GitHub Pages deployment require a separate review.

## Completed on Mac and Linux ARM64

| Requirement | Evidence available | Remaining gate |
| --- | --- | --- |
| CS-01 through CS-05 | Native caller identity, isolated concurrent commands, explicit reexecution, lost receipt recovery, capture sealing and durable delivery | Native amd64 acceptance |
| CS-06 and CS-07 | Bidirectional execution-link API, full and selected offline indices, saved native references | Approved production UI integration |
| CS-08 | External Mac caller and container caller accepted during development; final native concurrent capture refreshed on ARM64 | Final cross-environment review |
| RT-01 | Qualified identities, capture manifests, capability history, passive Pod attribution and JSONL receipts | Native amd64 matrix |
| RT-02 | Pinned gVisor SecCheck reception, persistence, fault recovery and signed delivery | Native amd64 runtime check |
| RT-03 | Guest image/kernel recipes, actual ARM64 systemd readiness and stop/seal/receipt acceptance | Firecracker hardware boot and controller-owned retirement |
| RT-04 | Actual runsc memory restore and two clones, external identity/key reauthorization and copied-spool deduplication | amd64 repeat of the selected profile |
| APP-01 and APP-02 | Real Claude Browser/Notebook tasks, basic/detailed retention, native IDs, attachments and offline reading | Approved reader integration |
| DEMO-01 through DEMO-06 | Grouped local preview, refreshed recordings, historical compatibility, bilingual source-preview documentation | Final UI approval, screenshots and final site assembly |
| DEMO-07 | Existing static publication path retained and locally checked | Publication approval and deployed-site readback |

Mac and Linux ARM64 full Go tests, vet and race pass. All eight frontend
regressions pass. Final performance passes the unchanged 18 Sensor, five
100,000-event ingestion and 68 context-storage/export limits. The performance
reports describe their measured profiles; these are environment-specific
regression budgets.

The latest captures include two native sessions with three isolated execution
attempts, a DeepSeek before/after investigation, and four separate Browser and
Notebook tasks. Original Grok evidence remains historical. The
[result index](report.json) records sources, hashes, commands, results and
preserved failures. Earlier acceptance evidence keeps its original revision.

## Read the Included Recordings

Verify [SHA256SUMS](SHA256SUMS) from this directory with `sha256sum -c SHA256SUMS`
on Linux or `shasum -a 256 -c SHA256SUMS` on macOS. Extract an archive from
`replays/` into a new directory and open its `index.html` through `file://`.
No daemon or original work directory is needed.

| Archive | Recorded workflow |
| --- | --- |
| `native-matrix.zip` | Two Claude sessions, three remote execution attempts, receipt-loss recovery |
| `native-case-a.zip` | Only the first session and its two attempts; the second session is excluded |
| `task-investigation.zip` | DeepSeek investigation before and after a configuration repair |
| `investigation-session.zip` | Selected child session from the repaired task |
| `browser-detailed.zip`, `browser-basic.zip` | Two independently executed browser tasks |
| `notebook-detailed.zip`, `notebook-basic.zip` | Two independently executed Notebook tasks |

These ZIPs are unsigned reading copies with per-file hashes. Original signed
Bundle hashes are recorded separately. Browser/Notebook captures use the
application entry with native Sensor disabled. Runtime gaps from the other
captures remain visible. The evidence reader treats saved commands and content
as data.

## Linux amd64 Continuation

### 1. Inspect and Build

Use Linux x86_64; a Windows host is not required. Record `uname -a`, CPU/RAM,
available disk, `go version`, Python/Node versions, BTF, cgroup v2, privilege and
`/dev/kvm` availability. `/dev/kvm` is needed for Firecracker; runsc `systrap`
and the ordinary Linux checks can run without it. Keep all outputs in a new
private directory outside the checkout. Go 1.26.4 was used for the ARM64 Linux
measurements; use the same compiler/build settings for any comparable rerun.

```sh
OUT=$(mktemp -d "${TMPDIR:-/tmp}/agentprov-v1-amd64.XXXXXX")
export OUT
go test -count=1 -p 2 -timeout 20m ./...
go vet ./...
go test -race -count=1 -p 2 -timeout 20m ./...
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/check_localized_docs.py
python3 scripts/build-release.py --version v1.0.0-candidate \
  --os linux --arch amd64 --output "$OUT/release"
python3 scripts/accept_release.py \
  "$OUT/release/agentprov_v1.0.0-candidate_linux_amd64.tar.gz"
```

Also run the eight `dashboard-display` commands in
[CI](../../../.github/workflows/ci.yml). Preserve each command's exit code and
log. Native tests requiring privileges must run in their documented live mode;
record skipped cases explicitly.

### 2. Exercise Real Producers and Delivery

| Check | Existing entry and setup |
| --- | --- |
| Sensor, TLS, namespace, syscall and audit matrix | `sensor-live-amd64` in [CI](../../../.github/workflows/ci.yml), including adjacent seccomp and mixed access-control cases |
| Concurrent native calls and fault recovery | [Execution guide](../../execution-handoff.md); `scripts/accept_execution_native_matrix.py prepare/run/verify` |
| Passive K3s attribution and restart | `scripts/accept_node_capture.py --agentprov BINARY --report REPORT --artifacts NEW_DIRECTORY`; choose an available image explicitly when needed |
| gVisor live/fault/restore | [Pinned SecCheck guide](../../gvisor-seccheck.md); `accept_seccheck.py`, `accept_seccheck_faults.py`, `accept_seccheck_restore.py` |
| Browser and Notebook | [Browser](../../browser-context.md) and [Notebook](../../notebook-context.md) setup; `accept_browser.py`, `accept_notebook.py --attachments`, then optional `accept_*_agent.py` with an operator-provided model credential |
| Guest service before hardware boot | `sudo python3 scripts/accept_execution_seal.py --native --binary BINARY --output NEW_DIRECTORY --guest-service-dir "$PWD/deploy/microvm"` |

Use separate executor workdirs and native capture for the concurrent command
fixture. It checks both commands at a barrier, exact native call IDs, isolated
cgroups, one explicit retry and a receipt response dropped after persistence.
Run its `verify` phase after stopping the executor and relocating original
workdirs. Model/API credentials must be supplied privately on the new host.

For performance, follow the existing
[measurement guide](../../performance-validation.md). Freeze amd64-specific
baselines before the candidate measurement; ARM64 timing limits are not portable
to a different machine. Keep input, compiler and instrument identities fixed.

### 3. Complete the Hardware-Specific Guest Check

Use the pinned Firecracker v1.18.0, Amazon Linux 6.18.62 kernel source and Ubuntu
24.04 rootfs definitions in [the guest recipe](../../execution-handoff.md#guest-service-and-image).
Build with `scripts/build_microvm_kernel.py` and `scripts/build_microvm_rootfs.py`.
Retain effective kernel configuration, BTF, image manifests and executable hashes.

Boot the actual guest with separate root, read-only configuration and persistent
evidence volumes. Verify automatic service startup, probe-gated readiness,
externally assigned instance/generation, a real dispatched command and its
process/file evidence. Stop dispatch, collect receipts, stop the guest service
and verify its final sealed packages at the receiver. Test controller-owned
retirement only after all required receipts are reconciled. Preserve the volume
on an incomplete or failed result. Host-level systemd acceptance is already
available; this step exercises actual guest boot and retirement.

### 4. Return Results for Review

Return a result index with checkout SHA, dirty state, environment, tool versions,
binary/image hashes, exact commands, exit codes, artifact hashes, failures and
skips. Keep full logs in a private archive; publish only reviewed summaries and
synthetic fixtures. Preserve the original failing result before retrying.

The remaining shared review items are production UI integration, a non-author
following the guide, final cross-environment reconciliation and publication.
They follow the x86 results and maintainer review. Do not broaden this work into
Windows/mobile collection, a sandbox scheduler or a new control plane.
