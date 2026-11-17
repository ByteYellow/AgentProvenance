# v1.0 Four-Capability Acceptance

English | [中文](README.zh-CN.md)

Acceptance source: **`831e85426393bdbf7757d37ee221cd8f3f0fd9ff`**.
This summary covers controlled workspaces, portable evidence delivery, runtime
adapters and layered Browser evidence. The [result index](report.json) records
commands, exit codes, source/build state, executable and report hashes, and
skipped conditions for the fixed-revision retest.

**UI status:** the local preview is retained; formal Dashboard integration is
deferred. The existing visual layout remains in place.

## Implemented Scope

| Capability | Code scope | Available local workflow |
| --- | --- | --- |
| Controlled workspace | [workspace](../../../internal/workspace), [stdio MCP bridge](../../../python/agentprov/workspace_mcp.py) | One remote-authoritative workspace, Target generation checks, revision/digest conflicts, input/output manifests and Read/Edit/Write/Bash receipts through CLI and MCP. |
| Evidence delivery | [derivedview](../../../internal/derivedview), [viewverify](../../../internal/viewverify), [independent verifier](../../../cmd/agentprov-verify) | Unsigned reading copies, exporter-signed selected readers and whole-run registered originals; recipient-owned trust separates file integrity, producer/exporter signatures and coverage. |
| Runtime adapters | [runtimeadapter](../../../internal/runtimeadapter), [handoff](../../../internal/handoff), [Kata fixture](../../../scripts/acceptance/kata-qemu) | Separate platform, execution and capture contracts; native default, Guest binding, fixed-container runsc execution, and bounded platform/cleanup checks. |
| Browser evidence | [browserlink](../../../internal/browserlink), [browsercustody](../../../internal/browsercustody), [provenance](../../../internal/provenance), [receipt persistence](../../../python/agentprov/browser_receipts.py) | Durable acceptance/results, restart queries without reexecution, receiver-owned verification, native-ID layers and explicit process-lifetime mappings. |

Observation-domain and capability-interval projections are implemented in
`internal/capturemanifest`. Local acceptance entry points include workspace
contract/Harness checks, controlled Chrome receipt recovery, independent delivery
verification, offline reading and a bounded daemon soak sampler. Native
Sensor-on and platform combinations have separate live acceptance requirements.

See the [four-capability procedure](../../validation/four-capabilities.md),
[workspace guide](../../workspace.md), [delivery guide](../../derived-evidence.md)
and [Browser guide](../../browser-context.md) for configuration and commands.

## Fixed-Revision Retest

Runtime binaries were built from the source above. Acceptance revision
`476ad41508a253b416e9d6689639e9760630d8f3` only clarifies the workspace task's
JSON strings and final newline, with three regression tests. Runtime code and
the exact 19-byte artifact check are unchanged. The first Harness failure and
the successful rerun are recorded separately.

Revision `dcc30062c499f16fdca3520d2876a1ff73e350e6` corrects the navigation
acceptance contract: compare native and static link sets exactly, while checking
every exported reference page. The original count check incorrectly included a
linked-only Kata guide in the homepage navigation. Fourteen bilingual regression
checks cover missing, extra, substituted and wrong-language links. No product
code or page layout changed.

| Validation | Result record |
| --- | --- |
| Full Go tests and vet | Passed; 49 tested packages. Commands, toolchain and logs are indexed in [report.json](report.json). |
| Race regressions | Passed with the existing CI configuration, `-race -p 2 -timeout 20m`. |
| Python and runtime fixture tests | Python suite: 98 passed, two skipped. Workspace: 37 passed. Kata fixture: 51 passed. |
| CLI delivery and independent verification | All 21 expected outcomes passed; three delivery modes and both Browser stores opened offline. |
| Static gallery and reader regressions | Passed: 12 replays, 106 bilingual pages, 17,910 query comparisons and 7,324 content pages. Native/static graph controls and selective downloads also passed. |

Each record identifies its source or acceptance-script revision. Historical
measurements below retain their original source and build identities.

## Historical Reference

| Earlier evidence | Recorded result | Profile |
| --- | --- | --- |
| ARM Linux real-daemon smoke | 60.001 seconds; 30 successful health samples; six independent commands; 12/12 compatibility checks; soak and daemon exit 0. | Isolated non-root daemon, Sensor off; CPU mean 3.76%, RSS 46.500 to 57.875 MiB, health latency p95 33.30 ms. |
| Local UI preview | 259 checks, 13 screenshots, Chrome 155.0.8059.85; zero browser errors and external HTTP requests. | Chinese/English desktop/mobile preview; Workspace examples are illustrative, with saved Browser receipts and separate delivery reports. |

The ARM sampler checkout was `4e367089eb9f768be4592b1268e93d05166097a8`
with tracked worktree **dirty=true**. Its binary embedded
`52c7200f1c3e382040f210a83d3af665d2396325`, **vcs.modified=true**.
The UI preview was an uncommitted local artifact; its historical Git revision,
process exit code and Chrome executable hash were not recorded. Original report
hashes and provenance are retained separately in the [result index](report.json).

## Later x86 Completion

The final [x86 results](../v1.0-x86-completion/README.md) close the earlier runsc,
Workspace/Browser Sensor-on and pinned Kata/QEMU requirements. They also record
bounded performance, same-source packages and the retained reader preview.
The 24-hour soak remains maintainer-deferred. Earlier measurements above retain
their original versions and conditions.
