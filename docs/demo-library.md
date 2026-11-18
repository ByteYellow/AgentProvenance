# Choose an investigation

English | [中文](zh-CN/demo-library.md)

Choose a question first, then open its recording. The examples below use the
existing demo names; paired captures are chapters of one investigation.

## First visit

Start with Task investigation and repair. It connects the common investigation steps:

1. **Understand the task.** Read the original instructions and tool output to establish the intended work and its recorded result.
2. **Check the evidence.** Find the relevant file or outbound record, read its saved content, and inspect the supporting events.
3. **Compare changes.** Compare the before-and-after Runs from the same repair case. Check configuration, files and network activity; differences in capture scope remain visible.
4. **Share the result.** Select the Runs or sessions to share, review the included content, and download the offline reader.

For a specific question, use the direct entry below. The graph follows relationships;
raw records supply the underlying detail.

| What you need | Entry | Result |
| --- | --- | --- |
| What the agent said and invoked | Task and conversation, Tool calls | Original instructions, inputs, outputs and timestamps |
| A particular error, domain or filename | Search | Matching saved text, full content and evidence links |
| Changes across two executions | Compare | Configuration, file and network comparisons with capture scope |
| The origin of file or network activity | Evidence graph | Supporting events, association basis and scope |
| Missing or omitted records | Collection status | Retained content, intentional omissions and capture gaps |
| Evidence for another investigator | Export | An offline reader; see the [verification guide](derived-evidence.md) for signed delivery |

Execution status describes the task outcome, capture status describes recorded
coverage, and verification describes evidence checks. Start with the result and
relevant content, then expand diagnostics when investigating a gap or disputed source.

## Recommended reading paths

| Question | Start here | Follow-up evidence |
| --- | --- | --- |
| What changed between inspection and repair? | [Evidence attribution](../demo/evidence-attribution/README.md) | Original task, tool-scoped intent, access-control decisions, retained TLS content, changed files and the repair Run |
| How did work move between agents and workloads? | [Agent team](../demo/multiagent-provenance/README.md) | Delegation, peer messages and refusal; then [cross-Pod evidence](../demo/k8s-cross-pod-a2a/README.md) for actual workload locations |
| What did the browser or notebook actually do? | [Browser capture](browser-context.md) and [Notebook capture](notebook-context.md) | Native operation/request identities, outputs, screenshots, HAR, retained content and portable replay |

The Browser and Notebook guides capture your own workload through optional local
entries. They are separate from the bundled historical recordings. Browser
request evidence and tool-operation evidence retain their own identities;
Notebook outputs retain their original request across late output and restarts.

For a controlled remote command, use the [execution handoff guide](execution-handoff.md).
For Sentry-origin events, use the [gVisor collection guide](gvisor-seccheck.md).

## Read the v1.0 candidate examples

The website groups its recordings into four illustrated entries: task investigation,
remote workspaces, Browser / Notebook, and multi-agent collaboration. Topics and
older investigations remain in separate sections. The repair card opens Compare
with the inspection as A and the repair as B.

Look for **Linux x86 recordings** on the Workspace and Browser / Notebook
cards. Workspace links directly to the Claude and Kata/QEMU runs; its case
details also contain the first boot, rebuilt guest and workspace revision
recordings. Browser links directly to Sensor-on and interruption recovery.
Each session has its own reader and original read-only ZIP download.

The shared reader has five reading paths, also available in the
[rebuildable local examples](../previews/v1.0-reader/README.md).
Start with the question in each row, then follow its evidence path:

| Entry | What happened | What to inspect |
| --- | --- | --- |
| Task investigation | DeepSeek investigated a task before and after a configuration repair | Read the task and tool results, then use Compare to inspect the configuration and file changes across the two Runs |
| Cross-environment execution | Two Claude sessions made three remote execution attempts; the capture also exercised a lost receipt response | Select a source Tool Call, follow its target Run and attempt, then compare execution, capture and delivery states; navigate back to the original call |
| Workspace | A remote-authoritative task read, edited and executed the same workspace | Inspect input and output revisions, operation receipts and the saved `result.txt` body |
| Browser | An Agent used the recorded browser entry for a web task | Expand the Agent session and open Browser / Notebook; inspect an operation's native references, saved text and screenshot, with request evidence alongside it |
| Notebook | A synthetic Jupyter capture contains a chart and a kernel restart | Inspect the request and parent-message references, open the chart, and compare kernel identities across the restart |

The first four use recorded candidate executions. The Notebook sample is
synthetic; the earlier real Claude Notebook recording remains in the
[candidate archive](benchmarks/v1.0-candidate/README.md). These are saved
observations: opening them reads evidence without rerunning the workload.
The source build includes these controls in the Dashboard, static readers and
new offline exports. It preserves the graph layout and adds Workspace revisions,
execution receipts, and Browser / Notebook text and attachment reading.
Website downloads include the current reader; original evidence downloads and
the `agentprov demo` entry names below remain available.

## Chapters and preserved entry names

| Story | Existing entry names | Distinct evidence |
| --- | --- | --- |
| Report repair: tools and outbound activity | `evidence-attribution`, `evidence-attribution-repaired` | November reproduction: disabling unnecessary diagnostics restores the report; inspect tool-scoped intent, audit and TLS records |
| Report repair: denials and configuration changes | `investigation-workflow`, `investigation-repaired` | October reproduction: calculation tests pass but diagnostics fail; inspect the reviewer, denials and changes to `settings.json` |
| DeepSeek development task | `deepseek-context` | September development task, seven recorded tests, tool results, configuration and final files |
| Collaboration and placement | `multiagent-provenance` | Logical delegation, peer influence, refusal and later execution |
| Collaboration and placement | `k8s-cross-pod-a2a`, `k8s-substrate` | Cross-Pod runtime events and deployment identity; the A2A guide identifies replayed application hooks separately |
| Supply-chain investigation | `snake-supply-chain` | Poisoned install hook, planted test secrets, network attempts and artifact history |
| Attribution semantics | `endpoint-attribution` | Signed synthetic example: body match, candidate source reads and unresolved execution identity |
| External evaluators | `llm-judge`, `jev-judge` | Optional evidence consumers and manual review; setup is separate from replay |
| Grok historical investigation | `grok-codebase-exfil`, `grok-3routes` | Two dated recordings with different Runs and signing keys |

Open an original recording directly with `agentprov demo <entry-name>`. The two
repair pairs load their companion Run for comparison. Old Run IDs, signatures
and evidence references continue to identify the original recording.

The October and November pairs are separate reproductions of the report
workflow. Compare within a pair to inspect a repair. A replay link can open
Compare directly with `compare_a=<before-run>&compare_b=<after-run>`; both Runs
must be present in that replay. Closing Compare returns to the current record.

## Recording types

- **Recorded execution:** retained observations from a particular execution.
  Its guide states the capture environment, source and date when recorded.
- **Mixed sources:** application context and runtime observations have different
  capture origins. The Kubernetes A2A example labels those origins explicitly.
- **Synthetic example:** constructed input for explaining association semantics.
  The outbound-attribution example uses a public marker.
- **Evaluator integration:** a consumer of existing evidence. Keyless fixtures
  exercise the integration; live judging requires the documented credentials.

## Historical Grok recordings

The original Grok scenario is currently not reproducible. Both recordings remain
available for signature verification, import, investigation and offline replay.
Use the [historical guide](../demo/grok-codebase-exfil/README.md) to distinguish the
observed model-request content, vendor telemetry and third-party analytics.

A newer reader can display these recordings without changing their original
capture date, evidence or signature. Newly captured examples receive new Run IDs
and separate signed bundles.

## Sharing an investigation

Use the Dashboard export preview to select Runs, sessions and retained records.
The resulting read-only directory works without the original workspace. A
selected reading copy and its original signed evidence bundle are separate
artifacts; keep the original bundle and public key when signature verification
is needed.

## Loading recordings

The static site loads a small catalog first, then the index and evidence for the
selected Run. Comparing Runs or following a related session loads the additional
recording when needed. Historical recordings stay unloaded until requested.

Existing replay links and original signed bundles remain available. The reader
also supports older sites with a single manifest and self-contained offline
exports.

To compare two exported sites on the same machine, run
`node scripts/bench_static_replay.cjs BEFORE_DIRECTORY AFTER_DIRECTORY` with the
Playwright dependency installed. `PLAYWRIGHT_CHANNEL=chrome` selects an installed
Chrome browser. The JSON report separates cold and warm cache measurements,
transferred bytes, graph readiness and retained JavaScript heap. It also records
the browser, CPU and source commits.

Return to [all demo commands](../demo/README.md) or the [project quickstart](../README.md#quickstart).
