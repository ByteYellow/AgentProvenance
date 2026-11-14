# Choose an investigation

English | [中文](zh-CN/demo-library.md)

Choose a question first, then open its recording. The examples below use the
existing demo names; paired captures are chapters of one investigation.

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

## Chapters and preserved entry names

| Story | Existing entry names | Distinct evidence |
| --- | --- | --- |
| Task investigation and repair | `evidence-attribution`, `evidence-attribution-repaired` | Two November captures with tool-scoped intent, audit and TLS attribution details |
| Task investigation and repair | `investigation-workflow`, `investigation-repaired` | Two October captures with a reviewer, denied diagnostics, repair and comparison |
| Task investigation and repair | `deepseek-context` | September development task, seven recorded tests, tool results, configuration and final files |
| Collaboration and placement | `multiagent-provenance` | Logical delegation, peer influence, refusal and later execution |
| Collaboration and placement | `k8s-cross-pod-a2a`, `k8s-substrate` | Cross-Pod runtime events and deployment identity; the A2A guide identifies replayed application hooks separately |
| Supply-chain investigation | `snake-supply-chain` | Poisoned install hook, planted test secrets, network attempts and artifact history |
| Attribution semantics | `endpoint-attribution` | Signed synthetic example: body match, candidate source reads and unresolved execution identity |
| External evaluators | `llm-judge`, `jev-judge` | Optional evidence consumers and manual review; setup is separate from replay |
| Grok historical investigation | `grok-codebase-exfil`, `grok-3routes` | Two dated recordings with different Runs and signing keys |

Open an original recording directly with `agentprov demo <entry-name>`. The two
repair pairs load their companion Run for comparison. Old Run IDs, signatures
and evidence references continue to identify the original recording.

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

Return to [all demo commands](../demo/README.md) or the [project quickstart](../README.md#quickstart).
