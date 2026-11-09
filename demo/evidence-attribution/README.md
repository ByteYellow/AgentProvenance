# Evidence attribution: inspect and repair

English | [中文](README.zh-CN.md)

These two signed captures record a real DeepSeek reporting task on Linux arm64
on November 6, 2026. They exercise the v0.10.1 evidence reader with tool-scoped
intent, AppArmor/seccomp decisions and recorded TLS completeness information.

```sh
agentprov demo evidence-attribution
```

Both runs load together. Replay works offline, without a model account or Linux VM.
Use **Compare** to choose **Evidence attribution: before** and
**Evidence attribution: after**.

## Recorded workflow

The agent inspected a local reporting pipeline with a reviewer sub-agent. Optional
diagnostics attempted a restricted file read and network connection. The agent
then continued the same native session, removed unnecessary diagnostics and
produced the expected report total of `42.00`.

| Capture | Run | Recorded messages | Tool calls | Audit records |
| --- | --- | ---: | ---: | ---: |
| Before | `run-2fd63df0ab9b` | 22 | 18 | 3 |
| After | `run-48baa3821074` | 54 | 51 | 0 |

The second capture continues the session and includes its retained conversation
history. Counts describe saved records, rather than a count of newly executed
steps between the two runs.

## Open the new details

1. [Inspect a tool-scoped intent association](/?run=run-2fd63df0ab9b&lens=intent&detail=raw&live=0&selected=diff%2Fv2%2F4958f6486e058efd80454be9ea8e6b8306c9cfc69337419c20db7db94f45b96c#inspection).
   The selected evidence names the tool call, supporting runtime event and
   `agentprov.intent_scope/v4` rule.
2. [Inspect a retained TLS fragment](/?run=run-2fd63df0ab9b&lens=agent-intent&detail=raw&live=0&selected=sha256%3A072f5b3948ca4c5693b882722815b3958815c72ba807706b926dc67001bbbb49#inspection).
   The record reports a capture limit, call position and the original byte count
   under `agentprov.tls_reassembly/v3`. The reader distinguishes captured fragments
   from complete HTTP content.
3. Open **Related sessions** to inspect the reviewer, or **Search** to read saved
   tool results and files. In **Compare**, inspect configuration, file and audit
   changes, then follow their evidence references into the graph.

## Capture and integrity

[The capture manifest](capture-manifest.json) lists capture time, platform,
binary hash, run identifiers and bundle checksums. The compressed bundles,
DSSE attestations and public key are preserved unchanged from the capture.
Import verifies signatures and graph integrity before serving the replay.

The workload uses a public canary and a loopback service. Its recorded collection
gaps remain visible. To inspect ambiguous outbound-source attribution separately,
open the [synthetic outbound example](../endpoint-attribution/README.md).

The earlier [diagnostic repair example](../investigation-workflow/README.md)
remains available with its original evidence and rule versions.
