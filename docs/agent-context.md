# Recorded Agent Context

[Chinese](zh-CN/agent-context.md)

Agent context preserves what a harness recorded: conversation messages, tool
inputs/results, task changes, configuration, and approval records. It is source
evidence, not a reconstruction of hidden model reasoning or an assertion that
a proposed action actually executed. Runtime evidence remains a separate layer.

## Capture

```sh
agentprov launch -- dsh headless --json 'Inspect the project and run its tests.'
agentprov launch --context-dir /path/to/native/sessions -- codex
agentprov launch --context-session SESSION_ID -- codex resume SESSION_ID
```

Recognized launch recipes are Claude Code, Codex, Kimi, and DeepSeek Harness.
Claude also receives per-run hooks when its settings allow the overlay. Wrapper
commands can declare `--context-harness claude|codex|deepseek|kimi|grok` and
`--context-dir DIR` or `--context-file FILE`. Old logs without native session
identity need both `--context-file` and `--context-session`; their identity is
explicitly operator-supplied. `--no-context` disables this capture and hooks.

Discovery honors `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, and `DSH_HOME`. When a wrapper
sets its home only in the child process, pass that directory explicitly. Capture
runs after execution exits. Selection does not use newest modification time:
concurrent candidates remain ambiguous. Resume verifies the pre-run source
prefix and excludes earlier activity from the new run. Actual child-session
identities can link children; a dispatch alone does not invent a child identity.

An existing transcript can also be imported explicitly:

```sh
agentprov context import --run RUN_ID --harness deepseek --file session.v4.jsonl.zstd
agentprov context coverage --run RUN_ID
agentprov context list --run RUN_ID --kind configuration --revisions
```

DeepSeek parsing supports v3 JSONL and v4 JSONL with concatenated Zstandard
frames. Unknown formats are reported, not interpreted as empty successful runs.

## Inspect and Compare

`context list` returns immutable entry IDs and content references. Use `--cursor`
to continue a page; `--revisions` includes earlier versions of the same record.
Without it, source position and then import time select the latest revision.
Source timestamps are retained separately from storage time.

```sh
agentprov context compare --run RUN_ID --left ENTRY_A --right ENTRY_B
agentprov context compare --run RUN_A --left ENTRY_A --right-run RUN_B --right ENTRY_B
agentprov context content --run RUN_ID --ref sha256:HASH --offset 0 --limit 65536
```

Comparison accepts two configuration records, approval records, or task records
(including user messages). It compares recorded content and source status.
`same` means those values agree; `different` identifies changed JSON paths;
`unknown` means the required body was not recorded or exceeds the comparison
budget. A missing field differs from explicit `null`, but neither implies an
effective authorization. A recorded permission request is not an approval.
Model selections, working directories, MCP/skills/plugins and sandbox settings
are only available when the source recorded them; current machine settings are
not substituted for historical evidence.

Limits are explicit: 200 changes, 512-byte value previews, nesting depth 32,
and 1 MiB per comparison body. Longer stored evidence remains accessible through
the content reader. Text storage is limited to 32 MiB per body, chunked at
128 KiB. Content reads default to 64 KiB and allow at most 256 KiB per page;
follow `next_offset` rather than computing a character offset.

## Coverage and Portability

Coverage is source-scoped: `disabled`, `no_input`, `empty`, `ok`, `partial`,
`failed`, `ambiguous`, or `legacy_not_recorded`. Null counts are unknown, not
zero. Reports distinguish parser failures, unrecognized records, deferred tails,
limits and duplicate imports. Launch processes at most 128 selected sources,
with a partial report when the limit is reached. Graph projections have separate
bounded budgets and persist processing failures.

Imported content is redacted before hashing and storage. Querying a saved body
never reopens the source path. Self-contained forensic bundles carry context,
coverage, configuration history, and chunked content. Import into another data
directory does not require the original harness or source files. Signing covers
the exported evidence; coverage and graph verification are separate checks.
Old bundles without context reports remain `legacy_not_recorded`.

## Dashboard

The execution graph and focused evidence remain above the initially collapsed
**Agent session** section. The session has three views: **Conversation & tools**,
**Permissions & configuration**, and **Collection status**. Overview shortcuts
open the corresponding view. Existing graph controls, signals, outbound data,
timeline, process tree, network, and compliance sections remain available.

Use **Open saved content** or **Raw source record** to inspect a context entry in
the independent **Saved content** panel. Body and raw-record selection, 64 KiB
page reads, and an enlarged view do not require keeping the session expanded.
The record list loads 30 entries per page; inline bodies preview at most 4 KiB
with four concurrent reads. Back navigation retains up to 200 page cursors;
**First page** resets the list without accumulating previous page bodies.

**Locate in graph** follows saved `context_tool_call`/`context_tool_result`
edges. Graph-to-session lookup also follows saved tool/runtime edges. These
are navigation relationships, not a new command or time-window inference.
Missing links explain the gap instead of choosing a similar command in another
session. Live refresh preserves opened records and content pages. Language
switches retain the selected view and reading position; browser session storage
holds navigation IDs/offsets only, not message or tool-output bodies.

Select two task, configuration, or approval records of the same kind to compare
their recorded values. A missing approval remains **Not recorded**, not denied
or allowed. The verification badge reports graph integrity; it does not claim
that collection is complete or that a bundle signature was checked.

Context text uses the chunked content reader. Legacy artifact/file preview and
export limits have their own integration gate in the delivery checklist; a
successful context-content test does not establish full artifact portability.

The dashboard and daemon share read-only `/api/context/*` and `/v1/context/*`
routes. See the [API contract](agent-context-api.yaml) and the
[delivery checklist](v0.9.0-delivery.md) for implementation and live-test status.
