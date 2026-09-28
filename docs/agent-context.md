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

## Runtime Association

Launch records `runtime_correlation` in its JSON result and saves the report as
an evidence object. Collection status links that object without mixing exec
counts with transcript-record counts. Its counters describe the eligible records
read by this pass; `input_complete: false` means those are only partial counts.
`ok` means the correlation pass completed for its inputs, not lossless collection.

The versioned `agentprov.command_time_process/v2` method requires a unique
literal-command candidate inside the recorded tool-call interval and a runtime
PID with a cgroup or container scope. Case and quoted whitespace are preserved;
arbitrary substrings do not match. Native sensor argv uses 16 slots of 32 bytes;
`argv_truncated` marks a reached capacity boundary (possible truncation, not the
original length). Only source-marked truncation permits a multi-token prefix
match. Events remain scoped by producer source, available origin metadata,
cgroup, container and PID. Recorded child execs may inherit a known parent.

Exec/exit boundaries invalidate prior PID ownership; same-instant ordering,
concurrent matching calls, conflicting parent evidence, missing scope and bad
timestamps remain gaps or ambiguities. Background activity beyond the recorded
tool interval is not attributed by widening a time window. Missing lifecycle
events or host/boot identity can still weaken the inference: this is not proof
of unique agent ownership from the kernel. New graph edges expose the method,
evidence references and confidence tier `0.8`, not a calibrated probability.
Intent diff does not undo a new correlation gap with a weaker time fallback.

Reads and edge replacement share one transaction; failures preserve the prior
edges. Budgets are 10,000 calls, 200,000 eligible runtime events, 64 KiB per input,
64 MiB each for commands and runtime payload, and two million candidate comparisons. Limits fail
explicitly rather than publishing a partial replacement. Historical stored
edges are not reclassified or automatically rebuilt when analyzing imported
graphs; new derivations do not change an original bundle's signature.

## Changed File Content

`record` saves post-execution text for files found by its working-tree comparison.
For `launch`, opt in with `--file-diff`; this remains off by default because
copying and comparing a large workspace can be expensive.

```sh
agentprov launch --file-diff -- dsh headless --json 'Inspect the project and run its tests.'
```

The writer saves at most 512 selected files, with 32 MiB per text body and
128 MiB of cumulative body reads and saved redacted text per run. The text limits
apply before and after redaction. A read may consume one extra probe byte to
detect a file growing beyond its limit. These are text-capture budgets, not
limits on the existing workspace snapshot/comparison I/O. Only regular UTF-8
files are supported; path traversal, symlinks, and special files are not followed.

The `artifact_capture` field in record/launch JSON and the saved
`artifact_capture` evidence object report `disabled`, `empty`, `ok`, `partial`,
or `failed`. `candidates: null` means selection was disabled or could not finish;
zero means comparison succeeded and found no changed files. Known omissions
include `source_missing`, `binary_omitted`, and `collection_limit`; unreadable
files and storage failures have separate reasons. For files beyond the 512-file
selection limit, the changed-file event records the omission without a body.

Each saved file descriptor and its text chunks share a database transaction.
The descriptor retains the capture time, source length, redacted body length,
body hash, and content reference. Query and offline import use those objects,
not a later version of the working file. This records the final post-execution
state, not every intermediate write; it is not an atomic filesystem snapshot.
An absent final file does not acquire a reconstructed body.

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

Graph content also supports byte paging through `/api/artifact`, independently
of the session section. Choose **Recorded graph content** or **Raw saved object**;
if a source has several saved versions, select an exact object hash. The body hash
describes the complete redacted display text, while `ref` identifies its saved
object envelope. Unavailable content has `total_bytes: null`, not a zero-byte
body. Object hashes and envelope run IDs are checked before rendering.

This endpoint reads only saved objects and identified database records. It never
opens a tool result path or a workspace file as a replacement historical body.
Metadata-only artifacts remain explicitly unavailable in body mode; raw mode
still exposes their recorded metadata. Legacy inline objects retain an 8 MiB
read budget. New chunked text supports up to 32 MiB without raising the existing
4 MiB per-object bundle limit, and storage chunks are not counted as file
artifacts. Signed offline HTTP-paging tests cover all three former size boundaries.
The changed-file writer uses the same chunked storage. Real record subprocess
tests verify capture, redaction, signing, and offline content beyond 8 MiB;
launch tests cover its opt-in and disabled paths. These are deterministic test
workloads, not the pending sensor-backed DeepSeek development-task demo.
The reader does not retroactively create bodies that an older capture omitted.

The dashboard and daemon share read-only `/api/context/*` and `/v1/context/*`
routes. See the [API contract](agent-context-api.yaml) and the
[delivery checklist](v0.9.0-delivery.md) for implementation and live-test status.

## External Queries and Runtime Coverage

External clients use the same stored-evidence queries as the Dashboard:

- `GET /v1/context/overview?run=RUN`: context counts and reports, plus
  `runtime_coverage.capture` and `runtime_coverage.correlation`.
- `GET /v1/context/entries?run=RUN&group=conversation&limit=50`: paged messages
  and tool inputs/results. Use `group=configuration` for authorization/configuration
  records; `revisions=true` includes retained revisions.
- `GET /v1/context/content?run=RUN&ref=HASH&offset=0&limit=65536`: saved-only,
  bounded content pages. Follow `next_offset` while `has_more` is true.
- `GET /v1/context/compare?run=RUN&left=ID&right=ID`: compare recorded snapshots.
- `GET /v1/context/links?run=RUN&entry=ID`: recorded graph links, not guesses.

`launch` saves a `runtime_capture` object before bundle export. It includes the
capture interval, kernel enablement, fresh probe snapshots and node counter
increments. Old cumulative losses are not charged to the new run. New node losses
may involve other workloads, so `run_dropped_events` stays null and impact remains
unknown. Counter resets, stale capabilities, pending backlog and unconfirmed
collector exit are explicit gaps. Endpoint snapshots do not establish continuous
collector health, full TLS visibility or lossless capture.

The correlation summary counts **all stored runtime events** in the selected run,
including native eBPF and recorder sources, without loading event bodies into
memory. It reports scope-field presence, not proof that an agent association is
correct. Gap examples are bounded at 25 in this API. Capture, correlation and
signature verification are independent results.

These fields also appear in the JSON output of `agentprov context coverage --run RUN` and the
Dashboard's Collection status tab. Offline import reads the saved capture report;
it never substitutes the new host's sensor status. Runs without this report,
including older bundles and independently recorded/imported sources, show
`legacy_not_recorded` for capture history while still exposing their stored events.

Read interfaces do not execute tools or accept arbitrary filesystem paths. Keep
the default local listener; remotely exposing the daemon requires its bearer
authentication and a controlled transport. The read-only Dashboard is not a
public unauthenticated evidence-sharing service.
