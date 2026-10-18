# Agent Session Guide

English | [中文](zh-CN/agent-context.md)

Preserve the task, conversation, tool inputs and results, plus the permissions
and configuration recorded during an execution. Follow a session entry into its
runtime evidence, open saved content, compare snapshots, and export for offline use.

Try `agentprov demo deepseek-context` first, or follow the capture steps below
to record your own agent. Sessions are collected after the agent exits;
`--file-diff` opts into saving final changed-file text.

**Jump to:** [Capture](#capture) · [Inspect and compare](#inspect-and-compare) · [Dashboard](#dashboard) · [Coverage](#coverage-and-portability) · [File content](#changed-file-content) · [API](#external-queries-and-runtime-coverage)

## Capture

```sh
agentprov launch -- claude
agentprov launch -- codex
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

### Native Format Compatibility

| Harness | Recorded context |
| --- | --- |
| Claude Code | Hooks and native transcripts, messages, tools, permission-mode changes and auxiliary session state; live task and resume checked with 2.1.293 |
| Codex | Native rollout records, completed messages, thread settings, world state and source-provided child identities; live task and resume checked with 0.159.2 |
| DeepSeek Harness | Native v4 Zstandard transcripts from 0.1.7-rc.2 and supported v3 records, including PTC tools and configuration |
| Kimi / Grok | Existing supported transcript formats; historical replay does not require a new live capture |

These versions identify checked formats, not a minimum-version guarantee. A
newer unknown record type is reported as a coverage gap. Session parsing and
signed offline replay are checked separately from Linux kernel/TLS collection.

### Source Selection and Resume

Discovery honors `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, and `DSH_HOME`. When a wrapper
sets its home only in the child process, pass that directory explicitly. Capture
runs after execution exits. Selection does not use newest modification time:
concurrent candidates remain ambiguous. Resume verifies the pre-run source
prefix and retains earlier records as `prior_context`, separate from the new
`current_execution` source range. Historical tools and model calls are not
projected as activity of the new run. Actual child-session
identities can link children; a dispatch alone does not invent a child identity.

Codex discovery also reads `threads.id` and `threads.rollout_path` from
`state_*.sqlite` catalogs under `CODEX_HOME`. Catalogs are opened read-only and
only locate source files; the transcript header still supplies identity and time.
An explicit `--context-dir` uses catalogs in that directory only, never another
ambient home. Conflicting identities or unreadable catalogs make automatic
selection incomplete instead of guessing. Catalog scans are bounded to 32 files,
4,096 rows and two seconds per catalog.

An existing transcript can also be imported explicitly:

```sh
agentprov context import --run RUN_ID --harness deepseek --file session.v4.jsonl.zstd
agentprov context coverage --run RUN_ID
agentprov context list --run RUN_ID --kind configuration --revisions
```

DeepSeek parsing supports v3 JSONL and v4 JSONL with concatenated Zstandard
frames. Unknown formats are reported, not interpreted as empty successful runs.
Directory discovery selects the highest numbered `session.vN` generation within
each session directory, including unknown versions; it never falls back to an
older supported file when the newer one fails. Duplicate files of the same
generation remain ambiguous. `--context-file` can select an older file explicitly.
If a known session moves to a different file during launch, the resume boundary
is unverified and capture reports ambiguity instead of counting history as new work.

An explicit import writes its saved coverage report as JSON to stdout. Only
`ok` and `empty` return exit status 0; partial, failed, missing or ambiguous
sources return a nonzero status after saving the diagnostic. Partial evidence
remains available, and repeating an unchanged successful import is successful
deduplication. This is the import status, not proof of complete runtime coverage.
`--after-line N` retains the first N physical records as prior context, not
current execution; it does not discard them or authorize the new execution.

## Inspect and Compare

`context list` returns immutable entry IDs and content references. Use `--cursor`
to continue a page; `--revisions` includes earlier versions of the same record.
Without it, source position and then import time select the latest revision.
Source timestamps are retained separately from storage time.

Claude sources may contain adjacent complete JSON objects on a physical line,
with whitespace or NUL padding between objects. These objects retain their order;
malformed content is not repaired or joined across lines. `sequence` remains the
physical line used for resume; optional `source_ordinal` orders normalized records
within that line, including pagination and offline replay. An absent/zero ordinal
means older evidence did not record it. Read/parsed counters count physical lines,
stored/duplicate counters count normalized entries, and unrecognized counts refer
to source objects. A valid prefix and an invalid suffix can share a partial line.

Codex `event_msg` user/assistant messages and source-provided reasoning are
retained even without a `response_item` copy. Event forms carry
`source_message_event` or `source_reasoning_event`; canonical response items keep
their own records. Similar text is not a shared identity, so these forms are not
heuristically collapsed. Message totals count saved source records, not unique
conversation turns; repeat imports still deduplicate the same recorded evidence.
Original source bodies and physical positions remain available for inspection.

Native Codex completed-message events, world-state snapshots and applied thread
settings are also retained. Completed command/file-change reports and token usage
remain source state; their execution-item IDs do not create model tool-call
identities. Claude attachments, session bookkeeping and cost estimates remain
source state, while native `mode` records enter configuration history. These
records preserve their raw bodies and resume ranges without adding synthetic
conversation turns or permission approvals.

Codex tool errors use explicit source flags/status, typed exit codes and supported
MCP/shell result envelopes. Words such as "error" in stdout or arbitrary nested
JSON do not determine outcome. `returned` means a result was recorded, not that
the tool succeeded or was authorized; a source error is not a policy refusal.

DeepSeek assistant `tool-call` blocks preserve model proposals. Native tool-call
records refine the same invocation when they share a recorded call ID. PTC
dispatch starts and completions expose sub-call inputs and results, with native
parent/root IDs retained in raw records. A completion without a start is labeled
`completion_only`, with `tool_start_time` missing; it cannot seed a runtime matching
interval. Typed source errors remain errors. A `surfaceOp: replace` result is
`context_replacement`: it preserves compaction references without replacing the
original outcome or claiming another execution.

```sh
agentprov context compare --run RUN_ID --left ENTRY_A --right ENTRY_B
agentprov context compare --run RUN_A --left ENTRY_A --right-run RUN_B --right ENTRY_B
agentprov context content --run RUN_ID --ref sha256:HASH --offset 0 --limit 65536
agentprov context list --run RUN_ID --group conversation --node GRAPH_NODE_ID
agentprov context list --run RUN_ID --entry ENTRY_ID
agentprov context links --run RUN_ID --entry ENTRY_ID
```

Graph navigation uses existing recorded links only. An empty link result includes
a reason; a similar command or timestamp does not create a link. `--group` accepts
`conversation` or `configuration`, including tool results or approvals respectively.
List pages contain 1-200 records; content pages contain 4-262144 UTF-8 bytes.

Comparison accepts two configuration records, approval records, or task records
(including user messages). It compares recorded content and source status.
`same` means those values agree; `different` identifies changed JSON paths;
`unknown` means the required body was not recorded or exceeds the comparison
budget. A missing field differs from explicit `null`, but neither implies an
effective authorization. A recorded permission request is not an approval.
Model selections, working directories, MCP/skills/plugins and sandbox settings
are only available when the source recorded them; current machine settings are
not substituted for historical evidence.

Configuration includes Codex/DeepSeek session metadata and turn/request records,
DeepSeek plan and permission changes, and Claude initialization/permission-mode
records when present in the selected source. These events remain separate
snapshots, not a reconstructed effective policy. Session logs do not necessarily
contain MCP, skills or plugin inventories; this does not add a Desktop adapter or
scan current machine configuration during historical imports.

Coverage reports list absent `configuration.*` fields for model/provider, application
version, working directory, permission/approval policy, sandbox, directory/network
restrictions, MCP servers, tools, skills and plugins. `task` and `approval_decision`
are checked separately. A permission request can exist while its decision is
missing. Explicit `null`, `false`, `{}` and `[]` are preserved as source values;
their presence does not prove effective authorization. Tool names alone are not
complete definitions. `ok` means no processing errors were observed in this range,
not that all fields or configuration changes were captured. Older reports retain
their original, potentially coarser missing-field checks.
Codex's native `model_provider_id` and `permission_profile` are recognized as
recorded provider and permission configuration. Directory and network coverage
require their own recorded profile fields; a profile name alone does not fill them.
Current reports also include `configuration.change_history_completeness`:
source snapshots cannot establish that every intervening change was logged,
even when all checked configuration fields are present. This is a coverage
limitation, not a processing error or a reason to discard the recorded snapshots.

Recorded working directories and application versions are scoped to their
source positions. Later Claude metadata or a Codex turn's changed directory
does not overwrite earlier entries or fill an earlier unknown value. Claude
directory/version changes also produce comparable source-metadata records.

Limits are explicit: 200 changes, 512-byte value previews, nesting depth 32,
and 1 MiB per comparison body. Longer stored evidence remains accessible through
the content reader. Text storage is limited to 32 MiB per body, chunked at
128 KiB. Content reads default to 64 KiB and allow at most 256 KiB per page;
follow `next_offset` rather than computing a character offset.

## Coverage and Portability

Coverage is source-scoped: `disabled`, `no_input`, `empty`, `ok`, `partial`,
`failed`, `ambiguous`, or `legacy_not_recorded`. Null counts are unknown, not
zero. Reports distinguish parser failures, unrecognized records, deferred tails,
limits and duplicate imports. Launch processes at most 128 selected transcript
sources. Its hook log and selected transcripts share a 256 MiB decompressed-input
budget and a 25,000 normalized-record budget; rejected and duplicate input still
consume those budgets. Per-source limits remain 128 MiB and 25,000 records.
Exhaustion is reported as partial coverage, never as a complete empty capture;
an incomplete resume checkpoint is not reported as a changed source. A source
ending exactly at the input budget can conservatively report exhaustion because
the parser cannot read beyond the budget to confirm EOF. Discovery and graph
projection have separate bounded budgets and persist their own diagnostics.

For resumed sessions, each entry carries `execution_scope`. The overview's
record totals include retained history; source reports put historical counts,
timestamps and missing fields in `prior_context`, separate from the current
processing range. Import totals count both ranges. An empty new range remains
`empty` even when history was saved. Historical approvals do not authorize new
actions, and an old configuration does not prove it remained effective after
resume. Older entries without a recorded boundary keep that distinction unknown.

Imported content is redacted before hashing and storage. Querying a saved body
never reopens the source path. Self-contained forensic bundles carry context,
coverage, configuration history, and chunked content. Import into another data
directory does not require the original harness or source files. Signing covers
the exported evidence; coverage and graph verification are separate checks.
Old bundles without context reports remain `legacy_not_recorded`.

New peer-message bodies larger than 64 KiB use the same chunked storage. The
graph retains one message node; its full saved body remains available to the
Dashboard and intent analysis after offline import. Existing inline messages
and the six historical signed demo bundles are not rewritten.

New exports also include full `telemetry_batch_records`, preserving ordered
event IDs and their hashes so the existing batch verifier still runs after
import. The older `telemetry_batches` summary field remains unchanged. A
historical summary without its event-ID list is not expanded into a fabricated
batch; that original bundle cannot provide batch-membership verification.

## Runtime Association

Launch records `runtime_correlation` in its JSON result and saves the report as
an evidence object. Collection status links that object without mixing exec
counts with transcript-record counts. Its counters describe the eligible records
read by this pass; `input_complete: false` means those are only partial counts.
`ok` means the correlation pass completed for its inputs, not lossless collection.

The Dashboard separates **session capture**, **runtime capture**, and
**tool-to-runtime association**. A partial association report is not a transcript
failure and has no transcript read/stored counters. Node backlog, probe coverage,
and unknown run-loss counts remain available under capture diagnostics; they are
not presented as events lost from this run. Uncertain completeness stays visible
in the summary, and a positive run-specific loss count is shown prominently.
Collapsing diagnostics does not change the saved report or its signature.

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

The graph and right-hand risk list remain the main view. Selecting evidence opens
one **Evidence reader** below the graph, with **Summary**, **Related events** and
**Saved content** tabs. Only the active tab is shown; the reader stays hidden
until there is something to inspect. Graph lenses, playback, zoom and evidence
links retain their existing behavior.

**Agent session** starts collapsed and keeps its three views: **Conversation &
tools**, **Permissions & configuration**, and **Collection status**. Overview
shortcuts open them directly. Execution sources, outbound data, timeline,
processes, network and compliance details also start collapsed, with counts in
their headings. Risk and collection-status summaries remain visible.

**Sessions & sources** groups recorded native session IDs within each harness.
A transcript and hooks source for the same session remain separately inspectable.
Recorded parent IDs link to sessions present in this run; missing parents and
conflicting or cyclic records are labeled. Sources without a session identity
have their own section, while processing diagnostics stay in collection status.
Click a session in the overview, or choose **View session graph** in the directory,
to filter the graph, related events and conversation. The scope label shows the
harness, native session ID, linked tool count and linked event count. **Back to
whole run** restores the previous lens, selected node, zoom and reading position.
Language switches and refreshes retain the session. **Read source records** opens
one source within the selected session; without a session filter it changes only
the conversation reader.

Session membership follows saved context-to-tool and tool-to-runtime edges.
Shared processes, files, directories and cgroups do not pull in another session's
events. Summary counts are calculated after filtering. Existing inferred edges
retain their rule and confidence; prior transcript history is excluded from the
current execution graph. A session with no linked execution evidence has an empty
graph and can still be read in the conversation view.

Risk, collection status and auxiliary sections keep their **Whole run** scope.
Following a risk or auxiliary evidence link returns to that scope. Public-demo
static exports use the same session selection and graph projections.

Expand **Known session relationships** in the directory to inspect recorded
connections. Matching harness and native session IDs link occurrences across
runs. Source metadata supplies parent/child relationships; typed Codex records
also supply delegation, fork and message-request relationships. Each relationship
keeps its direction and immutable source references under **Source and evidence**.
A message request describes the recorded request, not its delivery result.

**Other run** labels cross-run destinations. When a target has several recorded
occurrences, choose which run to view; the relationship is listed once. The return
button restores the preceding run, session filter, graph focus, zoom and reader.
Missing targets and conflicting parent claims remain visible. Navigation does
not change run membership or automatically include related runs in exports.
Static replay only discovers relationships within its exported run catalog.

Use **Open saved content** or **Raw source record** to open the reader's **Saved
content** tab. Body and raw-record selection, 64 KiB page reads, and an enlarged
view do not require keeping the session expanded.
The record list loads 30 entries per page; inline bodies preview at most 4 KiB
with four concurrent reads. Back navigation retains up to 200 page cursors;
**First page** resets the list without accumulating previous page bodies.

Complete structured pages can switch between **Readable view** and **Saved
bytes**. Readable tool results expose source text with real line breaks and
retain other recorded fields, including errors. This is a bounded display
projection, not a new evidence object. Hashes and offsets describe the saved
bytes; raw source records, partial pages and unsupported structures stay in
byte mode. No output is executed as HTML.

**Locate in graph** follows saved `context_tool_call`/`context_tool_result`
edges. Graph-to-session lookup also follows saved tool/runtime edges. These
are navigation relationships, not a new command or time-window inference.
Missing links explain the gap instead of choosing a similar command in another
session. Live refresh preserves opened records and content pages. Language
switches retain the selected view and reading position; browser session storage
holds navigation IDs/offsets only, not message or tool-output bodies.

For real interface examples, see the [DeepSeek walkthrough](../demo/deepseek-context/README.md):
conversation and tools, permissions/configuration, saved content and collection status.

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
workloads, separate from the [real sensor-backed DeepSeek task](../demo/deepseek-context/).
That signed offline example includes final file text, tool results and partial
runtime association, with its limitations and reproducible checks documented.
The reader does not retroactively create bodies that an older capture omitted.

The dashboard and daemon share read-only `/api/context/*` and `/v1/context/*`
routes. See the [API contract](agent-context-api.yaml) for fields, pagination,
errors and compatibility semantics.

The Dashboard's `/api/lens` and `/api/events` accept `harness` and `session`
together to select a recorded native session. The filter intersects other graph
or event filters; a missing session returns 404, and an incomplete pair returns
400. Scoped lens responses include `query.session_scope` with the identity,
link basis and counts. Resolution is limited to 256 sources and 10,000 current
tool records per session; exceeding a limit returns an error rather than a
partial graph. `/api/context/entries` and `/v1/context/entries` also accept
`harness` alongside `session` to distinguish matching native IDs from different
harnesses. This adds query filters without changing the evidence Bundle format.

## Search Saved Evidence

Use the magnifying-glass action above the graph. The temporary search window
shows matching excerpts on the left and the existing evidence reader on the
right. With a native session selected, search starts within that session;
**Whole run** explicitly includes other sessions and unassigned records.
Related sessions in other runs stay outside the search.

Search uses case-insensitive literal keywords, up to 256 characters. Categories
cover messages, tool inputs/results, configuration, saved files and runtime
records. It reads saved text in 64 KiB pages, including text beyond inline
previews. Each source contributes its first matching excerpt; identical body
hashes in a result page are grouped while retaining their source references.
Filename and other source-field matches are labeled separately from body matches.

Select a result to read its body or raw source record. **Locate in graph** uses
an existing relationship; **Return to search** restores the query, selected
source and reading position. Closing the window restores the original reader.
Results and navigation are retained in memory for up to eight run/session views.

Each result page scans until 50 matching source records or the end of the
catalog. **Search next page** advances to the next page; **Stop search** retains the
current results and marks the unsearched remainder. Read errors can be retried.
Unavailable bodies and collection reports remain visible under search coverage.
An empty result reads **No match found in saved content**. Rerun the search to
include records added while capture was continuing.

The Dashboard-only `GET /api/search/sources?run=RUN` returns a catalog of at
most 50 existing reader references. Pass `harness` and `session` together to
restrict it, then follow the opaque `next_cursor`. The client applies category
and keyword matching using `/api/context/content` and `/api/artifact`; no search
index or additional body copy is stored. Context entries use their latest saved
revision; saved artifact versions keep their exact object hashes. Raw source
envelopes are available for inspection but are not separately searched.
Fresh public-demo exports use the same catalog and scanner. Older exports
without a catalog display an unavailable-search message.

## Compare Runs

Use **Compare runs** above the graph. A starts with the current run; choose B
and use the swap button to reverse them. The window compares whole runs and
retains the Dashboard's session filter for your return. Each side shows its
recorded task, time range, sources and collection status.

The four views compare saved configuration fields, file evidence, network
destinations and outbound data types. Rows start collapsed with differences
selected. Expand a row to inspect A and B, choose a source reference, read its
saved body or locate its recorded graph node. **Return to comparison** restores
the original run, session scope, graph view and expanded comparison rows.

- Configuration keeps JSON types, including `null`, `false`, empty arrays and
  exact integers. Multiple recorded values retain their sources; the view does
  not select an effective configuration. Retained prior context is excluded.
- File access, write attempts and recorded content changes remain separate.
  Saved file bodies compare by digest; an empty file differs from unavailable
  content. Network rows distinguish connection attempts, requests and responses.
- **Only A recorded** and **Only B recorded** describe one-sided evidence.
  Incomplete values or reader limits appear as **Comparison incomplete**.
  Both task texts and capture reports remain available when conditions differ.
  Changes in configuration and network activity are investigation leads, not
  an automatically inferred cause.

The Dashboard-only `GET /api/compare/records?run=RUN` projects at most 50 saved
sources per page. Follow `next_cursor` until `has_more` is false. The endpoint
rejects session filters. Each record includes a comparison key, typed value
digest, bounded preview and its existing reader reference. Configuration reads
are limited to 1 MiB and 200 fields per snapshot; value previews use up to
512 UTF-8 bytes. The browser stops at 50,000 records or 100,000 sources per run
and reports the limit. The window lists 100 rows and 50 source references at a
time, with controls to continue. Refresh to include records saved during capture.

New public-demo exports include the same comparison catalog and reader. The
historical Grok pair demonstrates different saved outbound surfaces, rather
than a controlled before/after intervention. Older exports without a comparison
catalog display the reason it is unavailable.

## Offline Replay ZIP

Export one complete local run with its graph views, sessions, saved bodies,
configuration and raw records:

```bash
agentprov --data-dir .agentprov dashboard export --run RUN --output run-replay.zip
```

Unzip the archive and open `index.html` in a current Chrome or Edge browser.
The reader works offline without a local server, the CLI or the original
workspace. Language switching, graph navigation, session filters, saved-content
search and byte paging use the included data. A single-run export has no second
run for comparison.

The command exports the **whole run**, including unassigned records. It takes
a consistent database snapshot, reads only saved evidence and then freezes the
package. It never fills missing content from current workspace files. Linked
runs remain references. `export-inventory.json` lists the run, scope, file sizes
and SHA-256 digests; the command prints the ZIP size and inventory digest.
Existing output files are left unchanged.

This ZIP is an **unsigned sharing copy**. Original verification results and
capture gaps remain visible, while the package contains no original Bundle or
database. Review the archive before sharing: complete runs may contain prompts,
tool output, configuration and file contents. The command performs no upload.
Per-record exclusions and export-preview selection are not available in this
whole-run command.

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

New reports separate capture `issues` (loss, processing errors, required probe
failures) from `limitations` (optional probes and TLS visibility). The Dashboard
shows capability limits separately when they are the only reason for a partial
report. A backlog at seal remains **Capture completeness unconfirmed**, not an
ongoing background check. It never means all pending node events belong to this
run. Diagnostic details include individual probe outcomes and up to 64 bounded
node-level rejection examples, without rejected bodies, paths or command
arguments. Old signed reports are displayed as recorded, not rewritten.

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
