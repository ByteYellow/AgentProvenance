# Telemetry Event Schema

English · [简体中文](zh-CN/telemetry-schema.md)

AgentProvenance correlates application context with runtime telemetry. These
fields must stay separated so eBPF/Falco/Tetragon/LoongCollector-style events
can be ingested without pretending the kernel knows agent-level identifiers.

## Event Layers

| Layer | Examples | Source |
| --- | --- | --- |
| Application context | `run_id`, `trajectory_id`, `execution_scope_id`, `substrate_scope_id`, `tool_call_id`, `process_id`, `artifact_state_id` | AgentProvenance control plane or white-box tool router |
| Runtime identity | `raw_event_id`, `container_id`, `cgroup_id`, `pid`, `tgid`, `ppid`, `timestamp` | Runtime or telemetry substrate |
| Raw payload | syscall arguments, path, destination address, argv, event-specific fields | Runtime or telemetry substrate |
| Correlation result | `correlation.method`, `correlation.confidence`, `correlation.binding_id` | AgentProvenance correlator |
| Launch/correlation provenance | `binding_source`, `self_launched`, `correlation_class` | AgentProvenance correlator / recorder |

## Raw Payload Rules

The `payload` passed to `agentprov telemetry ingest` or `telemetry.IngestFiltered`
must be a JSON object. This is enforced at ingest time.

Application context and correlation results belong outside the raw payload.
The current validator recursively rejects these fields:

- `run_id`
- `rollout_id`
- `attempt_id`
- `session_id`
- `tool_call_id`
- `process_id`
- `snapshot_id`
- `correlation`

Those fields belong to structured ingest parameters or to the correlator output.
This keeps zero-SDK and eBPF-style events honest: raw runtime telemetry can be
linked to an execution scope, but it is not required to carry a ToolCallID.

Storage compatibility note: older bundle schemas and SQLite tables still use
`rollout_id`, `attempt_id`, `session_id`, and `snapshot_id`. They map to
`trajectory_id`, `execution_scope_id`, `substrate_scope_id`, and
`artifact_state_id` at API and documentation boundaries; raw telemetry should
prefer the new terms for structured context. Those newer aliases are not yet
in the raw-payload rejection list, so this validator is not a complete
application-field isolation guarantee.

`graph verify` also validates stored telemetry-source events after unwrapping
AgentProvenance correlation metadata. This catches malformed data loaded
directly into SQLite or produced by future receivers.

## Capture time and atomic ingestion

An explicit event `timestamp` must be RFC3339/RFC3339Nano. Ingestion preserves
that capture-time string in `events.created_at`; it does not replace it with
the later time at which a queued event reaches SQLite. If no timestamp is
provided, ingestion supplies the current time. Correlation compares parsed
instants, not the lexical ordering of differently formatted timestamps.

The shared ingest operation commits the event, runtime graph edges, evidence
row, binding closure and taint updates in one transaction. A write error rolls
back that event and is returned to the caller. JSONL imports use a savepoint
per row: a failed row leaves no partial evidence, while other valid rows in the
batch can commit. Policy evaluation is a subsequent operation, not part of
this event transaction. Existing stored evidence is not rewritten.

Native stream persistence and restart recovery have a separate
[documented contract](native-capture-spool.md). Event atomicity does not add
crash recovery to the legacy Falco spool worker.

## Event Body Shapes

The current MVP validates these minimum event-specific fields:

| Event type | Required body |
| --- | --- |
| `execve` | `argv` as a non-empty string array, or `command` |
| `process_exit` | numeric `exit_code` |
| `process_observed` | numeric `pid` |
| `file_open` / `file_write` / `secret_path` | non-traversal `path` or `file`; absolute host paths are accepted |
| `network_connect` / `metadata_ip` / `private_cidr` | `dst`, `dst_ip`, or `host` |
| `abnormal_process_tree` | numeric `pid` or `command` |
| `policy_verdict` | `decision` or `verdict` |
| `resource_pressure` | `resource` or `signal` |

The following types carry these fields but currently have no strict
required-body validation:

| Event type | Captured fields |
| --- | --- |
| `setuid` / `setgid` | `uid` / `gid` (privilege change; setuid/setgid to `0` is the escalation case) |
| `ptrace` | `request`, `target_pid` (process injection / inspection) |
| `file_rename` / `file_unlink` | `path` (tamper / cleanup) |
| `dns_query` | `host` (resolved name; egress by name, not just IP) |
| `tls_write` / `tls_read` | `preview_sha256` + short `preview` + allow-listed `http` metadata by default; optional body content as described below |

Empty paths and `..` traversal segments are rejected for file-oriented events.
Raw telemetry accepts absolute host paths; workspace file nodes retain their
relative-path constraint. The privilege/tamper/DNS/TLS types carry the fields
above but are not subject to a strict required-body check.

`secret_path` now covers a sensitive-path **read**, not only a write: the native
sensor captures filtered read opens of credential/secret paths.

`AGENTPROV_TLS_CAPTURE_BODY=1` explicitly retains captured plaintext in the
normalized event's `content` field for model-call materialization. This does
not guarantee a complete request or response. Without that
opt-in, normalization stores a hash and short preview rather than the full body.
Captured prompts, responses and raw spool payloads may contain sensitive data;
restrict access to the data directory and review bundles before sharing them.

For reassembled TLS messages, `http` preserves the sensor's parsed fields:

| Field | Meaning |
| --- | --- |
| `protocol`, `kind`, `headers_decoded` | HTTP version, request/response direction and reported header decoding state |
| `method`, `host`, `path`, `endpoint` | Request method, authority and encoded path; endpoint is authority + path |
| `status`, `content_type`, `is_stream` | Response status, media type without parameters and SSE indicator |
| `model`, `stream_id` | Model ID when available; HTTP/2 stream number within its connection |
| `connection_id` | Opaque `tls-v1:` capture-generation ID when OpenSSL lifecycle tracking and process identity are available |

Endpoint metadata excludes URL userinfo, query strings and fragments. Headers
such as Authorization and Cookie are not copied into `http`. Body/preview and
raw capture retention follow their existing settings independently. A stream ID
is connection-local and must be combined with a connection lifetime for pairing.
Reassembled `data` is the body, so it is not scanned for HTTP headers. Older raw
windows still use request/response-head parsing; a recognized HTTP/2 preface is
marked `headers_decoded: false`, while opaque binary bytes stay unclassified.
These optional fields require no database or bundle-format migration.

OpenSSL symbol inspection bounds each consumed ELF symbol/string section to
16 MiB and their combined size to 32 MiB. When an unused ordinary symbol or
string table exceeds those limits, the sensor can resolve exported OpenSSL
functions from the bounded dynamic table instead. It validates file-backed
executable offsets before attaching, without loading the oversized table.
This supports binaries such as Node.js that embed OpenSSL and export its APIs.

OpenSSL `SSL_read` and `SSL_read_ex` entry/return probes use the full kernel
`pid_tgid` and task start time. Each API retains up to four nested calls per
thread, with a bounded map of 4,096 threads. Returns beyond that depth are skipped
without consuming an outer frame and contribute to capture-loss diagnostics.
Returned byte counts are checked against the original buffer capacity; unreadable
`SSL_read_ex` output pointers also count as capture loss. Thread exit and successful
exec clear both read stacks, including the previous TID when a worker becomes the
process leader during exec. The existing
per-call plaintext cap remains 4 KiB. This pairing covers function invocations;
HTTP request/response association is a separate step.

OpenSSL capture generations combine the kernel boot, process start, SSL object
address and a kernel-stamped epoch. `SSL_new`, `SSL_clear`, `SSL_free` and BIO/FD
replacement probes bound the lifetime of retained HTTP/HPACK state. Each chunk
carries its epoch, and reads retain the entry epoch through return, so a lost
boundary record or delayed old read cannot join a newer buffered connection.
The epoch map holds at most 16,384 objects; userspace also bounds active and
closed-generation metadata. Discarded partial state is reported as a
`sensor_tls_reassembly` / `reassembly_gap` resource-pressure event.

Clear/rebind entries and `SSL_free` are conservative parsing boundaries:
the former may fail and the latter may only decrement a reference count.
The connection ID therefore identifies an observed capture generation, not a
TCP socket or proof of a completed handshake. Pending release/exit data remains
best-effort and truncated; new requests no longer implicitly end old responses.
Within one generation, HTTP/2 streams share their direction's HPACK dictionary.
If any required lifecycle probe fails, plaintext attachment for that target
waits for a successful retry; the capability report identifies the missing probe.
Other runtime probes continue independently. Go TLS and
legacy captures without an epoch omit `connection_id`; their lifecycle coverage
is unchanged. See [OpenSSL SSL_clear](https://docs.openssl.org/3.0/man3/SSL_clear/)
and [SSL_free](https://docs.openssl.org/3.0/man3/SSL_free/) for the API semantics.

## Example

Valid raw runtime event:

```sh
agentprov telemetry ingest \
  --type execve \
  --source tetragon_jsonl \
  --container-id container-1 \
  --cgroup-id cgroup-1 \
  --pid 424242 \
  --ppid 424200 \
  --payload '{"argv":["sh","-lc","pytest -q"]}'
```

Invalid raw payload:

```json
{
  "tool_call_id": "tool-123",
  "argv": ["pytest", "-q"]
}
```

The correct form is to pass `--tool-call tool-123` as structured application
context when it is known, or omit it and let the correlator resolve the event
through cgroup/container/pid/time evidence.

## Correlation Semantics

Correlation is not a single boolean. AgentProvenance keeps launch provenance and
runtime correlation separate:

| Field | Meaning |
| --- | --- |
| `binding_source` | How the scope binding was created, e.g. `zero_sdk_record`, `ai_asserted`, or receiver-specific context |
| `self_launched` | AgentProvenance directly launched the process scope, so descendants are expected to belong to this run |
| `correlation_class` | `self_observed`, `context_asserted`, `kernel_correlated`, or `uncorrelated` |
| `correlation_method` | The concrete join used, such as `process_id`, `cgroup_time_window`, `container_time_window`, or `pid_time_window` |
| `correlation_confidence` | Numeric confidence for that join |

Current confidence tiers:

| Method | Confidence | Notes |
| --- | --- | --- |
| Direct process / self-observed wrapper evidence | `1.0` | Self-consistency is not independent kernel corroboration |
| Real cgroup + time window | `0.98` | Execution-scope attribution |
| Container + time window | `0.92` | Execution-scope attribution |
| PID + time window | `0.85` | Process attribution, constrained by supplied scope keys; subject to PID reuse |
| `k8s_cgroup` binding source | default `0.8` | Passive Pod attribution without a recorder launch |
| `ai_asserted` binding source | default `0.5` | App-supplied claim, intentionally lower trust |

The final match uses the lower of the method confidence and the stored
binding confidence. These source values are defaults, not enforced limits on
every custom binding. Confidence is not a statistically calibrated probability.
Reported methods may also include a suffix describing the matched keys.

Confidence values are finite numbers in `[0,1]`. An omitted binding confidence
uses the source default; an explicit `0` stays zero during resolution, process-
lifetime inheritance, query and export. `telemetry bind --confidence 0` and
`POST /v1/telemetry/bind` follow the same rule. Negative, out-of-range and `null`
inputs are rejected. Clients that previously sent zero to request a default
should omit the field instead. Existing stored rows and signed bundles are not
rewritten.

Unified signals use the same numeric range and preserve explicit zero; omission
retains their default of `1`. Internal Go producers use `ConfidenceSet: true`
to supply an explicit zero. Graph edges with no recorded confidence leave the
field absent; the Dashboard shows `unknown` rather than `0.00`. Unresolved or
ambiguous joins retain their status/method alongside the numeric confidence.

Resolution checks the application process ID, kernel process-lifetime ID, then
PID with compatible scope keys before falling back to cgroup/container scope.
Every lookup uses the event's captured timestamp. A supplied process-lifetime
or application process ID disables bare-PID fallback. Container/cgroup matches
retain the common run, session and attempt; tool-call and application-process
IDs require more specific evidence.

Overlapping bindings are evaluated together. Conflicting candidates retain only
their common execution scope; conflicting runs remain unresolved. The saved
correlation envelope and `telemetry correlations` report include `scope_only`,
`ambiguous`, `candidate_count` and up to 32 sorted `candidate_binding_ids` when
applicable. All active candidates participate in resolution, even when the
diagnostic list is shortened. Report status distinguishes `scope_only` and
`ambiguous` from `resolved`, `provided` and `unresolved`.

These results are recorded with the event. Later binding changes do not replace
the recorded choice when opening its report. Existing events and signed bundles
keep their original correlation metadata.

### Runtime Process Graph Identity

New ingests with a PID store `runtime_process_identity` at the outer payload
envelope, with value `agentprov.runtime_process/v2`. This records the graph
identity contract separately from application `process_id` and scope binding.

- Native `agentprov_ebpf` records with a valid `process_instance_id`
  (`boot UUID:PID:start ns`) use `runtime_process/instance/<identity>` nodes.
  Labels and data-flow grouping use this identity across events, including
  cgroup moves; another birth time or kernel boot produces a separate node.
- Parent and optional thread-group lifetime references must match their numeric
  identifiers, share the child's boot and start no later than the child.
  Numeric PPID/TGID observations without a valid lifetime remain event-local.
  The native sensor currently supplies process and parent lifetimes; a missing
  thread-group lifetime is not synthesized from its TGID.
- Records without a usable native lifetime, including current external
  receiver and process-sampler records, use
  `runtime_process/observation/<event ID>/<pid|ppid|tgid>`. Their node metadata
  reports `identity_basis=event_observation`. Matching numeric PIDs alone does
  not join these observations or generate a same-process data-flow inference.
- Graph metadata distinguishes `kernel_process_instance`, `event_observation`
  and `legacy_pid`. New process-focused event queries and replay use recorded
  process-to-event edges, with the same pagination and evidence references.
- Verification checks v2 process edges against the event that produced them.
  Export/import preserves the identity marker, nodes and edges. Unversioned
  historical records keep their numeric-PID graph and `legacy_pid` metadata;
  opening them does not rewrite signed evidence.

This changes no database tables or bundle container format. Clients should treat
runtime graph node IDs as opaque strings rather than extracting a PID from a
fixed path segment.

In record-only mode, a synthetic scope id is sufficient because there is no
kernel telemetry to join. In supervised mode, `record` creates a real cgroup
scope and `sensor stream` observes syscalls from the host; the correlator joins
events back to the run by `cgroup_id` without requiring raw events to carry
agent identifiers.

## JSONL Receivers

The MVP can ingest already-filtered substrate JSONL:

```sh
agentprov telemetry ingest-jsonl --format tetragon --file tetragon-events.jsonl
agentprov telemetry ingest-jsonl --format falco --file falco-events.jsonl
agentprov telemetry ingest-jsonl --format loongcollector --file loong-events.jsonl
agentprov telemetry ingest-jsonl --format auto --file mixed-events.jsonl --json
agentprov telemetry ingest-falco --file falco-events.jsonl --json
falco -o json_output=true -o json_include_output_property=true | agentprov telemetry ingest-falco --file -
agentprov telemetry batches --run <run_id>
agentprov telemetry batches --run <run_id> --json
agentprov telemetry correlations --run <run_id> --json
agentprov telemetry correlations --event <event_id> --json
./scripts/demo_telemetry_jsonl.sh
```

Runnable fixtures live in `examples/telemetry/`.

`telemetry ingest-jsonl --json` returns both batch-level and row-level receiver
evidence. `receiver_summary` aggregates detected formats, normalized event
types, identity keys, resolved/unresolved rows, skipped rows, and failed rows.
`row_results` records the line number, detected format, normalized event type,
source, raw event id, identity keys, correlation method, and any skip/failure
reason. This keeps receiver behavior auditable without requiring raw telemetry
payloads to contain application context such as `tool_call_id`.

By default, `telemetry ingest-jsonl` also runs runtime-policy evaluation for
ingested events. Risky substrate rows such as metadata IP access, private CIDR
access, and secret-path reads create `policy_decisions`, `risk_signals`,
`response_actions`, graph edges, and timeline rows. The ingest result includes
`policy_decisions` and `policy_decision_ids`; pass `--no-policy` to disable
policy evaluation while retaining normalization, correlation, and storage.

`telemetry correlations --json` explains the second half of the path: why a
normalized runtime event was attached to an execution scope or tool call. The report includes
the raw runtime identity, resolved application context, matched binding,
matched identity keys such as `pid`, `container_id`, `cgroup_id`, and `time`,
confidence, time window, and drill-down refs.

The receiver maps recognized substrate events into the normalized schema:

| Source | Input shape | Normalized event |
| --- | --- | --- |
| Native eBPF sensor (`agentprov_ebpf`) | own-sensor JSONL, auto-detected | `execve`, `network_connect`/`metadata_ip`/`private_cidr`, `file_write`, sensitive read → `secret_path` (else `file_open`), `process_exit`, `setuid`/`setgid`, `ptrace`, `file_rename`, `file_unlink`, `tls_write`/`tls_read`, `dns_query`, `resource_pressure` |
| Tetragon | `process_exec` | `execve` |
| Tetragon | `process_exit` | `process_exit` |
| Falco | `execve`, `execveat`, `spawned_process` | `execve` |
| Falco | `open`, `openat`, `openat2`, `creat` | `file_open`, `file_write`, or `secret_path` |
| Falco | `connect` | `network_connect`, `metadata_ip`, or `private_cidr` |
| LoongCollector | `execve`, `process_exit`, `file_open`, `file_write`, `network_connect` | matching normalized family |

The native sensor (`internal/sensor`, `cmd/agentprov-sensor`; Linux amd64/arm64)
emits JSONL that the native mapper converts into the shared ingest schema,
so native telemetry drives the same correlation → policy → risk path as other
receivers. Ingestion preserves TLS observations. `launch` at sealing time, or
`graph materialize-llm --run <id>`, derives exchanges over the saved messages
using `agentprov.tls_connection_exchange/v1`:

- HTTP/2 pairs a unique request and final response by `connection_id` and
  `stream_id`. Concurrent streams and reversed ingestion order stay separate.
- HTTP/1.x accepts only complete, strictly alternating request/response records
  on one capture generation, ordered by capture time. Pipelining, equal times,
  duplicate responses or a broken sequence remain ambiguous. Truncation or a
  saved run report indicating capture loss/backlog prevents serial inference.
- Both paths require compatible capture origin, process and scope, decoded
  headers, and a response timestamp at or after its request. Missing connection
  or stream identity remains unknown; neither PID proximity nor an old pairing
  edge supplies the missing identity. Informational responses are retained
  separately from the final response.

Each materialized `llm_message` includes a `correlation` assessment with
`status` (`matched`, `unknown`, `ambiguous`), `reason`, rule, method, confidence
and matched peer event ID. Body retention remains opt-in; metadata-only messages
can still be paired. Graph queries expose pairing edges as derived, with source
event references. HTTP/2 identity matches use confidence `1`; HTTP/1 serial
inference uses `0.8`. These are association grades, not measured accuracy rates.

Reanalysis atomically replaces TLS-derived exchanges, including withdrawing a
pair when a late duplicate makes it ambiguous. It keeps raw events, transcript
and endpoint evidence intact. Opening an existing signed bundle preserves its
recorded graph; explicitly reanalysing an imported run creates updated derived
results in the local store. Original bundle files remain unchanged.
New ingestion no longer creates the legacy temporal `llm_intent_caused` edge.

The materialized `llm_caused` command association uses the stricter
`agentprov.intent_command_scope/v2` rule:

- An exec must occur strictly after the decision and within two minutes. TLS
  matching requires the same capture source and known kernel boot or node
  identity, plus a shared cgroup or container; conflicting known scope keys
  exclude a candidate. Ambiguous request/response pairings are excluded.
- Complete `argv` is compared without case folding, path aliases or extra
  arguments. Plain literal commands are compared argument by argument; complex
  shell syntax requires an intact `sh`/`bash`/`zsh -c` or `-lc` script argument.
  Joined command text, truncated argv and `process_observed` samples remain
  evidence, but do not supply an execution anchor.
- Transcript matching requires a recorded decision timestamp, `tool_use.id`,
  compatible agent/session identity, and the current direct `agent_syscall`
  exec anchor within the tool's recorded interval. It does not search the whole
  run by command text. Inherited child edges are not reused as direct anchors.
- A decision with multiple execution candidates, or an exec claimed by multiple
  decisions in the analysis input, remains unlinked. Request/response objects
  are retained for inspection. Endpoint upload ordering supplies no such anchor.

New command edges carry a versioned ID. Graph queries expose `derived: true`,
the rule name, heuristic confidence `0.8`, and evidence references, including
after signed bundle export/import. Existing imported edges retain their original
metadata. TLS and transcript passes use bounded inputs and transactional
replacement; an input-limit or database error preserves the previous stored
result instead of publishing a partial rebuild.

For local supervised capture, the CLI also exposes:

```sh
agentprov --data-dir <dir> sensor stream
```

This runs the native sensor as a per-node supervisor, ingests its normalized
events into the local store, applies policy/risk evaluation by default, and uses
the same cgroup/container/pid/time correlation path as JSONL receivers. It is
the product path used by the committed `run-snake-supervised` demo bundle.

Unrecognized rows are skipped. Malformed rows or rows that fail schema
validation are counted as failed and reported in the ingest result.

`telemetry ingest-falco` is the dedicated Falco-compatible path. It accepts a
Falco JSON/stdout file or stdin stream, maps process/file/network rows, then
runs runtime-policy evaluation by default. Metadata IP, private CIDR, and
secret-path Falco rows therefore create normalized runtime events plus
`policy_decisions`, `risk_signals`, `response_actions`, graph edges, and
timeline rows. Use `--no-policy` when the receiver should only normalize and
store telemetry.

`graph explain --risk <policy_decision_id> --json` links the resulting risk
back to the normalized runtime event and forward to the recorded response
action, so the receiver path can be audited end to end.

Each JSONL ingest also writes a compact telemetry batch manifest:

- `batch_id`
- source `format`
- input `path`
- input `file_sha256`
- row counters: read / ingested / skipped / failed
- mapped `event_ids_json`
- `event_ids_sha256`

The batch manifest intentionally does not copy the raw telemetry stream into
SQLite. It gives the provenance graph a stable audit handle for the external
evidence source while keeping AgentProvenance out of the long-term log storage
business. `graph verify` checks that batch event IDs still exist for the run
and that the event ID hash has not drifted.

After `graph materialize --run <run_id>`, the batch is also written as a
`telemetry_batch` content-addressed object. Its parent hashes point to the
normalized runtime event objects generated from that input batch. `graph
explain --event <event_id> --json` includes matching `telemetry_batches`, so an
operator can move from a substrate event to the original receiver batch, input
file hash, mapped event IDs, and object refs.

`graph explain --event <event_id> --json` includes a `telemetry` section for
runtime events. It reports the receiver (`tetragon`, `falco`,
`loongcollector`, or local wrapper), source format, normalized event type,
identity keys used for correlation, schema validation status, and correlation
status. This is the main inspection surface for answering how a substrate event
became part of the provenance DAG.
