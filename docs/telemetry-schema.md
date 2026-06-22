# Telemetry Event Schema

AgentProvenance correlates application context with runtime telemetry. These
fields must stay separated so eBPF/Falco/Tetragon/LoongCollector-style events
can be ingested without pretending the kernel knows agent-level identifiers.

## Event Layers

| Layer | Examples | Source |
| --- | --- | --- |
| Application context | `run_id`, `rollout_id`, `attempt_id`, `session_id`, `tool_call_id`, `process_id`, `snapshot_id` | AgentProvenance control plane or white-box tool router |
| Runtime identity | `raw_event_id`, `container_id`, `cgroup_id`, `pid`, `tgid`, `ppid`, `timestamp` | Runtime or telemetry substrate |
| Raw payload | syscall arguments, path, destination address, argv, event-specific fields | Runtime or telemetry substrate |
| Correlation result | `correlation.method`, `correlation.confidence`, `correlation.binding_id` | AgentProvenance correlator |

## Raw Payload Rules

The `payload` passed to `agentprov telemetry ingest` or `telemetry.IngestFiltered`
must be a JSON object. This is enforced at ingest time.

The raw payload must not contain application context or correlation result
fields:

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
linked to a ToolCallScope, but it is not required to carry a ToolCallID.

`graph verify` also validates stored telemetry-source events after unwrapping
AgentProvenance correlation metadata. This catches malformed data loaded
directly into SQLite or produced by future receivers.

## Event Body Shapes

The current MVP validates these minimum event-specific fields:

| Event type | Required body |
| --- | --- |
| `execve` | `argv` as a non-empty string array, or `command` |
| `process_exit` | numeric `exit_code` |
| `file_open` / `file_write` / `secret_path` | safe relative `path` or `file` |
| `network_connect` / `metadata_ip` / `private_cidr` | `dst`, `dst_ip`, or `host` |
| `abnormal_process_tree` | numeric `pid` or `command` |
| `policy_verdict` | `decision` or `verdict` |
| `resource_pressure` | `resource` or `signal` |

Absolute paths, `..` paths, and `/workspace/../...`-style escapes are rejected
for file-oriented events.

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
./scripts/demo_telemetry_jsonl.sh
```

Runnable fixtures live in `examples/telemetry/`.

The receiver maps recognized substrate events into the normalized schema:

| Source | Input shape | Normalized event |
| --- | --- | --- |
| Tetragon | `process_exec` | `execve` |
| Tetragon | `process_exit` | `process_exit` |
| Falco | `execve`, `execveat`, `spawned_process` | `execve` |
| Falco | `open`, `openat`, `openat2`, `creat` | `file_open`, `file_write`, or `secret_path` |
| Falco | `connect` | `network_connect`, `metadata_ip`, or `private_cidr` |
| LoongCollector | `execve`, `process_exit`, `file_open`, `file_write`, `network_connect` | matching normalized family |

Unrecognized rows are skipped. Malformed rows or rows that fail schema
validation are counted as failed and reported in the ingest result.

`telemetry ingest-falco` is the dedicated Falco-compatible path. It accepts a
Falco JSON/stdout file or stdin stream, maps process/file/network rows, then
runs runtime-policy evaluation by default. Metadata IP, private CIDR, and
secret-path Falco rows therefore create normalized runtime events plus
`policy_decisions`, `risk_signals`, `response_actions`, graph edges, and
timeline rows. Use `--no-policy` when the receiver should only normalize and
store telemetry.

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
