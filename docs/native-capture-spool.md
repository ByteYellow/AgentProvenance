# Native capture persistence and late attribution

English | [简体中文](zh-CN/native-capture-spool.md)

`agentprov sensor stream` uses the local telemetry spool for native eBPF capture.
It records normalized, privacy-filtered events on disk before asynchronously
correlating them into the evidence store. It no longer accumulates every event
ID in a single result until the process exits.

## Defaults and controls

| Flag | Default | Meaning |
| --- | --- | --- |
| `--batch-events` | `256` | Maximum events in one batch; allowed range 1–4096 |
| `--batch-bytes` | `1048576` | Maximum normalized bytes in one batch |
| `--flush-interval` | `1s` | Periodic batch sealing and processing |
| `--pending-ttl` | `2m` | Wait for missing execution context, measured from batch creation |
| `--max-queued-bytes` | `268435456` | Active spool backlog bound |
| `--max-queued-batches` | `4096` | Active spool batch count bound |
| `--keep-uncorrelated` | `false` | Retain unattributed events immediately instead of waiting and expiring |
| `--no-policy` | `false` | Disable policy evaluation after committed batches |

The queue reserves a full batch before opening its capture file. Admission is
therefore conservative: a new batch requires `batch-bytes` of free capacity.
When the queue is full, new events are discarded and a durable
`dropped_queue_full` counter increases. An oversized normalized event similarly
increases `dropped_oversize`. Encoded normalized rows must also be smaller than
1 MiB, even if the configured batch is larger, to remain replayable. This bounds temporary storage; it is not a promise
that every kernel event will be retained under arbitrary load.

## Durability and replay

Each accepted normalized row is appended to a mode-0600 file and fsynced.
The file's directory is synced when created. A batch is sealed at its size or
event limit, or on the next flush tick, and then becomes eligible for processing.
Schema 17 metadata distinguishes `initializing`, `capturing`, `queued`,
`processing`, and `processed` batches. No producer row can enter an initializing
batch: the file must first be created, its directory synced, and the metadata
transition committed. SQLite connections explicitly use `synchronous=FULL`.
Only one native collector may own a store at a time. Newer database schemas are
rejected before migration writes; keep older binaries away from an upgraded store.

On restart, complete rows in a previously capturing file are sealed and replayed.
A partial final row is truncated and counted as `dropped_partial_recovery`.
Interrupted processing returns to the queue. A per-batch, per-line receipt is
committed in the same transaction as its event, graph side effects, event
windows, and evidence batch manifest. Retrying the same spool row does not
duplicate the accepted event. Two separate captures with identical bytes remain
two events. Hashes verify spool contents before replay.

Restart may discard an empty or missing initializing file, since it could not
have accepted a row. A missing capturing file instead fails startup and records
the error; accepted evidence must never silently disappear. Correlation reads
share the event transaction, so an exit earlier in a batch closes its process
binding before a later reused-PID event is resolved.

Successfully processed payload files are removed and their directory is synced;
row receipts are also removed once the batch completes. Evidence events, bounded
batch manifests, spool outcome metadata, and cumulative loss counters remain in
the database. The database still grows with retained evidence; the queue limit
does not impose an evidence retention policy.

Failed file cleanup is retried in bounded sweeps while collection continues.
Cleanup failures do not block collector restart. Processed files awaiting cleanup still consume queue capacity and appear as
`cleanup_pending_batches`; their already committed events are not replayed.

The disk spool contains normalized events, not an unfiltered copy of sensor
stdout. Existing TLS preview/body selection and secret redaction run **before**
writing the spool. Batch content hashes refer to these normalized bytes.

## Late context

An unresolved native event stays in its durable batch until context arrives or
its TTL expires. Every retry uses the original capture timestamp. Closed binding
intervals remain eligible, so an informer can attribute a short container after
it exits. Replayed event timestamps and event windows retain capture time.

Already matched rows in a mixed batch are committed immediately; unmatched rows
do not block them. Manifests are separated by run and contain only the events
accepted in that processing pass. Pending batches wait at least one second
between attempts; new batches remain eligible. Processing failures preserve the
batch and its error, increment `retry_failures`, and retry after five seconds.

Expiry increases `expired_uncorrelated`. This count includes untracked host
activity: it does not prove every expired row belonged to a tracked workload.
If neither a stable container/cgroup identity nor a usable historical binding
survives, attribution remains unknown rather than guessed. Delayed process-exit
events cannot close a reused-PID binding that started after the captured exit.

## Status and limits

```sh
agentprov --data-dir /var/lib/agentprov sensor status --json
```

The response includes `collector_running`, `capabilities_historical`, the latest
timestamped probe capability snapshot, and `capture` counters, queued bytes,
queued batches, and pending event count. Liveness is established from the
process-held collector lock; a saved `ready` report alone cannot establish that
the collector survived a crash. The report remains a snapshot and can change
immediately after it is read.

`captured` counts sealed rows, including rows recovered after a crash. The active
batch appears in that counter at the next seal. Informational input/exclusion
counters flush periodically and can lag a hard crash. Queue rejection, expiry,
and replay outcomes are persisted separately. Kernel `resource_pressure` loss
events bypass the unresolved-context wait and are retained for producer health.

Producer health exposes the same node-wide counters as `native_node_capture`,
even for a run-filtered query: an unknown event cannot honestly be assigned to
one run. Pending capture and recorded loss prevent reporting complete coverage.

The durability boundary starts after the sensor has delivered a complete row to
the writer. Kernel ring-buffer loss, a process killed before delivery, and host
storage that cannot honor fsync remain outside that guarantee. If storage can no
longer persist capture, the collector returns an error. Post-commit policy
evaluation is best effort and has separate `policy_failures` counters; it is not
part of the evidence transaction.

Native replay is owned by `sensor stream`; the generic Falco spool worker leaves
native batches alone. Restart the native collector to resume their processing.

## Verification

`internal/telemetry/native_stream_test.go` covers closed-window late attribution,
crash recovery before sealing, interrupted processing without duplicate IDs,
transaction rollback/retry, TTL expiry, queue bounds, bounded live manifests,
identical distinct events, privacy before persistence, and collector exclusion.
`internal/correlation/binding_test.go` covers delayed exits after PID reuse.
Additional regressions cover same-batch exits, normalized row growth, lost
capture files, pre-capture initialization recovery and cleanup errors at restart.
