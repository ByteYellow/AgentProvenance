# Execution handoff protocol

[中文](zh-CN/execution-handoff.md)

This protocol connects an originating Agent Tool Call to independent commands
executed by another trusted producer. It preserves each executor's local Run and
uses explicit references for navigation and evidence delivery.

The current implementation provides durable admission, a bounded command worker,
restart recovery, stop requests and an authenticated HTTP API in `internal/handoff`
and `internal/daemon`. Evidence-transfer receipts, capability manifests and
Dashboard integration are being implemented. The
existing synchronous `POST /v1/record` API keeps its current behavior.

The local record engine exposes trusted in-process lifecycle hooks. Its prepared
checkpoint follows the saved execution binding and precedes command launch. Its
started checkpoint includes the actual PID and persisted start-event reference.
Execution cancellation uses an executor-owned context; a disconnected HTTP
client must not supply that context. Completion and the associated status rows
commit together, and evidence-write failures return an error. A failed checkpoint
after launch terminates and reaps the recorded process rather than continuing
without its execution evidence.

## Enable the executor

The API is disabled by default. Configure one trusted caller and one target in
an operator-owned JSON file; no credentials are stored in this file:

```json
{
  "target": {"producer_id": "lab", "instance_id": "vm-one", "generation": "deployment-one"},
  "caller": {"principal_id": "tool-router", "producer_id": "developer-mac", "namespace": "local-user"},
  "concurrency": 2
}
```

```sh
agentprov --data-dir ./executor-data daemon serve --execution-config ./execution.json
```

Use an isolated data directory for acceptance. Keep the daemon on loopback and
forward its port through the existing SSH connection. The caller uses the daemon
bearer credential and is trusted to assign native Tool Call references within
its configured namespace. `--insecure-open` is incompatible with this feature.
Shell, workdir and environment restrictions follow the existing record policy.

| Endpoint | Operation |
| --- | --- |
| `POST /v1/executions` | Admit a command; 202 for a new attempt, 200 for an idempotent replay |
| `GET /v1/executions/{id}` | Read attempt, checkpoint, local scope, output references and stop-request state |
| `GET /v1/executions?run=...&harness=...&session=...&tool_call=...` | Page through attempts for one source call |
| `POST /v1/executions/{id}/stop` | Persist `{"operation_id":"unique-stop-operation"}`; 202 acknowledges the request |

See the [OpenAPI contract](execution-handoff-api.yaml) for schemas and errors.
JSON writes are limited to 1 MiB and reject unknown fields or trailing JSON.
The daemon's existing bearer, Origin and Fetch Metadata checks remain in effect.

The worker holds an exclusive store lock, runs at most the configured number of
commands (default two), and keeps pending jobs in SQLite. On restart it recovers
saved execution-end events; unresolved starts become `unknown`. Recovery never
signals a process using only a historical PID. Stop requests for unresolved
attempts remain visible for operator reconciliation.

Each output stream retains at most 1 MiB before redaction and chunked storage;
larger streams report truncation and their observed byte count. `basic` omits
tool-result bodies unless explicitly enabled. Restart recovery reports lost
output as unknown. Successful execution currently leaves capture at `draining`
and delivery at `pending`, awaiting their respective evidence and receipt stages.

## Identity and trust

Every source reference contains `producer_id`, `namespace`, `run_id`, `harness`,
`session_id` and `tool_call_id`. A target contains `producer_id`, `instance_id`
and `generation`. The trusted host-side entry point assigns generation changes
for restore, rebuild and clone operations; copied guest boot IDs are additional
evidence, not the namespace authority.

A configured transport identity maps to one stable principal, one source
producer/namespace and an explicit set of permitted target instances. An empty
target set denies admission. The authenticated tool router owns its source
namespace and supplies the native Tool Call reference. Model-provided command
arguments do not select this identity. Operators revoke credentials at the
transport boundary; rotating a credential preserves the principal only when
its authorization remains the same. Historical signature keys are retained for
verification independently of active transport credentials.

The first deployment uses a preconfigured trust domain and an SSH tunnel to a
local executor. Transport authentication, source ownership and evidence
signatures are separate checks. A compromised trusted router or privileged
collector is outside the authenticity boundary of that producer's records.

## Dispatch and retry

`schema_version` is `agentprovenance.execution_handoff/v1`.

| Field | Meaning |
| --- | --- |
| `dispatch_id` | Logical handoff, scoped to the source producer and namespace |
| `operation_id` | Idempotency key for one admission or explicit reexecution |
| `previous_attempt_id` | Latest stopped or unknown attempt, required for reexecution |
| `valid_until` | Absolute admission/start deadline, at most 24 hours after receipt |
| `command` | Argument array, workdir, snapshot and context-retention settings |

Admission reserves the SQLite writer and commits the dispatch, attempt, request
digest and initial history together. The caller receives an executor-generated
attempt ID and local Run ID. Admission itself performs no command execution.

Repeated operations return the existing attempt. The same key with different
parameters returns `execution_conflict`. Reusing a dispatch with a different
source reference also conflicts. Explicit reexecution uses a new operation ID
and references the latest eligible attempt. Retrying that reexecution request
returns the same new attempt. An active attempt must first be stopped or
resolved; the executor never automatically queues an unknown attempt again.

Expired requests return `execution_request_expired`, including after deduplication
records have been removed. Their saved results remain queryable. An accepted
operation still queued past this deadline fails without starting. Once running,
the command uses the executor's separate timeout policy. Ledger records have
no automatic garbage collection in this implementation. A future cleanup policy
must retain all unexpired operation keys and all records required by evidence
and recovery retention; it must never silently admit an expired request anew.

## Canonical request digest

`digest_version` is `agentprovenance.execution_request_sha256/v1`. The executor:

1. Validates the version, identity fields, argument array and limits.
2. Normalizes `valid_until` to UTC, sampling to 25 ms when omitted, post-root
   observation to 250 ms when omitted, and context retention to `detailed` when
   omitted. `basic` and the optional tool-result override remain explicit.
3. Serializes the typed request in its declared field order using Go
   `encoding/json`. Optional `previous_attempt_id` and `tool_results` follow
   the field tags in `internal/handoff/contract.go`.
4. Serializes the two-element string array `[digest_version, canonical_json]`,
   computes SHA-256 over its UTF-8 bytes and returns lowercase hexadecimal.

The digest includes source, target generation, dispatch, operation, prior
attempt, deadline and command settings. Argument boundaries, whitespace and
paths retain their original meaning. Clients send ordinary JSON; the executor
computes the canonical digest. Unknown request fields must be rejected by the
transport adapter rather than silently changing the meaning of a signed request.

Identity fields are bounded to 512 UTF-8 bytes and exclude control characters.
Requests allow at most 256 arguments and 1 MiB of canonical JSON. Sampling is
1-60,000 ms and post-root observation is 1-30,000 ms. Shell, environment,
workspace and command-timeout restrictions remain executor policy, not fields
that an untrusted caller can relax.

## Independent states

| Dimension | States |
| --- | --- |
| Execution | `accepted`, `starting`, `running`, `succeeded`, `failed`, `cancelled`, `unknown` |
| Capture | `not_ready`, `collecting`, `draining`, `sealed`, `incomplete` |
| Delivery | `pending`, `transferring`, `acknowledged`, `conflict` |

The initial state is `accepted / not_ready / pending`. A compare-and-swap revision
allows exactly one worker to claim `accepted -> starting`. Starting and running
attempts survive restart as records for recovery inspection; they never return
to `accepted`. Verified recovery may resolve `unknown` to a running or terminal
state. Running and terminal observations require references to executor-produced
evidence. The worker must create and validate those references before advancing
the state. State and history updates commit together.

Capture moves through collection and draining to a sealed interval or an explicit
incomplete result. Sealing describes the recorded window and its known gaps.
Delivery acknowledgement describes a particular persisted evidence range and
digest. Neither field is changed by successful command completion. Late evidence
creates an additional package/version linked to the original digest.

Disconnecting a transport or cancelling a query leaves execution unchanged.
Stopping an attempt is a separate authenticated, idempotent operation. Its receipt
confirms storage of the request; the checkpoint records the observed command
outcome. Active noninteractive commands are cancelled through their process
group. Descendants outside that group require separate scope reconciliation.

## Capability and receipt contract

Each local Run will retain a capability manifest with producer/version, target
instance/generation, capture placement (host, guest or Sentry), runtime/kernel,
actual event support and enablement, content-retention settings, readiness,
capture intervals and known losses. Unknown loss counts stay unknown. Capability
changes create new intervals, preserving earlier observations. Existing native
capability and runtime-capture reports supply the native producer evidence.

Evidence receipts will bind issuer, receiver, target instance/generation,
Dispatch/Attempt, request digest, package digest and confirmed record range.
Acknowledgement follows durable receiver storage. Wrong destinations, identity
conflicts and mismatched digests must fail without altering accepted evidence.
Source clocks remain available; explicit dispatch/receipt links establish
cross-host ordering.

Full exports preserve original evidence packages and signatures. Selective
reading exports include only selected contents and permitted reference metadata.
They describe their selection separately from the original package signature.

## Compatibility and tests

Database schemas 21 and 22 add the execution ledger and durable stop requests without renaming legacy tables or
rewriting existing events. Older binaries reject the newer schema; use a backup
for a downgrade. Historic signed packages retain their original format.

Run the contract and persistence regressions with:

```sh
go test -race ./internal/handoff ./internal/daemon ./internal/store
```

The tests cover concurrent admission and worker claims, explicit reexecution,
source isolation, parameter conflicts, expiry, reopen recovery, transactional
history failures, bounded pagination, query cancellation, real command execution,
output retention, exclusive ownership and recovery of saved completion events.
`scripts/accept_execution_handoff.py` exercises an isolated daemon's public API
with concurrent CSV analysis, output artifacts, retry and cancellation. It uses
explicit fixture call IDs; native harness integration and evidence transfer have
separate acceptance gates.
