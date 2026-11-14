# Execution handoff protocol

[中文](zh-CN/execution-handoff.md)

This protocol connects an originating Agent Tool Call to independent commands
executed by another trusted producer. It preserves each executor's local Run and
uses explicit references for navigation and evidence delivery.

The current implementation provides durable admission, a bounded command worker,
restart recovery, stop requests and an authenticated HTTP API in `internal/handoff`
and `internal/daemon`. Signed packages and durable receiving receipts are available
through the pull API and `forensics collect-execution`. Capability manifests and
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
| `POST /v1/executions/{id}/deliveries` | Prepare `{"operation_id":"stable-delivery-operation"}`; 201 for a new package, 200 for replay |
| `GET /v1/execution-deliveries/{id}` | Read the signed manifest and any saved receipt |
| `GET /v1/execution-deliveries/{id}/bundle` | Download the exact signed bytes; authenticated, no-store, attachment-only |
| `POST /v1/execution-deliveries/{id}/receipt` | Submit the receiver's DSSE envelope; 200 after durable acknowledgment |

See the [OpenAPI contract](execution-handoff-api.yaml) for schemas and errors.
Execution JSON writes are limited to 1 MiB; receipt envelopes have a 64 KiB limit.
Unknown request fields and trailing JSON are rejected.
The daemon's existing bearer, Origin and Fetch Metadata checks remain in effect.

The worker holds an exclusive store lock, runs at most the configured number of
commands (default two), and keeps pending jobs in SQLite. On restart it recovers
saved execution-end events. When a Linux command is still running, it verifies
the saved boot, cgroup filesystem and kernel cgroup ID before reopening that
scope. The recovered task occupies an execution slot and retains its original
deadline and durable stop requests. The command is not launched again.
Unresolved starts and legacy scopes without a recovery anchor become `unknown`;
their stop requests remain visible for operator reconciliation.

The checkpoint's `recovery_report` records scope observations and any stop
result. A confirmed stop produces `cancelled`; a confirmed timeout produces
`failed`. If the scope empties naturally and no execution-end record survived,
execution remains `unknown`, with no invented exit code. Lost output remains
unknown and capture remains `incomplete`. The binding closes with the empty-scope
observation in the same transaction as the checkpoint. Signed delivery retains
these observations. Recovery controls only the verified cgroup descriptor,
including after a same-name path replacement; it never falls back to an old PID.

On Linux with a writable cgroup v2 subtree, cancellation, execution timeout and
post-launch checkpoint failure stop the owned cgroup using `cgroup.kill`. This
includes descendants that create a separate process group with `setsid`. The
executor holds the cgroup directory open. New commands use newly created scopes;
restart recovery can reopen only a scope matching its saved identity.
After the root is reaped, it waits up to two seconds for `cgroup.events` to report
an empty subtree. Other concurrent execution scopes are left running.

The result's `stop_report` records the method, signal result, observation times,
`scope_empty` and any error. A still-populated scope leaves the attempt `unknown`.
If cgroup stopping fails, the root is stopped and the scope error is retained.
Without a kernel cgroup, cancellation retains the existing process-group/root
behavior: command status describes the root, `scope_empty` is null and capture
is `incomplete`. Stop reports persist with the end event and survive recovery
and signed delivery. Processes deliberately moved outside the owned cgroup
require separate operator reconciliation.

Each output stream retains at most 1 MiB before redaction and chunked storage;
larger streams report truncation and their observed byte count. `basic` omits
tool-result bodies unless explicitly enabled. Restart recovery reports lost
output as unknown. Without an attached capture controller, successful execution
leaves capture at `draining`. Delivery advances independently through signed
packages and durable receipts.

### Native capture boundaries

On Linux, add `"capture": {"mode": "native"}` to the execution configuration to
start one shared Sensor and durable native spool with the daemon. It requires
BPF permissions and a writable cgroup v2 subtree. Omit `capture` to retain an
externally managed sensor or command-only deployment, including macOS.

The daemon waits for required probes before starting its execution worker and
HTTP listener. Startup failure releases the collector lock. An unexpected sensor
or spool failure stops the daemon; normal shutdown closes active executions
before the collector. A second collector using the same store is refused.
`sensor status --json` reads the same capability snapshot and spool counters.

Optional capture settings are `ring_buffer_mib` (default 64, power of two from
1 to 256), `tls_targets` (up to 128 absolute paths), `auto_tls`, `apparmor_state`
and `seccomp_state` (each enabled by default), `no_policy` (default false),
`startup_timeout_seconds` (default 15, range 1 to 120) and
`close_timeout_seconds` (default 3, range 1 to 30). Existing `AGENTPROV_SSL_LIB`,
`AGENTPROV_GO_TLS_BIN` and `AGENTPROV_LIBC_LIB` target settings are also used.
Collection uses the existing bounded native spool and late-binding retention.
It excludes the daemon's own cgroup; task workspaces inside the data directory
remain observable.

In-process integrations can also supply `Executor.Capture` and own the same
start/stop ordering themselves.

Before launch, the controller requires the execution's owned kernel cgroup and
ready mandatory probes. It inserts a marker into the live kernel ring and saves
the corresponding decoder boundary, capability snapshot and fixed spool prefix.
A failed preflight prevents command launch. At completion, `scope_observation`
records population through the still-owned directory descriptor; normal success
leaves deliberately backgrounded descendants running.

After the saved end event, the controller takes another boundary while still
holding the owned cgroup. It drains this collector epoch's accepted sequence
interval for that cgroup, with a three-second default budget. Unclassified rows
in the interval are included conservatively. An empty scope, settled scope
interval and no observed loss, state-sampling gaps or buffered TLS allow `sealed`;
pending records, loss, state-sampling gaps, changed collector identity or unknown population produce
`incomplete`. The cgroup is released after the completion hook returns.

`capture_report` version 2 retains `scope_prefix`, its durable `scope_progress`,
and the collector-wide `shared_prefix` separately. Unresolved rows in other
cgroups keep their original retention and processing status without blocking
this execution's scope drain. Scope counts survive batch payload cleanup;
already processed loss within the interval remains visible. Unlocalized kernel,
state-queue, TLS and pre-persistence spool losses remain collector-wide signals.
Buffered TLS is reported without flushing live connections. Probe limitations
remain in the saved capabilities. Historical version-1 reports keep their
original shared-prefix interpretation.

Execution success and receipt acknowledgment remain separate from capture state.
If the executor restarts during draining, it preserves the command result and
saved boundary, marks capture incomplete, and does not repeat the command.

Procfs state snapshots retain a separate `sampling_trigger` when a kernel event
requested the read. This assigns sampling work to its original scope for capture
accounting, even if the task exited before procfs could read it. Actual task state
still uses independently observed procfs identity. When the task is unavailable,
an unambiguous binding at the trigger time can retain the failed observation in
that Run with method `sampling_trigger_scope:cgroup_id+time`. It carries no
observed process, Tool Call, session or cgroup membership. Unbound or ambiguous
triggers retain the existing late-binding behavior.

Durably ingested unavailable task/security observations increment `sampling_gaps`,
a subset of `ingested`. The prefix can be `settled` while capture remains
`incomplete` with `scope_state_sampling_gap`; no drain timeout is needed to report
an already completed failed read. Counts survive replay and spool cleanup.
Schema 25 adds this counter without changing old events or signed reports;
historical reports retain their original interpretation.

## Route native Claude Bash calls

`launch --remote-execution route.json -- claude ...` connects Claude Code's
native `session_id` and `tool_use_id` to the execution protocol. This opt-in
integration requires Claude Code 2.1.295 or later, enabled hooks and a local
foreground session. The normal launch path is unchanged without this option.
Before launching the task, a no-model, non-persisted initialization probe checks
that the route hook actually runs under the effective settings. Disabled hooks
or a failed probe abort launch; its local log is retained for diagnosis.

Enable signed delivery on the executor as described below. Its workdir must
remain inside the executor's workspace root. Bash routing also requires the
operator to start that executor with `--record-allow-shell`; existing workdir,
environment and execution-time limits still apply.

Keep this caller-side configuration outside the agent workspace:

```json
{
  "schema_version": "agentprovenance.claude_command_route/v1",
  "url": "http://127.0.0.1:18575",
  "token_file": "executor.token",
  "execution_config": "execution.json",
  "workdir": "/srv/agentprov/workspaces/analysis",
  "receiver_id": "investigator",
  "sign_key_file": "investigator.key",
  "public_key_file": "executor.pub",
  "timeout_seconds": 300,
  "file_diff": false
}
```

Credential and execution-configuration paths are relative to this file.
`execution.json` supplies the same caller/target identities as the executor.
The transport must be HTTPS or literal loopback HTTP through the SSH tunnel.
`shell` defaults to `/bin/bash`. `timeout_seconds` bounds the wrapper's admission,
execution wait and collection; it does not extend the executor's own timeout.
Set `file_diff: true` to retain changed-file bodies using the existing snapshot
and artifact capture. This copies the workdir before each command, so use a
dedicated task workspace. Otherwise kernel file events remain available when
native capture is enabled, without a per-command workspace snapshot.

```sh
agentprov --data-dir ./caller-evidence launch \
  --remote-execution /path/to/operator/route.json -- claude
```

The per-run PreToolUse hook prepares a stable request without submitting it.
It rewrites Bash to the local remote-command wrapper, leaving the original
command visible for Claude's normal permission checks. The hook does not grant
permission. Once approved, the wrapper submits, waits, verifies the signed result,
persists the receipt and returns retained stdout/stderr with the remote exit code.
The overlay uses [Claude's blocking hook failure handling](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails).
Preparation failures are denied; hook-disabled and detached launch modes are
rejected. Remote routing is a trusted integration, not a replacement for the
harness's permission policy or OS isolation.

Only Bash is remote. Read, Write and Edit remain local. SessionStart explains
the target and remote workdir to the agent. Each Bash call starts an independent
shell; directory and environment changes do not persist between calls. Explicit
background Bash requests are rejected. Use the remote workdir for shared files.

Requests and admissions are saved under
`<data-dir>/execution-routes/<run-id>/`. Reinvoking the same prepared call recovers
the existing attempt; changing its command is a conflict. After authenticated
admission, a cancelled wrapper requests a durable stop, including during local
evidence persistence and collection. Reuse the prepared request to recover the
attempt if cancellation prevented the admission file from being saved.
Delivery errors leave the admission available for `forensics collect-execution`.
Execution, capture and delivery states are printed separately.

The router also saves a content-addressed `execution_source_admission` object
in the caller Run. It records the qualified native call, dispatch and attempt,
explicit-retry predecessor, authenticated principal and configured signing-key
fingerprints. Repeated admission keeps the original object; a conflicting
identity or fingerprint fails explicitly. This metadata carries no command body,
credentials or local configuration paths and is included in signed Bundle export.
It records admission; later results and delivery acknowledgment retain their
own evidence. The original route files remain the inputs for transport recovery.

After receiving a signed package, the same transaction saves an
`execution_delivery_evidence` object with the original manifest, receipt and
public verification material. The caller admission pins those public keys by
fingerprint. Both native routing and `forensics collect-execution` save this
relationship; retrying a previously received package can add its missing link
without rerunning the command. Signed Bundle exports retain these objects.

Tool output is read from the locally verified evidence projection, subject to
the existing redaction and 1 MiB-per-stream retention limit. Truncation is reported.
This path requires retained tool results; use detailed capture or explicitly
select `--capture basic --capture-tool-results=true`. Configuration preflight
does not silently change a selected omission policy.

### Query saved execution links

Use `GET /v1/execution-links?run=<caller-run>&direction=outgoing` on the local
daemon, or `GET /api/execution-links` on the Dashboard. Query
`run=<execution-run>&direction=incoming` to return toward the originating call.
The response retains producer, namespace, harness, native session/call, target
instance/generation, dispatch and attempt. Optional `harness`, `session` and
`tool_call` filters apply within each scanned page. Follow `next_cursor` while
`has_more` is true, including after an empty filtered page. `limit` is 1-100.

The reader verifies object hashes, both signatures and the admission's pinned
fingerprints. It returns the latest saved package version per admission and
leaves prior immutable packages available as evidence. `manifest.state` is the
executor's snapshot; `receipt.status=persisted` is the receiver's observation.
The signed receiving receipt does not report whether the sender received its ACK.
If only the execution Bundle was imported, `basis=unanchored_delivery` and
`source_admission_not_included` identify the missing caller record. Importing
the separately signed caller Bundle resolves that reference. Hash, signature
or identity conflicts fail the query rather than producing an empty page.

The [typed API](execution-handoff-api.yaml) describes these read responses.
Reading stored links needs no running executor or access to its workspace.

### Verify a real agent task

[`accept_execution_native.py`](../scripts/accept_execution_native.py) exercises
the native Claude route on the caller. It uses the caller's existing provider
configuration and makes model requests, with a USD 0.25 session budget flag.
Use an isolated executor workdir containing `input.csv`:

```csv
team,amount
alpha,10
beta,20
alpha,30
```

Enable native capture and signed delivery on the executor, and set `file_diff:
true` in the caller route. Then run:

```sh
python3 scripts/accept_execution_native.py run \
  --agentprov /path/to/agentprov --claude /path/to/claude \
  --route /path/to/operator/route.json --output /path/to/new/acceptance
```

The script checks native session/tool IDs and commands, distinct cgroups, settled
capture intervals, exact-request replay, acknowledged signed delivery, native
open-for-write evidence and the retained `totals.json` body. Sampling gaps stay
visible. After stopping the executor and removing or moving its task workdir,
run `verify` with the same arguments except `--claude` to read the receiving
store independently. Keep that caller store at its original path for this check.
Browser `file://` replay is a separate acceptance step.

The caller can run on macOS or inside a Linux container. The container needs
provider access, the protected route configuration and a writable evidence
directory; it does not need BPF privileges or the executor workspace mounted.
Use an SSH loopback tunnel across hosts. A same-node container can use a
deliberately shared host network for the loopback endpoint while using a non-root
user and separate PID/mount namespaces; record this topology in the run manifest.

### Concurrent calls and a lost receipt response

[`accept_execution_native_matrix.py`](../scripts/accept_execution_native_matrix.py)
adds a two-session native acceptance case. Use an isolated executor with native
capture, signed delivery and concurrency of at least two. Prepare two different
executor workdirs with the script's `prepare` command:

```sh
python3 scripts/accept_execution_native_matrix.py prepare \
  --workdir /isolated/tasks/a --case a --fixture-url http://127.0.0.1:18581
python3 scripts/accept_execution_native_matrix.py prepare \
  --workdir /isolated/tasks/b --case b --fixture-url http://127.0.0.1:18581
```

Configure two caller routes with these workdirs, the same loopback executor URL,
`file_diff: true` and a 180-second timeout. Run the caller on the same Linux node,
or in a container sharing that node's network, so both commands can reach the
test barrier. The task directories stay on the executor, outside the caller's
mounts. With the caller's provider already configured:

```sh
python3 scripts/accept_execution_native_matrix.py run \
  --agentprov /path/to/agentprov --claude /path/to/claude \
  --route-a /operator/route-a.json --route-b /operator/route-b.json \
  --fixture-port 18581 --output /path/to/new/matrix-acceptance
```

Both native calls run `python3 analyze.py`. A two-party barrier establishes that
they actually overlap. A test-only loopback relay drops one response after the
executor persists its receipt; the script then recovers the same prepared call.
It checks unchanged signed-package/receipt identities, replays both requests,
explicitly reexecutes one call and repeats that retry request. The saved command
side effects must be one per initial call and exactly two for the reexecuted
call. Source queries must return only their own attempts.

The test starts two real model-backed sessions with a USD 0.25 budget flag each.
Retain `initial.json`, `fixture.json`, `result.json` and both caller stores.
After stopping the executor and moving its workdirs away, run `verify` with
`--agentprov`, `--route-a`, `--route-b` and `--output` to check the saved graphs,
native file/network events and signed artifact bodies. Keep the caller stores
at their original paths. This fixture checks receiver-store recovery; browser replay is
tested separately. The relay is only for fault injection and is not installed
with the daemon.

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
outcome. An owned Linux cgroup includes descendants outside the root process
group; other environments use the process-group fallback described above.

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

## Evidence import

`forensics.Service.ImportBundleStrict` provides the receiving-store operation
for handoff delivery. It stages a complete bundle, publishes its embedded content
under the decoded bundle's SHA-256, then commits all evidence rows in one
transaction. Repeated rows with identical content are reused. An existing ID with
different evidence returns `bundle_evidence_conflict` and rolls back the entire
projection; existing records and local content paths remain unchanged.

The importer accepts JSON or gzip, with a 256 MiB limit on decoded JSON. Oversized
input fails explicitly. It validates the expected Run, record identities, object
hashes, object sizes and embedded-content references. Integer fields retain their
64-bit values, and empty files are preserved. Archives are synchronized before
the database references them. A database failure can leave an unreferenced archive
for later reconciliation; no receipt is issued by this method.

The authenticated delivery receiver uses `ImportBundleStrictWithCommit` to save
its receipt in the same transaction as the evidence projection. The existing
replay import keeps its replacement behavior for compatibility.

## Signed delivery

`handoff.DeliveryService` prepares immutable packages from a frozen SQLite view.
It exports saved evidence without rerunning analysis. Repeated analysis preserves
the first creation time of an unchanged content-addressed object, so later
packages can reuse that object without conflicting with earlier evidence.

The DSSE/in-toto manifest uses `agentprovenance.execution_delivery/v1`. It binds:

- The fully qualified source, target instance/generation, dispatch, attempt,
  local Run and canonical request digest.
- The configured receiver, stable delivery operation, package version and
  preceding manifest digest.
- The attempt revision, saved checkpoint, execution/capture/delivery states,
  export time, exact bundle digest and byte count.

`Prepare` persists the package before adding its outbox row. Retrying the same
operation returns the same bytes, including after restart. A new operation creates
a new package version. Transfer copies are retained by default; optional sender
cleanup is described below. A failed publication or transaction can leave an
unreferenced archive for reconciliation; automatic cleanup does not age-delete
these archives or active preparation directories.

`handoff.DeliveryReceiver` takes the expected identity from a separately trusted
admission record. It pins the target public key, receiver identity and permitted
source namespace. It verifies the signed statement and bundle checkpoint before
importing. The received archive is synchronized first; evidence rows, the original
manifest and the signed `agentprovenance.execution_receipt/v1` receipt then commit
atomically. Failed imports or receipt writes return no acknowledgment. A lost
receipt can be retrieved by resending the same manifest.

The sender verifies the receiver's pinned signature and the exact manifest/range
before persisting acknowledgment. Attempt delivery is `acknowledged` only when all
prepared packages have receipts. A new package reopens this aggregate state while
preserving old receipts. Capture state remains unchanged. Versions are received
in order, and each new version names the preceding manifest; conflicting IDs or
missing predecessors return a conflict.

Each service processes one package at a time. Manifests and receipts are capped
at 64 KiB; uncompressed bundle JSON is capped at 256 MiB. The exporter applies a
cumulative body/record budget and checks final serialized size. Cancellation
stops queued work, database queries and body copies. Transport adapters must also
set read deadlines for stalled network connections. Keep signing keys separate
from transport credentials and retain verification keys for archived evidence.

### Sender-copy retention

Set `delivery.retention_hours` to a positive whole number, for example `720`
for 30 days. Omitted or `0` keeps transfer copies indefinitely. The daemon's
existing GC worker handles at most `min(--gc-limit, 1000)` packages per pass;
`--gc-interval=0` disables its automatic cleanup.

The first saved receipt starts the local retention window. A copy remains until
both that window and the original execution request's validity have elapsed.
Existing receipts without a deadline receive a full window when the worker first
observes the enabled policy. Receipt retries and later configuration changes keep
the saved deadline; setting retention to zero pauses cleanup.

Cleanup first persists retirement, then removes only the sender's `bundle.json`
and `manifest.dsse.json` transfer files and their empty package directory. It
retries interrupted removals. The API's optional `storage` object reports the
deadline, retirement and completed purge separately from the signed manifest.
Unexpected directory entries or filesystem failures leave retirement visible,
are logged as errors and remain retryable. GC outcomes are saved as
`execution_delivery_cleanup` events; already-open downloads may finish.

After retirement, preparing the same operation or downloading its body returns
HTTP 410 `execution_delivery_retired`. Metadata queries and receipt replay still
work. A new explicit delivery operation can produce the next version from retained
source evidence. Signed manifests, receipts, operation deduplication records,
source evidence and receiver archives are not removed by this policy. The ledger
is retained for the lifetime of the store; processed native-spool payload cleanup
continues to follow its existing settlement rules. This setting bounds acknowledged
transfer copies, not total evidence-store growth.

### Configure and collect

Generate one signing keypair on each side with `agentprov forensics keygen --priv
signing.key --pub signing.pub`. Exchange and pin the public keys through the trusted
administration channel. Keep each private key on its owner host with mode `0600`.
Add this optional block to the executor's `execution.json` before starting it:

```json
"delivery": {
  "receiver_id": "investigator",
  "sign_key_file": "executor.key",
  "receiver_public_key_file": "investigator.pub"
}
```

Key paths are relative to the configuration file. Invalid or missing keys fail
startup. Omitting `delivery` leaves its HTTP routes disabled. The caller pulls
over the existing SSH tunnel; it needs no inbound receiver port.

Save the authenticated `POST /v1/executions` response as `admission.json` when
submitting the command. Collection uses this independent source identity, the
operator's caller/target configuration and pinned executor key:

```sh
# Set AGENTPROV_DAEMON_TOKEN to the executor's transport credential.
agentprov --data-dir ./received-evidence --daemon-url http://127.0.0.1:18575 \
  forensics collect-execution ./admission.json \
  --execution-config ./execution.json --receiver investigator \
  --sign-key ./investigator.key --pub-key ./executor.pub \
  --operation collect-initial
```

The output is English-keyed JSON. `acknowledged` means the receiver has committed
the evidence and signed receipt, and the executor has saved that receipt. If the
final confirmation fails, output reports `receipt_persisted` and the command exits
with an error; retry with the same admission and operation. Each new process can
recover from the saved records. New evidence requires a new operation and package
version. `--timeout` bounds the whole collection (default three minutes); each
HTTP transfer is limited to two minutes. The client rejects redirects and bounds
metadata responses to 256 KiB.

The [HTTP delivery acceptance script](../scripts/accept_execution_delivery.py)
runs a CSV command, collects twice through the public CLI, verifies the received
graph and reads the transferred artifact. It is an HTTP fixture, separate from
native harness and Sensor acceptance.

## Compatibility and tests

Database schemas 21-26 add the execution ledger, durable stop requests, delivery
outbox/receipts, sender-copy retention, per-scope capture accounting and sampling-gap counts without renaming legacy tables
or rewriting existing events.
Older binaries reject the newer schema; use a backup
for a downgrade. Historic signed packages retain their original format.

Run the contract and persistence regressions with:

```sh
go test -race ./internal/handoff ./internal/daemon ./internal/store ./internal/forensics
```

The tests cover concurrent admission and worker claims, explicit reexecution,
source isolation, parameter conflicts, expiry, reopen recovery, transactional
history failures, bounded pagination, query cancellation, real command execution,
output retention, exclusive ownership and recovery of saved completion events.
On a Linux host with writable cgroup v2 permissions, run the real crash and
identity-reuse regressions with:

```sh
AGENTPROV_TEST_REQUIRE_CGROUP=1 go test -count=1 -v ./internal/handoff ./internal/record \
  -run 'TestExecutorRecoversLiveScope|TestRecoveredScope'
```

These tests terminate the owning worker while its command survives, then check
stop requests, natural exit, the original deadline, single execution, signed
delivery and an unrelated live process. They also replace a cgroup at the same
path and reject mismatched boot, filesystem and cgroup identities.
`scripts/accept_execution_handoff.py` exercises an isolated daemon's public API
with concurrent CSV analysis, output artifacts, retry and cancellation. It uses
explicit fixture call IDs; native harness integration and evidence transfer have
separate acceptance gates.
With native capture configured, add `--require-sealed` to require clean scope
closure for both completed and stopped tasks. Shared node backlog remains in
the report independently of this assertion.
Strict-import regressions cover concurrent retransmission, conflicting evidence,
whole-transaction rollback, storage errors, portable content, missing bodies,
decoded-size limits and legacy-import interoperability.
Delivery regressions run a real CSV command, transfer its output and artifact to
a separate store, remove the source files, and verify the received graph and
content. They cover pinned identities/keys, tampering, lost receipts, restarts,
atomic acknowledgment failures, concurrent retries, ordered extensions and
reanalysis before a late-evidence package.
