# gVisor SecCheck Receiver

English | [中文](zh-CN/gvisor-seccheck.md)

The `internal/seccheck` package provides the transport layer for a gVisor
producer. It is pinned to `runsc release-20261109.0`, protocol version 1, and
source commit `a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`.

The receiver feeds typed events and stream diagnostics into the existing
durable spool, runtime graph, signed Bundle and offline Dashboard pipelines.
Use `telemetry seccheck-config` to generate the runtime trace configuration and
`telemetry receive-seccheck` to collect registered sandboxes on Linux amd64/arm64.

## Start Collection

Install the pinned runsc distribution, including its adjacent `gvisor-bin`
directory. Check `runsc --version` before launching the workload. The receiver
checks protocol v1; the runtime release in its configuration is a trusted
launcher assertion, since the wire handshake does not include a release number.

Create a directory owned by the receiver user with mode `0700`. Each socket is
created with mode `0600`; use the same local UID for the receiver and runtime
launcher. Keep the combined socket path below 108 bytes. For a root-run example:

```sh
sudo install -d -m 700 /run/agentprov-seccheck
agentprov telemetry seccheck-config \
  --socket /run/agentprov-seccheck/workload.sock > trace.json
```

Save the trusted registration as `registration.json`:

```json
{
  "schema_version": "agentprovenance.seccheck_collection/v1",
  "runtime_release": "release-20261109.0",
  "targets": [{
    "run_id": "gvisor-example",
    "socket_path": "/run/agentprov-seccheck/workload.sock",
    "registration": {
      "namespace": "local",
      "instance_id": "node-1",
      "generation": "workload-lifetime-1",
      "sandbox_id": "workload-1",
      "container_id": "workload-1",
      "peer_uid": 0
    }
  }]
}
```

The registered container ID must match the OCI container name. Assign a new
generation for a new sandbox lifetime. One receiver command owns the store's
SecCheck spool and accepts up to 64 distinct target registrations. Both socket
paths and lifecycle scopes must be unique.

Start collection in one terminal:

```sh
sudo agentprov --data-dir /var/lib/agentprov telemetry receive-seccheck \
  --config registration.json --json
```

Wait for `state: listening`, then launch an existing OCI bundle in another
terminal using the generated trace file:

```sh
sudo /path/to/runsc --root=/run/agentprov-runsc --platform=systrap \
  --pod-init-config=/absolute/path/to/trace.json \
  run --bundle=/absolute/path/to/oci-bundle workload-1
```

After the workload finishes and its target reports `disconnected`, stop the
receiver with Ctrl-C or SIGTERM. It stops accepting peers, drains accepted
records and emits a final status. Storage or drain errors return a nonzero exit;
unprocessed durable batches remain available to the next receiver invocation.
The receiver never creates, schedules or stops the sandbox itself.

## Status and Capability

`--json` emits `agentprovenance.seccheck_status/v1` records with live target
connection states, accepted observations, reported drops, identity gaps and the
shared node spool. `last_worker_error` is the last retry diagnostic; `error`
describes a terminal collection failure. Status output failure stops collection.
Periodic status is written to stdout, not accumulated in the evidence graph.

Read durable counters through the existing CLI or authenticated health API:

```sh
agentprov --data-dir /var/lib/agentprov telemetry producer-health \
  --run gvisor-example --json
```

The response includes `events.by_source.gvisor_seccheck` and
`seccheck_node_capture` alongside the unchanged `native_node_capture`.
Spool and loss counters are node-wide even with a Run filter. New stream counters
are accumulated during ingestion, once per distinct observation; historical
imports do not rebuild them. Saved diagnostics remain the per-record evidence.

Receiver readiness and orderly stop records retain the producer version,
registered lifetime and capability report in signed exports. System coverage is
`partial`, identity is Sentry-local, and model intent/application context are
`none` for this producer. The generated configuration requests ten checkpoints;
actual observed messages record individual checkpoints rather than continuous
enablement. A drained queue does not
change this partial coverage to complete. No raw packet body, exec environment
or credential structure is retained; normalized arguments are redacted.

The [saved capture manifest API](capture-manifest-api.yaml) includes both receiver
declarations and actual checkpoint witnesses. It selects one retained event per
registered scope, connection, protocol message, syscall number and stage, with
`interval_basis: checkpoint_observation` and `observed: true`. Entry and return
records stay separate. Nonzero drop deltas, counter resets and identity gaps remain visible even
for repeated points. Witness timestamps describe those saved events; the query
does not infer an enabled interval from their absence. Open/exec message families
retain the raw syscall number, since the reader may use a different architecture.

Witnesses are paged and preserve original evidence references through signed
import and offline export. Selective export chooses witnesses again within its
frozen selection. An excluded record can therefore be replaced by another
included observation of the same point, or the point disappears from that copy.

Tune `--batch-events`, `--batch-bytes`, `--max-queued-bytes` and
`--max-queued-batches` for the shared spool. Defaults are 256 records / 1 MiB per
batch and 256 MiB / 4096 batches queued. `--drain-timeout` defaults to 30 seconds.

## Scope and Identity

A trusted launcher registers a namespace, instance, lifecycle generation,
sandbox, container and expected local peer UID. Each sandbox uses a private
Unix `SOCK_SEQPACKET` endpoint. A second live connection is rejected; a reconnect
gets a new connection ID and receive sequence without changing the registered
lifecycle.

The receiver's local registration assigns the Run. Stored events use
`gvisor_seccheck`, `runtime_scope` and `runtime_scoped` for their source,
correlation method and class. Sentry observations never borrow or close host
PID bindings. Thread and process birth times retain nanosecond precision;
the versioned graph includes the namespace, instance, lifecycle and sandbox.
Files with the same absolute path in different sandbox lifetimes stay separate.
Relative paths and paths containing dot segments remain event-local observations.

The receiver distinguishes Sentry thread IDs and thread-group IDs (processes). Both use
their respective birth times and the registered scope. Parent group numbers
remain observations until a lifetime is known. The socket peer PID describes
the local transport client, not the process inside the sandbox. Payload
container IDs must match the registration.

## Events and Failures

The initial decoded subset includes container start, clone, exec, open,
connect and exit messages, including syscall entry and return records.
An absent return message stays distinct from a successful zero return.
Entry observations keep an unknown outcome. Return records use the existing
`syscall_result` event type and preserve both result and errno. For nonblocking
sockets, `EINPROGRESS` and `EALREADY` are in-progress results.

Packets are bounded to 1 MiB; handshakes to 256 bytes and five seconds by
default. Invalid packets, unknown types, rejected identities and disconnects
produce diagnostics. Cumulative drop counters are scoped to each connection.
A decrease is reported as a reset/wrap boundary with unknown delta.

Consumers accept records synchronously and must apply retention/redaction and
durably save them before returning success. A consumer error stops reception.
Ordinary EOF records a disconnection; final capture completeness also requires
the producer's lifecycle and shutdown evidence. No TLS body capability is
declared by this receiver.

## Persistence and Delivery

`telemetry.SecCheckStream` reuses the native spool engine with a separate owner
lock, format and counters. Native and SecCheck workers recover and drain only
their own batches. Queue reservations include both sources; a full queue or an
oversized SecCheck observation returns an error to the receiver.

The stored projection keeps the registered identity, capture and receive times,
packet digest, header, operation and result. Exec environment and credential
fields are omitted; command arguments pass through the existing redactor before
spooling. Accepted observations are fsynced before the sink returns.

Scope, connection ID and receive sequence identify an observation across spool
recovery. Reprocessing the same observation keeps one event; conflicting content
retains the batch with an error. A reconnect starts a new observation sequence.
This protocol does not supply a durable producer sequence for deduplicating
arbitrary resends across connections.

### Restart and Reconnect

An endpoint lock prevents two receivers from replacing each other's socket.
After an abrupt exit, the receiver reclaims an owned stale socket only after
checking that it refuses connections. Existing files, symlinks and active
listeners are retained. The private `.lock` file remains for later startups.

Restart with the same data directory and registration to recover accepted
spool observations. A recovered endpoint saves `stale_endpoint_recovered`;
producer health includes `sentry_node_receiver_restart_gap`. This node-level
diagnostic records an interval with unknown loss, without assigning a count.

The pinned runsc sink keeps its original connection. For a still-running
sandbox, wait for the restarted receiver to report `listening`, then recreate
its trace session using the original runtime state and tracing configuration:

```sh
sudo /path/to/runsc --root=/run/agentprov-runsc trace create \
  --force --config=/absolute/path/to/trace.json workload-1
```

The sandbox lifetime stays the same; the new connection has an independent
loss counter and observation sequence. Events emitted during the disconnected
interval remain a capture gap. When the receiver is temporarily slow, runsc
drops messages that cannot be sent; a later delivered message reports the
cumulative counter. No later message means the final loss total is unknown.

Graph verification checks the saved registration and source-qualified identities.
Signed Bundle export/import preserves these records and their graph edges.
Existing native process-identity versions and historical signed data remain
unchanged.

## Snapshot Restore and Clones

For the pinned runsc profile, keep the receiver, private socket directory,
registration and signing credentials on the host, outside the sandbox snapshot.
The external launcher owns lifecycle assignment. To resume an instance, retain
its `instance_id` and assign a new `generation`; each clone gets its own instance
and generation. Keep historical event IDs and payloads unchanged.

Use this startup order:

1. Stop accepting new work and checkpoint the sandbox. Drain the old receiver and
   close its endpoint. Retain the evidence store outside the snapshot.
2. Prepare a fresh OCI state directory and a distinct host `linux.cgroupsPath`.
   Register the new lifetime on a fresh private socket, then wait for the receiver
   to report `listening`.
3. Restore the memory image with the same runtime/platform configuration. Keep
   application work behind a launcher-controlled readiness gate.
4. Recreate tracing with `runsc trace create --force --config=NEW_TRACE CONTAINER`.
   Wait for the new target to report `connected`, then release the work gate.

The readiness gate belongs to the execution entry; the receiver does not suspend
an application. Any activity before tracing reconnects stays a capture gap.
The [upstream checkpoint guide](https://gvisor.dev/docs/user_guide/checkpoint_restore/)
describes the runtime lifecycle; this profile is tested against the pinned release
above, not against an arbitrary runsc version.

### Restore Authorization

This profile uses a private host socket and the configured Unix peer UID for
transport authorization. A copied guest token or producer configuration does not
register a lifetime. Keep receiver configuration on the trusted host, close the
old endpoint, assign the new instance/generation, and install the new tracing
configuration before releasing the work gate.

The signing credential belongs to the trusted host publisher, not to each
sandbox. If a snapshot contains a retired signing key, rotate the host signing
key and update the receiver's current public-key pin through the trusted
configuration channel. Keep the retired public key with archived Bundles;
historical verification uses that key, while new imports use the current pin.
The receiver must not choose a key from the copied guest configuration or from
the incoming package itself. Existing `forensics keygen`, `export --sign-key`
and `import --pub-key` provide these operations.

Run the isolated memory-continuity acceptance with a fresh output directory:

```sh
sudo python3 scripts/accept_seccheck_restore.py \
  --cli /tmp/agentprov --runsc /absolute/path/to/runsc \
  --rootfs /absolute/path/to/rootfs \
  --output /absolute/path/to/new-restore-acceptance-directory
```

The minimal rootfs needs BusyBox-compatible `sh`, `cat`, `date`, `hostname`,
`sleep` and `touch`. The script checkpoints a running shell and tmpfs, resumes
the original instance and restores two clones from the same image. It verifies
preserved memory, equal hostname/boot/PID/birth identity, four distinct graph
identities, rejected stale trace configuration, unchanged historical evidence
and a signed export/import. It keeps logs and hashes and removes its own runtime
state. The selected mode is `systrap` with networking disabled, exercised on
ARM64 and amd64. The [amd64 archive](benchmarks/v1.0-amd64/README.md) includes
the original receive, fault-recovery and restore/two-clone results, executable
hashes, the initial rootfs-reporting failure and the corrected result.

The script also retains an actual sealed queue batch and its independently
stored digest, copies it to both clones, and replays it into fresh and existing
stores. Historical observations retain their original identities; each clone
receives a separate durable upload receipt. Retrying the command reuses that
receipt.

The same acceptance deliberately places a synthetic retired signing key in the
sandbox's memory-backed filesystem. Each restored copy retains it. A new package
signed with that copied key verifies under the old public key but fails import
under the externally rotated current key, before a receiving store is created.
The original historical Bundle remains verifiable and the new host-signed
package imports successfully. Private key bytes stay out of arguments and logs.
The retained test snapshot contains the synthetic retired key: keep the output
directory private and do not use test keys for production evidence.

### Replay a Copied Queue Batch

Use `telemetry replay-seccheck` for a sealed normalized JSONL batch. Supply the
SHA-256 retained by the trusted original collector and a current registration
from outside the copied state:

```sh
agentprov --data-dir /var/lib/agentprov telemetry replay-seccheck \
  --config /etc/agentprov/current-seccheck.json \
  --file /private/inherited-batch.jsonl \
  --sha256 "$EXPECTED_BATCH_SHA256" --json
```

If the configuration contains several targets, select the uploader with
`--socket /private/current.sock`. This is a local operator command: it opens no
listener and does not establish remote uploader authentication. Its receipt
records `authority_basis: local_operator_registration`.

The original Run, instance, generation, timestamps and event IDs stay unchanged.
The receipt records the current uploader, original event references, batch
digest and first-import/duplicate counts. A retry by the same uploader returns
the original receipt; a different instance or generation receives its own.
The target's `run_id` remains its live-collection destination; copied events and
their receipts stay in each historical Run reported by the replay command.

A batch is limited to 16 MiB and 4,096 records, with each JSONL line below 1 MiB.
Its final newline and retained digest must match. A conflicting event, foreign
namespace, invalid record or receipt write failure aborts the whole batch.
Upload receipts are included in signed Bundles. Selective reading exports
withhold a receipt when any of its supporting historical events is excluded.

## Offline Reading

After importing a signed Bundle, use the existing `dashboard export --run RUN_ID`
command to produce a read-only ZIP. Extract it and open `index.html` locally.
Saved event bodies, search and the process/file graphs retain the Sentry scope.
The ZIP is an unsigned reading copy; keep the original Bundle and attestation
for signature verification. Category exclusions apply to these events too;
excluding all runtime records produces an empty view with its selection inventory.

## Linux Acceptance

The public CLI acceptance script uses the same controlled workload as the
transport tests and runs two isolated sandboxes concurrently:

```sh
go build -o /tmp/agentprov ./cmd/agentprov
CGO_ENABLED=0 go test -c ./internal/seccheck -o /tmp/seccheck.test
sudo python3 scripts/accept_seccheck.py \
  --cli /tmp/agentprov --runsc /absolute/path/to/runsc \
  --rootfs /absolute/path/to/rootfs --workload /tmp/seccheck.test \
  --output /absolute/path/to/new-acceptance-directory
```

It requires Python 3.11 or later and preserves the registration, runtime config,
CLI status, health, graph verification and binary digests. It cleans its own
runtime state and network namespace mounts without changing Docker/K3s.

The fault acceptance script uses the same arguments with a fresh output path:

```sh
sudo python3 scripts/accept_seccheck_faults.py \
  --cli /tmp/agentprov --runsc /absolute/path/to/runsc \
  --rootfs /absolute/path/to/rootfs --workload /tmp/seccheck.test \
  --output /absolute/path/to/new-fault-acceptance-directory
```

It pauses the real receiver while the sandbox emits a bounded syscall burst,
checks actual reported loss, injects a temporary database insertion failure to
retain fsynced batches, and kills the collector. It then restarts collection,
reconnects the same sandbox and checks retained identities, unchanged evidence,
one event per recovered observation, capture gaps and graph verification. A
signed export/import checks that all observations and diagnostics stay unchanged.
The database failure affects only this script's private store. Runtime, process
signals, socket congestion and restart are real; no kernel crash is simulated.

Use an isolated OCI root filesystem, the pinned runtime distribution and its
adjacent `gvisor-bin` directory. No Docker or K3s runtime registration is needed.
Build the test binary for the Linux host, then run:

```sh
go test -c ./internal/seccheck -o /tmp/seccheck.test
sudo env \
  AGENTPROV_TEST_RUNSC=/absolute/path/to/runsc \
  AGENTPROV_TEST_GVISOR_ROOTFS=/absolute/path/to/rootfs \
  AGENTPROV_TEST_SECCHECK_OUTPUT=/absolute/path/to/acceptance-output \
  /tmp/seccheck.test -test.v -test.timeout=1m
```

The live fixture uses `systrap`, isolated OCI state, read-only root filesystems
and loopback-only networking. Two concurrent sandboxes exercise separate PID 1
lifetimes, multiple threads, execs, file results and blocking/nonblocking network
results. It cleans its own runtime state and namespace mounts.
Protocol fault tests cover reconnects, loss-counter changes, invalid handshakes,
foreign identity, competing connections and persistence failure. Live capture
and injected protocol faults are reported separately.

The transport fixture's JSON output contains controlled acceptance data. To
also exercise persistence, source isolation, graph verification and a signed
Bundle round trip, build the telemetry fixture and reuse the workload binary:

```sh
go test -c ./internal/telemetry -o /tmp/telemetry.test
sudo env \
  AGENTPROV_TEST_RUNSC=/absolute/path/to/runsc \
  AGENTPROV_TEST_GVISOR_ROOTFS=/absolute/path/to/rootfs \
  AGENTPROV_TEST_SECCHECK_WORKLOAD_BINARY=/tmp/seccheck.test \
  AGENTPROV_TEST_SECCHECK_OUTPUT=/absolute/path/to/persistence-output \
  /tmp/telemetry.test -test.run='^TestSecCheckLivePersistence$' -test.v -test.timeout=2m
```

Use a fresh output directory for each acceptance run. The persistence fixture
keeps the source store, imported receiver store, event inventory and result
summary. The source store contains the signed Bundles and attestations.
Schema sources and regeneration steps are in the
[wire schema notes](../internal/seccheck/wire/README.md).
