# gVisor SecCheck Receiver

English | [中文](zh-CN/gvisor-seccheck.md)

The `internal/seccheck` package provides the transport layer for a gVisor
producer. It is pinned to `runsc release-20261109.0`, protocol version 1, and
source commit `a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`.

The receiver feeds typed events and stream diagnostics into the existing
durable spool, runtime graph, signed Bundle and offline Dashboard pipelines.
User-facing collection setup and producer health reporting are the next
integration steps; there is no new collection command yet.

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

Graph verification checks the saved registration and source-qualified identities.
Signed Bundle export/import preserves these records and their graph edges.
Existing native process-identity versions and historical signed data remain
unchanged.

## Offline Reading

After importing a signed Bundle, use the existing `dashboard export --run RUN_ID`
command to produce a read-only ZIP. Extract it and open `index.html` locally.
Saved event bodies, search and the process/file graphs retain the Sentry scope.
The ZIP is an unsigned reading copy; keep the original Bundle and attestation
for signature verification. Category exclusions apply to these events too;
excluding all runtime records produces an empty view with its selection inventory.

## Linux Acceptance

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
