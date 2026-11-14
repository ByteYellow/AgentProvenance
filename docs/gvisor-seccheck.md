# gVisor SecCheck Receiver

English | [中文](zh-CN/gvisor-seccheck.md)

The `internal/seccheck` package provides the transport layer for a gVisor
producer. It is pinned to `runsc release-20261109.0`, protocol version 1, and
source commit `a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`.

The package receives typed events and stream diagnostics. Durable spool,
runtime graph projection, CLI setup and replay integration are the next
integration steps; there is no new user-facing collection command yet.

## Scope and Identity

A trusted launcher registers a namespace, instance, lifecycle generation,
sandbox, container and expected local peer UID. Each sandbox uses a private
Unix `SOCK_SEQPACKET` endpoint. A second live connection is rejected; a reconnect
gets a new connection ID and receive sequence without changing the registered
lifecycle.

The receiver distinguishes Sentry thread IDs and process-group IDs. Both use
their respective birth times and the registered scope. Parent group numbers
remain observations until a lifetime is known. The socket peer PID describes
the local transport client, not the process inside the sandbox. Payload
container IDs must match the registration.

## Events and Failures

The initial decoded subset includes container start, clone, exec, open,
connect and exit messages, including syscall entry and return records.
An absent return message stays distinct from a successful zero return.
For nonblocking sockets, `EINPROGRESS` is an in-progress result.

Packets are bounded to 1 MiB; handshakes to 256 bytes and five seconds by
default. Invalid packets, unknown types, rejected identities and disconnects
produce diagnostics. Cumulative drop counters are scoped to each connection.
A decrease is reported as a reset/wrap boundary with unknown delta.

Consumers accept records synchronously and must apply retention/redaction and
durably save them before returning success. A consumer error stops reception.
Ordinary EOF records a disconnection; final capture completeness also requires
the producer's lifecycle and shutdown evidence. No TLS body capability is
declared by this receiver.

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

The optional JSON output contains controlled fixture data. It is an acceptance
artifact, not a signed evidence Bundle. Schema sources and regeneration steps
are in the [wire schema notes](../internal/seccheck/wire/README.md).
