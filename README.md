# agentprovenance

`agentprovenance` is a CLI-first Agent Computer Control Plane for local AI
agent sandboxes.

It treats a sandbox as a leaseable, executable, snapshotable, forkable, auditable
computer instead of a one-shot container.

## What v1 proves

- Docker-backed sandbox sessions can be created and executed through `agentprov`.
- `/workspace` can be snapshotted and forked into independent attempt workspaces.
- Policy events can be correlated with `run_id` and `session_id`, then persisted.
- Risky events can quarantine sessions and taint snapshots.
- Run-level cost output includes active CPU, wall time, snapshot bytes, policy
  blocks, quarantines, and an estimated `cost_per_run`.

## Quick start

Prerequisites:

- Go 1.23+
- Docker Desktop or a compatible Docker daemon

```sh
go build ./cmd/agentprov

./agentprov init
lease_id=$(./agentprov lease create --task examples/tasks/bugfix.yaml)
session_id=$(./agentprov session create --lease "$lease_id")

./agentprov session inspect "$session_id"
./agentprov exec "$session_id" --stream -- go version
./agentprov exec "$session_id" --stream -- sh -lc 'echo hello > hello.txt'

./agentprov snapshot create "$session_id" --type directory --path /workspace --name ready
./agentprov fork ready --count 3

./agentprov policy test examples/events/metadata-egress.jsonl
./agentprov policy decisions --run run-demo-bugfix
./agentprov cost show run-demo-bugfix
./agentprov session rm "$session_id"
```

Or run the full v1 demo:

```sh
./scripts/demo_v1.sh
```

## V1 commands

```sh
agentprov init
agentprov lease create --task examples/tasks/bugfix.yaml
agentprov session create --lease <lease_id>
agentprov session list
agentprov session inspect <session_id>
agentprov session stop <session_id>
agentprov session rm <session_id>
agentprov exec <session_id> --stream -- <command...>
agentprov process interrupt <process_id>
agentprov port expose <session_id> <port>
agentprov snapshot create <session_id> --type directory --path /workspace --name ready
agentprov fork ready --count 3
agentprov policy test examples/events/metadata-egress.jsonl
agentprov policy decisions --run <run_id>
agentprov cost show <run_id>
agentprov bench overcommit --sessions 20 --idle-ratio 0.8
```

## V1 boundaries

V1 is intentionally single-node and Docker-first. It does not implement
multi-node scheduling, Raft, Firecracker memory snapshots, live migration,
deep-learning anomaly detection, or custom eBPF LSM enforcement.
