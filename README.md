# agentprovenance

`agentprovenance` is a CLI-first Agent Computer Control Plane for local AI
agent sandboxes.

It treats a sandbox as a leaseable, executable, snapshotable, forkable, auditable
computer instead of a one-shot container.

## What v1 proves

- Docker-backed sandbox sessions can be created and executed through `agentprov`.
- Sandbox HTTP services can be exposed through a local preview URL proxy.
- Runtime backends are registered behind a common interface, with Docker active
  and gVisor/Firecracker/bubblewrap represented as extension targets.
- Environment templates can be built from task YAML and used to derive
  `template -> ready snapshot -> attempt workspace` lineage.
- `/workspace` can be snapshotted and forked into independent attempt workspaces.
- Structured Agent Computer API calls can read/write/search/export/call inside a
  sandbox and record `run_id`, `session_id`, `tool_call_id`, and `result_ref`.
- Runtime telemetry, policy decisions, provenance traces, and forensics bundles
  are persisted in SQLite.
- Risky runtime/API/egress events can kill or quarantine sessions and taint
  snapshots where applicable.
- Run-level cost output includes active CPU, wall time, snapshot bytes, policy
  blocks, quarantines, Docker stats samples, overcommit ratio, active CPU debt,
  and an estimated `cost_per_run`.

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
./agentprov exec "$session_id" --stream -- sh -lc 'echo hello > hello.txt'
./agentprov port expose "$session_id" 8000

./agentprov runtime list
./agentprov template build --task examples/tasks/bugfix.yaml --name bugfix
./agentprov snapshot stack --template bugfix
./agentprov snapshot create "$session_id" --type directory --path /workspace --name ready
./agentprov snapshot list
./agentprov snapshot inspect ready
./agentprov fork ready --count 3
./agentprov attempt best-of --snapshot ready \
  --strategy "pass::test -f hello.txt" \
  --strategy "fail::test -f missing.txt"

./agentprov policy test examples/events/metadata-egress.jsonl
./agentprov policy decisions --run run-demo-bugfix
./agentprov api write-file "$session_id" --path notes.txt --content 'hello'
./agentprov telemetry list --session "$session_id"
./agentprov graph trace --run run-demo-bugfix
./agentprov forensics export run-demo-bugfix
./agentprov cost sample "$session_id"
./agentprov cost show run-demo-bugfix
./agentprov session rm "$session_id"
```

Run the main v1 demo or one focused demo:

```sh
./scripts/demo_v1.sh
./scripts/demo_preview_url.sh
./scripts/demo_snapshot_fanout.sh
./scripts/demo_best_of_forks.sh
./scripts/demo_policy_quarantine.sh
./scripts/demo_cost_accounting.sh
./scripts/demo_provenance_trace.sh
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
agentprov port list
agentprov port close <port_id>
agentprov runtime list
agentprov runtime inspect docker
agentprov template build --task examples/tasks/bugfix.yaml --name bugfix
agentprov template list
agentprov template inspect bugfix
agentprov api read-file <session_id> --path notes.txt
agentprov api write-file <session_id> --path notes.txt --content hello
agentprov api search <session_id> --pattern hello
agentprov api export-artifact <session_id> --path notes.txt
agentprov api call <session_id> --module shell --function exec --command 'echo ok'
agentprov telemetry list --run <run_id>
agentprov graph trace --run <run_id>
agentprov forensics export <run_id>
agentprov snapshot create <session_id> --type directory --path /workspace --name ready
agentprov snapshot stack --template bugfix
agentprov snapshot list
agentprov snapshot inspect <snapshot_name_or_id>
agentprov fork ready --count 3
agentprov attempt best-of --snapshot ready --strategy "name::command"
agentprov policy test examples/events/metadata-egress.jsonl
agentprov policy decisions --run <run_id>
agentprov egress check --run <run_id> --session <session_id> --dst-ip 169.254.169.254
agentprov credential inject --run <run_id> --session <session_id> --name github-token --host api.github.com
agentprov cost sample <session_id>
agentprov cost show <run_id>
agentprov baseline learn --template bugfix --run <run_id>
agentprov baseline check --template bugfix --run <run_id>
agentprov pool create --template bugfix --size 2
agentprov pool status
agentprov node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
agentprov node list
agentprov bench overcommit --sessions 20 --idle-ratio 0.8
```

## V1 boundaries

V1 is still Docker-first and local-first. It has a node registry and placement
signals, but not a real distributed scheduler. It does not implement Raft,
Firecracker memory snapshots, live migration, deep-learning anomaly detection,
or custom eBPF LSM enforcement.
