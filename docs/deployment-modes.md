# Deployment Modes

AgentProvenance should be adoptable without forcing every user into a platform
deployment. The product has three deployment shapes.

## 1. Library / CLI-only Recorder

This is the default entry point for RL, benchmark, evaluator, CI, and local
red-team harnesses.

Shape:

```text
agent / evaluator / batch job
  -> agentprov record -- <command>
  -> local SQLite + local content-addressed objects
  -> evidence manifest / EvalContext / trajectory signals
```

Expected properties:

- one Go binary;
- optional thin Python helper package;
- no long-running service required;
- no framework integration required;
- default capture stays lightweight: process, file diff, artifact, exit,
  resource, and summary runtime evidence;
- every trajectory can have its own `run_id`;
- batch jobs can use `agentprov record batch --file jobs.jsonl --json` to get
  one `agentprovenance.record_batch/v1` manifest across many trajectories;
- `agentprov evidence batch-summary --shard/--job/--run` lets a pipeline query
  stored batch status without parsing stdout logs;
- `agentprov signal batch-context --batch/--shard/--runs` exports matching
  trajectories as EvalContext JSONL for reward, filtering, or benchmark
  consumers;
- `agentprov forensics export-batch --batch/--shard/--latest` writes one
  sha256-verified batch audit bundle with batch summary, per-run forensics
  refs, optional EvalContext records, and replay/query commands;
- outputs are JSON-friendly and batch-friendly.

Boundary:

- this mode does not provide shared query service, central retention, or
  multi-host telemetry aggregation;
- it is the easiest path for RL pipelines because the pipeline keeps ownership
  of scheduling, reward, ranking, and dataset policy.

## 2. Sidecar / Local Daemon

This is the medium-complexity shape for sandbox workers, CI workers, local
security harnesses, or teams that need local ingest/query APIs.

Shape:

```text
agent / sandbox worker / CLI / SDK
  -> local agentprov daemon
  -> spool / backpressure / retention
  -> local query + graph verify + forensics API
```

Expected properties:

- daemon owns SQLite, object store, correlation, policy, risk, response, graph
  verification, forensics export, and telemetry spool;
- CLI and Python helpers act as clients;
- raw telemetry can be queued and drained without blocking the control/query
  path;
- local APIs expose observability, timeline, graph explain, security evidence,
  evidence manifest, forensics export, and signal import.

Boundary:

- this is still local-first;
- it is not a multi-tenant central service;
- it should be deployable beside a worker without requiring Kubernetes or a
  central database.

## 3. Central Evidence Service

This is the later enterprise shape for security, audit, SRE, compliance, and
incident review.

Shape:

```text
many workers / sidecars / collectors
  -> central evidence ingest
  -> object storage + retention + auth
  -> query API + UI + audit export
```

Expected properties:

- shared ingest and query service;
- object storage for forensics and content-addressed evidence objects;
- retention, auth, tenant isolation, and audit controls;
- UI/API for investigation and evidence review;
- integration points for Falco/Tetragon/LoongCollector, webhook, Feishu,
  DingTalk, CI, and enterprise security workflows.

Boundary:

- this is not the default RL adoption path;
- it should reuse the same evidence schemas and graph invariants from the
  local modes;
- it requires explicit productization work rather than hidden assumptions in
  the local CLI.

## Design Rule

The three modes share one evidence model:

```text
Execution Context
  -> Evidence Ingest
  -> Runtime Causality Graph
  -> Git-like Provenance DAG
  -> Evidence Query / Risk / Replay / Audit
```

Only the deployment boundary changes. RL users should be able to stay in
Library / CLI-only mode. Enterprise users can move to sidecar or central service
mode when they need shared operations.
