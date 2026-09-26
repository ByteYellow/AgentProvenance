# Python integration

English | [中文](zh-CN/python-sdk.md)

The Python helpers call `agentprov`, read execution evidence and submit evaluator signals. Rules are ordinary Python functions, suitable for test, benchmark and RL pipelines.

## Install

Use Python 3.9+ and a working `agentprov` binary. From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
export AGENTPROV_BIN=/absolute/path/to/agentprov
```

Set `AGENTPROV_BIN` to the CLI path. See [Quick Start](../README.md#quick-start) for prebuilt packages. The `agentprov` and `agentprov_eval` packages export the same API. Tool output and JSON fields remain English.

## Record, evaluate and import

This script records a file write, counts file changes with a custom rule, then imports the result. Its temporary directory is cleaned up on exit.

```python
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from agentprov import Client, Registry, Signal, evaluate_context

registry = Registry(name="example-quality")

@registry.rule("changed_files")
def changed_files(ctx):
    return Signal.quality_signal(
        "changed_files", float(len(ctx.file_changes())), "File changes observed"
    )

with TemporaryDirectory(prefix="agentprov-python-") as directory:
    root = Path(directory)
    work = root / "work"
    work.mkdir()
    client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=root / "data")
    manifest = client.record(
        [sys.executable, "-c", "from pathlib import Path; Path('result.txt').write_text('ok')"],
        run_id="run-python-example", workdir=work,
    )
    context = client.eval_context(manifest["run_id"])
    report = evaluate_context(context, registry=registry, engine=registry.name)
    imported = client.import_signal_reports([report], engine=registry.name)
    print(manifest["run_id"], report["signal_count"], imported["signal_count"])
    print(client.signals(manifest["run_id"])["schema_version"])
```

`Client.record` executes the command. `evaluate_context` runs the rules in the Python process; `import_signal_reports` persists their results.

## Batch processing

`run_batch_pipeline` records a batch, reads contexts, evaluates rules, imports signals and exports a forensic bundle. Concurrent jobs use separate working directories:

```python
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from agentprov import Client, Registry, Signal

registry = Registry(name="batch-quality")

@registry.rule("changed_files")
def changed_files(ctx):
    return Signal.quality_signal(
        "changed_files", float(len(ctx.file_changes())), "File changes observed"
    )

with TemporaryDirectory(prefix="agentprov-batch-") as directory:
    root = Path(directory)
    client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=root / "data")
    jobs = []
    for index in range(2):
        work = root / str(index)
        work.mkdir()
        jobs.append({
            "run_id": f"run-python-batch-{index}", "job_id": f"job-{index}",
            "workdir": str(work),
            "command": [sys.executable, "-c", "from pathlib import Path; Path('result.txt').write_text('ok')"],
        })
    result = client.run_batch_pipeline(jobs, registry, concurrency=2)
    print(result.batch_id, len(result.run_ids), result.signal_count)
```

Signal import and forensic export are enabled by default. Set `import_signals=False` and `include_forensics=False` to skip them. `BatchPipelineResult` contains `record_manifest`, `contexts`, `reports`, `import_report`, `forensics` and `summary`, with `batch_id`, `run_ids`, `signal_count` and `to_dict()` helpers.

## Client configuration

| Parameter | Purpose |
|---|---|
| `binary` | CLI path; defaults to `agentprov` on PATH |
| `data_dir` | Local data directory |
| `daemon_url` | Daemon address; selected methods use HTTP, while others still call the CLI |
| `env` | Environment overrides for CLI subprocesses |
| `timeout` | Timeout for ordinary CLI and HTTP calls, default 600 seconds; `None` disables it |

With `daemon_url`, `record`, `eval_context` and `signals` call HTTP directly. Other methods still require the CLI. The direct HTTP path has no Bearer Token option; use the [REST API](ai-access.md) directly when authentication is required.

`iter_eval_contexts` streams from a subprocess and does not use `timeout`; consumers manage cancellation or deadlines.

## Client methods

| Method | Purpose |
|---|---|
| `run_cli(args, input_text=None)` | Return a `CommandResult`; use `json()` to parse output |
| `record(command, ...)` | Record a command with run, workdir, name and sampling options |
| `batch_record(jobs, continue_on_error=False)` | Record sequentially; optionally retain failed-job entries |
| `record_batch(jobs, concurrency=1)` | Record through the CLI batch workflow and return a manifest |
| `evidence_manifest(run_id, materialize=False)` | Query the evidence manifest, optionally materializing graph objects |
| `batch_summary(...)` | Query a batch, run, job or shard summary |
| `eval_context(run_id)` | Read one evaluator context |
| `batch_eval_contexts(...)` | Read contexts into a list |
| `iter_eval_contexts(...)` | Stream contexts line by line |
| `signals(run_id, dimension=None)` | Read unified signals, optionally filtered by dimension |
| `score_trajectory(command, registry, ...)` | Record and evaluate one run; return a `TrajectoryScore` |
| `import_signals(run_id, signals, validate=True)` | Import signals with optional local validation |
| `import_signal_reports(reports, engine="python-sdk")` | Import evaluator reports in a batch |
| `evaluate_batch(registry, ..., import_signals=False)` | Evaluate recorded runs, optionally importing results |
| `batch_forensics(...)` | Export a batch bundle, optionally including run bundles and contexts |
| `run_batch_pipeline(jobs, registry, ...)` | Run the full batch workflow |

Batch selectors generally include `batch_id`, `run_id`, `job_id`, `shard_id`, `latest` and `limit`; context readers also accept `run_ids`. See the [Client source](../python/agentprov_eval/__init__.py) for complete signatures.

## Evaluator rules

Create a `Registry(name=...)`, then use `@registry.rule(...)` or `registry.register(fn, ...)`. Rules accept `name`, `description` and `tags` metadata. `registry.rules()` lists rules; `registry.evaluate(ctx)` runs them.

Each function receives an `EvalContext` and returns a `Signal`, dictionary, sequence of signals or `None`:

| Context method | Contents |
|---|---|
| `trajectories()` | Trajectory manifests |
| `runtime_events(event_type=None)` | Runtime events |
| `risks(severity=None)` | Risk signals |
| `responses(action=None)` | Response actions |
| `file_changes(change_type=None)` | File changes |
| `has_event_type(event_type)` | Whether an event type is present |

`ctx.run_id` is the run identifier; `ctx.raw` retains the full input.

| Signal constructor | Kind |
|---|---|
| `Signal.reward_feature(name, score, reason, ...)` | `reward_feature` |
| `Signal.penalty(name, score, reason, ...)` | `penalty` |
| `Signal.dataset_label(name, label, score, reason, ...)` | `dataset_label` |
| `Signal.quality_signal(name, score, reason, ...)` | `quality_signal` |

Shared fields include `run_id`, `attempt_id`, `tool_call_id` and `evidence`. Use `to_dict()` for serialization and `validate()` for name, kind and score checks; dictionaries use `validate_signal_dict()`. Corresponding `KIND_*` constants are exported.

`TrajectoryScore` stores `run_id`, `record_manifest`, `context` and `report`, and exposes `signals`. `reward()` sums reward-feature and penalty scores by default. Use `include_kinds` to select kinds and `weights` for per-name weights; unlisted names have zero weight when a weights dictionary is supplied. Reward policy belongs to the caller.

## Standalone evaluators and helpers

- `evaluate()` returns signal dictionaries; `evaluate_context()` returns one report.
- `evaluate_batch()` accepts context objects, dictionaries or JSONL lines and returns reports.
- `reports_jsonl()` returns a JSONL string; `emit_jsonl()` writes to a stream, defaulting to stdout.
- Global `rule()` and `register()` use `default_registry`; separate registries keep independent evaluators isolated.
- `main(registry)` reads one context from stdin and writes signal JSON to stdout for CLI evaluator integration.
- Top-level `record`, `batch_record`, `record_batch`, `batch_eval_contexts`, `batch_forensics` and `run_batch_pipeline` helpers accept `binary`, `data_dir` and related options.

See [python_signal_eval.py](../examples/evaluators/python_signal_eval.py) for a complete evaluator and [LLM Judge](../demo/llm-judge/README.md) for model integration.

## Errors

Invalid parameters or signal formats raise `ValueError`. Nonzero CLI exits, ordinary call timeouts and HTTP errors raise `RuntimeError` with command or server details. Use `batch_record(..., continue_on_error=True)` to retain successful jobs when another job fails.
