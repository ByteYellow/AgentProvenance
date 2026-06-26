"""Thin Python helpers for AgentProvenance users.

The package intentionally does not define reward logic. It provides two small
surfaces:

- wrappers around the local `agentprov` binary for lightweight recorder usage;
- helpers for external evaluators that consume EvalContext JSON and emit
  EvalSignal-shaped dictionaries.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Iterable, Sequence


KIND_REWARD_FEATURE = "reward_feature"
KIND_PENALTY = "penalty"
KIND_DATASET_LABEL = "dataset_label"
KIND_QUALITY_SIGNAL = "quality_signal"

SignalLike = "Signal | dict[str, Any]"
RuleReturn = "Signal | dict[str, Any] | Iterable[Signal | dict[str, Any]] | None"
RuleFunction = Callable[["EvalContext"], RuleReturn]


@dataclass
class CommandResult:
    """Result from invoking the local agentprov binary."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    def json(self) -> dict[str, Any]:
        if not self.stdout.strip():
            return {}
        return json.loads(self.stdout)


class Client:
    """Small wrapper around the local agentprov CLI.

    This is deliberately a thin helper, not a Python control plane. It keeps RL
    and benchmark harness integration lightweight: one Go binary plus this
    optional Python package.
    """

    def __init__(
        self,
        binary: str | os.PathLike[str] = "agentprov",
        data_dir: str | os.PathLike[str] | None = None,
        daemon_url: str | None = None,
        env: dict[str, str] | None = None,
    ):
        self.binary = str(binary)
        self.data_dir = str(data_dir) if data_dir is not None else None
        self.daemon_url = daemon_url
        self.env = dict(env or {})

    def run_cli(self, args: Sequence[str], *, input_text: str | None = None) -> CommandResult:
        cmd = [self.binary]
        if self.data_dir:
            cmd.extend(["--data-dir", self.data_dir])
        if self.daemon_url:
            cmd.extend(["--daemon-url", self.daemon_url])
        cmd.extend(str(arg) for arg in args)
        env = os.environ.copy()
        env.update(self.env)
        proc = subprocess.run(
            cmd,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        result = CommandResult(args=cmd, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        if proc.returncode != 0:
            raise RuntimeError(
                f"agentprov command failed returncode={proc.returncode} args={cmd!r} stderr={proc.stderr.strip()}"
            )
        return result

    def record(
        self,
        command: Sequence[str],
        *,
        run_id: str = "",
        workdir: str | os.PathLike[str] | None = None,
        name: str = "record",
        sample_interval_ms: int | None = None,
        post_root_grace_ms: int | None = None,
    ) -> dict[str, Any]:
        args = ["record", "--json"]
        if run_id:
            args.extend(["--run", run_id])
        if workdir is not None:
            args.extend(["--workdir", str(workdir)])
        if name:
            args.extend(["--name", name])
        if sample_interval_ms is not None:
            args.extend(["--sample-interval-ms", str(sample_interval_ms)])
        if post_root_grace_ms is not None:
            args.extend(["--post-root-grace-ms", str(post_root_grace_ms)])
        args.append("--")
        args.extend(str(part) for part in command)
        return self.run_cli(args).json()

    def batch_record(self, jobs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        manifests = []
        for job in jobs:
            command = job.get("command")
            if not command:
                raise ValueError("batch record job must include command")
            manifests.append(
                self.record(
                    command,
                    run_id=job.get("run_id", ""),
                    workdir=job.get("workdir"),
                    name=job.get("name", "record"),
                    sample_interval_ms=job.get("sample_interval_ms"),
                    post_root_grace_ms=job.get("post_root_grace_ms"),
                )
            )
        return manifests

    def record_batch(self, jobs: Iterable[dict[str, Any]]) -> dict[str, Any]:
        rows = []
        for job in jobs:
            if not job.get("command"):
                raise ValueError("batch record job must include command")
            rows.append(json.dumps(job, separators=(",", ":")))
        if not rows:
            raise ValueError("batch record requires at least one job")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            path = handle.name
            handle.write("\n".join(rows))
            handle.write("\n")
        try:
            return self.run_cli(["record", "batch", "--file", path, "--json"]).json()
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def evidence_manifest(self, run_id: str, *, materialize: bool = False) -> dict[str, Any]:
        args = ["evidence", "manifest", "--run", run_id, "--json"]
        if materialize:
            args.append("--materialize")
        return self.run_cli(args).json()

    def batch_summary(
        self,
        *,
        batch_id: str = "",
        run_id: str = "",
        job_id: str = "",
        shard_id: str = "",
        latest: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        args = ["evidence", "batch-summary", "--json", "--limit", str(limit)]
        if batch_id:
            args.extend(["--batch", batch_id])
        if run_id:
            args.extend(["--run", run_id])
        if job_id:
            args.extend(["--job", job_id])
        if shard_id:
            args.extend(["--shard", shard_id])
        if latest:
            args.append("--latest")
        return self.run_cli(args).json()

    def eval_context(self, run_id: str) -> dict[str, Any]:
        return self.run_cli(["signal", "context", "--run", run_id]).json()

    def batch_eval_contexts(
        self,
        *,
        run_ids: Iterable[str] | None = None,
        batch_id: str = "",
        run_id: str = "",
        job_id: str = "",
        shard_id: str = "",
        latest: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        args = ["signal", "batch-context", "--limit", str(limit)]
        input_text = None
        if run_ids is not None:
            args.extend(["--runs", "-"])
            input_text = "\n".join(json.dumps({"run_id": value}) for value in run_ids)
            if input_text:
                input_text += "\n"
        if batch_id:
            args.extend(["--batch", batch_id])
        if run_id:
            args.extend(["--run", run_id])
        if job_id:
            args.extend(["--job", job_id])
        if shard_id:
            args.extend(["--shard", shard_id])
        if latest:
            args.append("--latest")
        result = self.run_cli(args, input_text=input_text)
        contexts = []
        for line in result.stdout.splitlines():
            if line.strip():
                contexts.append(json.loads(line))
        return contexts

    def batch_forensics(
        self,
        *,
        batch_id: str = "",
        run_id: str = "",
        job_id: str = "",
        shard_id: str = "",
        latest: bool = False,
        limit: int = 100,
        include_run_bundles: bool = True,
        include_eval_contexts: bool = False,
    ) -> dict[str, Any]:
        args = ["forensics", "export-batch", "--json", "--limit", str(limit)]
        if batch_id:
            args.extend(["--batch", batch_id])
        if run_id:
            args.extend(["--run", run_id])
        if job_id:
            args.extend(["--job", job_id])
        if shard_id:
            args.extend(["--shard", shard_id])
        if latest:
            args.append("--latest")
        if not include_run_bundles:
            args.append("--include-run-bundles=false")
        if include_eval_contexts:
            args.append("--include-eval-contexts")
        return self.run_cli(args).json()

    def import_signals(self, run_id: str, signals: Iterable["Signal | dict[str, Any]"]) -> dict[str, Any]:
        payload = {"signals": [signal.to_dict() if isinstance(signal, Signal) else signal for signal in signals]}
        return self.run_cli(
            ["signal", "import", "--run", run_id, "--file", "-", "--json"],
            input_text=json.dumps(payload, separators=(",", ":")),
        ).json()

    def import_signal_reports(
        self,
        reports: Iterable[dict[str, Any]],
        *,
        engine: str = "python-sdk",
    ) -> dict[str, Any]:
        rows = [json.dumps(report, separators=(",", ":")) for report in reports]
        if not rows:
            raise ValueError("import_signal_reports requires at least one report")
        return self.run_cli(
            ["signal", "import-batch", "--file", "-", "--engine", engine, "--json"],
            input_text="\n".join(rows) + "\n",
        ).json()

    def evaluate_batch(
        self,
        registry: "Registry",
        *,
        run_ids: Iterable[str] | None = None,
        batch_id: str = "",
        run_id: str = "",
        job_id: str = "",
        shard_id: str = "",
        latest: bool = False,
        limit: int = 100,
        import_signals: bool = False,
        engine: str = "python-sdk",
    ) -> list[dict[str, Any]]:
        contexts = self.batch_eval_contexts(
            run_ids=run_ids,
            batch_id=batch_id,
            run_id=run_id,
            job_id=job_id,
            shard_id=shard_id,
            latest=latest,
            limit=limit,
        )
        reports = [evaluate_context(ctx, registry=registry, engine=engine) for ctx in contexts]
        if import_signals:
            self.import_signal_reports(reports, engine=engine)
        return reports

    def run_batch_pipeline(
        self,
        jobs: Iterable[dict[str, Any]],
        registry: "Registry",
        *,
        engine: str | None = None,
        shard_id: str = "",
        limit: int = 1000,
        import_signals: bool = True,
        include_forensics: bool = True,
        include_eval_contexts_in_forensics: bool = False,
    ) -> "BatchPipelineResult":
        record_manifest = self.record_batch(jobs)
        selected_engine = engine or registry.name
        selected_shard = shard_id
        contexts = self.batch_eval_contexts(
            batch_id=record_manifest["batch_id"],
            shard_id=selected_shard,
            limit=limit,
        )
        reports = evaluate_batch(contexts, registry=registry, engine=selected_engine)
        import_report = None
        if import_signals:
            import_report = self.import_signal_reports(reports, engine=selected_engine)
        forensics_report = None
        if include_forensics:
            forensics_report = self.batch_forensics(
                batch_id=record_manifest["batch_id"],
                shard_id=selected_shard,
                limit=limit,
                include_eval_contexts=include_eval_contexts_in_forensics,
            )
        summary = self.batch_summary(batch_id=record_manifest["batch_id"], shard_id=selected_shard, limit=limit)
        return BatchPipelineResult(
            record_manifest=record_manifest,
            contexts=contexts,
            reports=reports,
            import_report=import_report,
            forensics=forensics_report,
            summary=summary,
        )


def record(
    command: Sequence[str],
    *,
    run_id: str = "",
    workdir: str | os.PathLike[str] | None = None,
    binary: str | os.PathLike[str] = "agentprov",
    data_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Record one command through the local agentprov binary."""

    return Client(binary=binary, data_dir=data_dir).record(command, run_id=run_id, workdir=workdir)


def batch_record(
    jobs: Iterable[dict[str, Any]],
    *,
    binary: str | os.PathLike[str] = "agentprov",
    data_dir: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Record many commands sequentially for batch/evaluator pipelines."""

    return Client(binary=binary, data_dir=data_dir).batch_record(jobs)


def record_batch(
    jobs: Iterable[dict[str, Any]],
    *,
    binary: str | os.PathLike[str] = "agentprov",
    data_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Record many commands through `agentprov record batch` and return one manifest."""

    return Client(binary=binary, data_dir=data_dir).record_batch(jobs)


def batch_eval_contexts(
    *,
    run_ids: Iterable[str] | None = None,
    batch_id: str = "",
    run_id: str = "",
    job_id: str = "",
    shard_id: str = "",
    latest: bool = False,
    limit: int = 100,
    binary: str | os.PathLike[str] = "agentprov",
    data_dir: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Export many EvalContext objects through `agentprov signal batch-context`."""

    return Client(binary=binary, data_dir=data_dir).batch_eval_contexts(
        run_ids=run_ids,
        batch_id=batch_id,
        run_id=run_id,
        job_id=job_id,
        shard_id=shard_id,
        latest=latest,
        limit=limit,
    )


def batch_forensics(
    *,
    batch_id: str = "",
    run_id: str = "",
    job_id: str = "",
    shard_id: str = "",
    latest: bool = False,
    limit: int = 100,
    include_run_bundles: bool = True,
    include_eval_contexts: bool = False,
    binary: str | os.PathLike[str] = "agentprov",
    data_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Export a batch-level forensics audit bundle."""

    return Client(binary=binary, data_dir=data_dir).batch_forensics(
        batch_id=batch_id,
        run_id=run_id,
        job_id=job_id,
        shard_id=shard_id,
        latest=latest,
        limit=limit,
        include_run_bundles=include_run_bundles,
        include_eval_contexts=include_eval_contexts,
    )


def run_batch_pipeline(
    jobs: Iterable[dict[str, Any]],
    registry: "Registry",
    *,
    binary: str | os.PathLike[str] = "agentprov",
    data_dir: str | os.PathLike[str] | None = None,
    daemon_url: str | None = None,
    engine: str | None = None,
    shard_id: str = "",
    limit: int = 1000,
    import_signals: bool = True,
    include_forensics: bool = True,
    include_eval_contexts_in_forensics: bool = False,
) -> "BatchPipelineResult":
    """Run the Deploy 1 offline batch workflow end to end."""

    return Client(binary=binary, data_dir=data_dir, daemon_url=daemon_url).run_batch_pipeline(
        jobs,
        registry,
        engine=engine,
        shard_id=shard_id,
        limit=limit,
        import_signals=import_signals,
        include_forensics=include_forensics,
        include_eval_contexts_in_forensics=include_eval_contexts_in_forensics,
    )


class EvalContext:
    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.run_id = raw.get("run_id", "")

    def trajectories(self) -> list[dict[str, Any]]:
        manifest = self.raw.get("trajectories") or {}
        return list(manifest.get("trajectories") or [])

    def runtime_events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        events = list(self.raw.get("runtime_events") or [])
        if event_type is None:
            return events
        return [event for event in events if event.get("event_type") == event_type]

    def risks(self, severity: str | None = None) -> list[dict[str, Any]]:
        risks = list(self.raw.get("risks") or [])
        if severity is None:
            return risks
        return [risk for risk in risks if risk.get("severity") == severity]

    def responses(self, action: str | None = None) -> list[dict[str, Any]]:
        responses = list(self.raw.get("responses") or [])
        if action is None:
            return responses
        return [response for response in responses if response.get("action") == action]

    def file_changes(self, change_type: str | None = None) -> list[dict[str, Any]]:
        changes = list(self.raw.get("file_changes") or [])
        if change_type is None:
            return changes
        return [change for change in changes if change.get("change_type") == change_type]

    def has_event_type(self, event_type: str) -> bool:
        return bool(self.runtime_events(event_type))


@dataclass
class Signal:
    name: str
    kind: str
    score: float
    reason: str
    label: str = ""
    run_id: str = ""
    attempt_id: str = ""
    tool_call_id: str = ""
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "score": self.score,
            "reason": self.reason,
        }
        if self.label:
            item["label"] = self.label
        if self.run_id:
            item["run_id"] = self.run_id
        if self.attempt_id:
            item["attempt_id"] = self.attempt_id
        if self.tool_call_id:
            item["tool_call_id"] = self.tool_call_id
        if self.evidence:
            item["evidence"] = self.evidence
        return item

    @classmethod
    def reward_feature(cls, name: str, score: float, reason: str, **kwargs: Any) -> "Signal":
        return cls(name=name, kind=KIND_REWARD_FEATURE, score=score, reason=reason, **kwargs)

    @classmethod
    def penalty(cls, name: str, score: float, reason: str, **kwargs: Any) -> "Signal":
        return cls(name=name, kind=KIND_PENALTY, score=score, reason=reason, **kwargs)

    @classmethod
    def dataset_label(
        cls, name: str, label: str, score: float, reason: str, **kwargs: Any
    ) -> "Signal":
        return cls(
            name=name,
            kind=KIND_DATASET_LABEL,
            label=label,
            score=score,
            reason=reason,
            **kwargs,
        )

    @classmethod
    def quality_signal(cls, name: str, score: float, reason: str, **kwargs: Any) -> "Signal":
        return cls(name=name, kind=KIND_QUALITY_SIGNAL, score=score, reason=reason, **kwargs)


@dataclass
class BatchPipelineResult:
    record_manifest: dict[str, Any]
    contexts: list[dict[str, Any]]
    reports: list[dict[str, Any]]
    import_report: dict[str, Any] | None = None
    forensics: dict[str, Any] | None = None
    summary: dict[str, Any] | None = None

    @property
    def batch_id(self) -> str:
        return self.record_manifest.get("batch_id", "")

    @property
    def run_ids(self) -> list[str]:
        return list(self.record_manifest.get("run_ids") or [])

    @property
    def signal_count(self) -> int:
        return sum(int(report.get("signal_count", 0)) for report in self.reports)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "agentprovenance.python_batch_pipeline/v1",
            "batch_id": self.batch_id,
            "run_ids": self.run_ids,
            "record_manifest": self.record_manifest,
            "context_count": len(self.contexts),
            "report_count": len(self.reports),
            "signal_count": self.signal_count,
            "import_report": self.import_report,
            "forensics": self.forensics,
            "summary": self.summary,
        }


@dataclass
class Rule:
    name: str
    fn: RuleFunction
    description: str = ""
    tags: tuple[str, ...] = ()


class Registry:
    """In-process evaluator registry for RL/evaluator pipelines.

    A registry owns Python-side signal functions. AgentProvenance still owns
    evidence capture and manifests; these functions only map EvalContext into
    EvalSignal records.
    """

    def __init__(self, name: str = "python-sdk"):
        self.name = name
        self._rules: list[Rule] = []

    def register(
        self,
        fn: RuleFunction,
        *,
        name: str | None = None,
        description: str = "",
        tags: Iterable[str] = (),
    ) -> RuleFunction:
        rule_name = name or getattr(fn, "__name__", "anonymous_rule")
        self._rules.append(Rule(name=rule_name, fn=fn, description=description, tags=tuple(tags)))
        return fn

    def rule(
        self,
        name: str | None = None,
        *,
        description: str = "",
        tags: Iterable[str] = (),
    ) -> Callable[[RuleFunction], RuleFunction]:
        def decorator(fn: RuleFunction) -> RuleFunction:
            return self.register(fn, name=name, description=description, tags=tags)

        return decorator

    def rules(self) -> list[Rule]:
        return list(self._rules)

    def evaluate(self, ctx: EvalContext) -> list[Signal | dict[str, Any]]:
        signals: list[Signal | dict[str, Any]] = []
        for registered in self._rules:
            produced = registered.fn(ctx)
            for signal in _normalize_rule_output(produced):
                if isinstance(signal, Signal) and not signal.name:
                    signal.name = registered.name
                signals.append(signal)
        return signals


default_registry = Registry()


def rule(
    name: str | None = None,
    *,
    description: str = "",
    tags: Iterable[str] = (),
) -> Callable[[RuleFunction], RuleFunction]:
    """Register a signal function in the default Python evaluator registry."""

    return default_registry.rule(name=name, description=description, tags=tags)


def register(
    fn: RuleFunction | None = None,
    *,
    name: str | None = None,
    description: str = "",
    tags: Iterable[str] = (),
) -> RuleFunction | Callable[[RuleFunction], RuleFunction]:
    """Register a signal function.

    Supports both `register(fn)` and `@register(name="...")`.
    """

    if fn is None:
        return rule(name=name, description=description, tags=tags)
    return default_registry.register(fn, name=name, description=description, tags=tags)


def evaluate(ctx: EvalContext | dict[str, Any], registry: Registry | None = None) -> list[dict[str, Any]]:
    """Evaluate one context and return EvalSignal dictionaries."""

    context = ctx if isinstance(ctx, EvalContext) else EvalContext(ctx)
    selected = registry or default_registry
    return [_signal_to_dict(signal, context.run_id, index) for index, signal in enumerate(selected.evaluate(context), start=1)]


def evaluate_context(
    raw: EvalContext | dict[str, Any],
    *,
    registry: Registry | None = None,
    engine: str = "python-sdk",
    decision_owner: str = "external_evaluator",
) -> dict[str, Any]:
    """Evaluate one EvalContext and return an EvalReport-shaped dictionary."""

    context = raw if isinstance(raw, EvalContext) else EvalContext(raw)
    signals = evaluate(context, registry=registry)
    result_set_id, page_hash = _report_hashes(context.run_id, engine, signals)
    return {
        "schema_version": "agentprovenance.eval_signals/v1",
        "run_id": context.run_id,
        "engine": engine,
        "decision_owner": decision_owner,
        "signal_count": len(signals),
        "result_set_id": result_set_id,
        "page_hash": page_hash,
        "signals": signals,
    }


def evaluate_batch(
    contexts: Iterable[EvalContext | dict[str, Any] | str],
    *,
    registry: Registry | None = None,
    engine: str = "python-sdk",
) -> list[dict[str, Any]]:
    """Evaluate many contexts.

    Each item can be an EvalContext object, a raw dict, or one JSONL line.
    """

    reports = []
    for item in contexts:
        if isinstance(item, str):
            item = json.loads(item)
        reports.append(evaluate_context(item, registry=registry, engine=engine))
    return reports


def emit_jsonl(reports: Iterable[dict[str, Any]], out: Any = sys.stdout) -> None:
    for report in reports:
        json.dump(report, out, separators=(",", ":"))
        out.write("\n")


def reports_jsonl(reports: Iterable[dict[str, Any]]) -> str:
    return "".join(json.dumps(report, separators=(",", ":")) + "\n" for report in reports)


def _normalize_rule_output(produced: RuleReturn) -> list[Signal | dict[str, Any]]:
    if produced is None:
        return []
    if isinstance(produced, (Signal, dict)):
        return [produced]
    return [item for item in produced if item is not None]


def _signal_to_dict(signal: Signal | dict[str, Any], run_id: str, index: int) -> dict[str, Any]:
    item = signal.to_dict() if isinstance(signal, Signal) else dict(signal)
    item.setdefault("id", f"signal-{index:03d}")
    if run_id:
        item.setdefault("run_id", run_id)
    if "name" not in item or not item["name"]:
        item["name"] = item["id"]
    if "kind" not in item or not item["kind"]:
        item["kind"] = KIND_QUALITY_SIGNAL
    item.setdefault("score", 0.0)
    item.setdefault("reason", "")
    return item


def _report_hashes(run_id: str, engine: str, signals: list[dict[str, Any]]) -> tuple[str, str]:
    result_raw = json.dumps(
        {"kind": "eval_signals_result_set", "run_id": run_id, "engine": engine, "signals": signals},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    page_raw = json.dumps(
        {"kind": "eval_signals_page", "run_id": run_id, "engine": engine, "signals": signals},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + sha256(result_raw).hexdigest(), "sha256:" + sha256(page_raw).hexdigest()


def main(evaluate: Callable[[EvalContext], Iterable[Signal | dict[str, Any]]] | Registry | None = None) -> None:
    ctx = EvalContext(json.load(sys.stdin))
    if isinstance(evaluate, Registry):
        report = evaluate_context(ctx, registry=evaluate, engine=evaluate.name)
    elif evaluate is None:
        report = evaluate_context(ctx)
    else:
        registry = Registry(name=getattr(evaluate, "__name__", "python-function"))
        registry.register(evaluate)
        report = evaluate_context(ctx, registry=registry, engine=registry.name)
    json.dump({"signals": report["signals"]}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


__all__ = [
    "Client",
    "CommandResult",
    "EvalContext",
    "Registry",
    "Rule",
    "Signal",
    "BatchPipelineResult",
    "batch_eval_contexts",
    "batch_forensics",
    "batch_record",
    "default_registry",
    "emit_jsonl",
    "evaluate",
    "evaluate_batch",
    "evaluate_context",
    "main",
    "register",
    "reports_jsonl",
    "record",
    "record_batch",
    "rule",
    "run_batch_pipeline",
    "KIND_REWARD_FEATURE",
    "KIND_PENALTY",
    "KIND_DATASET_LABEL",
    "KIND_QUALITY_SIGNAL",
]
