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
from typing import Any, Callable, Iterable, Sequence


KIND_REWARD_FEATURE = "reward_feature"
KIND_PENALTY = "penalty"
KIND_DATASET_LABEL = "dataset_label"
KIND_QUALITY_SIGNAL = "quality_signal"


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

    def import_signals(self, run_id: str, signals: Iterable["Signal | dict[str, Any]"]) -> dict[str, Any]:
        payload = {"signals": [signal.to_dict() if isinstance(signal, Signal) else signal for signal in signals]}
        return self.run_cli(
            ["signal", "import", "--run", run_id, "--file", "-", "--json"],
            input_text=json.dumps(payload, separators=(",", ":")),
        ).json()


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


def main(evaluate: Callable[[EvalContext], Iterable[Signal | dict[str, Any]]]) -> None:
    ctx = EvalContext(json.load(sys.stdin))
    signals = []
    for signal in evaluate(ctx):
        if isinstance(signal, Signal):
            signals.append(signal.to_dict())
        else:
            signals.append(signal)
    json.dump({"signals": signals}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


__all__ = [
    "Client",
    "CommandResult",
    "EvalContext",
    "Signal",
    "batch_eval_contexts",
    "batch_record",
    "record",
    "record_batch",
    "KIND_REWARD_FEATURE",
    "KIND_PENALTY",
    "KIND_DATASET_LABEL",
    "KIND_QUALITY_SIGNAL",
]
