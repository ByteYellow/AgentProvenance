"""Thin Python helpers for external AgentProvenance evaluators.

The SDK intentionally does not define reward logic. It only wraps the
EvalContext JSON passed by `agentprov signal run --external` and emits
validated EvalSignal-shaped dictionaries.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, Iterable


KIND_REWARD_FEATURE = "reward_feature"
KIND_PENALTY = "penalty"
KIND_DATASET_LABEL = "dataset_label"
KIND_QUALITY_SIGNAL = "quality_signal"


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
