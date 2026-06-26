#!/usr/bin/env python3
"""Example external evaluator for AgentProvenance.

This file is deliberately policy-light: it demonstrates how a benchmark,
RL trainer, red-team harness, or dataset pipeline can read evidence and emit
its own signals without AgentProvenance owning the scoring policy.
"""

from agentprov import Signal, main, rule


@rule("example.file_change_count")
def file_change_count(ctx):
    file_changes = ctx.file_changes()
    return Signal.reward_feature(
        "example.file_change_count",
        float(len(file_changes)),
        "external evaluator counted file state changes",
        evidence={"file_change_count": len(file_changes)},
    )


@rule("example.exec_observed")
def exec_observed(ctx):
    exec_events = ctx.runtime_events("execve")
    if exec_events:
        return Signal.quality_signal(
            "example.exec_observed",
            1.0,
            "external evaluator observed runtime execution evidence",
            evidence={"exec_event_count": len(exec_events)},
        )
    return None


@rule("example.dataset_label")
def dataset_label(ctx):
    risks = ctx.risks()
    label = "needs_review" if risks else "candidate"
    return Signal.dataset_label(
        "example.dataset_label",
        label,
        1.0 if label == "candidate" else 0.0,
        "external evaluator assigned a dataset label from provenance evidence",
        evidence={"risk_count": len(risks)},
    )


if __name__ == "__main__":
    main()
