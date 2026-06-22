# Comparisons

AgentProvenance is easiest to understand by separating three adjacent layers:

```text
LLM gateway
  -> routes and controls model requests

LLM / agent observability platform
  -> traces prompts, model calls, tool calls, latency, cost, feedback, evals

AgentProvenance
  -> turns execution context, runtime evidence, state changes, artifacts,
     risk, and promotion evidence into a Git-like provenance DAG
```

## LangSmith

LangSmith is an LLM and agent observability, evaluation, and monitoring
platform. It is strong at tracing application-level agent runs, LLM calls, tool
calls, prompts, costs, latency, feedback, human review, dashboards, and online
evals.

AgentProvenance should not try to be an open-source LangSmith clone. Its source
of truth is not a trace dashboard. Its source of truth is the sandbox execution
provenance graph:

```text
snapshot -> attempt -> tool_call -> process -> file diff -> artifact
                         |              |
                         v              v
                  runtime event      risk/cost evidence
                         |
                         v
                 taint / quarantine / promotion barrier
```

AgentProvenance can complement LangSmith-style systems by exporting lower-level
execution evidence:

- which snapshot an attempt came from;
- which process a tool call started;
- which process changed a file;
- which artifact came from which attempt;
- which runtime event caused risk or taint;
- why a local candidate was allowed or blocked at the promotion barrier;
- how to reconstruct the result through a replay manifest.

## LLM Gateways

LLM gateways sit on the model request path:

```text
application -> gateway -> model provider
```

They usually handle routing, fallback, rate limits, authentication, provider
abstraction, caching, cost controls, request logging, and sometimes prompt or
response policy.

AgentProvenance does not sit on the model request path. It sits on the sandbox
execution evidence path:

```text
agent harness -> sandbox runtime -> runtime telemetry / file diff / artifacts
                            |
                            v
                    provenance graph
```

## AgentProvenance Boundary

AgentProvenance consumes observability signals, but it is not a generic
observability platform. It consumes runtime substrates, but it is not a generic
sandbox runtime. It can support RL-style rollout experiments, but it is not an
RL trainer, winner selector, or throughput scheduler.

Its job is narrower:

> Combine execution context, system-level telemetry, state diff, artifact
> lineage, risk, and promotion evidence into a queryable, diffable, replayable,
> and auditable execution graph.

That graph should answer:

- What produced this artifact?
- Which tool call started this process?
- Which process changed this file?
- Which runtime event maps to this agent action?
- Which branch was tainted or quarantined?
- Which local candidate passed the promotion barrier, and what behavior/risk
  evidence should an external evaluator score before assigning reward,
  penalty, filtering, or review decisions?
- Can the result be replayed or audited later?
