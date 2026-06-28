# AI Access: making AgentProvenance AI-native

> Status: direction + contract doc. AgentProvenance should be callable BY agents,
> not just observed by humans. The asset is the capability surface (already
> `daemon /v1` REST + CLI `--json`); MCP, OpenAPI, provider tool-schemas, SDK
> wrappers, and the CLI are all thin ADAPTERS over the same contract. Define the
> contract once (this doc), generate the adapters.

## 0. The trust boundary (load-bearing, applies to every adapter)

- An agent MAY **query everything** (read tools) and MAY **assert its own
  app-side context** (bind a ToolCallScope, record a tool call).
- An agent MUST NOT be able to **fabricate system-side events or signatures**.
  System evidence and off-host signing stay outside the agent's control, or the
  tamper-evidence thesis breaks.
- Verdicts (the inline gate) are computed by the trusted policy/correlation
  engine, never by the calling model.

So: ship read-only tools first (zero trust risk), then context-write tools, then
the gate.

## 1. The capability contract (read surface)

Every operation already exists as a daemon endpoint and a CLI command, each
returning a versioned JSON envelope. This is the canonical list adapters expose.

| Operation | Daemon endpoint | CLI | Schema |
|---|---|---|---|
| verify_run | GET /v1/graph/verify?run= | graph verify --run --json | agentprovenance.verify/v1 |
| get_signals | GET /v1/signals?run= | signals list --run --json | agentprovenance.signals/v1 |
| explain | GET /v1/graph/explain?{event,process,tool-call,file,risk,artifact}= | graph explain --json | agentprovenance.explain/v1 |
| get_timeline | GET /v1/timeline?run= | timeline --run --json | agentprovenance.timeline/v1 |
| observe_summary | GET /v1/observe/summary?run= | observe summary --json | agentprovenance.observability_summary/v1 |
| list_risks | GET /v1/security/risks?run= | security risks --run --json | agentprovenance.security_risks/v1 |
| list_responses | GET /v1/security/responses?run= | security responses --run --json | agentprovenance.security_responses/v1 |
| list_deviations | GET /v1/security/deviations?run= | security deviations --run --json | (deviations) |
| list_events | GET /v1/telemetry/events?run= (paged) | telemetry list --run --json | agentprovenance.telemetry_events/v1 |
| list_windows | GET /v1/telemetry/windows?run= | telemetry windows --run --json | agentprovenance.telemetry_event_windows/v1 |
| explain_correlations | GET /v1/telemetry/correlations?run= | telemetry correlations --run --json | agentprovenance.telemetry_correlations/v1 |
| health | GET /v1/health | (daemon) | agentprovenance.daemon_health/v1 |

Context-write surface (phase 2, **shipped** as AI tools): `bind_scope` (register a
ToolCallScope binding, over `correlation.RecordBinding`) and `record_tool_call`
(anchor an app-asserted tool call). Both write only app-side context — forced
`binding_source=ai_asserted` / `status=asserted`, no execution, no system events —
so they cannot fabricate independent (kernel_correlated) evidence. The daemon
analogues remain `POST /v1/telemetry/bind` and `POST /v1/record` (the latter also
executes; the AI tool deliberately does not). Gate (phase 3, shipped):
`evaluate_action`.

## 2. Adapters (one contract, many surfaces)

| Adapter | What it is | Effort | Audience |
|---|---|---|---|
| CLI-as-tool | a stable `--json` contract + a tool manual prompt | ~0 (exists) | code-execution agents (Claude Code, etc.) |
| OpenAPI spec | one openapi.yaml over the read endpoints | low | GPT Actions, any OpenAPI tool importer |
| Provider tool-schemas | Anthropic tool-use / OpenAI function defs + dispatcher | low-med | direct tool-calling apps |
| MCP server | stdio MCP server wrapping the read surface + gate (`agentprov ai mcp`) — **shipped** | med | MCP clients |
| SDK framework tools | LangChain/LlamaIndex/CrewAI/Agents-SDK wrappers over the Python SDK | med | agents built in those frameworks |
| A2A agent-card | expose AgentProvenance as a delegatable agent | med (frontier) | agent-to-agent delegation |

### 2.1 MCP server (`agentprov ai mcp`)

A stdio MCP server (spec revision `2025-06-18`, JSON-RPC 2.0 over stdin/stdout)
generated from the same `internal/aitools.Catalog()` / `Dispatch` as the provider
tool-schemas and `ai call` — so MCP clients see exactly the eight tools (five read,
the `evaluate_action` gate, and the `bind_scope` / `record_tool_call` context-write
tools) with no separate contract to drift. The two write tools carry
`annotations.readOnlyHint=false`; everything else is hinted read-only. Only
JSON-RPC is written to stdout; diagnostics stay on stderr. Tool results carry the
serialized JSON in a `text` content block, with object results also surfaced as
`structuredContent`. Wire it into a client, e.g.:

```json
{ "mcpServers": { "agentprovenance": { "command": "agentprov", "args": ["ai", "mcp"] } } }
```

`initialize` → `tools/list` → `tools/call` is the full handshake; the trust
boundary in §0 is inherited unchanged (no fabrication of system events/signatures;
the gate verdict is the engine's, not the model's). Implementation:
`internal/mcpserver`.

## 3. The differentiated one: the inline gate (push, not pull)

Beyond "agent queries provenance," the unique capability is an **in-loop
guardrail**: the agent harness calls `evaluate_action(proposed_action, scope)`
before/after a tool call; the trusted engine returns allow / deny / quarantine
with the correlated evidence behind it. This turns AgentProvenance from an
observer into a step in the agent's decision loop -- backed by correlation +
verifiable evidence, which a plain query tool cannot provide.

## 4. Roadmap

1. **Read adapters** (done): CLI tool manual + OpenAPI spec, provider
   tool-schemas, and the stdio MCP server (§2.1) -- all over section 1.
2. **Context-write tools** (done): bind_scope / record_tool_call so an agent
   registers its own ToolCallScope (zero-instrumentation correlation), within the
   trust boundary — app-asserted only, never forging system evidence.
3. **Inline gate**: evaluate_action over the policy/correlation engine.
4. **Analysis direction** (optional): an observer-LLM step over the SIGNED graph
   (semantic risk explanation on tamper-evident evidence).
