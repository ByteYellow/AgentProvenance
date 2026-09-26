# AI tool reference

English | [中文](zh-CN/ai-tools.md)

These eight tools are shared by `ai call`, stdio MCP and provider tool definitions. See [AI access](ai-access.md) for setup.

`bind_scope` and `record_tool_call` write application context. Other tools are read-only. Preflight and context operations do not launch commands.

## `verify_run`: Verify evidence

Check object hashes, parent links and policy/risk/response/signal relationships. Returns an ok or failed status and a list of issues.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `run` | `string` | yes | run id to verify |

## `get_signals`: Query signals

Read the behavior, cost, quality and security signals for a run.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `run` | `string` | yes | run id |

## `list_risks`: Query risks

Read risk signals, recommended actions and evidence references.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `run` | `string` | yes | run id |

## `list_events`: Query runtime events

Filter runtime events by type. Returns up to 50 events by default. For subsequent pages, use the REST endpoint with its cursor parameter.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `limit` | `integer` | no | max events (default 50) |
| `run` | `string` | yes | run id |
| `type` | `string` | no | optional event_type filter, e.g. execve, metadata_ip |

## `get_timeline`: Query the timeline

Merge application context and runtime events in table or causality views.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `run` | `string` | yes | run id |
| `view` | `string` | no | timeline view |

## `evaluate_action`: Evaluate a proposed action

Evaluate a proposed action with the default policy engine. Returns allow, deny, quarantine or kill, plus rule_id and reason. The caller applies the decision.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `args` | `array` | no | structured argv for execve actions; preferred when the caller already has tokenized arguments |
| `command` | `string` | no | the command line for execve actions |
| `dst_ip` | `string` | no | destination IP for network_connect actions |
| `event_type` | `string` | yes | one of: execve, network_connect, file_write, file_open |
| `path` | `string` | no | file path for file actions |

## `bind_scope`: Bind an execution scope

Associate a tool call with process, container or cgroup identifiers. The binding source is ai_asserted for later runtime event correlation.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `cgroup_id` | `string` | no | optional runtime-observable cgroup id |
| `container_id` | `string` | no | optional runtime-observable container id |
| `ended_at` | `string` | no | optional RFC3339 end; empty leaves the scope open |
| `pid` | `integer` | no | optional OS process id |
| `process_id` | `string` | no | optional AgentProvenance process id for this scope |
| `root_pid` | `integer` | no | optional root OS process id for the scope |
| `run` | `string` | yes | run id this scope belongs to |
| `started_at` | `string` | no | optional RFC3339 start; defaults to now |
| `tool_call` | `string` | yes | tool_call id to bind |

## `record_tool_call`: Record a tool call

Save an application-declared tool call and return its tool_call identifier for bind_scope. The stored status is asserted.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `command` | `string` | yes | the tool name / command line the agent is asserting it invoked |
| `run` | `string` | yes | run id this tool call belongs to |
| `tool_call` | `string` | no | optional tool_call id to use; generated when omitted |

## Examples

```sh
agentprov ai tools --provider generic
agentprov ai tools --provider anthropic
agentprov ai tools --provider openai
agentprov --data-dir .agentprov ai call list_events --input '{"run":"run-example","limit":20}'
```

Replace `run-example` with a recorded run ID. The provider options emit definitions without calling a model. Tool descriptions and output default to English.

A `tools/call` request over MCP:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_timeline","arguments":{"run":"run-example","view":"table"}}}
```

Initialize MCP first. Results contain `content`, with `structuredContent` for object results. Check `isError` for tool failures and the JSON-RPC `error` field for protocol errors.
