# AI 工具参考

[English](../ai-tools.md) | 中文

以下八个工具共用于 `ai call`、stdio MCP 和模型工具描述。参数名及 JSON 结果保持英文。接入步骤见 [AI 接入指南](ai-access.md)。

工具分为查询、预检和上下文写入。`bind_scope` 与 `record_tool_call` 写入应用上下文；其他工具只读。预检和上下文写入均不启动命令。

## `verify_run`：校验证据链

检查对象哈希、父节点关系，以及策略、风险、响应与信号的关联。结果包含 ok 或 failed 状态和问题列表。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `run` | `string` | 是 | 执行 ID |

## `get_signals`：查询统一信号

读取一次执行的行为、成本、质量和安全信号。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `run` | `string` | 是 | 执行 ID |

## `list_risks`：查询风险

读取风险信号、建议动作及相关证据。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `run` | `string` | 是 | 执行 ID |

## `list_events`：查询运行时事件

按类型筛选运行时事件。默认返回最多 50 条；连续翻页请使用 REST 接口的 cursor 参数。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `limit` | `integer` | 否 | 返回数量上限，默认 50 |
| `run` | `string` | 是 | 执行 ID |
| `type` | `string` | 否 | 可选事件类型，例如 execve、metadata_ip |

## `get_timeline`：查询时间线

合并应用上下文与运行时事件，支持 table 和 causality 视图。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `run` | `string` | 是 | 执行 ID |
| `view` | `string` | 否 | 时间线视图：table 或 causality |

## `evaluate_action`：策略预检

将拟执行的操作交给默认策略引擎，返回 allow、deny、quarantine 或 kill，以及 rule_id 和 reason。调用方负责执行该决策。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `args` | `array` | 否 | 已拆分的命令参数数组，元素为字符串 |
| `command` | `string` | 否 | 工具名或命令行；预检已有 args 时优先使用 args |
| `dst_ip` | `string` | 否 | 网络连接的目标 IP |
| `event_type` | `string` | 是 | 操作类型：execve、network_connect、file_write 或 file_open |
| `path` | `string` | 否 | 文件操作的路径 |

## `bind_scope`：绑定执行范围

将工具调用与进程、容器或 cgroup 标识关联。写入来源为 ai_asserted，供后续运行时事件匹配。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `cgroup_id` | `string` | 否 | 运行时 cgroup ID |
| `container_id` | `string` | 否 | 运行时容器 ID |
| `ended_at` | `string` | 否 | RFC3339 结束时间，留空表示仍在执行 |
| `pid` | `integer` | 否 | 操作系统进程 ID |
| `process_id` | `string` | 否 | AgentProvenance 中的进程 ID |
| `root_pid` | `integer` | 否 | 执行范围的根进程 ID |
| `run` | `string` | 是 | 执行 ID |
| `started_at` | `string` | 否 | RFC3339 开始时间，默认当前时间 |
| `tool_call` | `string` | 是 | 要绑定的工具调用 ID |

## `record_tool_call`：记录工具调用

保存应用声明的工具调用，返回 tool_call 标识，后续可用 bind_scope 绑定。状态为 asserted。

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `command` | `string` | 是 | 工具名或命令行 |
| `run` | `string` | 是 | 执行 ID |
| `tool_call` | `string` | 否 | 工具调用 ID，省略时自动生成 |

## 调用示例

```sh
agentprov ai tools --provider generic
agentprov ai tools --provider anthropic
agentprov ai tools --provider openai
agentprov --data-dir .agentprov ai call list_events --input '{"run":"run-example","limit":20}'
```

将 `run-example` 替换为已记录的执行 ID。三个 provider 选项只生成工具定义，不会调用模型。工具描述和输出默认英文。

MCP 的 `tools/call` 请求示例：

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_timeline","arguments":{"run":"run-example","view":"table"}}}
```

MCP 先完成 `initialize`。成功结果包含 `content`，对象结果同时提供 `structuredContent`。执行失败时检查 `isError`；协议错误则位于 JSON-RPC 的 `error` 字段。
