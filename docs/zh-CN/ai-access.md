# AI 接入与工具契约

[English](../ai-access.md) | 中文

本文说明已有工具接口及后续接入方向。AgentProvenance 除了供人查询，也可以被 Agent 调用。后台服务的 `/v1` REST 接口和 CLI 的 `--json` 输出构成基础契约；MCP、OpenAPI、模型工具描述和 SDK 封装应复用这些能力，避免各自维护不同的数据语义。

接口参考：[中文 OpenAPI](openapi.yaml) · [八个 AI/MCP 工具](ai-tools.md) · [Python 接入](python-sdk.md)。

## 信任边界

这条边界适用于所有适配器：

- Agent 可以调用开放的查询接口，也可以声明应用侧上下文，例如绑定 ToolCallScope、记录工具调用。
- Agent 不能通过这些工具伪造系统侧事件或签名。部署时还需将系统证据采集和签名权限与 Agent 隔离；工具接口本身不能代替主机权限隔离。
- 策略预检结果由可信规则引擎计算，不由调用模型自行决定。

接入顺序为只读查询、应用上下文写入、策略预检。只读查询仍需具备读取相应证据的权限。

## 基础查询契约

以下能力已有后台服务接口及 CLI 命令，使用带版本的 JSON 结果。表格是底层查询范围；当前 MCP 和模型工具目录只暴露其中一部分，见后文的八个工具。

| 操作 | 后台服务接口 | CLI | 格式版本 |
|---|---|---|---|
| verify_run | GET /v1/graph/verify?run= | graph verify --run --json | agentprovenance.verify/v1 |
| get_signals | GET /v1/signals?run= | signals list --run --json | agentprovenance.signals/v1 |
| explain | GET /v1/graph/explain?{event,process,tool-call,file,risk,artifact}= | graph explain --json | agentprovenance.explain/v1 |
| get_timeline | GET /v1/timeline?run= | timeline --run --json | agentprovenance.timeline/v1 |
| observe_summary | GET /v1/observe/summary?run= | observe summary --json | agentprovenance.observability_summary/v1 |
| list_risks | GET /v1/security/risks?run= | security risks --run --json | agentprovenance.security_risks/v1 |
| list_responses | GET /v1/security/responses?run= | security responses --run --json | agentprovenance.security_responses/v1 |
| list_deviations | GET /v1/security/deviations?run= | security deviations --run --json | agentprovenance.security_deviations/v1 |
| list_events | GET /v1/telemetry/events?run=（分页） | telemetry list --run --json | agentprovenance.telemetry_events/v1 |
| list_windows | GET /v1/telemetry/windows?run= | telemetry windows --run --json | agentprovenance.telemetry_event_windows/v1 |
| explain_correlations | GET /v1/telemetry/correlations?run= | telemetry correlations --run --json | agentprovenance.telemetry_correlations/v1 |
| health | GET /v1/health | 后台服务接口 | agentprovenance.daemon_health/v1 |

表内命令省略了具体参数值，实际使用时需填写执行 ID 等信息。

应用上下文写入工具已经提供：`bind_scope` 通过 `correlation.RecordBinding` 注册 ToolCallScope，`record_tool_call` 记录应用声明的工具调用。它们只写应用侧上下文，来源强制标记为 `binding_source=ai_asserted`，调用状态标记为 `status=asserted`，不执行命令，也不创建系统事件。因此，这些记录不能冒充独立的内核关联证据。

后台服务对应的接口为 `POST /v1/telemetry/bind` 和 `POST /v1/record`。后者还会实际执行命令，不能与只声明调用的 AI 工具混为一谈。策略预检工具 `evaluate_action` 也已提供。

## 接入方式

下表中的工作量用于说明接入方案，不代表所有方案已经实现。

| 方式 | 作用与状态 | 工作量 | 适用对象 |
|---|---|---|---|
| 将 CLI 作为工具 | 已有 `--json` 契约与工具使用说明 | 已有基础能力 | Claude Code 等能执行命令的 Agent |
| OpenAPI | 通过一份 openapi.yaml 描述查询接口 | 小 | GPT Actions、OpenAPI 工具导入器 |
| 模型工具描述 | Anthropic tool-use、OpenAI function 描述及本地调用入口 | 小至中 | 直接使用模型工具调用的应用 |
| MCP 服务 | 已提供 `agentprov ai mcp`，复用查询、上下文写入及预检工具 | 中 | MCP 客户端 |
| SDK 框架工具 | 基于 Python SDK 为 LangChain、LlamaIndex、CrewAI、Agents SDK 等封装工具 | 中 | 使用这些框架构建的 Agent |
| A2A Agent Card | 将 AgentProvenance 暴露为可被委派任务的 Agent，属于探索方向 | 中，仍需探索 | Agent 间任务委派 |

### MCP 服务

`agentprov ai mcp` 通过标准输入、标准输出传输 JSON-RPC 2.0，默认 MCP 协议版本为 `2025-06-18`。它与模型工具描述和 `ai call` 复用 `internal/aitools.Catalog()`、`Dispatch`，当前提供八个工具：

- 五个查询工具：`verify_run`、`get_signals`、`list_risks`、`list_events`、`get_timeline`。
- 策略预检：`evaluate_action`。
- 应用上下文写入：`bind_scope`、`record_tool_call`。

两个写入工具声明 `annotations.readOnlyHint=false`，其他工具声明为只读。这是客户端提示信息，不能替代实际权限控制。

标准输出只写 JSON-RPC，诊断信息写入标准错误。工具结果在 `text` 内容块中提供序列化 JSON；对象结果还通过 `structuredContent` 返回。客户端配置示例：

```json
{ "mcpServers": { "agentprovenance": { "command": "agentprov", "args": ["ai", "mcp"] } } }
```

基本交互顺序为 `initialize` → `tools/list` → `tools/call`。前述信任边界不变：工具不能伪造系统事件或签名，预检结论来自规则引擎。实现位于 `internal/mcpserver`。

## 策略预检

Agent 执行框架可以在尝试命令、网络连接或文件操作前调用 `evaluate_action`。当前实现把调用方提供的 `event_type`、`command`/`args`、`dst_ip`、`path` 交给本地默认策略引擎，返回 `allow`、`deny`、`quarantine` 或 `kill`，以及命中的规则标识和原因。

该调用本身不执行或阻止操作，不保存策略决策，也不查询运行时证据来核实实际发生了什么。调用方需要执行返回结果。输入描述的是拟执行操作，预检通过不证明后续操作与声明一致，也不证明传感器观测到了它。执行后的证据关联仍通过独立查询完成。

## 后续方向

1. 已有查询适配器：CLI 工具说明、OpenAPI、模型工具描述和 stdio MCP 服务。
2. 已有上下文写入工具：`bind_scope`、`record_tool_call`。它们记录应用声明，不伪造系统证据。
3. 已有默认策略引擎预检：`evaluate_action`。是否执行其决策由调用方负责。
4. 可选分析方向：让观察者模型读取签名证据图，给出语义层面的风险解释。模型结论应与原始证据区分。
