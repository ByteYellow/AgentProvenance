# 安全证据命令

[English](../security-commands.md) | 中文

本页按用途列出执行级安全证据命令。支持 `--json` 的查询可供外部工具读取；具体字段、格式版本和完整性哈希以各命令的返回模型为准。配置或变更类命令不一定提供同样的 JSON 结构。

```sh
./agentprov observe summary --run <run_id>
./agentprov observe summary --run <run_id> --json
./agentprov observe coverage --run <run_id>
./agentprov observe coverage --run <run_id> --json
./agentprov observe scopes --run <run_id>
./agentprov observe scopes --run <run_id> --json
./agentprov observe event --run <run_id> --event <event_id>
./agentprov observe event --run <run_id> --event <event_id> --json
./agentprov observe process --run <run_id> --process <process_id>
./agentprov observe process --run <run_id> --process <process_id> --json
./agentprov observe flow --run <run_id>
./agentprov observe flow --run <run_id> --json
./agentprov evidence manifest --run <run_id>
./agentprov evidence manifest --run <run_id> --json
./agentprov evidence manifest --run <run_id> --materialize --json
./agentprov telemetry correlations --run <run_id>
./agentprov telemetry correlations --run <run_id> --json
./agentprov telemetry correlations --event <event_id> --json
./agentprov timeline --run <run_id>
./agentprov timeline --run <run_id> --view causality
./agentprov timeline --run <run_id> --limit 100 --cursor <next_cursor> --json
./agentprov timeline --run <run_id> --tool-call <tool_call_id> --json
./agentprov timeline --run <run_id> --process <process_id> --json
./agentprov timeline --run <run_id> --type risk_signal --json
./agentprov security risks --run <run_id>
./agentprov security risks --run <run_id> --json
./agentprov security deviations --run <run_id>
./agentprov security deviations --run <run_id> --json
./agentprov security responses --run <run_id>
./agentprov security responses --run <run_id> --json
./agentprov baseline learn --template <template_name> --run <run_id>
./agentprov baseline check --template <template_name> --run <run_id>
./agentprov signal context --run <run_id>
./agentprov signal batch-context --batch <batch_id>
./agentprov signal batch-context --shard <shard_id>
./agentprov signal batch-context --runs runs.jsonl
./agentprov signal run --run <run_id>
./agentprov signal run --run <run_id> --json
./agentprov signal run --run <run_id> \
  --external "PYTHONPATH=python python3 examples/evaluators/python_signal_eval.py" --json
./agentprov signal import --run <run_id> --file external-signals.json --json
./agentprov signal import-batch --file signal-reports.jsonl --engine python-sdk --json
./agentprov compliance frameworks
./agentprov compliance map --framework owasp-asi --run <run_id>
./agentprov compliance explain --framework owasp-asi --run <run_id> --item ASI05
./agentprov compliance gaps --framework owasp-asi --run <run_id>
./agentprov compliance report --framework nist-rfi-2026-00206 --run <run_id>
./agentprov ai tools --provider openai
./agentprov ai tools --provider anthropic
./agentprov ai call evaluate_action --input '{"event_type":"network_connect","dst_ip":"169.254.169.254"}'
./agentprov policy test examples/events/metadata-egress.jsonl
./agentprov policy decisions --run <run_id>
./agentprov forensics export <run_id>
./agentprov forensics export-batch --batch <batch_id>
./agentprov forensics export-batch --latest --include-eval-contexts --json
```

## 各命令的用途

| 命令 | 用途 |
|---|---|
| `observe summary` | 汇总一次执行的应用上下文、运行时遥测、风险、基线、响应和证据引用。 |
| `observe coverage` | 检查运行时遥测的关联质量，列出缺少会话、工具调用或进程身份的事件。 |
| `observe scopes` | 按工具调用查看进程、运行时事件、风险、策略决策、响应及详情入口。 |
| `observe event` | 解释单个运行时事件，展示关联的 Agent 上下文、风险、策略、响应证据及详情入口。 |
| `observe process` | 解释单个进程，展示工具调用上下文、运行时事件、风险、策略、响应证据及详情入口。 |
| `observe flow` | 查看从运行时事件到风险信号、策略决策和响应操作的简要因果链。 |
| `evidence manifest` | 生成执行级证据索引，关联观测摘要、时间线哈希、按内容寻址的对象引用、风险与响应报告哈希及建议查询。`--materialize` 将索引写为 `evidence_manifest` 溯源对象。 |
| `telemetry correlations` | 解释运行时事件为何归属某个 ToolCallScope，包括原始身份、匹配绑定、匹配字段、置信度、时间窗口及详情引用。 |
| `timeline` | 按时间展示应用上下文、运行时遥测、证据、风险、基线、响应及外部操作。 |
| `security risks` | 列出从策略和运行时证据生成的 `RiskSignal`。JSON 包含格式与哈希元数据，以及事件、进程、时间线和因果解释的引用。 |
| `security deviations` | 列出行为特征检查生成的 `BaselineDeviation`。JSON 包含格式与哈希元数据，以及时间线和摘要的引用。 |
| `security responses` | 列出已记录的 `ResponseAction`，例如审计、拒绝、终止、隔离、污染标记、导出或通知钩子。JSON 包含格式与哈希元数据，以及风险、进程和因果解释的引用。 |
| `baseline learn/check` | 学习进程、文件、网络、风险和运行时特征向量，生成偏差记录及基于基线的风险信号。 |
| `signal context/batch-context/run/import/import-batch` | 为单次执行、批次、分片或执行列表导出 `EvalContext` 或 JSONL 流；运行内置或外部评估器；校验并导入 `EvalSignal` 或 JSONL `EvalReport` 批次。可用于奖励设计、数据筛选、质量评分和外部基准评估。项目负责证据协议，奖励策略由消费者决定。 |
| `compliance frameworks/map/explain/gaps/report` | 将本次执行中的检测规则及命中结果映射到 OWASP Agentic Security、NIST AI Agent 安全评估配置，逐项展示自评证据和缺口。 |
| `ai tools/call` | 提供证据查询和策略预检的工具描述及本地调用入口，不充当模型网关。模型可以请求查询或规则判断，不能通过这些工具创建独立观测的运行时事件、签名或溯源对象。 |
| `policy test/decisions` | 评估事件、保存策略决策，并为风险与响应图提供数据。 |
| `forensics export` | 导出一次执行的可审计证据；JSON 使用 `agentprovenance.forensics_export/v1`，包含证据包路径、SHA-256、大小和状态。 |
| `forensics export-batch` | 为记录批次导出审计包；JSON 使用 `agentprovenance.batch_forensics_export/v1`，包含批次摘要、各执行的取证引用、可选 EvalContext、结果与分页哈希，以及经过 SHA-256 校验的包路径。 |
