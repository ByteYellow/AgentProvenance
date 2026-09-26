# 证据图命令

[English](../graph-commands.md) | 简体中文

`graph` 命令用于查询和校验证据对象，操作方式借鉴 Git。对象以内容哈希寻址，可以追溯执行过程、比较文件变化，也可以导出供其他分析器使用的记录。

下面列出命令入口。示例中的执行记录 ID、文件名和占位符需要替换成实际值。

```sh
./agentprov graph trace --run run-demo-bugfix
./agentprov graph refs --run run-demo-bugfix
./agentprov graph log --run run-demo-bugfix
./agentprov graph materialize --run run-demo-bugfix
./agentprov graph objects --run run-demo-bugfix
./agentprov graph objects --run run-demo-bugfix --limit 50 --json
./agentprov graph objects --run run-demo-bugfix --limit 50 --cursor <next_cursor> --json
./agentprov graph verify --run run-demo-bugfix
./agentprov graph verify --run run-demo-bugfix --json
./agentprov graph replay --run run-demo-bugfix
./agentprov graph replay --run run-demo-bugfix --json
./agentprov graph trajectories --run run-demo-bugfix --json
./agentprov graph lens --run run-demo-bugfix --lens default --json
./agentprov graph lens --run run-demo-bugfix --lens data-flow-taint --overlay risk --json
./agentprov graph lens --run run-demo-bugfix --lens data-flow-taint --detail expanded --json
./agentprov graph lens --run run-demo-bugfix --lens process --detail raw --focus runtime_event/<event_id> --json
./agentprov graph lens --run run-demo-bugfix --lens process --focus runtime_event/<event_id> --json
./agentprov graph diff --run run-demo-bugfix --file calculator.py
./agentprov graph diff --run run-demo-bugfix --file calculator.py --json
./agentprov graph blame --run run-demo-bugfix --file calculator.py
./agentprov graph blame --run run-demo-bugfix --file calculator.py --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py
./agentprov graph explain --run run-demo-bugfix --file calculator.py --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --cursor <next_cursor> --json
./agentprov graph explain --tool-call <tool_call_id>
./agentprov graph explain --risk <policy_decision_id> --json
```

## 命令用途

| 命令 | 用途 |
|---|---|
| `trace` | 查看执行上下文、运行时因果关系、溯源关系、风险，以及响应控制的证据 |
| `refs` | 输出稳定引用，标识执行范围、产物状态、产物和决策 |
| `log` | 按时间查看执行历史 |
| `materialize` | 将证据写成按内容寻址的溯源对象 |
| `materialize-llm` | 将已采集的模型请求和响应正文保存为对象，并为执行记录建立 `llm_call` 节点和 `llm_caused` 关系 |
| `objects` | 列出对象引用、哈希、父对象哈希、来源 ID、路径和大小；使用 `--limit` 和 `--cursor` 分页 |
| `verify` | 检查图的完整性、风险与响应证据链、污染标记与响应屏障、对象哈希、回放计划生成、排空水位、遥测批次哈希，以及主命令退出后仍在运行的 zero-SDK 子进程的生命周期证据 |
| `replay` | 输出执行记录的重建计划；不会重新执行原命令 |
| `trajectories --json` | 按执行范围输出行为证据、风险与偏差、成本、产物和运行时事件，供外部评估器或强化学习的奖励与惩罚流程使用 |
| `lens` | 按指定视图投影证据图；输出格式为 `agentprovenance.graph_lens/v1` |
| `diff` | 比较基准状态与执行范围内的文件状态 |
| `blame` | 追溯文件状态对应的执行范围、工具调用、进程、策略、命令和本地候选状态 |
| `explain` | 汇总目标的上下游关系及证据，说明执行过程与结果之间的关联 |

## 图视图与展开范围

`lens` 输出原始节点和关系、推断关系、聚焦对象、叠加标记、布局提示、原始事件数，以及当前未展示的节点和关系数。

使用 `--detail` 控制展开范围：

- `summary`：查看分组摘要。
- `expanded`：展开更多节点和关系。
- `raw`：查看原始记录。

`--focus` 指定要追溯的节点，`--overlay` 增加风险或来源标记。推断关系与原始关系分别输出，不能将推断结果当作传感器直接观测到的事实。

## 解释结果与分页

`explain` 会结合执行轨迹、运行时因果关系、文件差异与归属、遥测接收器信息、批次清单、进程观测、策略、证据对象引用、风险信号、基线偏差和响应证据。

`--json` 输出 `agentprovenance.explain/v1`，主要字段如下：

| 字段 | 含义 |
|---|---|
| `upstream`、`downstream` | 上游和下游关系 |
| `causality_path` | 按查询边界截取的因果路径 |
| `query` | 本次查询的参数和范围 |
| `evidence`、`objects` | 证据及其对象引用 |
| `risks` | 关联风险 |
| `telemetry_batches` | 遥测批次 |
| `process_observations` | 进程观测记录 |
| `replay_refs` | 回放引用 |

运行时事件还包含接收器及来源格式、规范化后的事件类型、身份标识、数据格式校验状态和关联状态。

使用 `--depth` 限制追溯深度，使用 `--limit` 限制单页结果数量，再通过 `--cursor` 获取后续结果。未在当前页展示的关系不代表不存在。
