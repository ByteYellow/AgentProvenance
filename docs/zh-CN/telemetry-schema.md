# 遥测事件格式

[English](../telemetry-schema.md) · 简体中文

AgentProvenance 将应用上下文与运行时遥测关联。两类信息必须分开：eBPF、Falco、Tetragon、LoongCollector 等来源无需携带 Agent 层面的标识，也不能据此声称内核直接观测到了这些标识。

## 数据分层

| 层次 | 字段或内容 | 来源 |
|---|---|---|
| 应用上下文 | `run_id`、`trajectory_id`、`execution_scope_id`、`substrate_scope_id`、`tool_call_id`、`process_id`、`artifact_state_id` | AgentProvenance 控制面或应用侧工具路由 |
| 运行时身份 | `raw_event_id`、`container_id`、`cgroup_id`、`pid`、`tgid`、`ppid`、`timestamp` | 运行环境或遥测采集端 |
| 原始载荷 | 系统调用参数、路径、目标地址、argv 及事件专用字段 | 运行环境或遥测采集端 |
| 关联结果 | `correlation.method`、`correlation.confidence`、`correlation.binding_id` | AgentProvenance 关联器 |
| 启动与关联来源 | `binding_source`、`self_launched`、`correlation_class` | 关联器或记录器 |

## 原始载荷规则

传给 `agentprov telemetry ingest` 或 `telemetry.IngestFiltered` 的 `payload` 必须是 JSON 对象，接收时会检查这一点。

应用上下文和关联结果应放在结构化接收参数中，或由关联器生成，不应放入原始载荷。目前校验器递归拒绝以下字段：

- `run_id`
- `rollout_id`
- `attempt_id`
- `session_id`
- `tool_call_id`
- `process_id`
- `snapshot_id`
- `correlation`

旧版证据包和 SQLite 表仍使用 `rollout_id`、`attempt_id`、`session_id`、`snapshot_id`，分别对应接口和文档中的 `trajectory_id`、`execution_scope_id`、`substrate_scope_id`、`artifact_state_id`。新的概念名称同样应放在应用上下文中；当前原始载荷拒绝列表尚未包含这些别名，不能把它当作完整的字段隔离保证。

零 SDK 接入和 eBPF 事件可以通过运行时身份关联到执行作用域，无需自行提供 `tool_call_id`。`graph verify` 会解开已存事件中的 AgentProvenance 关联包装，再检查遥测原始正文，发现直接写入 SQLite 或其他接收器产生的格式问题。

## 采集时间与原子写入

显式提供的 `timestamp` 必须符合 RFC3339 或 RFC3339Nano。接收流程将这个采集时间字符串保存在 `events.created_at`，不会改成队列事件稍后进入 SQLite 的时间。未提供时使用当前时间。时间窗口关联比较解析后的时刻，不按不同格式字符串的字典顺序判断。

共享接收操作在同一事务中写入事件、运行时图边、证据行、绑定结束状态和污点更新。写入失败会回滚该事件并向调用方返回错误。JSONL 导入为每行使用保存点：失败行不留下部分证据，同批其他有效行仍可提交。策略评估在之后进行，不属于事件事务；已有证据不会被重写。

原生事件流的持久化和重启恢复见[缓冲队列说明](native-capture-spool.md)。单个事件原子写入不意味着旧版 Falco 队列工作进程具备崩溃恢复能力。

## 事件正文

当前校验器检查以下最低要求：

| 事件类型 | 正文要求 |
|---|---|
| `execve` | 非空字符串数组 `argv`，或 `command` |
| `process_exit` | 数值型 `exit_code` |
| `process_observed` | 数值型 `pid` |
| `file_open` / `file_write` / `secret_path` | 不含目录穿越的 `path` 或 `file`，允许主机绝对路径 |
| `network_connect` / `metadata_ip` / `private_cidr` | `dst`、`dst_ip` 或 `host` |
| `abnormal_process_tree` | 数值型 `pid`，或 `command` |
| `policy_verdict` | `decision` 或 `verdict` |
| `resource_pressure` | `resource` 或 `signal` |

下列事件携带相应字段，但当前未实施上述严格的必填正文检查：

| 事件类型 | 采集字段与含义 |
|---|---|
| `setuid` / `setgid` | `uid` / `gid`，表示身份变更；目标为 `0` 时属于提权情形 |
| `ptrace` | `request`、`target_pid`，表示进程检查或注入相关操作 |
| `file_rename` / `file_unlink` | `path`，表示重命名或删除 |
| `dns_query` | `host`，表示解析的域名 |
| `tls_write` / `tls_read` | 默认包含 `preview_sha256`、短 `preview` 和允许保留的 `http` 元数据；正文保留方式见下文 |

文件类事件拒绝空路径和包含 `..` 穿越段的路径。原始遥测允许主机绝对路径；工作区文件节点另有相对路径约束。

`secret_path` 也覆盖敏感路径读取：原生传感器会采集经过过滤的凭据或密钥路径打开事件，不限于写操作。

显式设置 `AGENTPROV_TLS_CAPTURE_BODY=1` 后，标准化事件的 `content` 字段保留已捕获的明文，供模型调用物化使用；这不保证获得完整的请求或响应。默认只保留捕获字节的哈希和短预览。提示词、响应和原始队列载荷可能包含敏感数据，应限制数据目录访问，并在分享前检查取证包。

## 示例

有效的原始运行时事件：

```sh
agentprov telemetry ingest \
  --type execve \
  --source tetragon_jsonl \
  --container-id container-1 \
  --cgroup-id cgroup-1 \
  --pid 424242 \
  --ppid 424200 \
  --payload '{"argv":["sh","-lc","pytest -q"]}'
```

无效的原始载荷：

```json
{
  "tool_call_id": "tool-123",
  "argv": ["pytest", "-q"]
}
```

已知工具调用时，应通过 `--tool-call tool-123` 传入结构化应用上下文；未知时省略，由关联器根据 cgroup、容器、PID 和时间证据判断归属。

## 关联语义

关联结果不是一个简单的布尔值。启动来源与运行时关联分别记录：

| 字段 | 含义 |
|---|---|
| `binding_source` | 绑定的建立方式，例如 `zero_sdk_record`、`ai_asserted`、`k8s_cgroup` 或接收器来源 |
| `self_launched` | 作用域是否由 AgentProvenance 直接启动 |
| `correlation_class` | `self_observed`、`context_asserted`、`kernel_correlated` 或 `uncorrelated` |
| `correlation_method` | 实际匹配方式，例如 `process_id`、`cgroup_time_window`、`container_time_window`、`pid_time_window`，结果还可能带有匹配条件后缀 |
| `correlation_confidence` | 该次匹配使用的置信值，不是经统计校准的正确率 |

方法的基础置信值及来源限制：

| 方法或来源 | 数值 | 说明 |
|---|---|---|
| 直接进程匹配或记录器自身观测 | `1.0` | 自身记录的一致性不等于独立内核佐证 |
| 真实 cgroup 与时间窗口 | `0.98` | 用于子树归属 |
| 容器与时间窗口 | `0.92` | 常见的运行环境匹配方式 |
| PID 与时间窗口 | `0.85` | 回退方式，受 PID 重用和短命进程遗漏影响 |
| `k8s_cgroup` 绑定来源 | 默认 `0.8` | 被动归属到 Pod，未由记录器直接启动 |
| `ai_asserted` 绑定来源 | 默认 `0.5` | 应用提供的归属声明 |

最终置信值还受绑定保存的正数置信值限制，取较低值。上表列出默认来源值，不是所有自定义绑定的强制上限。

基础记录模式没有需要匹配的内核遥测，因此可以使用合成作用域标识。监督采集模式由 `record` 创建真实 cgroup，`sensor stream` 在宿主内核观测系统调用，关联器据 `cgroup_id` 将事件归入执行记录。原始事件仍无需携带 Agent 标识。

## JSONL 接收器

可以接收采集端已经过滤的 JSONL：

```sh
agentprov telemetry ingest-jsonl --format tetragon --file tetragon-events.jsonl
agentprov telemetry ingest-jsonl --format falco --file falco-events.jsonl
agentprov telemetry ingest-jsonl --format loongcollector --file loong-events.jsonl
agentprov telemetry ingest-jsonl --format auto --file mixed-events.jsonl --json
agentprov telemetry ingest-falco --file falco-events.jsonl --json
falco -o json_output=true -o json_include_output_property=true | agentprov telemetry ingest-falco --file -
agentprov telemetry batches --run <run_id>
agentprov telemetry batches --run <run_id> --json
agentprov telemetry correlations --run <run_id> --json
agentprov telemetry correlations --event <event_id> --json
./scripts/demo_telemetry_jsonl.sh
```

可运行的输入样例位于 `examples/telemetry/`。

`telemetry ingest-jsonl --json` 同时返回批次和逐行接收证据。`receiver_summary` 汇总检测到的格式、标准化事件类型、身份键、已关联与未关联行、跳过行和失败行。`row_results` 记录行号、格式、事件类型、来源、原始事件标识、身份键、关联方法，以及跳过或失败原因。

默认还会对写入事件运行策略评估。访问云元数据地址、私有网段和敏感路径等事件，可生成 `policy_decisions`、`risk_signals`、`response_actions`、图边和时间线记录。返回结果包含 `policy_decisions` 和 `policy_decision_ids`。使用 `--no-policy` 可关闭策略评估，保留标准化、关联和存储。

`telemetry correlations --json` 解释标准化事件为何归属于某个工具调用作用域，包括原始运行时身份、已解析的应用上下文、匹配绑定、使用的 `pid`、`container_id`、`cgroup_id`、`time` 等键、置信值、时间窗口及进一步查询的引用。

接收器识别并转换以下事件：

| 来源 | 输入形式 | 标准化事件 |
|---|---|---|
| 原生 eBPF 传感器 `agentprov_ebpf` | 自动识别传感器 JSONL | `execve`、`network_connect` / `metadata_ip` / `private_cidr`、`file_write`、敏感读取 `secret_path` 或普通读取 `file_open`、`process_exit`、`setuid` / `setgid`、`ptrace`、`file_rename`、`file_unlink`、`tls_write` / `tls_read`、`dns_query`、`resource_pressure` |
| Tetragon | `process_exec` | `execve` |
| Tetragon | `process_exit` | `process_exit` |
| Falco | `execve`、`execveat`、`spawned_process` | `execve` |
| Falco | `open`、`openat`、`openat2`、`creat` | `file_open`、`file_write` 或 `secret_path` |
| Falco | `connect` | `network_connect`、`metadata_ip` 或 `private_cidr` |
| LoongCollector | `execve`、`process_exit`、`file_open`、`file_write`、`network_connect` | 对应的标准化事件类型 |

原生传感器位于 `internal/sensor` 和 `cmd/agentprov-sensor`，支持 Linux amd64、arm64。其 JSONL 经原生事件映射后，进入与其他来源共用的关联、策略和风险流程。

接收流程还会根据 TLS 事件派生 `llm_call`（请求与响应）和 `llm_intent_caused`（响应与后续操作）关系。当前依据同一执行记录中、已知时同一进程内的两分钟时间窗口选择最近事件；`llm_call` 只关联第一个响应片段。它们是推断关系，不能据此证明模型响应造成了某个系统调用，也不能保证并发请求正确配对或流式正文完整重组。

本地监督采集入口：

```sh
agentprov --data-dir <dir> sensor stream
```

该命令启动节点级原生传感器，将事件写入本地存储，默认进行策略与风险评估，并使用与 JSONL 接收器相同的 cgroup、容器、PID 和时间关联流程。仓库中的 `run-snake-supervised` 示例包使用此采集路径。

无法识别的行会跳过；格式损坏或未通过校验的行计为失败，并在接收结果中报告。

`telemetry ingest-falco` 是专用的 Falco 兼容入口，支持 JSON 文件或标准输入，映射进程、文件和网络事件，默认进行策略评估。`--no-policy` 可关闭该步骤。`graph explain --risk <policy_decision_id> --json` 将风险追溯到运行时事件，并列出记录的响应动作，供端到端审计使用。

## 批次清单与追溯

每次 JSONL 接收保存一份简明清单：

- `batch_id`：批次标识。
- `format`：来源格式。
- `path`：输入路径。
- `file_sha256`：输入文件哈希。
- 已读取、已写入、已跳过、失败的行数。
- `event_ids_json`：映射得到的事件标识。
- `event_ids_sha256`：事件标识列表的哈希。

清单不把整份原始遥测流复制到 SQLite，而是提供稳定的来源审计引用。`graph verify` 检查对应事件是否仍存在，以及事件标识哈希是否一致。

运行 `graph materialize --run <run_id>` 后，批次也会保存为 `telemetry_batch` 内容寻址对象，父对象哈希指向该批次产生的标准化事件对象。`graph explain --event <event_id> --json` 的 `telemetry_batches` 列出对应的接收批次、输入哈希、事件标识和对象引用。

同一解释结果的 `telemetry` 部分报告接收器、来源格式、标准化类型、关联身份键、格式校验状态和关联状态。可据此追踪一条采集端事件如何进入溯源图。
