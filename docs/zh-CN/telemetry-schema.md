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

重组后的 TLS 消息在 `http` 中保留传感器已解析的字段：

| 字段 | 含义 |
| --- | --- |
| `protocol`、`kind`、`headers_decoded` | HTTP 版本、请求／响应方向、已报告的头部解码状态 |
| `method`、`host`、`path`、`endpoint` | 请求方法、主机与端口、编码后的路径；endpoint 为主机与路径组合 |
| `status`、`content_type`、`is_stream` | 响应状态码、不含参数的媒体类型、SSE 标记 |
| `model`、`stream_id` | 已识别的模型 ID；HTTP/2 连接内部的流编号 |
| `connection_id` | OpenSSL 生命周期探针与进程身份可用时生成的 `tls-v1:` 不透明采集代次标识 |

端点元数据移除 URL 用户信息、查询参数和片段；Authorization、Cookie 等请求头不复制进 `http`。
正文、短预览和原始采集数据沿用各自的保留设置。Stream ID 仅在连接内部有效，配对时需要同时使用连接生命周期。
重组后的 `data` 已是正文，不再扫描其中的 HTTP 请求示例来推定端点。旧原始窗口继续解析请求／响应头；识别出的 HTTP/2 前言标为 `headers_decoded: false`，不明二进制内容保留为未分类。
这些可选字段无需修改数据库或 Bundle 格式。

OpenSSL 的 `SSL_read`、`SSL_read_ex` 入口／返回探针使用完整的内核 `pid_tgid` 和任务启动时间配对。
每个接口为每条线程保留最多 4 层嵌套调用，映射容量为 4,096 条线程。超过深度的返回会跳过并计入采集丢失诊断，外层调用仍按原顺序恢复。
返回字节数须在原始缓冲区容量内；无法读取 `SSL_read_ex` 输出指针也计入采集丢失。每条线程退出或成功 exec 时清理两个读取栈；工作线程 exec 导致 TID 改变时，同时清理旧身份。
每次调用的明文上限仍为 4 KiB。这里完成函数调用配对，HTTP 请求／响应关联由后续步骤处理。

OpenSSL 采集代次结合内核启动实例、进程启动时间、SSL 对象地址和内核生成的 epoch。
`SSL_new`、`SSL_clear`、`SSL_free` 及 BIO／FD 替换探针限定 HTTP／HPACK 状态的保留范围。
每个数据块携带代次，读取在入口保存代次并沿用到返回；边界事件缺失或旧读取晚返回时，旧数据也不会接入更新连接的缓冲。
内核代次映射最多保留 16,384 个对象，用户态对活动连接与已关闭代次的元数据同样设有容量上限。
被丢弃的未完成状态通过 `sensor_tls_reassembly`／`reassembly_gap` 资源压力事件报告。

清理／重新绑定入口和 `SSL_free` 按保守解析边界处理：前者可能执行失败，后者可能只减少引用计数。
因此连接标识表示观测到的采集代次；释放／退出时尚未完成的正文保留为截断记录，新请求不再隐式结束旧响应。
同一代次内 HTTP/2 多流继续共用各自方向的 HPACK 字典。任一必需生命周期探针挂载失败时，该目标的明文采集等待重试成功，能力报告列明缺失探针；其他运行时探针继续工作。
Go TLS 与缺少 epoch 的历史来源省略 `connection_id`，其对象生命周期覆盖范围保持原状。
接口语义见 [OpenSSL SSL_clear](https://docs.openssl.org/3.0/man3/SSL_clear/) 和 [SSL_free](https://docs.openssl.org/3.0/man3/SSL_free/)。

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
| 真实 cgroup 与时间窗口 | `0.98` | 执行作用域归属 |
| 容器与时间窗口 | `0.92` | 执行作用域归属 |
| PID 与时间窗口 | `0.85` | 结合已提供的作用域键匹配进程，受 PID 重用影响 |
| `k8s_cgroup` 绑定来源 | 默认 `0.8` | 被动归属到 Pod，未由记录器直接启动 |
| `ai_asserted` 绑定来源 | 默认 `0.5` | 应用提供的归属声明 |

最终置信值取匹配方法与绑定保存值中的较低值。上表列出默认来源值，不是所有自定义绑定的强制上限。

置信值接受 `[0,1]` 内的有限数。绑定未提供该字段时采用来源默认值；显式 `0` 在匹配、进程生命周期继承、查询和导出中始终保留。`telemetry bind --confidence 0` 与 `POST /v1/telemetry/bind` 遵循同一规则；负数、超范围值与 `null` 会被拒绝。以前用 `0` 请求默认值的客户端应改为省略字段。已有数据库记录和签名 Bundle 保持原值。

统一信号采用同一数值范围并保留显式 `0`，省略字段仍默认 `1`。内部 Go 调用通过 `ConfidenceSet: true` 表达显式零值。没有记录置信值的图边继续省略该字段，Dashboard 显示“未知”；未关联或有歧义的匹配还会保留对应状态和方法。

关联器依次检查应用进程 ID、内核进程生命周期 ID、作用域相容的 PID，最后回退到 cgroup／容器作用域。各层均使用事件的采集时间校验绑定窗口；提供了应用进程 ID 或生命周期 ID 时，跳过裸 PID 回退。cgroup／容器匹配保留共同的 Run、Session 和 Attempt，工具调用及应用进程身份通过更精确的证据关联。

时间重叠的绑定一起参与判断。有冲突时只保留共同的执行作用域；Run 也冲突时保持未归属。事件保存的关联信息和 `telemetry correlations` 报告按需包含 `scope_only`、`ambiguous`、`candidate_count`，以及最多 32 个按 ID 排序的 `candidate_binding_ids`。即使诊断列表被缩短，全部有效候选仍参与判断。报告状态区分 `scope_only`（仅作用域）、`ambiguous`（有歧义）、`resolved`（已关联）、`provided`（直接提供）和 `unresolved`（未关联）。

关联结果随事件保存，后续修改绑定不会在打开报告时替换当时的结果。已有事件和签名 Bundle 保留原来的关联信息。

### 运行时进程图身份

带 PID 的新摄取事件在最外层 payload 保存 `runtime_process_identity=agentprov.runtime_process/v2`，区分图节点身份、应用 `process_id` 与作用域绑定。

- 原生 `agentprov_ebpf` 记录的有效 `process_instance_id` 格式为 `boot UUID:PID:启动纳秒数`，对应 `runtime_process/instance/<identity>` 节点。同一生命周期的名称和数据流按此身份聚合，迁移 cgroup 后仍保持身份；PID 复用或内核重启后分开。
- 父进程与可选线程组生命周期须匹配对应 PID、处于同一次内核启动，且启动时间不晚于子进程。缺少有效生命周期的 PPID／TGID 保存为事件级观察。目前原生 Sensor 提供进程及父进程生命周期；未提供的线程组生命周期保留为空。
- 缺少有效原生生命周期的记录，包括当前外部接收器与进程采样记录，使用 `runtime_process/observation/<事件 ID>/<pid|ppid|tgid>`，节点标记 `identity_basis=event_observation`。仅 PID 相同的观察分别保存，不派生同进程数据流。
- 节点元数据区分 `kernel_process_instance`、`event_observation` 和 `legacy_pid`。进程详情及回放根据已保存的进程／事件边定位，保留分页和证据引用。
- 校验 v2 进程边时同时检查来源事件。导出／导入保留版本标记、节点和关系。没有版本标记的历史记录继续使用原有 PID 图，标记为 `legacy_pid`，读取时保留签名证据原样。

这项调整不改数据库表和 Bundle 容器格式。客户端应将运行时节点 ID 作为完整标识使用，不按固定路径位置截取 PID。

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

`telemetry correlations --json` 解释标准化事件为何归属于某个执行作用域或工具调用，包括原始运行时身份、已解析的应用上下文、匹配绑定、使用的 `pid`、`container_id`、`cgroup_id`、`time` 等键、置信值、时间窗口及进一步查询的引用。

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

接收流程保留 TLS 观察记录。`launch` 封存时，或执行 `graph materialize-llm --run <id>` 时，按 `agentprov.tls_connection_exchange/v1` 分析已保存消息：

- HTTP/2 按 `connection_id` 与 `stream_id` 配对唯一的请求和最终响应，支持并发流和乱序入库。
- HTTP/1.x 按采集时间检查同一采集代次内完整、严格交替的请求／响应序列。流水线重叠、相同时间、重复响应和序列缺口保留为歧义；消息截断，或已保存的 Run 采集报告记录丢失／积压时，停用串行推断。
- 两条路径都检查采集来源、进程和作用域相容性、头部解码状态及请求响应时间。连接或流身份缺失时保持未知，不用最近 PID 事件或旧配对边填补身份。临时响应与最终响应分开保留。

每份物化的 `llm_message` 携带 `correlation`：状态 `matched`／`unknown`／`ambiguous`、原因、规则、方法、置信值和配对事件 ID。正文保留仍由采集设置控制；仅保存元数据也能配对。图查询将配对边标为派生关系，并附来源事件引用。HTTP/2 身份匹配使用置信值 `1`，HTTP/1 串行推断使用 `0.8`；这表示关联依据等级，而非实测准确率。

重分析以事务替换 TLS 派生结果；迟到的重复记录引入歧义时，会撤回此前配对。原始事件、transcript 和 endpoint 证据继续保留。直接打开已有签名 Bundle 保持原图；明确对导入的 Run 重新分析时，在本地存储更新派生结果，原 Bundle 文件不变。新摄取不再生成旧的时间邻近关系 `llm_intent_caused`。

物化后的 `llm_caused` 命令关联使用更严格的 `agentprov.intent_command_scope/v2` 规则：

- 执行时间严格晚于决策，间隔不超过两分钟。TLS 匹配要求相同采集来源、已知的内核启动或节点身份，以及共同的 cgroup 或容器；已知作用域字段冲突或请求／响应配对有歧义时跳过。
- 按完整 `argv` 比较，保留大小写、路径和参数边界。普通命令逐参数匹配；复杂 Shell 语法要求完整的 `sh`／`bash`／`zsh` 的 `-c` 或 `-lc` 脚本参数。拼接命令文本、截断参数和 `process_observed` 采样仍作为证据保存，不作为执行锚点。
- Transcript 需要决策原始时间、`tool_use.id`、相容的 Agent／Session 身份，以及当前版本 `agent_syscall` 中位于调用时间区间内的直接 exec 锚点。关联不再按命令文本扫描整个 Run，也不把继承的子进程边当成直接执行锚点。
- 一个决策对应多个执行候选，或一个执行被同批多个决策匹配时，保持未关联，请求／响应正文继续保留。Endpoint 上传序号不作为模型执行锚点。

新连线使用带版本的 ID，图查询返回 `derived: true`、规则名称、启发式置信值 `0.8` 和证据引用；签名 Bundle 导出、导入后仍保留这些信息。历史导入连线维持原有记录。TLS 和 transcript 分析采用有界输入与事务替换，遇到输入上限或数据库错误时保留上次结果。

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
