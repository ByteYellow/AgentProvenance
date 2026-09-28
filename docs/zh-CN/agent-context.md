# Agent 上下文记录

[English](../agent-context.md)

Agent 上下文保存的是 harness 实际记录的对话、工具输入与结果、任务变化、配置和审批记录。
这些属于来源证据，不代表模型隐藏的推理过程，也不能单凭工具提议认定操作已经执行。
系统侧运行时证据仍是独立的一层。

## 采集

```sh
agentprov launch -- dsh headless --json 'Inspect the project and run its tests.'
agentprov launch --context-dir /path/to/native/sessions -- codex
agentprov launch --context-session SESSION_ID -- codex resume SESSION_ID
```

启动入口识别 Claude Code、Codex、Kimi 和 DeepSeek Harness。Claude 的设置允许时，
还会注入本次执行专用的 hooks。包装命令可指定
`--context-harness claude|codex|deepseek|kimi|grok`，并提供 `--context-dir DIR`
或 `--context-file FILE`。没有原生会话 ID 的旧日志须同时指定文件和
`--context-session`，身份会标为用户显式指定。`--no-context` 关闭上下文采集和 hook 注入。

目录发现遵循 `CLAUDE_CONFIG_DIR`、`CODEX_HOME` 和 `DSH_HOME`。
如果包装脚本只在子进程内部设置目录，需要显式传入该目录。
采集在执行退出后进行，不按文件修改时间选择“最新会话”；多个候选不能唯一匹配时保留歧义。
恢复会话会验证执行前的日志前缀，将先前记录保存为 `prior_context`，
与新记录的 `current_execution` 范围区分。历史工具调用和模型调用不会投影为本次执行。
子会话必须有真实身份依据，单独一条委派请求不会生成虚构的子 Agent ID。

Codex 还会只读查询 `CODEX_HOME` 下 `state_*.sqlite` 中的 `threads.id` 与
`threads.rollout_path`，发现目录树之外的日志。目录数据库仅提供文件位置，身份与时间仍由
日志头验证。显式 `--context-dir` 只查询该目录中的数据库，不扫描其他默认目录。
身份冲突或目录数据库不可读时，不猜测唯一会话。目录查询最多读取 32 个数据库、
合计 4,096 行，每个数据库限时两秒。

也可以显式导入已有日志：

```sh
agentprov context import --run RUN_ID --harness deepseek --file session.v4.jsonl.zstd
agentprov context coverage --run RUN_ID
agentprov context list --run RUN_ID --kind configuration --revisions
```

DeepSeek 解析支持 v3 JSONL，以及含多个连续 Zstandard 帧的 v4 JSONL。
未知格式会明确报告，不会当成成功采集到空记录。
目录发现按每个会话目录中编号最高的 `session.vN` 选择格式代际，包括未知版本；
新文件失败时不偷偷回退到旧格式。同代际的重复文件保留歧义。
`--context-file` 仍可显式选择旧文件。启动期间已知会话更换了文件时，恢复边界无法验证，
会明确报告歧义，不把历史记录重算成本次工作。

显式导入会将保存后的覆盖报告以 JSON 输出到标准输出。只有 `ok` 和 `empty` 返回退出码 0；
部分成功、失败、未找到来源或关联不确定，会先保存诊断，再返回非零退出码。
已经保存的部分证据仍可查询；重复导入未改变的有效来源属于成功去重。
这是导入状态，不代表运行时证据完整。`--after-line N` 将前 N 条物理记录保留为历史上下文，
不丢弃它们，也不将它们视为本次执行或本次授权。

## 查看与比较

`context list` 返回不可变记录 ID 和正文引用，用 `--cursor` 翻页。
`--revisions` 包含同一记录的历史版本；默认按来源位置、再按导入时间选择最新版本。
来源时间与存储时间分别保留。

Claude 同一物理行内相邻的完整 JSON 对象可以分别读取，允许对象之间存在空白或 NUL 填充。
对象顺序保留；不会修复损坏内容，也不会跨行拼接。`sequence` 仍表示用于恢复的物理行，
可选的 `source_ordinal` 表示该行内的规范化记录次序，分页与离线回放沿用此顺序。
旧证据没有保存该字段时保持缺失或零。读取/解析计数按物理行，保存/去重计数按规范化条目，
未识别计数按来源对象；同一行中可同时存在已保留的有效前缀和解析失败的后缀。

Codex `event_msg` 中的用户、助手消息及来源提供的推理记录，即使没有对应的
`response_item` 也会保存。事件形式标记为 `source_message_event` 或
`source_reasoning_event`，完整响应项保留自己的记录。文字相似不代表身份相同，
因此不做启发式合并。消息数量统计已保存的来源记录，不推算唯一对话轮次；
重复导入相同证据仍会去重。原始记录与物理位置均可查看。

Codex 工具错误依据来源的显式标记、状态、数值退出码，以及支持的 MCP/命令执行结果封装。
不会根据输出中的“error”字样或任意嵌套 JSON 判定失败。`returned` 仅表示记录了返回结果，
不代表工具成功或获得授权；来源报告的错误也不等于策略拒绝。

DeepSeek 助手消息中的 `tool-call` 保存为模型提议；后续原生工具调用记录具有相同调用 ID 时，
补充同一次调用，而非新增一次调用。PTC 开始与完成记录提供子调用输入、结果，原始记录保留
parent/root ID。只有完成记录、没有开始记录时，标记 `completion_only` 和缺失的
`tool_start_time`，不生成用于运行时匹配的执行区间。显式来源错误保持为错误。
`surfaceOp: replace` 的结果标记 `context_replacement`，保留压缩引用，
但不覆盖原始结果，也不表示又执行了一次。

```sh
agentprov context compare --run RUN_ID --left ENTRY_A --right ENTRY_B
agentprov context compare --run RUN_A --left ENTRY_A --right-run RUN_B --right ENTRY_B
agentprov context content --run RUN_ID --ref sha256:HASH --offset 0 --limit 65536
agentprov context list --run RUN_ID --group conversation --node GRAPH_NODE_ID
agentprov context list --run RUN_ID --entry ENTRY_ID
agentprov context links --run RUN_ID --entry ENTRY_ID
```

图谱导航仅使用已记录关联。无关联时返回原因，不因命令或时间相似而猜测。
`--group` 支持 `conversation` 和 `configuration`，分别包括工具结果与审批记录。
列表每页 1-200 条；正文每页 4-262144 个 UTF-8 字节。

比较支持两份同类配置、审批或任务记录，任务记录包括用户消息。
比较对象是来源记录的正文和状态：`same` 表示这些值相同，`different` 表示存在字段变化，
`unknown` 表示缺少正文或超出比较预算。字段缺失与显式 `null` 不同，
但两者都不能自动解释为有效权限。来源记录的权限请求也不代表批准。
模型选择、工作目录、MCP/skills/plugins 和沙箱配置仅在来源提供时可见；
不会用当前机器的配置替代历史证据。

配置记录包括 Codex/DeepSeek 会话元数据与轮次/请求配置、DeepSeek 计划与权限变化，
以及选中来源实际提供的 Claude 初始化与权限模式记录。各事件分别保存为快照，
不自动合成为“实际生效策略”。会话日志不一定包含 MCP、skills 或 plugins 清单；
这不代表新增了 Desktop 适配器，也不会在导入历史记录时扫描当前机器配置。

覆盖报告通过 `configuration.*` 列出未记录的模型/服务商、应用版本、工作目录、
权限/审批策略、沙箱、目录/网络限制、MCP 服务、工具、技能和插件字段。
`task` 与 `approval_decision` 分别检查；有审批请求不代表已经取得审批决定。
显式 `null`、`false`、`{}`、`[]` 保留原样，不当作字段缺失，也不代表权限实际生效。
仅有工具名称不等于保存了完整工具定义。`ok` 表示本次范围没有发现处理错误，
不是所有字段或配置变化均已采集的保证。旧报告保留其原有、可能较粗的缺失检查。
新报告还会列出 `configuration.change_history_completeness`：即使所检查的配置字段
均存在，来源快照也不能证明期间的每一次变化均被记录。这是覆盖范围限制，不代表
解析失败，也不会丢弃已记录的快照。

工作目录和应用版本按来源中的位置保存。后续 Claude 元数据或 Codex 新一轮的目录变化，
不会覆盖早期记录，也不会反向填充当时未知的值。Claude 的目录/版本变化还会形成
可比较的来源元数据记录。

比较最多返回 200 处差异，每个值预览最多 512 字节，递归展开至 32 层，
单份比较正文预算为 1 MiB。更长的已保存正文仍可通过内容读取接口访问。
文本存储每份正文最多 32 MiB，按 128 KiB 分段保存；默认每页读取 64 KiB，
最多 256 KiB。翻页应使用返回的 `next_offset`，而不是按字符数计算偏移。

## 覆盖与移植

恢复会话中的每条记录带有 `execution_scope`。概览的记录总数包含历史上下文；
来源报告在 `prior_context` 中单独记录历史部分的计数、时间范围和缺失字段，
不混入本次处理范围。导入总数包含两段记录。本次范围没有新记录时仍为 `empty`，
不会因为保留了历史而变成有新活动。历史审批不授权新操作，旧配置也不能证明恢复后
仍然生效。旧记录没有保存范围时，继续显示范围未知。

覆盖情况按来源区分：`disabled`、`no_input`、`empty`、`ok`、`partial`、
`failed`、`ambiguous`、`legacy_not_recorded`。空值表示未知，不等于零。
报告区分解析失败、未识别记录、尚未写完的尾行、采集限制与重复导入。
一次启动最多处理 128 个已选中的会话来源。Hook 日志与选中的会话共同使用
256 MiB 解压后输入预算和 25,000 条归一化记录预算；被拒绝和重复的输入同样消耗预算。
单来源仍有 128 MiB 和 25,000 条记录上限。预算用尽标为部分覆盖，不冒充完整的空采集；
未能完整核验的恢复检查点不误报为源文件被修改。来源恰好在输入预算边界结束时，
由于不能继续读取以确认 EOF，也可能保守地报告预算用尽。
来源发现和图谱投影另有独立预算，并保存各自的诊断。

正文先脱敏，再计算哈希和保存。查询已保存的正文不会重新打开来源路径。
自包含证据包保存上下文、覆盖报告、配置历史和分段正文；导入新的数据目录后，
不依赖原 harness 或原始文件。签名覆盖导出的证据，采集覆盖与图完整性分别校验。

新导出还包含完整的 `telemetry_batch_records`，保留有序事件 ID 清单及其哈希，
使既有批次校验在导入后仍能执行。原有 `telemetry_batches` 摘要字段不变。
历史摘要缺少事件 ID 清单时，不补造完整批次；原包无法提供的批次成员校验仍然缺失。
没有上下文采集报告的旧包保留 `legacy_not_recorded`。

新增的对等消息正文超过 64 KiB 时复用分段存储。图中仍只有一个消息节点；
离线导入后，Dashboard 和意图分析仍可读取完整的已保存正文。
旧内嵌消息和六份历史签名 demo 包不改写。

## 运行时关联

启动结果 JSON 的 `runtime_correlation` 与证据包保存同一份关联报告。
“采集情况”引用该报告，不把 exec 数量和会话记录数量混算。计数表示本次处理已读到的
适用记录；`input_complete: false` 表示输入尚未完整读取，不能把当前计数视为总量。
`ok` 只表示本次关联完成，不表示采集无丢失。

`agentprov.command_time_process/v2` 要求：命令在已记录的工具调用时间段内唯一匹配，
运行时 PID 有 cgroup 或容器范围。匹配保留大小写与引号内空白，不接受任意子串。
原生 sensor 的 argv 为 16 个 32 字节槽位；`argv_truncated` 表示触及容量边界，
即“可能截断”，不是原始长度。只有源记录明确标记时才允许多词前缀匹配。
事件按来源、可用节点标识、cgroup、容器与 PID 限定；已观察的子进程 exec 可继承父进程关联。

exec/exit 会结束先前的 PID 归属；同一时刻无法确定先后、并发相同命令、父链冲突、
缺失范围或无效时间均保留缺口或歧义。后台事件超过工具时间段，不扩大窗口强行归属。
缺失生命周期事件或主机/启动身份仍会削弱推断，因此不能称为内核确认的 Agent 身份。
新边展示推断方法、证据引用与 `0.8` 置信等级，这不是校准概率；意图分析不再用更弱的
时间窗口补齐新关联器明确留下的缺口。

读取与替换边在同一事务内，失败保留旧结果。预算为 10,000 个工具调用、200,000 条适用
运行时事件、单份输入 64 KiB、命令与运行时 payload 各合计 64 MiB、200 万次候选比较。
超限明确失败，不发布半套关联。已存在的历史边不会被重新分类或自动重建；
新派生结果也不会改变原始证据包签名。

## 变更文件正文

`record` 保存工作目录比较所发现的变更文件在执行结束后的文本。
`launch` 需显式开启 `--file-diff`；默认仍关闭，因为复制和比较大型工作目录可能耗时较长。

```sh
agentprov launch --file-diff -- dsh headless --json 'Inspect the project and run its tests.'
```

一次最多选择 512 个文件，单份文本最多 32 MiB，累计正文读取与脱敏正文保存各有 128 MiB 预算。
文本限制在脱敏前后均检查；为检测读取期间文件增长，最多额外读取一个探测字节。
这些是正文采集预算，不限制现有工作目录快照与比较的 I/O。
只支持普通 UTF-8 文件，不跟随符号链接或特殊文件，也不接受越出工作目录的路径。

record/launch JSON 中的 `artifact_capture` 以及保存的同名证据对象报告
`disabled`、`empty`、`ok`、`partial`、`failed`。`candidates: null` 表示选择未启用
或未能完成；零则表示比较成功且没有变更文件。已知省略包括 `source_missing`、
`binary_omitted`、`collection_limit`；不可读文件和存储失败另有具体原因。
超过 512 个文件选择限制的条目仍在变更事件中标明省略，不声称保存了正文。

每份文件描述与分段正文共用数据库事务，保留采集时间、源文件长度、脱敏正文长度、哈希和引用。
查询及离线导入读取这些保存对象，不读取工作文件的新版本。
这是执行结束后的最终状态，不是每次中间写入的历史，也不是原子文件系统快照；
最终已不存在的文件不会被补造正文。

## Dashboard

执行图谱与所选证据位于默认收起的 **Agent 会话** 之前。会话分为 **对话与工具**、
**权限与配置**、**采集情况** 三个视图，执行概览可直接跳转。
原有图谱控制、风险信号、数据外发、时间线、进程树、网络访问与规则覆盖仍然保留。

通过 **查看已保存正文** 或 **原始来源记录**，可在独立的 **已保存正文** 区查看内容。
正文与原始记录切换、64 KiB 分页及放大阅读不依赖会话保持展开。
记录列表每页加载 30 条，行内正文最多预览 4 KiB，同时最多发起 4 次读取。
返回导航保留最近 200 个分页游标，**首页** 可重置列表，不累计保留所有旧页正文。

完整的结构化页面可在**可读视图**与**原始字节**之间切换。可读工具结果保留真实换行，
并保留错误等其他已记录字段；这是有界的显示投影，不产生新证据对象。哈希和偏移对应
保存的原始字节。原始来源记录、不完整页面和不支持的结构继续按字节显示，不执行 HTML。

**定位到图谱** 只沿已保存的 `context_tool_call` / `context_tool_result` 边定位，
图谱反查会话也只使用已保存的工具与运行时关联。这里不再根据相似命令或时间窗口猜测。
没有关联时说明原因，不跳到另一个相似会话。自动刷新保留展开记录与正文页；
切换语言时保留视图及阅读位置。浏览器会话存储只保存导航 ID 和偏移，不保存消息或工具正文。

可选择两份同类任务、配置或审批记录比较来源值。缺少审批继续显示 **未记录**，
不解释成拒绝或允许。校验徽章只报告图完整性，不声称采集完整或证据包签名已经验证。

图谱正文也通过 `/api/artifact` 分页读取，不依赖会话展开。
可切换 **图谱已记录内容** 与 **已保存对象原文**；同一来源有多个已保存版本时，
必须选择确切的对象哈希。正文哈希对应完整的脱敏展示文本，`ref` 则标识保存的对象封装。
内容不可用时 `total_bytes` 为 `null`，不冒充零字节正文；读取前校验对象哈希和封装中的 Run ID。

接口只读取保存对象及明确标识的数据库记录，不打开工具结果路径或工作目录文件来替代历史正文。
仅保存元数据的制品会明确提示正文缺失，仍可切换到原始记录查看元数据。
旧内嵌对象继续保留 8 MiB 读取预算；新分段正文支持最多 32 MiB，不增加证据包每个对象
4 MiB 的内嵌上限，内部存储分段也不会被统计成文件制品。
签名、跨目录离线导入后的 HTTP 分页测试已覆盖上述三个旧容量边界。
文件变化采集端已使用相同的分段存储。真实 record 子进程测试验证了超过 8 MiB 的采集、
脱敏、签名与离线正文；launch 测试覆盖显式开启和默认关闭。
这些是确定性测试负载，与[真实传感器配合的 DeepSeek 开发任务](../../demo/deepseek-context/README.zh-CN.md)
分开验收。后者已提供签名离线示例，包含最终文件正文、工具结果和部分运行时关联，
边界与复验步骤见示例指南。
读取能力不会补造旧采集漏掉的正文。

Dashboard 和 daemon 共用只读 `/api/context/*` 与 `/v1/context/*` 接口。

## 外部查询与运行时覆盖

外部程序与 Dashboard 使用同一套证据查询：

- `GET /v1/context/overview?run=RUN`：上下文数量与报告，以及
  `runtime_coverage.capture` 和 `runtime_coverage.correlation`。
- `GET /v1/context/entries?run=RUN&group=conversation&limit=50`：分页消息与工具输入、结果。
  `group=configuration` 查询授权、配置；`revisions=true` 包含保留的历史版本。
- `GET /v1/context/content?run=RUN&ref=HASH&offset=0&limit=65536`：只读已保存的正文。
  `has_more` 为真时，使用 `next_offset` 继续读取。
- `GET /v1/context/compare?run=RUN&left=ID&right=ID`：比较已记录快照。
- `GET /v1/context/links?run=RUN&entry=ID`：查询已有图谱关联，不猜测归属。

`launch` 在导出前保存 `runtime_capture` 对象，包含采集区间、内核采集启用状态、
本次探针快照及节点计数增量。旧的节点累计丢失不算到新运行；新发生的节点丢失也可能
属于其他工作负载，因此 `run_dropped_events` 保持 null，对本次运行的影响无法确定。
计数重置、过期探针快照、未处理积压和未确认正常退出都会明确报告。
区间端点快照不能证明采集器全程健康、TLS 全覆盖或零丢失。

关联摘要统计所选运行**已保存的全部运行时事件**，包含原生 eBPF 和 recorder 来源，
不把事件正文整体载入内存。它衡量作用域字段是否齐全，不证明 Agent 归因正确；
此 API 最多返回 25 个缺口示例。采集、关联和签名验证是相互独立的结果。

相同字段也通过 `agentprov context coverage --run RUN` 的 JSON 输出及 Dashboard“采集情况”
展示。离线导入读取已保存报告，不使用导入机器当前的传感器状态。
旧包及未保存此报告的独立录制、导入来源显示 `legacy_not_recorded`，但仍可查询已有事件。

这些只读接口不能执行工具，也不接受任意磁盘路径。默认保留本地监听；远程暴露 daemon
时需配置现有 bearer 认证及受控传输。只读 Dashboard 不是可直接公开的匿名证据分享服务。
具体字段、分页、错误和兼容语义见 [API 契约](../agent-context-api.yaml)。
