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
恢复会话会验证执行前的日志前缀，不把先前活动重新归到本次执行。
子会话必须有真实身份依据，单独一条委派请求不会生成虚构的子 Agent ID。

也可以显式导入已有日志：

```sh
agentprov context import --run RUN_ID --harness deepseek --file session.v4.jsonl.zstd
agentprov context coverage --run RUN_ID
agentprov context list --run RUN_ID --kind configuration --revisions
```

DeepSeek 解析支持 v3 JSONL，以及含多个连续 Zstandard 帧的 v4 JSONL。
未知格式会明确报告，不会当成成功采集到空记录。

## 查看与比较

`context list` 返回不可变记录 ID 和正文引用，用 `--cursor` 翻页。
`--revisions` 包含同一记录的历史版本；默认按来源位置、再按导入时间选择最新版本。
来源时间与存储时间分别保留。

```sh
agentprov context compare --run RUN_ID --left ENTRY_A --right ENTRY_B
agentprov context compare --run RUN_A --left ENTRY_A --right-run RUN_B --right ENTRY_B
agentprov context content --run RUN_ID --ref sha256:HASH --offset 0 --limit 65536
```

比较支持两份同类配置、审批或任务记录，任务记录包括用户消息。
比较对象是来源记录的正文和状态：`same` 表示这些值相同，`different` 表示存在字段变化，
`unknown` 表示缺少正文或超出比较预算。字段缺失与显式 `null` 不同，
但两者都不能自动解释为有效权限。来源记录的权限请求也不代表批准。
模型选择、工作目录、MCP/skills/plugins 和沙箱配置仅在来源提供时可见；
不会用当前机器的配置替代历史证据。

比较最多返回 200 处差异，每个值预览最多 512 字节，递归展开至 32 层，
单份比较正文预算为 1 MiB。更长的已保存正文仍可通过内容读取接口访问。
文本存储每份正文最多 32 MiB，按 128 KiB 分段保存；默认每页读取 64 KiB，
最多 256 KiB。翻页应使用返回的 `next_offset`，而不是按字符数计算偏移。

## 覆盖与移植

覆盖情况按来源区分：`disabled`、`no_input`、`empty`、`ok`、`partial`、
`failed`、`ambiguous`、`legacy_not_recorded`。空值表示未知，不等于零。
报告区分解析失败、未识别记录、尚未写完的尾行、采集限制与重复导入。
一次启动最多处理 128 个已选中的来源，超限会标为部分覆盖。
图谱投影还有独立的处理预算，失败会保存为处理报告。

正文先脱敏，再计算哈希和保存。查询已保存的正文不会重新打开来源路径。
自包含证据包保存上下文、覆盖报告、配置历史和分段正文；导入新的数据目录后，
不依赖原 harness 或原始文件。签名覆盖导出的证据，采集覆盖与图完整性分别校验。
没有上下文采集报告的旧包保留 `legacy_not_recorded`。

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
这些是确定性测试负载，不代表仍待完成的传感器配合 DeepSeek 开发任务实测。
读取能力不会补造旧采集漏掉的正文。

Dashboard 和 daemon 共用只读 `/api/context/*` 与 `/v1/context/*` 接口。
具体字段见 [API 契约](../agent-context-api.yaml)，实现与实机验证状态见
[交付检查表](v0.9.0-delivery.md)。
