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
| `process_exit` / `thread_exit` | 数值型 `exit_code`，或 1 到 64 之间的整数 `exit_signal` |
| `syscall_result` | `operation` 和数值型 `syscall_result` |
| `access_control` | 审计 schema 版本、`mechanism`（`apparmor` 或 `seccomp`）、`audit_id` 和 `decision` |
| `access_control_state` | `agentprovenance.access_control_state/v1`、观测区间、任务身份及独立的 `apparmor`／`seccomp` 状态 |
| `access_control_collection` | `agentprovenance.audit_collection/v1`、采集器标识、来源范围、状态、断点和计数 |
| `process_observed` | 数值型 `pid` |
| `file_open` / `file_write` / `secret_path` | 非空且不含 NUL 的 `path` 或 `file`，允许主机绝对路径 |
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

文件类事件拒绝空路径和 NUL。原始遥测按实际系统调用参数保留绝对路径和点路径段；工作区文件节点另有相对路径约束。

`secret_path` 也覆盖敏感路径读取：原生传感器会采集经过过滤的凭据或密钥路径打开事件，不限于写操作。

### 原生调用尝试与实际结果

新采集的 `openat`、amd64 `open` 和 IPv4 `connect` 区分两类记录：入口标为
`observation_stage: attempt`，返回另外保存为 `syscall_result`，携带内核实际返回值、目标和操作名称。
现有敏感读取过滤同时用于两类记录。若路径到返回时才可读取，则保存一条 `attempt_and_result`，
保留 `path_observation: syscall_exit_retry`，说明路径的实际观测阶段。

`operation_id` 结合内核启动实例、进程与线程生命周期、调用入口时间，标识同一次调用。
记录同时保留原始 syscall 编号、`sensor_arch` 和十进制字符串形式的单调时钟时间。
`sensor_arch` 表示 Sensor 的构建架构，不用于代替 audit ABI。
正在执行的调用最多保留 4,096 条线程状态，返回时核对任务生命周期与调用编号，返回、exec 或退出时清理。
容量不足和环形缓冲写入失败计入采集丢失诊断。

`syscall_outcome` 区分成功 `success`、失败 `failure`、异步连接待完成 `pending`、内核重启调用
`kernel_restart`。打开文件成功与读取文件内容分别判断，连接成功与数据发送分别判断。
结果记录不重复产生原尝试的策略决策。seccomp 可以在入口探针之前拒绝调用，此时保留缺失阶段；
返回码本身不标明拒绝机制。

新原生事件的 `pid` 和 `tgid` 表示主机线程组；`tid`、`thread_instance_id`、`thread_start_ns`
保存实际执行线程。单条线程退出记为 `thread_exit`，保持进程关联；没有存活线程时才记为 `process_exit`。
退出记录保留 `raw_exit_status`，并分别使用 `exit_code` 或 `exit_signal`；信号终止不填正常退出码。
历史记录保留原字段与身份，新增信息使用现有事件载荷，无需迁移数据库或 Bundle。

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

OpenSSL 符号检查将实际读取的 ELF 符号／字符串节限制为每节 16 MiB、合计 32 MiB。
未使用的普通符号表或字符串表超过限制时，可从有界动态表解析已导出的 OpenSSL 函数，
校验其可执行文件偏移后挂载探针，不加载超限的大表。这适用于内嵌 OpenSSL 并导出其接口的 Node.js 等二进制。

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

## AppArmor 与 seccomp 审计采集

把已有 AppArmor 和 seccomp 日志接入 Run 的证据。根据输入选择读取方式，再查询决定与运行时关联：

| 任务 | 命令 | 输入与结果 |
| --- | --- | --- |
| 导入已有日志 | `telemetry ingest-audit` | 读取有限的 audit 文本或 journal JSON 文件，完成后退出 |
| 持续采集日志 | `telemetry follow-audit` | 跟踪仅追加的文件，重启后从断点续读 |
| 查询关联 | `telemetry audit-associations` | 查询已保存的决定、进程候选与实际结果 |

例如，读取每行一个对象的 `journalctl -o json` 文件：

```sh
agentprov telemetry ingest-audit --run RUN --file audit.jsonl --json
agentprov telemetry audit-associations --run RUN --limit 100 --json
```

用 `--mechanism apparmor` 或 `--mechanism seccomp` 选择一种来源，默认读取两种。
`--file -` 接受标准输入中的有限记录。命令只读取提供的日志，不安装 profile、不附加 seccomp
过滤器、不修改日志配置，也不接管 auditd。

CLI、HTTP、SDK 和 MCP 的 JSON 字段、状态、原因码及系统生成的错误统一使用英文。
路径、命令和日志正文按 Run 的留存及脱敏设置保存，保留原语言。

`ingest-audit` 一次性处理已有记录；`follow-audit` 持续跟随已有、仅追加的日志文件。
两者需要在 `launch` 之外单独启动，`launch` 暂不自动启动审计读取器。
原生 Sensor 的 procfs 快照记录已启用状态，审计读取器补充来源日志报告的实际决定。

Journal 记录通过 `_MACHINE_ID` 和 `_BOOT_ID` 提供来源身份。普通 audit 文本需要通过
`--host-id` 和 `--boot-id` 指定来源主机及启动实例，不能填写正在执行导入的另一台机器的身份。
命令会拒绝与 journal 不一致的显式身份。身份不完整的记录仍可保存，并在 `identity_incomplete`
中计数；跨次导入去重需要完整的主机与启动身份。

| 保存字段 | 含义 |
| --- | --- |
| `source` | `apparmor_audit` 或 `seccomp_audit` |
| `event_type` | `access_control`，与尝试、系统调用结果分开 |
| `audit_id`、`record_id` | 原审计时间／序号，以及稳定的来源记录标识 |
| `timestamp`、`timestamp_precision_ns` | 审计头中的时间及其小数精度 |
| `audit_pid`、`pid_semantics` | 日志记录的主机线程组身份，不推测线程生命周期 |
| AppArmor 字段 | 已记录的 profile／命名空间、label、class、operation、目标、决定和掩码 |
| seccomp 字段 | 原始架构、syscall 编号、action 码及数据部分、报告的信号；按记录中的 ABI 解析调用名称 |
| `raw_record` | 原始消息字节数、哈希、留存状态及可选的脱敏正文 |

原始消息哈希在脱敏前计算，字段会标明这一范围。新 Run 默认详细档；`--capture basic` 省略审计全文，
保留结构化决定、引用和哈希。已有 Run 沿用固定的上下文留存设置，包括原始记录省略选项；
修改档位不用于清理已保存内容。

去重标识结合主机、启动实例、审计时间／序号、记录类型和全部解析字段。传输前缀、字段顺序和空白
变化不会产生第二个事件。重复字段保留在身份计算中，有歧义的解析值保持未知。
每批最多 128 行或约 1 MiB，单行最多 64 KiB。事件、图边、窗口计数和批次凭据在同一事务提交；
数据库失败回滚当前批，已提交的前批保留，可通过再次导入去重恢复。
汇总限制行引用和错误数量，并报告截断。超大行会停止导入；无效记录返回部分完成结果，CLI 以非零状态退出。

`--run` 指定记录所属 Run，不分配 Agent 会话。审计 PID 先保留在载荷中，后续关联需要建立进程生命周期
和操作上下文。现有遥测查询、图校验、签名 Bundle 导出和导入均保留这些未关联记录。
读取外部机制的决定时，不再次执行 AgentProvenance 策略规则。

AppArmor 的 profile 模式需要独立状态证据。seccomp 的 `LOG`、`ERRNO` 和 `KILL_PROCESS` 分别保留；
系统调用返回和进程退出属于独立观测。缺失或无法识别的字段保持未知，普通 EPERM/EACCES 消息不作为
AppArmor/seccomp 决定导入。PID 字段语义依据内核的
[LSM 审计记录](https://github.com/torvalds/linux/blob/v6.8/security/lsm_audit.c)和
[seccomp 审计记录](https://github.com/torvalds/linux/blob/v6.8/kernel/audit.c)。

`action_data` 是**日志中** `action_code` 的低 16 位，不是观测到的 errno。
Linux 可能只记录动作类型：`ERRNO` 的日志为 `code=0x50000` 时，低位为零，进程仍可能收到 EPERM。
动作、独立来源记录的过滤器参数和实际 syscall 返回值应分别读取。
内核的 [seccomp 决策路径](https://github.com/torvalds/linux/blob/v6.8/kernel/seccomp.c)
将掩码后的动作传给审计日志。

同一操作可能同时产生 seccomp `LOG` 和 AppArmor `DENIED`，两条决定可引用同一候选操作 ID 及其已保存的失败返回，
操作尝试只计一次。在 syscall 入口前发生的 seccomp `ERRNO` 则可能只有进程生命周期证据，
没有原生入口或返回记录。过滤器已启用、没有可用审计时，仅保留实际状态证据。

### 持续文件采集

持续读取已有、仅追加的 audit 日志或转发后的 journal JSON 文件：

```sh
agentprov telemetry follow-audit --run RUN --file audit.jsonl --json
```

普通 audit 文本仍使用来源主机的 `--host-id` 和 `--boot-id`。两种命令共用
`--mechanism apparmor|seccomp|all` 和 Run 固定的留存设置。采集器支持 Linux、macOS，
需要日志读取权限，不修改主机日志或策略配置。此入口读取普通文件，不直接读取 journal 数据库、
FIFO 或标准输入流。

首次从文件开头读取，将断点保存在本地数据库。默认标识由 Run、绝对文件路径和机制组成，
使用相同设置重启即可续读。显式指定 `--reader-id` 可建立独立断点；已有标识的来源身份和留存设置
不可静默改变。`--once` 处理启动时已有的完整记录后退出；末尾缺少换行的记录等待下次补齐。

源文件作为持久输入队列，每批最多 128 条、1 MiB。事件、去重、批次凭据和读取断点在同一事务提交。
数据库阻塞时暂停读取，当前批失败则保留断点并报错退出；重启从原位置继续，来源身份不完整的记录
也不会因重启被重复读取。未读完的源文件需要保留到采集追平。

文件身份和有界指纹用于检测轮转、截断及常见的覆盖写入。发现变化时停止并报告原因，保留原断点，
不直接跳到新文件末尾。请保留旧文件用于恢复，再为新文件指定新的采集器标识。
该模式要求输入仅追加；指纹检查不扫描全部历史字节。

`--json` 使用 `agentprovenance.audit_reader/v1` 输出英文状态。持续模式每次更新输出一个 JSON 对象，
`--once` 只输出最终对象；证据原文保留原语言。`reader` 对象包含：

| 字段 | 含义 |
| --- | --- |
| `status`、`reason` | 最近观测的 `reading`、`waiting`、`stopped` 或 `failed` 状态，以及机器可读原因 |
| `observed_at`、`last_read_at` | 状态观测时间、最近一次批次提交时间 |
| `committed_offset`、`pending_bytes` | 已提交的来源字节偏移，以及最近检查时的未读字节数 |
| `read`、`ingested`、`duplicates`、`skipped`、`failed` | 断点累计计数；不支持的记录和格式错误分别统计 |
| `identity_incomplete` | 缺少跨文件去重所需来源身份的受支持记录数 |
| `coverage_scope`、`upstream_loss` | 固定为 `selected_source_file` 和 `unknown`；源文件无法提供上游审计抑制或丢失总量 |

启动、停止、错误、状态变化及定期观测保存为 `audit_reader` 来源的 `access_control_collection` 事件。
这类记录描述采集情况，与策略状态、审计决定和 syscall 结果分开。通过现有遥测接口查询：

```sh
agentprov telemetry list --run RUN --type access_control_collection --json
```

后台服务的 `/v1/telemetry/events?run=RUN&type=access_control_collection` 返回同一组保存的观测。
状态以观测时间为准，不充当当前进程存活检查。签名 Bundle 保留这些事件；本地读取断点不进入导出包，
导入也不会恢复采集器。此功能将本地数据库升级为 schema 20；升级前请备份数据目录，旧二进制无法打开新版数据库。

### 配置声明与实际状态

原生 Sensor 独立于审计导入读取任务状态。`sensor stream` 和 `agentprov-sensor` 默认开启两种读取，
可以分别关闭，互不影响：

```sh
agentprov sensor stream --apparmor-state=false --seccomp-state=true
```

内核事件触发异步、有界的 procfs 读取：队列最多 128 项，调度缓存最多 2,048 项；同一任务／作用域
仍在缓存期间，每两秒最多读取一次。空闲或已退出任务不会自动轮询补采。队列超限通过
`state_snapshot_queue_drop` 和 `dropped_delta` 报告。能力报告中的 `apparmor_collection_enabled`、
`seccomp_collection_enabled` 表示采集设置，实际内核策略由状态记录提供。

来源 `procfs_access_control` 输出 `access_control_state`，schema 为
`agentprovenance.access_control_state/v1`，`evidence_kind` 为 `state_snapshot`。
载荷保存读取开始和结束时间、来源主机／启动实例、TGID（`pid`）、TID、procfs 启动时钟 tick 和
PID 命名空间。AppArmor 只读专属的 `attr/apparmor/current`，保存标签及其中报告的模式。
seccomp 读取任务 `status`：模式 0／1／2 对应 `disabled`／`strict`／`filter`，另保存可用的
`filter_count`、`no_new_privs`。观测到零值、字段缺失、无权限和主动关闭分别表示。
这些字段在观测区间内依次读取，并非原子快照。字段语义见
[AppArmor 内核文档](https://docs.kernel.org/admin-guide/LSM/apparmor.html)及
[procfs status 说明](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)。

读取期间固定同一个 procfs 任务目录，并在前后核对身份。该身份独立于原生 `process_instance_id`，
延迟采样不会借用触发事件的进程或 Tool Call。只有独立解析的 cgroup v2 inode 稳定且与触发记录一致时，
才用于作用域归属，来源类型仍为 `self_observed`。归属失败时保留状态与原因；常规事件流按留存设置
处理未关联记录，需要保存它们时应显式启用对应选项。

K8s informer 将配置另存为 `k8s_api` 来源的 `access_control_config`，schema 为
`agentprovenance.access_control_config/v1`，类型为 `configuration_declaration`。
结构化容器字段优先于 Pod 字段；旧注解独立保留原值和字段路径。结构化字段未声明时记录
`not_declared`，不推测默认模式。每次观测保留 Pod／容器身份、资源版本及时间。
配置变化追加记录，历史 `pod_metadata` 和已结束的作用域保持不变；当前配置不会赋给补录的上一次执行。
同一 informer 运行期间，只有状态导致的资源版本变化不重复写入；重启后按相同资源版本和内容去重。

现有事件查询、签名 Bundle 导出和导入在两个采集档位中均保留这些记录。审计关联接口继续返回
单次机制决定；配置和状态通过独立事件读取。这些只读观测不安装 profile、不修改过滤器，也不再次触发策略动作。

### 查询运行时关联

```sh
agentprov telemetry audit-associations --run RUN --limit 100 --json
agentprov --daemon-url http://127.0.0.1:8574 telemetry audit-associations --run RUN --json
```

同一查询还通过后台服务 `GET /v1/telemetry/audit-associations` 和 Dashboard
`GET /api/audit/associations` 提供。参数为 `run`、可选 `event`、`limit`（1-500，默认 100）和
`cursor`。未知或重复参数、暂不支持的 Session 筛选返回 HTTP 400；读取失败返回 503；
没有匹配的已保存记录时返回空 `items`。后台服务沿用 Bearer Token 认证。
[OpenAPI 契约](audit-associations-api.yaml) 列出候选、引用、实际返回值和错误响应。

Python 使用 `Client.audit_associations`，AI/MCP 使用只读工具 `get_audit_associations`。
接口字段、状态和生成的错误信息统一英文，不随语言设置改变；证据原文保持原样。
审计导入仍由受信任的采集端或 CLI 执行。

用 `--event EVENT` 查看单条已保存审计，或用 `--cursor` 读取下一页。
在线查询标明分析规则 `agentprov.audit_lifecycle_operation/v2`，保留原审计 PID、Agent 会话和图边。
迟到记录到达后，再次查询会在同一数据库快照上重新计算候选。
签名 Bundle 导出、导入保留分析输入，可在离线数据库上使用同一规则复核。

新导出的网页回放会冻结候选结果，`AgentProvReplay.query` 通过相同 Dashboard 路径支持分页。
部分导出只包含所选审计记录；如果支持证据或竞争候选被排除，则以 `replay_evidence_excluded`
标记并省略该关联，避免把剩余候选升级为唯一匹配。被排除的工具上下文同样省略。
报告 schema 仍为 `agentprovenance.audit_associations/v1`，分析规则单独版本化。
已经冻结的 v1 网页回放保留原规则和结果，不重新计算或改标为 v2。回放读取器支持冻结的
v1 和 v2 分页；旧索引未标记 `rule` 时按 v1 读取。分页与索引规则必须一致，游标也须使用同一规则。
不含这项数据的旧网页回放会明确提示未收录。

`analysis_scope=query_page` 描述当前在线查询的有界分析，`export_pages` 描述回放查询读取的
冻结分页。回放中的运行时检查数和诊断属于这些分页，单条查询也沿用该范围。
报告的 `complete` 表示分析完成，采集完整性单独报告。在线分页每页读取新快照；导出先冻结完整来源。

进程关联需要来源主机、启动实例、日志 PID 一致，并有同一内核进程生命周期的观测覆盖审计区间。
原生 Sensor 从 `/proc/1/root/etc/machine-id` 读取机器身份；节点部署需按既有配置使用宿主 PID
可见性。读取不到时保留缺失。来源内核的 `CLOCK_REALTIME_COARSE` 分辨率保存在
`realtime_coarse_resolution_ns`。

[内核的 syscall 审计上下文](https://github.com/torvalds/linux/blob/v6.8/kernel/auditsc.c)使用粗粒度实时时钟。
审计头的小数位数只描述打印精度。关联窗口加上已保存的来源时钟分辨率，并通过 `time_window`
展示实际采用的区间。缺少时钟信息、生命周期证据冲突或墙上时钟与单调时钟偏差异常时保留未关联。
导入机器不提供替代身份或时钟参数。

v2 在找到唯一进程生命周期后，先检查 seccomp 动作兼容性，再搜索常规 syscall 采集器的入口／返回记录：

| 记录的 seccomp 动作 | 操作关联 |
| --- | --- |
| `ERRNO`、`KILL_PROCESS`、`KILL_THREAD`、`TRAP` | `unassociated`，原因 `seccomp_original_syscall_not_executed`；原调用在执行前被阻止 |
| `TRACE`、`USER_NOTIF` | `unassociated`，原因 `seccomp_mediation_evidence_unavailable`；介入处理可能替换或跳过调用，需要带共同调用标识的证据 |
| `LOG`、`ALLOW` | 仅在已记录 action code 一致时进入候选筛选；缺失／冲突分别使用 `seccomp_action_unknown`／`seccomp_action_conflict` |
| 未知动作 | `unassociated`，原因 `seccomp_action_unknown` |

动作兼容性检查独立保留进程关联和同进程退出引用，不为被阻止或介入处理的决定附加操作候选或邻近调用的返回值。
AppArmor 继续按其已记录字段筛选候选。

可继续关联的操作再核对线程／操作身份和已记录字段：AppArmor `open` 使用完整绝对路径精确匹配，seccomp
使用实际 ABI 和 syscall 编号。唯一的已保存候选标为 `inferred`，依据为 `lifetime_syscall_time_candidate`，
原因为 `shared_call_identity_unavailable`：时间窗口和已记录字段共同确定候选，审计记录与运行时调用缺少共同调用标识。
多个候选标为 `ambiguous`，
不按最近时间选择。其他 AppArmor 操作仍可保留进程级关联。进程退出与 syscall 返回分别列出；
Agent／Tool Call 上下文引用运行时记录原有的关联方式和置信值，不直接分配给审计事件。

每个操作分别保留尝试、结果的状态、记录数和引用。界面中的尝试和返回值来自候选操作已保存的运行时证据，
机制决定来自独立的审计记录。两种机制的决定可引用同一候选操作标识。
缺少入口或返回时显示 `not_observed`；在入口之前被 seccomp 拒绝的调用不通过信号或 errno 补造。
候选引用有上限，并标明截断。每页最多检查 50,000 条原生记录及 32 MiB 载荷；超限返回 `incomplete`，
该页不建立关联。高流量 Run 可缩小分页或指定单条审计查询。关联结果描述已保存证据，采集覆盖和策略状态分别提供。

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

原生生命周期绑定包含已记录的 `host_id`。父进程继承和退出使用同一主机及规范化的 boot／PID／启动时间身份；只有数字 PID 的退出记录不关闭原生生命周期绑定。旧采集缺少主机身份时继续使用 boot 身份，与带主机的绑定分开。

Hook 到运行时的分析规则为 `agentprov.command_time_process/v3`。命令和时间匹配后，后续事件还须保持已采集的进程生命周期。原生子进程继承核对父进程的确切生命周期、主机、启动实例和出生先后。生命周期缺失或冲突时，不用复用的 PID 补齐。没有原生生命周期的来源继续使用受作用域和时间限制的启发式关联。

### 运行时进程图身份

带 PID 的新摄取事件在最外层 payload 保存 `runtime_process_identity=agentprov.runtime_process/v3`，区分图节点身份、应用 `process_id` 与作用域绑定。

- 原生 `agentprov_ebpf` 记录的有效 `process_instance_id` 格式为 `boot UUID:PID:启动纳秒数`。已记录 `host_id` 时，节点 ID 包含主机哈希，节点数据保留原主机标识；缺少主机时使用 `runtime_process/instance/<identity>`。同一生命周期的名称和数据流按此身份聚合，迁移 cgroup 后仍保持身份；不同主机、PID 复用或内核重启后分开。
- 父进程与可选线程组生命周期须匹配对应 PID、处于同一次内核启动，且启动时间不晚于子进程。缺少有效生命周期的 PPID／TGID 保存为事件级观察。目前原生 Sensor 提供进程及父进程生命周期；未提供的线程组生命周期保留为空。
- 缺少有效原生生命周期的记录，包括当前外部接收器与进程采样记录，使用 `runtime_process/observation/<事件 ID>/<pid|ppid|tgid>`，节点标记 `identity_basis=event_observation`。仅 PID 相同的观察分别保存，不派生同进程数据流。
- 节点元数据区分 `kernel_process_instance`、`event_observation` 和 `legacy_pid`。进程详情及回放根据已保存的进程／事件边定位，保留分页和证据引用。
- 校验版本化的进程边时同时检查来源事件。导出／导入保留版本标记、节点和关系。v2 记录沿用原有 boot／PID／启动时间图；没有版本标记的历史记录继续使用原有 PID 图，标记为 `legacy_pid`，读取时保留签名证据原样。

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

接收流程保留 TLS 观察记录。`launch` 封存时，或执行 `graph materialize-llm --run <id>` 时，按 `agentprov.tls_connection_exchange/v2` 分析已保存消息：

- HTTP/2 按 `connection_id` 与 `stream_id` 配对唯一的请求和最终响应，支持并发流和乱序入库。
- HTTP/1.x 按采集时间检查同一采集代次内完整、严格交替的请求／响应序列。流水线重叠、相同时间、重复响应和序列缺口保留为歧义；消息截断，或已保存的 Run 采集报告记录丢失／积压时，停用串行推断。
- 两条路径都检查采集来源、进程和作用域相容性、头部解码状态及请求响应时间。连接或流身份缺失时保持未知，不用最近 PID 事件或旧配对边填补身份。临时响应与最终响应分开保留。
- 采集来源由最强的已记录主机身份与启动实例共同确定。明确的主机或启动身份冲突时不配对；相同 boot 不覆盖不同主机，包装层之间身份不一致时保持未知。

每份物化的 `llm_message` 携带 `correlation`：状态 `matched`／`unknown`／`ambiguous`、原因、规则、方法、置信值和配对事件 ID。正文保留仍由采集设置控制；仅保存元数据也能配对。图查询将配对边标为派生关系，并附来源事件引用。HTTP/2 身份匹配使用置信值 `1`，HTTP/1 串行推断使用 `0.8`；这表示关联依据等级，而非实测准确率。

重分析以事务替换 TLS 派生结果；迟到的重复记录引入歧义时，会撤回此前配对。原始事件、transcript 和 endpoint 证据继续保留。直接打开已有签名 Bundle 保持原图；明确对导入的 Run 重新分析时，在本地存储更新派生结果，原 Bundle 文件不变。新摄取不再生成旧的时间邻近关系 `llm_intent_caused`。

物化后的 `llm_caused` 命令关联使用更严格的 `agentprov.intent_command_scope/v3` 规则：

- 执行时间严格晚于决策，间隔不超过两分钟。TLS 匹配要求相同采集来源、已知的内核启动或节点身份，并保留已记录的主机身份，以及共同的 cgroup 或容器；已知作用域字段冲突或请求／响应配对有歧义时跳过。
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
