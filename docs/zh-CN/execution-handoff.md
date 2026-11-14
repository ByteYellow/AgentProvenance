# 跨沙箱执行交接协议

[English](../execution-handoff.md)

本协议将来源 Agent 的 Tool Call 与另一个可信 producer 上的独立命令关联。
执行端保留自己的 Run，通过显式引用实现调查跳转和证据交付。

当前实现提供持久接收账本、有界命令执行器、重启恢复、停止请求和鉴权 HTTP API，
代码位于 `internal/handoff` 和 `internal/daemon`。拉取 API 和
`forensics collect-execution` 已支持签名证据包及持久接收回执；
能力清单和 Dashboard 接入正在实现。
现有同步接口 `POST /v1/record` 保持原有行为。

本地 record 引擎提供可信的进程内生命周期回调：准备阶段在绑定保存后、命令启动前
调用；启动阶段携带实际 PID 和已保存的启动事件引用。执行器持有独立的取消上下文，
客户端 HTTP 断线不取消远端任务。结束事件和相关状态行在同一事务提交，证据写入
失败会返回错误。启动后检查点保存失败时，终止并回收已启动的命令。

## 启用执行器

接口默认关闭。先在运维配置文件中指定一个可信调用端和一个执行目标。
配置文件只保存身份映射，不保存凭据：

```json
{
  "target": {"producer_id": "lab", "instance_id": "vm-one", "generation": "deployment-one"},
  "caller": {"principal_id": "tool-router", "producer_id": "developer-mac", "namespace": "local-user"},
  "concurrency": 2
}
```

```sh
agentprov --data-dir ./executor-data daemon serve --execution-config ./execution.json
```

验收使用独立数据目录。Daemon 保持回环监听，通过已有 SSH 连接转发端口。
调用端使用 Daemon 的 bearer 凭据，并负责在配置的命名空间内提供原生 Tool Call 引用。
该功能拒绝与 `--insecure-open` 同时使用；Shell、工作目录和环境变量沿用 record 策略。

| 接口 | 用途 |
| --- | --- |
| `POST /v1/executions` | 持久接收命令；新尝试返回 202，重发返回已有尝试及 200 |
| `GET /v1/executions/{id}` | 查询尝试、检查点、本地作用域、输出引用和停止请求 |
| `GET /v1/executions?run=...&harness=...&session=...&tool_call=...` | 分页查询来源调用的执行尝试 |
| `POST /v1/executions/{id}/stop` | 提交 `{"operation_id":"unique-stop-operation"}`；202 表示请求已保存 |
| `POST /v1/executions/{id}/deliveries` | 提交 `{"operation_id":"stable-delivery-operation"}`；新包返回 201，重发返回 200 |
| `GET /v1/execution-deliveries/{id}` | 读取签名清单及已保存的接收回执 |
| `GET /v1/execution-deliveries/{id}/bundle` | 下载签名对应的原始字节；需要鉴权，禁止缓存，以附件返回 |
| `POST /v1/execution-deliveries/{id}/receipt` | 提交接收方的 DSSE 回执；持久保存后返回 200 |

字段和错误码见 [OpenAPI 定义](../execution-handoff-api.yaml)。执行 JSON 写请求最多 1 MiB，回执上限为 64 KiB，
拒绝未知字段和尾随 JSON；保留现有 bearer、Origin 和 Fetch Metadata 校验。

执行器独占数据目录，默认同时运行两个命令，其余任务保存在 SQLite。
重启时读取已保存的结束事件。Linux 命令仍在运行时，核对启动前保存的 boot、
cgroup 文件系统和内核 cgroup ID，再重新打开原作用域。恢复的任务占用执行名额，
沿用原超时期限及已保存的停止请求，命令只执行一次。启动状态不明，或旧记录缺少
恢复身份时，保留 `unknown` 和停止请求，供运维核对。

检查点的 `recovery_report` 保存作用域观察和停止结果。确认停止后为 `cancelled`，
确认超时停止后为 `failed`；自然退出且没有已保存的结束事件时，执行保持 `unknown`，
退出码留空。丢失的输出标为未知，采集保持 `incomplete`。作用域为空的观察与检查点
在同一事务中保存并关闭绑定，签名交付保留这些记录。恢复后持续使用已核验的 cgroup
句柄；即使同名路径被替换，也不会转向新作用域或历史 PID。

Linux 上具备可写 cgroup v2 子树时，取消、执行超时和启动后检查点失败都会通过
`cgroup.kill` 停止本次执行的 cgroup，包括使用 `setsid` 新建进程组的子进程。
新命令使用新建的作用域，重启恢复核对已保存的身份；执行器持续持有 cgroup 目录句柄。根进程回收后，
最多等待两秒，读取 `cgroup.events` 确认子树是否为空；其他并发执行保持运行。

结果中的 `stop_report` 保存停止方式、信号结果、观察时间、`scope_empty` 和错误。
作用域仍有进程时，尝试状态保留为 `unknown`。cgroup 停止失败时，回退为终止根进程，
同时保留作用域错误。没有内核 cgroup 的环境沿用进程组或根进程停止方式：命令状态
描述根进程结果，`scope_empty` 为 null，采集状态为 `incomplete`。停止报告与结束事件
一同保存，重启恢复和签名交付均保留。主动迁移到作用域外的进程交由运维另行核对。

每路输出最多保留 1 MiB，再脱敏并分块保存。超出部分记录截断原因和已观察字节数。
`basic` 默认省略工具结果正文，也可单独启用；重启时未保存的输出标为未知。
未接入采集控制器时，命令成功后采集保持 `draining`。交付状态由签名包与持久回执
独立推进。

### 原生采集边界

Linux 上可在执行配置中增加 `"capture": {"mode": "native"}`，由 Daemon 启动一个
共享 Sensor 和持久 spool。运行账号需要 BPF 权限及可写的 cgroup v2 子树。省略
`capture` 时，保留外部采集器或仅命令记录的部署方式，macOS 也可使用。

Daemon 等待必需探针就绪后，再启动执行器和 HTTP 监听。准备失败会释放采集器锁；
Sensor 或 spool 意外退出时，Daemon 停止服务。正常关闭先收尾执行任务，再关闭采集。
同一数据目录拒绝重复启动采集器。`sensor status --json` 可查询对应能力快照与队列计数。

可选配置包括：`ring_buffer_mib`（默认 64，范围 1–256 的二次幂）、`tls_targets`
（最多 128 个绝对路径）、`auto_tls`、`apparmor_state`、`seccomp_state`（默认启用）、
`no_policy`（默认 false）、`startup_timeout_seconds`（默认 15，范围 1–120）及
`close_timeout_seconds`（默认 3，范围 1–30）。同时沿用 `AGENTPROV_SSL_LIB`、
`AGENTPROV_GO_TLS_BIN`、`AGENTPROV_LIBC_LIB` 环境配置。
采集复用现有有界 spool 和迟到绑定留存机制，排除 Daemon 自身 cgroup；数据目录中的
任务工作区仍参与采集。

进程内集成也可直接配置 `Executor.Capture`，按相同顺序管理启动和关闭。

命令启动前，控制器检查本次执行拥有的内核 cgroup 和必需探针的就绪状态，在内核
环形缓冲区插入标记，保存对应的解码边界、能力快照及固定 spool 范围。准备失败时
不启动命令。命令结束时，通过持续持有的目录句柄读取 `scope_observation`；正常
成功退出仍保留主动放到后台的子进程。

结束事件保存后，控制器在仍持有本次 cgroup 时取得第二个边界，默认最多用三秒
处理同一采集器代次、起止序号之间属于该 cgroup 的记录；区间内无法分类的记录也
纳入检查。作用域为空、对应记录处理结束、未观察到丢失或状态采样缺口且没有 TLS 缓存残留时，
状态为 `sealed`。本次记录仍待处理、存在丢失或状态采样缺口、采集实例变化或作用域状态未知时，
状态为 `incomplete`。完成回调返回后才释放 cgroup。

第 2 版 `capture_report` 分别保存本次 `scope_prefix`、持久化处理结果
`scope_progress` 和共享范围 `shared_prefix`。其他 cgroup 的积压继续保留原有
留存时间与处理状态，不阻塞本次作用域收尾。批次文件清理后仍保留作用域计数，
区间内已经处理过的丢失记录也参与检查。无法定位到具体作用域的内核、状态队列、
TLS 及写入前 spool 丢失继续作为采集器级信号报告。TLS 缓存只报告状态，不强制
清空连接；探针限制保留在能力快照中。历史第 1 版报告保持原有共享范围语义。

执行结果、采集收尾及证据回执分别保存。收尾中途重启时，保留命令结果及已有边界，将采集标为
未完成，不重新执行命令。

内核事件触发的 procfs 状态采样会单独保存 `sampling_trigger`。即使进程已退出，
采集计数仍能确定这次采样由哪个作用域触发；实际状态继续使用独立读取到的 procfs 身份。
进程身份不可用时，可按触发时间的无歧义绑定，将读取失败记录保存在对应 Run，关联方法为
`sampling_trigger_scope:cgroup_id+time`。该记录不填写实际进程、Tool Call、会话或
cgroup 成员身份。无绑定或存在歧义时，继续等待迟到绑定。

已保存的进程或安全状态不可用记录计入 `sampling_gaps`，它是 `ingested` 的子集。
处理区间可以达到 `settled`，采集仍以 `scope_state_sampling_gap` 标记为 `incomplete`，
避免已经完成的读取失败继续等待队列超时。计数经重放和 spool 清理后仍保留。
schema 25 新增该计数，旧事件和签名报告保持原样，历史报告沿用原有解释。

## 路由 Claude 原生 Bash 调用

`launch --remote-execution route.json -- claude ...` 将 Claude Code 原生
`session_id`、`tool_use_id` 接入执行交接协议。该模式要求 Claude Code 2.1.295
或更新版本、已启用 hooks，并使用本地前台会话。不传此参数时保持原有 launch 行为。
任务启动前先运行一次不调用模型、不保存会话的初始化检查，确认当前有效配置确实
执行了路由 hook。关闭 hooks 或初始化失败时停止启动，并保留本地诊断日志。

先按后文配置执行端签名交付。远端工作目录须位于执行器允许的工作区内；Bash
路由还需要运维人员显式使用 `--record-allow-shell` 启动该执行器。工作目录、
环境变量和执行超时继续沿用原有约束。

调用端配置放在 Agent 工作区之外：

```json
{
  "schema_version": "agentprovenance.claude_command_route/v1",
  "url": "http://127.0.0.1:18575",
  "token_file": "executor.token",
  "execution_config": "execution.json",
  "workdir": "/srv/agentprov/workspaces/analysis",
  "receiver_id": "investigator",
  "sign_key_file": "investigator.key",
  "public_key_file": "executor.pub",
  "timeout_seconds": 300,
  "file_diff": false
}
```

凭据及执行配置路径相对于本文件解析。`execution.json` 中的调用端、执行目标须
与执行器配置一致。传输使用 HTTPS，或经 SSH 隧道连接的回环 IP HTTP 地址。
`shell` 默认为 `/bin/bash`；`timeout_seconds` 限定包装命令的接收、等待和交付总时长，
执行端自己的超时仍独立生效。

设置 `file_diff: true` 可复用快照和制品采集保存变更文件正文。该选项会在每条
命令前复制工作目录，适合独立任务目录。关闭时省略逐命令快照，已启用的内核
文件事件采集继续工作。

```sh
agentprov --data-dir ./caller-evidence launch \
  --remote-execution /path/to/operator/route.json -- claude
```

每次 PreToolUse 先生成稳定请求，此时尚未提交执行。Hook 将 Bash 改写为本地
远端命令包装器，并在命令中保留原始内容，交由 Claude 原有权限流程检查。
Hook 不自动授权。获准后，包装器提交请求、等待执行、验证签名结果、保存回执，
再返回已留存的 stdout/stderr 和远端退出码。

临时配置使用 [Claude 的 hook 失败阻断机制](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails)。
准备失败会拒绝调用；关闭 hooks 的模式和脱离前台的启动模式会被预检拒绝。
路由属于可信接入，权限控制由 harness 和操作系统继续承担。

只有 Bash 在远端执行；Read、Write、Edit 保持本地。SessionStart 会向 Agent
说明目标实例和远端目录。每次 Bash 启动独立 shell，目录切换和环境变量不会
跨调用保留；显式后台 Bash 请求会被拒绝。跨调用共享文件使用远端工作目录。

请求和接收记录保存在 `<data-dir>/execution-routes/<run-id>/`。
再次运行同一已准备调用会恢复原尝试，修改命令则报冲突。经过鉴权接单后，包装器
取消时提交持久停止请求，覆盖本地证据保存和收取结果期间。若取消导致接收记录文件
尚未保存，可复用已准备请求恢复原尝试。交付失败后可通过
`forensics collect-execution` 接着收取。执行、采集和交付状态分别输出。

路由同时在调用端 Run 中保存内容寻址的 `execution_source_admission` 对象，
记录完整限定的原生调用、派发、执行尝试、显式重试前序、已认证主体及配置中的签名公钥指纹。
重复接收沿用原对象，身份或指纹冲突时明确报错。这份元数据不保存命令正文、凭据或本地配置路径，
会随签名 Bundle 导出。它记录接收事实；执行结果和交付确认继续使用各自的证据。
传输恢复仍使用原来的路由文件。

收到签名包后，同一事务会保存 `execution_delivery_evidence` 对象，保留原始签名清单、
接收回执和公开验签材料。调用端接收记录中的指纹限定所用公钥。原生路由和
`forensics collect-execution` 都会保存这条关系；重复收取已接收的包可以补上缺少的
关系记录，命令沿用原尝试。签名 Bundle 导出会保留这些对象。

工具输出从本地已验证的证据投影读取，沿用脱敏规则和每路 1 MiB 留存上限，
发生截断时会提示。此路径需要保存工具结果，可使用 detailed，或显式选择
`--capture basic --capture-tool-results=true`。预检不会自动改变用户的省略设置。

### 查询已保存的执行关联

在本地 Daemon 调用 `GET /v1/execution-links?run=<caller-run>&direction=outgoing`，
或在 Dashboard 调用 `GET /api/execution-links`，查看调用侧的执行关系。
使用 `run=<execution-run>&direction=incoming` 可从执行侧查询来源调用。
响应分别保留 producer、命名空间、harness、原生会话与调用、目标实例与代次、派发及尝试。
可选 `harness`、`session`、`tool_call` 筛选作用于每个已扫描页面；只要 `has_more`
为 true，就继续使用 `next_cursor`，包括筛选后为空的页面。`limit` 范围是 1-100。

读取时核对对象哈希、两端签名及调用端记录中的公钥指纹，按包版本返回每条接收记录的
最新交付，历史包继续保留。`manifest.state` 是执行端快照，`receipt.status=persisted`
记录接收端已保存证据；发送端是否收到 ACK 需查其对应记录。
只导入执行端 Bundle 时，`basis=unanchored_delivery` 和
`source_admission_not_included` 标明缺少调用侧记录。再导入独立签名的调用侧 Bundle
即可解析该引用。哈希、签名或身份冲突会返回错误。

字段及错误格式见[接口定义](../execution-handoff-api.yaml)。查询已保存关联无需连接
执行器，也不读取其原始工作目录。

### 离线分享执行关联

[离线回放导出](agent-context.md)在同一冻结快照中生成所选 Run 的分页执行关联索引。
静态阅读器在 `file://` 下支持相同的 `/api/execution-links` 查询及原生调用筛选，
无需连接执行器。旧回放缺少该索引时，会明确提示未包含执行关联。

- 同时选择两端：保留调用准入、交付及接收回执。
- 只选调用端：保留准入记录，标记 `execution_run_not_selected`，省略执行检查点、交付和回执。
- 只选执行端：保留交付，使用 `basis=unanchored_delivery` 和 `source_run_not_selected`。
  来源调用只保留引用，不复制正文。
- 排除来源调用：省略其正向关联和准入记录；已选执行保留 `source_call_excluded_by_selection` 边界。
- 排除部分执行记录：省略内嵌检查点，标记 `checkpoint_excluded_by_selection`，保留原检查点引用。

会话、类别和记录筛选在写入关联分片前生效；关联不会自动将其他 Run 加入导出。
ZIP 仍是未签名的阅读副本，原始签名 Bundle 单独保存。图谱、会话、搜索和 Compare
继续展示所选内容。

### 验证真实 Agent 任务

[`accept_execution_native.py`](../../scripts/accept_execution_native.py) 在调用端验证
Claude 原生路由。脚本沿用已配置的模型服务，会发起真实请求，并传入 0.25 美元的
会话预算参数。先在独立的执行端工作目录准备 `input.csv`：

```csv
team,amount
alpha,10
beta,20
alpha,30
```

执行端启用原生采集及签名交付，调用端路由设置 `file_diff: true`，然后运行：

```sh
python3 scripts/accept_execution_native.py run \
  --agentprov /path/to/agentprov --claude /path/to/claude \
  --route /path/to/operator/route.json --output /path/to/new/acceptance
```

脚本核对原生会话、调用 ID 和命令、独立 cgroup、采集区间收尾、原请求重发、签名
交付、内核打开文件写入事件及留存的 `totals.json` 正文；状态采样缺口照常保留。
停止执行端并移走或删除其任务目录后，把命令中的 `run` 换成 `verify`，去掉
`--claude` 参数，验证调用端已收到的证据。此检查保持调用端数据目录位置不变。
浏览器 `file://` 回放另行验收。

调用端可以运行在 macOS 或 Linux 容器中。容器需要模型服务、受保护的路由配置
和可写证据目录，无须 BPF 权限或挂载执行端工作区。跨主机通过 SSH 本地转发接入；
同节点容器可显式共享宿主网络以访问回环地址，同时保留独立账号、PID 和挂载环境，
并在运行清单中记录这一部署方式。

### 并发调用与回执响应丢失

[`accept_execution_native_matrix.py`](../../scripts/accept_execution_native_matrix.py)
用于两个原生会话的组合验收。执行端使用独立测试环境，启用原生采集、签名交付，
并发数至少为 2。先通过 `prepare` 创建两个不同的执行端工作目录：

```sh
python3 scripts/accept_execution_native_matrix.py prepare \
  --workdir /isolated/tasks/a --case a --fixture-url http://127.0.0.1:18581
python3 scripts/accept_execution_native_matrix.py prepare \
  --workdir /isolated/tasks/b --case b --fixture-url http://127.0.0.1:18581
```

分别配置两份调用端路由，指向这两个目录及同一个回环执行地址，并设置
`file_diff: true` 和 180 秒超时。调用端放在同一 Linux 节点，或共享该节点网络
的容器内，让两条命令都能访问测试同步点。执行端目录无需挂载到调用端。
调用端配置好模型服务后运行：

```sh
python3 scripts/accept_execution_native_matrix.py run \
  --agentprov /path/to/agentprov --claude /path/to/claude \
  --route-a /operator/route-a.json --route-b /operator/route-b.json \
  --fixture-port 18581 --output /path/to/new/matrix-acceptance
```

两个原生调用都执行 `python3 analyze.py`，到达同一同步点后才继续，确保实际存在
并发。测试专用的本地转发器在执行端保存回执后，丢弃一次响应；脚本随后使用原
准备请求恢复交付，核对签名包与回执身份保持一致。之后重发两个原请求，显式
重执行其中一个调用，再重复提交该重执行请求。初次执行各产生一次副作用，
重执行的一方总计两次；按来源查询时只返回本会话的尝试。

测试启动两个真实模型会话，每个传入 0.25 美元的预算参数。保留 `initial.json`、
`fixture.json`、`result.json` 和两份调用端数据。停止执行端并移走其工作目录后，
使用 `verify`，保留 `--agentprov`、`--route-a`、`--route-b` 和 `--output` 参数，
检查已保存的图谱、内核文件与网络事件及签名制品正文。调用端数据目录位置保持不变。
这项检查针对接收端存储恢复，浏览器回放另行验收。转发器仅用于故障注入，
不会随 daemon 安装。

## 身份与信任

来源引用包含 `producer_id`、`namespace`、`run_id`、`harness`、`session_id`
和 `tool_call_id`。执行目标包含 `producer_id`、`instance_id` 和 `generation`。
恢复、重建和克隆时，由可信的外部入口登记新的生命周期代次；guest 内复制的
boot ID 作为补充证据保存。

传输身份由配置映射到稳定的主体、来源 producer／命名空间，以及明确允许访问的
目标实例。目标列表为空时拒绝接收。经过认证的工具路由拥有自己的来源命名空间，
负责提供原生 Tool Call 引用；模型生成的命令参数不能选择可信身份。
凭据撤销在传输入口生效。轮换凭据时，授权保持一致才沿用同一主体；历史签名公钥
独立保留，用于验证已有证据。

首个部署采用预配置的单信任域，通过 SSH 通道访问本地执行器。
分别检查传输认证、来源授权和证据签名。已受信路由或高权限采集器被攻破时，
其记录真实性超出该 producer 的信任边界。

## 派发与重试

`schema_version` 为 `agentprovenance.execution_handoff/v1`。

| 字段 | 含义 |
| --- | --- |
| `dispatch_id` | 一次逻辑交接，限定在来源 producer 和命名空间内 |
| `operation_id` | 一次接收或显式重执行的幂等键 |
| `previous_attempt_id` | 显式重执行时引用的最近一次已停止或状态未知的尝试 |
| `valid_until` | 接收及启动的绝对截止时间，距接收时最多 24 小时 |
| `command` | 参数数组、工作目录、快照和上下文留存设置 |

接收时先取得 SQLite 写事务，再原子保存派发、执行尝试、请求摘要和初始历史。
执行端生成 Attempt ID 和本地 Run ID；接收账本本身不启动命令。

重复操作返回已有尝试。同一个幂等键携带不同参数时返回 `execution_conflict`；
同一派发改为引用另一来源调用时也返回冲突。显式重执行使用新的操作 ID，并引用
最近一次允许重执行的尝试。重发这个重执行请求仍返回同一个新尝试。
活动中的尝试须先停止或确认结果；未知状态不会被自动放回执行队列。

过期请求返回 `execution_request_expired`，即使去重记录已清理也一样。
已有执行结果仍可查询。排队超过截止时间的任务以失败结束，不再启动。
已经运行的命令使用执行器独立配置的超时。
当前账本没有自动清理功能；后续清理策略须保留有效期内的幂等键，以及证据和
恢复窗口所需记录，过期请求不得被静默视为新命令执行。

## 请求摘要

`digest_version` 为 `agentprovenance.execution_request_sha256/v1`。计算顺序：

1. 校验版本、身份、参数数组及资源限制。
2. 将截止时间转为 UTC；缺省采样间隔为 25 毫秒，根进程退出后观察期为
   250 毫秒，上下文档位为 `detailed`。显式的 `basic` 和工具结果覆盖配置保留。
3. 按类型声明的字段顺序，使用 Go `encoding/json` 序列化。
   `previous_attempt_id`、`tool_results` 按 `internal/handoff/contract.go`
   的字段标签处理省略。
4. 将 `[digest_version, canonical_json]` 作为两个字符串组成的数组序列化，
   对 UTF-8 字节计算 SHA-256，返回小写十六进制摘要。

摘要覆盖来源、目标及代次、派发、操作、上一次尝试、截止时间和命令设置。
参数边界、空白和路径保持原意。客户端发送普通 JSON，由执行端计算规范摘要。
传输适配器须拒绝未知请求字段，避免静默改变请求含义。

身份字段最多 512 个 UTF-8 字节，排除控制字符。参数数组最多 256 项，规范化后的
请求 JSON 最多 1 MiB。采样间隔为 1～60,000 毫秒，根进程退出后观察期为
1～30,000 毫秒。Shell、环境变量、工作区及运行超时由执行端策略管理。

## 三类状态

| 维度 | 状态 |
| --- | --- |
| 执行 | `accepted`、`starting`、`running`、`succeeded`、`failed`、`cancelled`、`unknown` |
| 采集 | `not_ready`、`collecting`、`draining`、`sealed`、`incomplete` |
| 交付 | `pending`、`transferring`、`acknowledged`、`conflict` |

初始状态是 `accepted / not_ready / pending`。通过修订号比较更新，只有一个
worker 能取得 `accepted -> starting` 的启动权。重启后检查已经处于 starting／running
的记录并恢复查询，不将它们自动改回 accepted。取得新的执行证据后，可以将
unknown 确认为运行中或终态。运行及终态记录需要执行器生成的证据引用，执行器
在推进状态前负责创建并验证引用。状态和历史在同一事务中提交。

采集经过 collecting、draining 后封存一个区间，或明确报告 incomplete。
封存记录窗口范围和已知缺口。交付确认对应接收端已持久化的具体范围及摘要。
命令成功不会修改采集或交付状态。迟到证据产生新包或追加版本，引用原始摘要。

传输断开、取消查询均保持执行状态不变。停止执行使用独立鉴权和幂等操作。
回执确认请求已保存，检查点记录实际执行结果。自有 Linux cgroup 覆盖脱离根进程组的后代；
其他环境沿用上文说明的进程组回退方式。

## 能力与回执契约

每个本地 Run 将保存能力清单，包含 producer 及版本、目标实例及代次、采集位置
（宿主、guest、Sentry）、运行时和内核、实际支持与启用的事件、正文留存、探针
就绪状态、采集区间和已知丢失。未知丢失数量保留未知。能力变化产生新区间并保留
历史；原生 producer 复用已有探针能力报告和运行时采集报告。

证据回执将绑定签发主体、接收主体、目标实例及代次、Dispatch／Attempt、请求摘要、
证据包摘要及已确认记录范围。接收端持久化后才确认。错误目标、身份冲突和摘要
不匹配须拒绝，已有证据保持原样。跨主机顺序由派发和回执关系表达，各端原始时间保留。

完整导出保留原包及签名；选择性阅读导出只包含选中内容和允许公开的引用元数据，
单独标注选择范围及其签名状态。

## 证据导入

`forensics.Service.ImportBundleStrict` 提供交付链路的接收端存储操作。
先在隔离目录校验完整包，将正文按解码后 Bundle 的 SHA-256 保存，再用一个事务
提交全部证据行。同内容重发复用已有记录；同 ID 携带不同证据时返回
`bundle_evidence_conflict`，整批回滚，已有记录与本地正文路径保持原样。

支持 JSON 和 gzip，解码后的 JSON 上限为 256 MiB，超限明确失败。
导入检查预期 Run、记录身份、对象哈希、对象大小和正文引用，保留 64 位整数
及空文件。归档文件同步落盘后才写入数据库引用；数据库失败时可能留下待核对的
未引用归档，这个方法本身不生成交付回执。

经过鉴权的交付接收器使用 `ImportBundleStrictWithCommit`，在同一事务中保存
证据索引和签名回执。已有回放导入保留原有覆盖行为，保持兼容。

## 签名交付

`handoff.DeliveryService` 从冻结的 SQLite 视图生成不可变证据包，只导出已保存的
证据，不在交付时重新分析。重新分析遇到相同内容哈希时，保留对象首次创建时间，
使后续包能够复用已有对象。

DSSE/in-toto 清单使用 `agentprovenance.execution_delivery/v1`，绑定以下信息：

- 完整来源身份、目标实例及代次、派发、执行尝试、本地 Run 和规范化请求摘要。
- 配置中的接收方、稳定交付操作、包版本及前一清单摘要。
- 执行修订号、已保存检查点、三个状态维度、导出时间、包摘要和确切字节数。

`Prepare` 先持久化包，再登记发件记录。同一操作重发或重启后重试，返回原始字节；
新的操作生成新版本。默认保留发送端副本，可按下节启用留存清理。文件发布或事务失败
可能留下未引用归档，供后续核对；自动清理不按文件年龄删除此类归档或准备中的目录。

`handoff.DeliveryReceiver` 从独立可信的接收记录取得预期执行身份，并固定目标公钥、
接收方和允许的来源命名空间。导入前验证签名、清单和包内检查点。归档同步落盘后，
证据行、原始清单及 `agentprovenance.execution_receipt/v1` 签名回执在同一事务中
提交。导入或回执写入失败时返回错误。回执丢失后，重发原清单即可取得已保存回执。

发送端核对接收方签名、清单和确认范围后保存回执。一个执行尝试的全部已准备包均有
回执时，汇总交付状态才进入 `acknowledged`。新包将汇总状态改为等待交付，旧包和
回执保持原样，采集状态独立保留。各版本按顺序接收并引用前一清单；身份冲突或缺少
前序包时明确返回冲突。

每个服务一次处理一个包。清单和回执上限为 64 KiB，未压缩 Bundle JSON 上限为
256 MiB；导出累计检查记录及正文预算，并校验最终序列化大小。取消操作覆盖排队、
数据库查询和正文复制；传输适配器还需设置网络读取超时。签名密钥与传输凭据分别
保管，历史公钥用于归档验证。

### 发送端副本留存

将 `delivery.retention_hours` 设为正整数即可启用，例如 `720` 表示 30 天。
省略或设为 `0` 时持续保留副本。Daemon 现有 GC worker 每轮最多处理
`min(--gc-limit, 1000)` 个包；`--gc-interval=0` 关闭自动清理。

首次保存回执时开始计算本地留存期，同时保护原执行请求的有效期，两者均结束后才清理。
已有回执尚未设置期限时，从 worker 首次应用策略开始保留完整窗口。重发回执及后续
配置修改沿用已保存的期限；设为零会暂停清理。

清理先持久化退役状态，再删除发送端的 `bundle.json`、`manifest.dsse.json`
及其空目录。中途失败可重试。API 的可选 `storage` 对象分别报告留存截止、退役及
完成删除的时间，原签名清单保持不变。目录内发现其他文件或删除失败时保留待清理状态，
记录错误并继续重试。结果保存为 `execution_delivery_cleanup` 事件；已打开的下载可继续完成。

副本退役后，重用原操作准备交付或下载正文会返回 HTTP 410
`execution_delivery_retired`；元数据查询和回执重发继续可用。需要再次交付时，
显式使用新操作 ID，从仍留存的源证据生成下一版本。

该策略仅清理已确认的发送端传输副本。签名清单、回执、操作去重记录、源证据和接收端
归档继续保存；账本随数据目录保留。原生 spool 已处理正文仍按现有结算规则清理。
证据库整体容量需另按实际留存需求管理。

### 配置与接收

两端分别使用 `agentprov forensics keygen --priv signing.key --pub signing.pub`
生成密钥对，通过可信管理渠道交换公钥。私钥保留在各自机器，文件权限设为 `0600`。
启动执行器前，在 `execution.json` 中加入以下可选配置：

```json
"delivery": {
  "receiver_id": "investigator",
  "sign_key_file": "executor.key",
  "receiver_public_key_file": "investigator.pub"
}
```

密钥路径相对于配置文件解析；文件缺失或内容无效时启动失败。
省略 `delivery` 时，交付接口保持关闭。调用端通过已有 SSH 隧道拉取证据，无需开放接收端口。

提交命令时，将经过鉴权的 `POST /v1/executions` 响应保存为 `admission.json`。
接收时使用这份独立的来源记录、运维配置中的调用方及目标身份，以及预先核对的执行端公钥：

```sh
# 将 AGENTPROV_DAEMON_TOKEN 设为执行器的传输凭据。
agentprov --data-dir ./received-evidence --daemon-url http://127.0.0.1:18575 \
  forensics collect-execution ./admission.json \
  --execution-config ./execution.json --receiver investigator \
  --sign-key ./investigator.key --pub-key ./executor.pub \
  --operation collect-initial
```

命令输出使用英文字段的 JSON。`acknowledged` 表示接收端已提交证据和签名回执，
执行端也已保存该回执。最后确认失败时，输出 `receipt_persisted` 并以错误退出；
沿用原接收记录和操作 ID 重试即可。进程重启后继续使用已保存的记录。
补交新证据时使用新的操作 ID，生成新的包版本。`--timeout` 限制整个接收过程，
默认三分钟；单次 HTTP 传输最多两分钟。客户端拒绝重定向，元数据响应上限为 256 KiB。

[HTTP 交付验收脚本](../../scripts/accept_execution_delivery.py) 运行真实 CSV 命令，
通过公开 CLI 连续接收两次，检查接收端图谱和制品正文。
该脚本使用 HTTP 测试入口，原生 harness 与 Sensor 另行验收。

## 兼容与测试

数据库 schema 21–26 增加执行账本、持久停止请求、交付发件记录和回执、发送端副本留存，以及作用域采集和采样缺口计数，
保留既有物理表名和事件内容。
旧程序会拒绝新版 schema；降级使用升级前备份。历史签名包维持原有格式。

```sh
go test -race ./internal/handoff ./internal/daemon ./internal/store ./internal/forensics
```

回归测试覆盖并发接收与启动权、显式重执行、来源隔离、参数冲突、过期、重开数据库、
历史写入失败回滚、有界分页、取消查询、真实命令、输出留存、独占执行器及结束事件恢复。
在具备可写 cgroup v2 权限的 Linux 主机上，运行真实崩溃和身份重用回归：

```sh
AGENTPROV_TEST_REQUIRE_CGROUP=1 go test -count=1 -v ./internal/handoff ./internal/record \
  -run 'TestExecutorRecoversLiveScope|TestRecoveredScope'
```

测试让执行器异常退出、命令继续运行，再检查停止请求、自然退出、原超时期限、
单次副作用、签名交付及旁路对照进程。同时验证同名 cgroup 替换，以及 boot、
文件系统和 cgroup 身份不匹配时的处置。

`scripts/accept_execution_handoff.py` 通过独立 Daemon 的公共 API 验证并发 CSV 分析、
文件产物、重试和取消。该脚本使用明确标注的调用标识 fixture；原生 harness 接入和
证据传输分别验收。
配置原生采集后，加上 `--require-sealed`，可要求正常完成和已停止任务的作用域采集
均完成封存；共享节点的积压仍单独保留在报告中。
严格导入的回归覆盖并发重发、证据冲突、整批回滚、存储错误、正文迁移、
缺失正文、解码大小限制，以及与旧回放导入的兼容。
交付测试运行真实 CSV 命令，将输出和制品传入独立存储，删除来源文件后检查接收端
图谱和正文；覆盖固定身份与公钥、篡改、回执丢失、重启、确认写入回滚、并发重试、
顺序追加包，以及重新分析后的迟到证据交付。
