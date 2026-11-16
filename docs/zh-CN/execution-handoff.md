# 跨沙箱执行交接协议

[English](../execution-handoff.md)

本协议将来源 Agent 的 Tool Call 与另一个可信 producer 上的独立命令关联。
执行端保留自己的 Run，通过显式引用实现调查跳转和证据交付。

## 一条命令如何跨越沙箱边界

以 Mac 或沙箱 A 中的 Agent 请求沙箱 B 执行 `python analyze.py` 为例：
来源会话记录了请求，进程、文件和网络活动却发生在目标环境。执行交接将两端记录连接起来：

```text
来源 Run / 会话 / 原生 Tool Call
  → 已鉴权的派发 / 执行尝试
  → 目标 Run / 执行作用域 / 进程与运行时事件
  → 保存的结果 / 签名 Bundle / 接收回执
```

可信路由提供来源引用，执行器记录实际执行尝试和作用域。
调查远端文件时，就可以沿这条关系返回对应的工具调用。
[部署指南](deployment-modes.md#先看-agent-和工具在哪里运行)说明三种执行位置的组合。

阅读时区分三类状态：**执行**回答命令发生了什么，**采集**回答保留了哪些观测，
**交付**回答证据包及其回执处于什么阶段。响应丢失时重试同一次操作，
明确要求重新运行时创建新的执行尝试，分别记录传输恢复和命令重跑。

当前实现提供持久接收账本、有界命令执行器、重启恢复、停止请求和鉴权 HTTP API，
代码位于 `internal/handoff` 和 `internal/daemon`。拉取 API 和
`forensics collect-execution` 已支持签名证据包及持久接收回执；
原生采集检查点保存探针能力、作用域边界和队列收尾结果，只读执行关联 API
支持双向查询。对应阅读器可在[候选预览](../../previews/v1.0-reader/README.zh-CN.md)
中体验，正式 Dashboard 尚未接入。
现有同步接口 `POST /v1/record` 保持原有行为。

首次接入按以下顺序阅读：[启用执行器](#启用执行器)、
[路由 Claude 原生调用](#路由-claude-原生-bash-调用)、
[配置签名交付与接收](#配置与接收)，再[查询执行关联](#查询已保存的执行关联)。
后面的协议与恢复说明解释这条流程的具体行为。

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
VM 内可设置 `placement: guest_kernel`，节点采集器设置 `placement: host_kernel`。
默认值 `local_kernel` 只说明采集本地内核，不推测部署拓扑；该字段由部署方配置。
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

首次运行前，可用 `agentprov doctor --remote-execution /path/to/operator/route.json --json`
核对配置。它通过需要认证的 `GET /v1/execution-readiness` 检查调用方、目标实例及代次、
接收方、双方公钥指纹、执行器运行状态和采集等待设置，不派发任务，也不输出凭据。
`launch --remote-execution` 会执行同样的检查；必要配置不匹配时，先修正再启动 Agent。
两端程序都需要支持这个接口，旧执行器报接口不可用时应先更新。

在运行时所在的 Linux 主机上，还可以检查固定版本的程序、选用的文件和设备权限：

```sh
agentprov doctor --runtime runsc --runtime-binary /opt/runsc/runsc \
  --runtime-rootfs /path/to/rootfs --json
agentprov doctor --runtime firecracker --runtime-binary /opt/firecracker/firecracker \
  --runtime-rootfs /path/to/rootfs.ext4 --runtime-kernel /path/to/vmlinux --json
```

Firecracker 检查包括 `/dev/kvm`、`/dev/net/tun` 和 guest 验收脚本需要的辅助程序。
省略的文件路径会提示尚未检查。检查期间不启动容器或虚拟机，后续继续用实际启动和证据
用例完成运行时验收。

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

路由中设置 `wait_capture: true` 后，会等执行端的原生采集变为 `sealed` 或
`incomplete` 再收取结果；设置为 `false` 时，命令结果可以先返回，采集继续收尾。
省略时，只有调用端的 `execution.json` 包含 `capture` 配置才会等待。执行端独立
配置原生采集时，建议明确设置这个选项。要求等待但执行端没有原生采集报告时，
CLI 会指出配置问题，并保留原请求供修正配置后恢复。

重复使用同一交付操作会收到原来的签名包。恢复时，从该包已验证的交付清单读取
对应检查点和输出；远端采集已经推进时，CLI 分别显示保存的包版本与最新远端状态。
重试原请求会补交回执、返回已保存的输出，命令只执行一次。

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

原生检查点的 `capture_report` 保存开始和结束时的探针能力、采集器边界、
独立作用域及队列收尾结果。外层检查点保存来源、目标实例及代次、请求摘要和
输出留存状态。查询某次执行时读取其已保存的检查点，而非采集器当前的健康报告。
早期检查点继续作为内容寻址证据保存，未知丢失数量保持未知。

其他 producer 分别保存带来源标识的能力证据。例如，[gVisor 流记录](gvisor-seccheck.md)
包含 Sentry 身份域、固定协议版本和可用事件类型。

### 查询已保存的采集信息

在 Daemon 中调用 `GET /v1/capture-manifest?run=<run-id>&limit=50`，沿用其 Bearer
鉴权；本地 Dashboard 使用 `GET /api/capture-manifest`。
[接口定义](../capture-manifest-api.yaml)列出启动采集报告、原生执行检查点、应用上下文
覆盖、留存设置、gVisor 流记录及实际观察到的事件点，以及普通 `record` 的采集边界。
`has_more` 为 `true` 时，携带 `next_cursor` 继续读取。
查询保留各次报告和检查点修订，身份包含来源及生命周期代次，按证据 ID 分页。

`supported`、`enabled` 和 `ready` 分别表示支持、启用和就绪状态，未知值为 `null`，
缺少版本时为 `unknown`。丢失计数保留原始作用域和统计依据，例如节点累计值、
采集区间增量或单次运行计数。数值采用十进制字符串，避免浏览器损失 64 位整数精度。
采集时的留存设置与导出时的选择范围分别记录。

`observation` 单独说明证据来自宿主内核（`host_kernel`）、Guest 内核
（`guest_kernel`）、Sentry 或应用层（`application`），与接收器所在位置分开。
每个采样边界保留自己的 boot、采集器、版本及部署位置依据。未记录内核拓扑时为
`unknown`；起止边界不一致时，摘要标为 `mixed`，具体变化查看各次采样。
作用域引用结合所在记录的身份与 generation 使用；投影同时提供规则版本和原始证据引用。

AppArmor/seccomp 状态采样项说明采集配置，`policy_subject.role` 保持 `unknown`。
实际决策影响哪个进程、使用什么策略，查看对应的访问控制原始证据。执行检查点另外
提供 `execution_state`，分别保留执行、采集和交付状态。例如，执行成功时，采集可能
不完整，交付仍在等待中。历史检查点缺失的状态值按原样保留。

新导出的离线页面在 `file://` 下支持同一分页查询。完整导出包含已保存的采集记录；
选择性导出只读取冻结后的选中范围，返回 `selection_scope: selected_evidence`，
排除的原生检查点正文和探针路径保持排除。原 Bundle 签名及对象哈希保留。
未包含该索引的旧回放会提示数据不可用。

普通 `record` 在原始生命周期事件中保存采集端版本、操作系统与架构、可读取的 Linux
内核和 boot 身份、进程轮询间隔、根进程退出后的观察时间，以及文件快照开关。
查询记录采用 `source: record`、`identity_domain: record_scope` 和
`interval_basis: recorder_observation`。结束或错误边界保留进程表读取失败，以及
采样进程绑定和事件写入失败的次数；采样间隙漏掉的进程总数保持未知。文件快照单独
记录状态，关闭时明确标为禁用。命令退出状态与采集状态分别保存。同一 Run 使用原生
Sensor 时，内核采集能力仍由其自身的采集记录说明。旧生命周期事件保持原样；
选择性导出排除某条生命周期事件时，也排除该事件中的采集信息。

原生采集监督进程还会保留起止采样之间的能力变化。每次 Sensor 启动使用独立身份；
探针或就绪状态变化时增加修订号并记录时间，仅计数器增长时沿用当前修订号。
版本、源码提交、架构、内核、boot ID 和部署方声明的采集位置随记录保存。
能力采样时间与内核标记时间分别保留。

launch 或远端执行收尾时，逐条保存这些区间，查询中的
`interval_basis` 为 `recorded_capability_changes`。所属采集报告的
`capability_history` 给出修订范围、已保存数量及缺口。中途必需探针失效后即使恢复，
报告仍保留采集问题；缺失、冲突或无法读取的修订标为历史不完整，写入失败时停止采集。
旧报告继续按起止采样解释。

被动 `sensor stream` 采集（包括 K8s 节点采集）按 spool 批次保留原采集器身份和
能力历史。作用域迟到绑定、重启后补处理时，沿用这些原始观察，与归属后的事件和
摄入回执在同一事务中提交；历史缺失时保留待处理批次，等待重试。
这类记录的 `interval_basis` 为 `collector_receive_window`，同时保存批次和接收器身份。
区间描述采集器接收事件的窗口，缓冲事件仍保留原时间。崩溃前未封存的窗口增加
`collector_receive_window_unsealed`，只保留最后已观察的边界；工作负载采集结束时间
保持未知，节点级丢失统计仍归节点。签名 Bundle 和选择性回放保留范围内的能力对象。

本地历史位于 `logs/sensor-capabilities/<collector-id>/`，单份快照上限为 1 MiB，
按区间逐条读取。相关 Run 保存历史前应保留该目录；导出的内容对象与本地目录独立。
单独运行 `agentprov-sensor` 时，变化写入诊断流；使用 `sensor stream` 或 Daemon 原生
采集可自动持久化。两个 sensor 入口均支持 `--placement`。

gVisor 的 `checkpoint_observation` 引用已保存的原始事件。同一实例代次与连接中，
每种协议消息、syscall 编号和采集阶段保留一条确定的代表证据；非零丢失增量及计数器
重置、身份缺口另行保留。`observed: true` 表示实际收到过对应消息，缺少启用或就绪证据时，
`enabled`、`ready` 保持未知。共享消息类型保留原 syscall 编号，不用阅读端架构猜测
调用名称。选择性导出从选中事件重新选择代表证据，排除的记录不会参与该副本的清单。

### 证据回执

证据回执绑定签发主体、接收主体、目标实例及代次、Dispatch／Attempt、请求摘要、
证据包摘要及已确认记录范围。接收端持久化后才确认。错误目标、身份冲突和摘要
不匹配会被拒绝，已有证据保持原样。跨主机顺序由派发和回执关系表达，各端原始时间保留。

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

### 中断发布清理

同一个 GC worker 还会清理发送端 `execution-deliveries` 中遗留的 `.prepare-*`
暂存目录，以及数据库未引用的 `package-*` 目录。即使未启用已确认副本留存策略，
这项核对仍会执行。每轮流式读取目录、通过索引检查数据库引用，最多删除
`min(--gc-limit, 1000)` 个目录，执行期限为两分钟。

发布器从创建暂存目录到发件记录提交期间持有跨进程共享锁。GC 获取独占锁；
发现其他发布器正在工作时，留到下一轮处理。进程崩溃后锁由系统释放，
后续核对即可清理遗留文件，无需按文件年龄猜测发布是否结束。
已登记的包继续保留，包括待交付包及其他接收方的包。

数据库查询失败会停止核对；目录内的异常文件或链接保留并报告。
删除结果和错误保存为 `execution_publication_cleanup` 事件。
接收端归档和源证据位于本项清理范围之外。
升级共享数据目录前先停止全部写入端，再统一启动新版，确保发布器遵守同一锁协议。

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

### 回收前封存 guest 证据

回收 guest 前，先停止执行器和采集器，再把已保存的执行记录打包。
数据目录应放在 guest 删除后仍保留的卷上。init 服务可在 daemon 进程退出后调用：

```sh
agentprov --data-dir /mnt/agentprov-evidence \
  forensics seal-executions \
  --execution-config /run/agentprov/execution.json \
  --operation "$RETIREMENT_ID" > /mnt/agentprov-evidence/seal.jsonl
```

`RETIREMENT_ID` 由可信生命周期控制端提供。中断重试沿用同一个 ID；
后续归档需要包含新证据时，使用新的 ID。命令只处理配置中调用方命名空间和
目标 producer、实例、生命周期代次对应的执行，按有界分页枚举，复用已有签名交付格式，
保留原执行状态和采集状态。执行器或 daemon 仍在运行时拒绝封包。

中英文界面均输出英文字段和状态值的 JSONL。每条执行记录的状态为
`prepared`、`reused`、`unfinished` 或 `failed`，最后一行汇总数量及 `complete`、
`receipts_verified`、`receipts_pending`、`delivery_complete`。
已打包记录包含包路径和签名清单，包保存在数据目录的
`artifacts/execution-deliveries` 下。归档时同时保留这些包和 JSONL 索引。

未结束的执行保持原状。缺少检查点、已有包损坏、存储失败、取消或输出失败时，
命令以非零状态退出；已经准备好的包保留，供重试复用。封包失败时，init 或控制端
必须保留证据卷。`complete` 表示选中的本地执行已打包；接收方确认仍走上文的
签名回执流程。包正文仍在留存期内时，即使接收端已经确认，同一操作 ID 仍复用原包。
正文已回收时返回 `execution_delivery_retired`；需要重新导出仍保留的源证据时，使用新的操作 ID。

此命令只操作本地存储，拒绝 `--daemon-url`。签名密钥及外部指定的实例、生命周期代次
来自已有执行配置，应与可重复使用的 guest 镜像分开提供。

### 执行器停止后接收证据

把封存目录中的 `bundle.json` 和 `manifest.dsse.json` 原样复制到接收端，
不要从 CLI 的 JSON 输出重新生成清单文件。
调用方须保留从受信提交响应取得的 admission，接收时独立核对，
不能用待接收包反向构造。执行端私钥保留在原执行端。

```sh
agentprov --data-dir ./received-evidence forensics collect-execution admission.json \
  --execution-config ./trusted-target.json --package-dir ./sealed-package \
  --receiver investigator --sign-key ./receiver.key --pub-key ./executor.pub \
  > collection.json
jq '.receipt' collection.json > receipt.dsse.json
```

`--package-dir` 使用本地文件传输，省略 `--daemon-url` 和 `--operation`。
封存包已有固定交付身份，接收仍校验预先配置的发送端公钥、独立 admission、
严格导入及前驱关系。多版本包按 `package_version` 顺序接收；缺少前驱时明确报错，
因此最后封包时也要保留尚未接收的早期包。重复接收返回原来的签名回执。

接收结果状态为 `receipt_persisted`。把 `receipt.dsse.json` 传回已停止执行器的
证据卷，再在执行端运行：

```sh
agentprov --data-dir /mnt/agentprov-evidence forensics acknowledge-execution \
  DELIVERY_ID receipt.dsse.json --execution-config /run/agentprov/execution.json
```

`DELIVERY_ID` 使用接收结果中的 `delivery_id`。命令校验接收方签名、包摘要、
执行尝试和生命周期代次后保存回执。重复操作复用已有回执，只更新交付状态；
一次尝试的所有待交付包都有回执后，交付状态才变为 `acknowledged`。
命令不启动执行器，遇到运行中的 daemon 会拒绝操作。回执传回后，
在保留的发送端存储中检查整批交付结果：

```sh
agentprov --data-dir /mnt/agentprov-evidence forensics seal-executions \
  --execution-config /run/agentprov/execution.json \
  --operation "$RETIREMENT_ID" --require-receipts
```

沿用最初的操作 ID。命令按配置的接收方公钥、包摘要和执行身份逐一核验已保存回执。
回执尚未齐全时，退出码非零，汇总显示 `complete: true`、`delivery_complete: false`
和待收数量。损坏或错配的回执显示 `failed` 及具体错误。所有选中包的回执均通过核验后，
`delivery_complete` 为 `true`，退出码为零。任务失败、采集缺口仍保留各自的原始状态。

汇总范围是本次操作配置的调用方和目标生命周期代次；空范围显示零条执行。
生命周期控制端须将范围和数量与回收清单核对，并保留其他代次或调用方的数据。
后续新增证据使用新操作 ID，并重新取得对应回执。这些命令不删除证据或改变采集完整性。

[封包验收脚本](../../scripts/accept_execution_seal.py) 启动隔离的本地执行器，运行成功的
CSV 任务和退出码为 7 的失败命令。停止 daemon 后连续封包两次，分别检查未收到回执、
收到一份回执和全部收到时的结果，再移走原数据目录，在新存储中验证两份包的签名和正文。
在具备采集权限的 Linux 主机上加 `--native`，要求内核采集达到 sealed 状态：

```sh
python3 scripts/accept_execution_seal.py \
  --binary /path/to/agentprov --output /path/to/new/acceptance --native
```

合成输入名为 `credentials-fixture.csv`，用于触发现有敏感读取规则，内容不含凭据。
脚本核对导入包中的输入读取、结果写入及原 cgroup 归属。
此脚本验收命令级流程；guest 开机和快照恢复另行验收。

### Guest 服务与镜像

可选的 [guest 部署](../../deploy/microvm/agentprov-guest.service) 复用
`daemon serve` 和 `seal-executions`。镜像方案选定 Firecracker **v1.18.0**，
源码提交为 `eaf83bb718a559d324613d566eaf776b31a62340`，Ubuntu 24.04 基础镜像的
固定摘要保存在 [runtime.json](../../deploy/microvm/runtime.json)。guest 内核选用
Amazon Linux **6.18.62**，源码提交为 `b7522fb67989bd879de78486e9e253fd2f21f1dd`。
内核构建脚本校验固定上游配置，合入 [Sensor 配置片段](../../deploy/microvm/sensor-kernel.config)，
再检查实际生效的 BTF、BPF events、syscall tracepoint、uprobe 和启动驱动。
构建脚本不启动 guest，因此镜像及内核清单中的 `boot_tested` 保持 `false`。
独立的 [amd64 验收](../benchmarks/v1.0-amd64/README.zh-CN.md)已使用 Firecracker v1.18.0
和 6.18.62 内核实际启动 guest，验证两条命令、原生文件证据、签名交付及回执齐全后回收。
结果索引保存对应镜像、内核和程序哈希。恢复与克隆验收选用 Sentry，见 [SecCheck 指南](gvisor-seccheck.md)。
配置依据见上游[内核策略](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/kernel-policy.md)
和[镜像构建指南](https://github.com/firecracker-microvm/firecracker/blob/eaf83bb718a559d324613d566eaf776b31a62340/docs/rootfs-and-kernel-setup.md)。

在 Linux ARM64 或 x86_64 主机上原生构建内核。准备 Git、Make、GCC、binutils、
`bc`、`flex`、`bison`、OpenSSL／ELF 开发头文件、`pkg-config`、支持 DWARF 5 的
`pahole` 和 `bpftool`。构建无需 root 或 `/dev/kvm`，也不会安装宿主内核。
源码与输出使用不同目录：

```sh
git clone --depth 1 --single-branch \
  --branch kernel6.18-6.18.62-127.179.amzn2023 \
  https://github.com/amazonlinux/linux.git /path/to/linux-source
python3 scripts/build_microvm_kernel.py \
  --source /path/to/linux-source --output /path/to/new/guest-kernel --jobs 2
```

源码必须是固定提交的干净工作区。脚本按 SHA-256 校验上游配置；可用
`--base-config /path/to/config` 指定已下载副本，仍执行同样的校验。
采集所需功能和块设备、网络驱动直接编入内核，rootfs 无需另装内核模块。
配置或编译失败时保留日志，不生成 `manifest.json`。

ARM64 使用 `Image`，x86_64 使用去除调试信息后的 ELF `vmlinux`。
输出还包括经过解析检查的 `kernel.btf`、最终 `kernel.config`、`System.map`、
构建日志，以及输入、产物摘要和工具版本清单。将这些文件与对应 rootfs 一起保留；
保留最终产物后可删除中间 `build/` 目录，脚本默认留存该目录便于排查。
固定输入用于识别构建，编译器和软件包版本也会作为环境信息记录。

在安装了 Docker、Python 3、`systemd-analyze`、`chroot`、`mkfs.ext4` 和 `e2fsck` 的 Linux 上构建：

```sh
sudo python3 scripts/build_microvm_rootfs.py \
  --binary /path/to/linux-agentprov --output /path/to/new/guest-image
```

CLI 使用构建主机对应的架构。脚本直接生成 ext4 文件，无须挂载 rootfs，保存
二进制、镜像和软件包摘要，并清理自己创建的临时容器与镜像标签。它只构建镜像，
不启动 VM，也不改已有服务。发行版软件包在构建时解析；部署时保留实际镜像及软件包清单。

guest 使用三个块设备：

| 设备 | 挂载位置 | 内容与管理方 |
| --- | --- | --- |
| `/dev/vda` | `/` | 可复用的 systemd rootfs，不含实例身份、API token 或签名密钥 |
| `/dev/vdb` | `/etc/agentprov-guest` | 可信外部控制端提供的只读配置卷 |
| `/dev/vdc` | `/var/lib/agentprov-guest` | 独立保留的证据卷，保存数据库、正文对象和签名包 |

配置卷包含本指南中的 `execution.json`，启用 `capture.mode=native`、
`capture.placement=guest_kernel` 和签名 `delivery`；
权限为 0400／0600 的 `daemon-token`；配置引用的发送端私钥、接收端公钥；SSH
`authorized_keys` 和每个实例独立的 `ssh_host_ed25519_key`。目录只向管理账号开放。
外部控制端指定 `target.producer_id`、`instance_id` 和 `generation`，服务沿用这些身份。
SSH 只允许密钥登录，API 监听 `127.0.0.1:8574`，继续使用 SSH 转发连接。
示例网络配置通过 `eth0` 请求 DHCP，VM 宿主提供网络，也可替换为运维自己的网络配置。

服务随正常开机目标启动。启动后检查 daemon PID 是否匹配、探针就绪后的健康状态，
以及带鉴权的执行查询；检查通过后，`systemctl start agentprov-guest` 才返回成功。
API token 从私有文件读入 daemon 环境，不放入命令行参数；启动过程不生成替代身份或凭据。

执行 `systemctl stop agentprov-guest` 时，daemon 先关闭任务和采集，再由停止钩子封包。
就绪记录、停止报告和分页包索引保存在 `guest-lifecycle/`。同一次服务 invocation
使用固定封包操作 ID，重试复用原包。身份或配置被改写、缺少就绪记录、封包未完成时，
服务明确报错，证据卷继续保留。服务关闭自动重启，由外部控制端决定沿用原实例启动，
还是配置新生命周期代次。内存快照恢复不会重新执行开机钩子。

正常回收时，先在可信调用端停止新派发，等待现有任务结束或显式停止任务；服务仍可用时，
通过已有交付协议拉取证据并确认接收。随后停止服务，保留最后生成的包及尾部证据。
停止报告的 `sealed` 描述本地封包结果；钩子未联系接收端，`receiver_acknowledged`
记录为 `null`，`may_reclaim` 保持 `false`。外部控制端核对最终包和接收回执后，
再决定删除证据卷。

在现有 Linux VM 中验证实际服务生命周期，不替换机器原有的采集器：

```sh
sudo python3 scripts/accept_execution_seal.py --native \
  --binary /path/to/agentprov --output /path/to/new/service-acceptance \
  --guest-service-dir "$PWD/deploy/microvm"
```

脚本创建唯一命名的临时服务，核对真实内核采集、停止钩子自动封包、
无 daemon 的封存包接收、签名回执回写及独立签名导入，
结束后只移除自己的服务。完整 guest 启动、恢复和克隆另用对应运行时环境验收。

## 兼容与测试

数据库 schema 21–27 增加执行账本、持久停止请求、交付发件记录和回执、发送端副本留存、发布路径引用索引，以及作用域采集和采样缺口计数，
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
