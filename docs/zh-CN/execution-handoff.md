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
重启时读取已保存的结束事件；启动结果缺少依据时保留 `unknown`，不使用历史 PID
直接发送信号。未知尝试的停止请求继续保留，供运维核对。

Linux 上具备可写 cgroup v2 子树时，取消、执行超时和启动后检查点失败都会通过
`cgroup.kill` 停止本次执行的 cgroup，包括使用 `setsid` 新建进程组的子进程。
执行器持续持有 cgroup 目录句柄，并且只使用本次新建的作用域。根进程回收后，
最多等待两秒，读取 `cgroup.events` 确认子树是否为空；其他并发执行保持运行。

结果中的 `stop_report` 保存停止方式、信号结果、观察时间、`scope_empty` 和错误。
作用域仍有进程时，尝试状态保留为 `unknown`。cgroup 停止失败时，回退为终止根进程，
同时保留作用域错误。没有内核 cgroup 的环境沿用进程组或根进程停止方式：命令状态
描述根进程结果，`scope_empty` 为 null，采集状态为 `incomplete`。停止报告与结束事件
一同保存，重启恢复和签名交付均保留。主动迁移到作用域外的进程交由运维另行核对。

每路输出最多保留 1 MiB，再脱敏并分块保存。超出部分记录截断原因和已观察字节数。
`basic` 默认省略工具结果正文，也可单独启用；重启时未保存的输出标为未知。
命令成功后，采集暂处于 `draining`，交付处于 `pending`，后续分别由采集收尾和回执推进。

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
回执确认请求已保存，检查点记录实际执行结果。当前通过进程组取消活动中的非交互命令；
脱离该进程组的后代需要另外核对其作用域。

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
新的操作生成新版本。当前保留归档和账本，不自动清理交付记录。文件发布或事务失败
可能留下未引用归档，供后续核对。

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

数据库 schema 21–23 增加执行账本、持久停止请求及交付发件记录和回执，
保留既有物理表名和事件内容。
旧程序会拒绝新版 schema；降级使用升级前备份。历史签名包维持原有格式。

```sh
go test -race ./internal/handoff ./internal/daemon ./internal/store ./internal/forensics
```

回归测试覆盖并发接收与启动权、显式重执行、来源隔离、参数冲突、过期、重开数据库、
历史写入失败回滚、有界分页、取消查询、真实命令、输出留存、独占执行器及结束事件恢复。
`scripts/accept_execution_handoff.py` 通过独立 Daemon 的公共 API 验证并发 CSV 分析、
文件产物、重试和取消。该脚本使用明确标注的调用标识 fixture；原生 harness 接入和
证据传输分别验收。
严格导入的回归覆盖并发重发、证据冲突、整批回滚、存储错误、正文迁移、
缺失正文、解码大小限制，以及与旧回放导入的兼容。
交付测试运行真实 CSV 命令，将输出和制品传入独立存储，删除来源文件后检查接收端
图谱和正文；覆盖固定身份与公钥、篡改、回执丢失、重启、确认写入回滚、并发重试、
顺序追加包，以及重新分析后的迟到证据交付。
