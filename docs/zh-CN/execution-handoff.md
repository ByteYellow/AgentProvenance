# 跨沙箱执行交接协议

[English](../execution-handoff.md)

本协议将来源 Agent 的 Tool Call 与另一个可信 producer 上的独立命令关联。
执行端保留自己的 Run，通过显式引用实现调查跳转和证据交付。

当前实现提供持久接收账本、有界命令执行器、重启恢复、停止请求和鉴权 HTTP API，
代码位于 `internal/handoff` 和 `internal/daemon`。
证据传输回执、能力清单和 Dashboard 接入正在实现。
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

字段和错误码见 [OpenAPI 定义](../execution-handoff-api.yaml)。JSON 写请求最多 1 MiB，
拒绝未知字段和尾随 JSON；保留现有 bearer、Origin 和 Fetch Metadata 校验。

执行器独占数据目录，默认同时运行两个命令，其余任务保存在 SQLite。
重启时读取已保存的结束事件；启动结果缺少依据时保留 `unknown`，不使用历史 PID
直接发送信号。未知尝试的停止请求继续保留，供运维核对。

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

发送端授权、签名验证和持久交付回执由交付协议完成，尚未通过此入口开放。
已有回放导入保留原有覆盖行为，保持兼容。

## 兼容与测试

数据库 schema 21、22 增加执行账本和持久停止请求，保留既有物理表名和事件内容。
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
