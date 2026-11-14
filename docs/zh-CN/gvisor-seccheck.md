# gVisor SecCheck 接收器

[English](../gvisor-seccheck.md) | 中文

`internal/seccheck` 提供 gVisor producer 的传输接收层，固定使用
`runsc release-20261109.0`、协议版本 1，以及源码提交
`a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`。

类型化事件和连接诊断已接入现有持久缓冲、运行时图谱、签名 Bundle 及离线回放链路。
使用 `telemetry seccheck-config` 生成运行时采集配置，再通过
`telemetry receive-seccheck` 在 Linux amd64/arm64 上接收已登记的沙箱事件。

## 启动采集

安装固定版本的 runsc 发行包，保留相邻的 `gvisor-bin` 目录。启动负载前执行
`runsc --version` 核对版本。接收器校验协议 v1；配置中的运行时版本由可信启动方
声明，握手消息本身只携带协议版本。

创建接收器用户拥有的 `0700` 目录。套接字权限为 `0600`，接收器与运行时启动方
使用同一个本地 UID。套接字完整路径须短于 108 字节。以下示例以 root 运行：

```sh
sudo install -d -m 700 /run/agentprov-seccheck
agentprov telemetry seccheck-config \
  --socket /run/agentprov-seccheck/workload.sock > trace.json
```

将可信登记配置保存为 `registration.json`：

```json
{
  "schema_version": "agentprovenance.seccheck_collection/v1",
  "runtime_release": "release-20261109.0",
  "targets": [{
    "run_id": "gvisor-example",
    "socket_path": "/run/agentprov-seccheck/workload.sock",
    "registration": {
      "namespace": "local",
      "instance_id": "node-1",
      "generation": "workload-lifetime-1",
      "sandbox_id": "workload-1",
      "container_id": "workload-1",
      "peer_uid": 0
    }
  }]
}
```

登记的 container ID 与 OCI 容器名称保持一致。创建新的沙箱生命周期时分配新的
generation。一个接收命令独占该数据目录的 SecCheck 队列，最多接收 64 个登记目标；
套接字路径和生命周期作用域均须唯一。

在一个终端启动接收器：

```sh
sudo agentprov --data-dir /var/lib/agentprov telemetry receive-seccheck \
  --config registration.json --json
```

等待输出 `state: listening`，再在另一个终端使用生成的配置运行已有 OCI bundle：

```sh
sudo /path/to/runsc --root=/run/agentprov-runsc --platform=systrap \
  --pod-init-config=/absolute/path/to/trace.json \
  run --bundle=/absolute/path/to/oci-bundle workload-1
```

负载结束、对应目标显示 `disconnected` 后，用 Ctrl-C 或 SIGTERM 停止接收器。
它会关闭接入、处理已接收记录并输出最终状态。存储或排空失败时返回非零退出码，
未处理的持久批次留给下次启动恢复。沙箱的创建、调度和停止仍由外部启动方负责。

## 状态与能力

`--json` 输出 `agentprovenance.seccheck_status/v1`，包含本次进程的目标连接状态、
已接收记录、上游报告丢失、身份字段缺口和节点队列。`last_worker_error` 保留最近一次
重试诊断，`error` 表示采集终止错误。状态输出失败也会停止采集。
周期状态写到标准输出，避免反复追加到证据图。

已有 CLI 和需鉴权的健康接口可以读取持久统计：

```sh
agentprov --data-dir /var/lib/agentprov telemetry producer-health \
  --run gvisor-example --json
```

响应增加 `events.by_source.gvisor_seccheck` 和 `seccheck_node_capture`，
保留原来的 `native_node_capture`。队列与丢失计数采用节点范围，即使指定了 Run。
新增连接统计在摄取时按唯一记录累加，历史包导入不重建累计计数；逐条诊断仍随证据保存。

就绪和正常停止记录保存 producer 版本、登记生命周期及能力报告，并进入签名导出。
系统遥测覆盖为 `partial`，身份域为 Sentry；本 producer 的模型意图和应用上下文能力为
`none`。生成配置请求十个采集点，实际收到的消息用于确认已观察到的覆盖范围。
队列排空后仍保留局部覆盖状态。原始报文正文、exec 环境和凭据结构不留存，正规化参数经过脱敏。

通过 `--batch-events`、`--batch-bytes`、`--max-queued-bytes` 和
`--max-queued-batches` 调整共享队列。默认单批 256 条／1 MiB，队列上限
256 MiB／4096 批。`--drain-timeout` 默认 30 秒。

## 作用域与身份

可信执行入口登记命名空间、实例、生命周期代次、sandbox、container，以及预期
本地连接用户的 UID。每个 sandbox 使用独立的私有 Unix `SOCK_SEQPACKET`
端点。同时到来的第二条连接会被拒绝；重连获得新的连接 ID 和接收序号，
已登记的生命周期保持不变。

Run 由接收器本地登记配置指定。保存事件的来源、关联方法和分类分别为
`gvisor_seccheck`、`runtime_scope` 和 `runtime_scoped`。Sentry 事件不会借用或
关闭宿主机 PID 绑定。线程和进程出生时间保留纳秒精度；版本化图身份包含
命名空间、实例、生命周期及 sandbox。不同沙箱生命周期中的相同绝对路径分别
建模；相对路径及包含点路径段的路径先保留为单条事件的观察值。

接收器分别保存 Sentry 的线程 ID、线程组（进程）ID，以及各自的出生时间，并结合
登记作用域生成身份。父线程组编号先作为观察值保留，后续再根据生命周期证据关联。
Socket 对端 PID 用于描述本地传输客户端，与沙箱内进程身份分开。
消息中的 container ID 必须与登记值一致。

## 事件与异常

首批解析 container start、clone、exec、open、connect 和 exit 消息，保留系统调用
入口和返回记录的区别。入口事件的结果保留未知；返回记录沿用 `syscall_result`
类型，同时保留结果值和 errno。缺少返回消息与返回值为零分别表达；非阻塞网络
调用的 `EINPROGRESS` 和 `EALREADY` 按“进行中”处理。

单条消息上限为 1 MiB，握手上限为 256 字节，默认握手超时为 5 秒。
非法消息、未知类型、身份不符和断线都会产生诊断。累计丢失计数按连接记录；
计数下降时标记重置或回绕边界，增量保留未知。

消费端须同步完成留存规则、脱敏和持久接收，再返回成功；写入失败会停止接收。
正常 EOF 记录为断线，完整性结论还需结合 producer 的生命周期和采集收尾证据。
该接收器的能力清单不包含 TLS 正文采集。

## 持久化与交付

`telemetry.SecCheckStream` 复用原生 spool 引擎，分别保留运行锁、格式和计数器。
原生与 SecCheck worker 只恢复、处理各自的批次；容量预留同时计入两类来源。
队列已满或 SecCheck 记录超限时，消费端向接收器返回错误。

入库存储登记身份、采集与接收时间、消息摘要、消息头、操作和结果。
exec 环境变量及凭据字段被省略，命令参数在落盘前经过现有脱敏器处理。
消费端完成 fsync 后才返回接收成功。

作用域、连接 ID 和接收序号共同标识观察记录。spool 恢复后重复处理同一记录只保留
一条事件；相同身份对应不同正文时，批次保留并记录冲突。重连创建新的观察序列。
当前协议没有跨连接的持久 producer 序号，无法据此对任意跨连接重发去重。

### 重启与重连

接收器通过端点锁避免相互替换套接字。异常退出后，只清理由接收器用户拥有、
且经连接检查确认已失效的套接字。普通文件、符号链接和活动监听器保留原样；
私有 `.lock` 文件留给下次启动继续使用。

使用同一数据目录和登记配置重启，可恢复已经持久接收的批次。恢复遗留端点时
保存 `stale_endpoint_recovered`，健康报告增加
`sentry_node_receiver_restart_gap`。这是节点范围的中断诊断，丢失数量保留未知。

固定版本 runsc 的发送端沿用原连接。沙箱仍在运行时，先等待新接收器显示
`listening`，再用原运行时状态目录和配置重建 trace session：

```sh
sudo /path/to/runsc --root=/run/agentprov-runsc trace create \
  --force --config=/absolute/path/to/trace.json workload-1
```

沙箱生命周期保持不变，新连接独立记录丢失计数和观察序号；断线期间的事件保留为
采集缺口。接收器暂时过慢时，runsc 会丢弃未能发送的消息，并在后续送达消息中
报告累计丢失数；若没有后续消息，最终丢失总量保持未知。

图谱校验检查保存的登记证据及完整限定的身份。签名 Bundle 导入、导出保留事件
和图边，既有原生进程身份版本与历史签名数据保持原样。

## 离线阅读

导入签名 Bundle 后，可用现有 `dashboard export --run RUN_ID` 命令生成只读 ZIP。
解压后直接打开 `index.html`，查看已保存事件正文、搜索结果及进程、文件图谱，
各项记录保留 Sentry 作用域。ZIP 是未签名的阅读副本，请保留原 Bundle 和签名文件
用于签名核验。分类排除同样适用；排除全部运行时记录时，回放展示空视图和选择清单。

## Linux 验收

正式 CLI 验收脚本复用传输测试的受控负载，并发运行两个隔离沙箱：

```sh
go build -o /tmp/agentprov ./cmd/agentprov
CGO_ENABLED=0 go test -c ./internal/seccheck -o /tmp/seccheck.test
sudo python3 scripts/accept_seccheck.py \
  --cli /tmp/agentprov --runsc /absolute/path/to/runsc \
  --rootfs /absolute/path/to/rootfs --workload /tmp/seccheck.test \
  --output /absolute/path/to/new-acceptance-directory
```

脚本需要 Python 3.11 或更新版本，保存登记配置、运行时配置、CLI 状态、健康结果、
图验证结果及二进制摘要。结束后清理自身的运行时状态与网络 namespace 挂载，
保留 Docker/K3s 的现有配置。

故障验收使用相同参数，另选一个新输出目录：

```sh
sudo python3 scripts/accept_seccheck_faults.py \
  --cli /tmp/agentprov --runsc /absolute/path/to/runsc \
  --rootfs /absolute/path/to/rootfs --workload /tmp/seccheck.test \
  --output /absolute/path/to/new-fault-acceptance-directory
```

脚本暂停真实接收进程，让沙箱产生有界 syscall 突发，核对上游实际报告的丢失；
再向独立测试库注入临时写入失败，保留已 fsync 的批次后强杀采集器。重新启动并
接回同一沙箱后，检查身份连续性、原证据不变、恢复记录去重、采集缺口及图谱校验，
并通过签名导出、导入核对全部观察记录及诊断保真。
数据库故障通过测试触发器注入；运行时、进程信号、套接字拥塞和重启均实际执行。

准备独立 OCI 根文件系统、固定版本运行时及其相邻的 `gvisor-bin` 目录。
无需修改 Docker 或 K3s 的运行时配置。按 Linux 主机架构编译并运行：

```sh
go test -c ./internal/seccheck -o /tmp/seccheck.test
sudo env \
  AGENTPROV_TEST_RUNSC=/absolute/path/to/runsc \
  AGENTPROV_TEST_GVISOR_ROOTFS=/absolute/path/to/rootfs \
  AGENTPROV_TEST_SECCHECK_OUTPUT=/absolute/path/to/acceptance-output \
  /tmp/seccheck.test -test.v -test.timeout=1m
```

实机用例采用 `systrap`、独立 OCI 状态目录、只读根文件系统和仅回环网络。
两个并发沙箱验证独立的 PID 1 生命周期、多线程、exec、文件结果，以及阻塞和
非阻塞网络结果。测试结束后清理自身创建的运行时状态和网络命名空间挂载。
协议故障用例另行覆盖重连、丢失计数变化、非法握手、外来身份、竞争连接和
写入失败，报告中区分实机采集与注入的协议故障。

传输用例的 JSON 输出保存受控验收数据。若要同时验证持久化、来源隔离、图谱校验
和签名 Bundle 往返，可编译 telemetry 用例并复用 workload 二进制：

```sh
go test -c ./internal/telemetry -o /tmp/telemetry.test
sudo env \
  AGENTPROV_TEST_RUNSC=/absolute/path/to/runsc \
  AGENTPROV_TEST_GVISOR_ROOTFS=/absolute/path/to/rootfs \
  AGENTPROV_TEST_SECCHECK_WORKLOAD_BINARY=/tmp/seccheck.test \
  AGENTPROV_TEST_SECCHECK_OUTPUT=/absolute/path/to/persistence-output \
  /tmp/telemetry.test -test.run='^TestSecCheckLivePersistence$' -test.v -test.timeout=2m
```

每次验收使用新的输出目录。持久化用例保留来源存储、导入后的接收存储、
事件清单及结果摘要，来源存储中包含签名 Bundle 和签名文件。
协议来源及生成步骤见[协议说明](../../internal/seccheck/wire/README.zh-CN.md)。
