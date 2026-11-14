# gVisor SecCheck 接收器

[English](../gvisor-seccheck.md) | 中文

`internal/seccheck` 提供 gVisor producer 的传输接收层，固定使用
`runsc release-20261109.0`、协议版本 1，以及源码提交
`a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`。

类型化事件和连接诊断已接入现有持久缓冲、运行时图谱、签名 Bundle 及离线回放链路。
用户采集配置和 producer 健康报告继续推进，
目前尚未增加面向用户的采集命令。

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

图谱校验检查保存的登记证据及完整限定的身份。签名 Bundle 导入、导出保留事件
和图边，既有原生进程身份版本与历史签名数据保持原样。

## 离线阅读

导入签名 Bundle 后，可用现有 `dashboard export --run RUN_ID` 命令生成只读 ZIP。
解压后直接打开 `index.html`，查看已保存事件正文、搜索结果及进程、文件图谱，
各项记录保留 Sentry 作用域。ZIP 是未签名的阅读副本，请保留原 Bundle 和签名文件
用于签名核验。分类排除同样适用；排除全部运行时记录时，回放展示空视图和选择清单。

## Linux 验收

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
