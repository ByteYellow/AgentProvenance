# gVisor SecCheck 接收器

[English](../gvisor-seccheck.md) | 中文

`internal/seccheck` 提供 gVisor producer 的传输接收层，固定使用
`runsc release-20261109.0`、协议版本 1，以及源码提交
`a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`。

当前模块接收类型化事件和连接诊断。持久缓冲、运行时图谱映射、CLI 配置及回放
将在后续接入，目前尚未增加面向用户的采集命令。

## 作用域与身份

可信执行入口登记命名空间、实例、生命周期代次、sandbox、container，以及预期
本地连接用户的 UID。每个 sandbox 使用独立的私有 Unix `SOCK_SEQPACKET`
端点。同时到来的第二条连接会被拒绝；重连获得新的连接 ID 和接收序号，
已登记的生命周期保持不变。

接收器分别保存 Sentry 的线程 ID、进程组 ID，以及各自的出生时间，并结合登记
作用域生成身份。父进程组编号先作为观察值保留，后续再根据生命周期证据关联。
Socket 对端 PID 用于描述本地传输客户端，与沙箱内进程身份分开。
消息中的 container ID 必须与登记值一致。

## 事件与异常

首批解析 container start、clone、exec、open、connect 和 exit 消息，保留系统调用
入口和返回记录的区别。缺少返回消息与返回值为零分别表达；非阻塞网络调用的
`EINPROGRESS` 按“进行中”处理。

单条消息上限为 1 MiB，握手上限为 256 字节，默认握手超时为 5 秒。
非法消息、未知类型、身份不符和断线都会产生诊断。累计丢失计数按连接记录；
计数下降时标记重置或回绕边界，增量保留未知。

消费端须同步完成留存规则、脱敏和持久接收，再返回成功；写入失败会停止接收。
正常 EOF 记录为断线，完整性结论还需结合 producer 的生命周期和采集收尾证据。
该接收器的能力清单不包含 TLS 正文采集。

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

可选 JSON 输出保存受控用例数据，供验收复查；签名证据 Bundle 在后续交付链路
接入。协议来源及生成步骤见[协议说明](../../internal/seccheck/wire/README.zh-CN.md)。
