# v0.10.1 Windows 更新后的 KVM 验收

[English](README.md) | 中文

2026-11-06，用户重启 Windows 后补跑验收。**真实 KVM 加速已恢复，功能验收全部通过。**
WHPX 下仍存在的 CET 崩溃在下文单独记录。

测试源码为 `8ea1dbf226cba48e38754ee7d90af7d0fa6fbdf5`，其中生产代码对应
`d77712dca426ddbea3340f0a74ecf316bb491c83`。本轮复用[此前 procfs 验收](../v0.10.1-procfs/README.zh-CN.md)
的同一组程序，没有修改生产代码、采集预算或等待时间。
[源码与程序校验值](source-identity.json)记录实际版本；ARM64 对象保持原样。

## 环境

安装 KB5127936 并重启后，Windows 版本为 `26300.9818`，已无待重启状态。
WSL 内核 `6.18.33.2-microsoft-standard-WSL2` 重新暴露 `svm`；`/dev/kvm` 的 API
版本为 12，创建虚拟机成功。Linux QEMU 10.2.1 使用 `-accel kvm -cpu host` 启动，
QMP 返回 KVM `enabled=true, present=true`，guest 内 `systemd-detect-virt` 返回 `kvm`。

Ubuntu guest 使用 `6.8.0-139-generic`、4 个 vCPU 和 4 GiB 内存，正常启动参数中没有
`nousershstk`。此嵌套 KVM CPU 未暴露 `user_shstk`，显式启用影子栈返回 `-95`。
启用 CET 的运行情况见独立的 WHPX 实验。
[宿主记录](host.json) · [Guest 环境](environment.txt) · [CPU 标志](cpu-flags.txt) · [CET 检查](cet-check.log)

## 验收结果

| 检查项 | 结果 | 证据 |
| --- | --- | --- |
| 原生探针测试 | 14 个顶层测试、8 种 TLS 发现模式全部通过，无失败或跳过 | [日志](native.log) |
| 独立系统调用、DNS、C/OpenSSL 与 Go TLS 检查 | 62/62 项通过 | [报告](sensor-live.json) |
| systemd 采集、签名导出与导入 | 18 条原生工作负载事件；原始图、签名和导入后的图均通过校验 | [报告](guest-service.json) |
| K3s 归属与 Pod 删除 | 105 条原生事件、12 条绑定关闭，图校验通过 | [报告](guest-k3s.json) |
| 容器 TLS 发现与重建 | 30/30 项通过 | [报告](container-tls.json) |
| 迟到绑定、SIGKILL 恢复与去重 | 13/13 项通过 | [报告](node-capture.json) |
| Daemon 就绪状态与存储故障 | 11/11 项通过 | [报告](daemon-readiness.json) |
| 采集服务重启 | 两个 Run 的入库事件数保持为 27 和 111，服务恢复 active、ready | [报告](service-restart.json) |

首次恢复测试与常驻采集器及其他 guest 实验同时运行，13 项目标断言通过，同时记录了
**11,923 条内核丢弃事件**。[原始报告](node-capture-concurrent.json)已保留。
随后暂停常驻采集器，单独复跑恢复测试，再恢复服务：13 项再次通过，报告中没有出现内核丢弃计数。
本轮完成的是功能与恢复验收；此前暂缓的 24 小时长跑仍未执行。

[原始证据包](kvm-evidence.tar.gz)包含完整 JSON、命令日志、采集事件、签名回放包及验签公钥。
本目录便于阅读的 JSON 副本省略了部分冗长的 stderr/diagnostics 字段，完整内容保留在证据包中。
原生测试入口为 [run-native.sh](run-native.sh)，其余检查使用仓库现有的
`accept_sensor_live.py`、`accept_kvm_guest.py`、`accept_k3s_guest.py`、
`accept_container_tls.py`、`accept_node_capture.py` 和 `accept_daemon_readiness.py`。
服务重启检查保存在 [service-restart.py](service-restart.py)。

## WHPX 与 CET 对照实验

更新后的 Windows 上，QEMU 11.1.0/WHPX 配合同一 Ubuntu 6.8 内核仍暴露 `user_shstk`。
小型影子栈启用、状态读取、函数返回及关闭检查通过，随后 14 个原生测试全部通过。
但 guest 在启动约 204.58 秒后因 PID 1 退出而发生内核崩溃。
[环境](whpx-environment.txt) · [CET 检查](whpx-cet-check.log) ·
[原生测试日志](whpx-native.log) · [控制台](whpx-cet-console.log.gz)

随后两次冷启动从内核参数中屏蔽 `agentprov-sensor`、K3s 和 Docker，确认三个服务均未运行，
也没有 AgentProvenance 进程。启动独立的 [CET 测试程序](cet-context-check.c)后，
分别在启动约 54.65 秒和 78.46 秒时再次出现 PID 1 崩溃。
最后一次宿主日志只收到启动标记和连接中断，没有收到辅助程序成功启动或完成的消息。
这两次启动过程中未运行项目采集器，仍复现了故障；WHPX/CET 的具体故障原因还未解决。

[对照环境](whpx-control-environment.txt) · [首次对照控制台](whpx-control-console.log.gz) ·
[再次对照控制台](whpx-control-final-console.log.gz) · [宿主侧输出](whpx-control-live.log) ·
[QEMU 错误日志](whpx-control-final-stderr.log.gz)

这台机器使用本轮通过验收的 KVM 路径。原始虚拟机磁盘与宿主安全设置均已保留；实验使用独立
KVM 差分盘和 WHPX 临时副本。[SHA256SUMS](SHA256SUMS)覆盖本报告的文件，不包含自身。
