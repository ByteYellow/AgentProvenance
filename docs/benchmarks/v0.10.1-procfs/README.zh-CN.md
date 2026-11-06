# v0.10.1 procfs 命名空间适配与后续验收

[English](README.md) | 中文

后续结果：Windows 重启后，真实 KVM 已恢复，功能验收通过。
[重启后报告](../v0.10.1-kvm-postreboot/README.zh-CN.md)也记录了仍存在的 WHPX/CET 故障。
本报告保留此前的验收结果和重启前安装状态。

2026-11-06 从 `fix/v0.10.1-pr34-integration` 的 `2ab9e92` 继续验收。
本轮修复 WSL 直接采集，并增加嵌套 PID 命名空间回归检查。
[源码与程序校验值](source-identity.json)记录实际测试版本；ARM64 eBPF 对象保持原样。

## 修复内容

amd64 探针保留原始内核 PID/TID 和进程生命周期，另外使用容量为 16,384 的 LRU 映射，
记录任务在采集器 PID 命名空间中的地址，也支持容器的子命名空间。
采集器运行期间持有命名空间文件描述符。状态采样、TLS 发现和容器 procfs 回退查询使用映射后的地址。
规范化事件新增 `procfs_pid`、`procfs_tid`、`procfs_pid_namespace`，入库后仍保留这些字段。

映射缺失时跳过 procfs 查询，增加 `lookup_misses` 并报告降级；不可见命名空间中的任务单独计数。
`/proc` 挂载与采集器命名空间不匹配时，启动直接报错。
能力报告列出命名空间、映射容量、转换次数、不可见任务数和映射缺失数。

guest 验收脚本也补上 QEMU/WHPX 的识别：hypervisor 为 Microsoft 时，仍要求 DMI 明确标识 QEMU，
报告保留两项实际观测值。

## 验收结果

| 检查 | 结果 |
| --- | --- |
| WSL 自动状态采样 | 通过；实际发生 PID 转换，映射缺失为零。[最终日志](access-state-final.log) |
| WSL 短命 TLS 进程 | 八种模式全部通过。[最终日志](tls-final.log) |
| 嵌套 PID 与挂载命名空间 | 状态采样，以及自动发现、并发、延迟加载、新 Go 程序四种 TLS 场景通过。[日志](pid-namespace.log) |
| 错误 proc 挂载 | 正确挂载可采集，错误挂载按预期拒绝启动。[日志](namespace-guard.log) |
| 软件回归 | sensor、accesscontrol、telemetry、producer、K8s informer 五个包的 race 测试通过。[日志](race-final.log) |
| guest 识别与签名回放 | 三项测试通过。[日志](guest-script-tests.log) |
| 探针生成 | 重新生成检查通过，ARM64 对象未变。[日志](regenerate.log) |
| Ubuntu 6.8 原生测试 | 14 个顶层测试、八种 TLS 发现模式全部通过，无失败或跳过。[日志](native.log) |
| 独立 syscall/C/Go ABI 检查 | 62 项断言全部通过。[报告](sensor-live.json) |
| systemd 采集与签名回放 | 20 条工作负载原生事件；原始图谱、签名和导入后的图谱均验证通过。[报告](guest-service.json) |
| K3s 归属与 Pod 删除 | 104 条原生事件、12 条关闭的绑定，图谱验证通过。[报告](guest-k3s.json) |
| 容器重建后的 TLS 自动发现 | 30 项断言全部通过。[报告](container-tls.json) |

首次 WSL TLS 测试与构建任务同时运行时，漏掉一次延迟加载后的首个请求；[失败日志](tls-initial.log)已保留。
随后该场景独立[重复三次](tls-delayed-repeat.log)均通过，最终八种模式也全部通过。
自动挂载仍可能晚于最早的 TLS 调用，需要覆盖首个调用时应预先指定目标。
本轮未延长用例等待时间，也未提高采集上限。

[完整 guest 证据包](guest-evidence.tar.gz)保留完整报告、事件、签名回放包及验证公钥。
采集服务保持 active，重启次数为零；见[服务状态](service-state.txt)与[环境记录](environment.txt)。

## Windows 宿主与 CET 排查

本机为 AMD 平台，Windows build `26300.9711`，已安装 KB5127648。
当前 WSL 缺少 `svm` 标志，加载 `kvm_amd` 报 CPU 不支持。
微软在 [KB5127936、build 26300.9818](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/10/kb5127936-windows-11-25h2-26h2-update)
中列出了嵌套虚拟化修复。对应 x64 安装包已从 Microsoft Update Catalog 下载，
SHA-256 与官方目录元数据一致。安装阶段于北京时间 23:14 完成，WUSA 返回
**3010（成功，需重启）**；目标更新包已登记，系统处于待重启状态。
按用户要求，由用户稍后手动重启，本轮未触发重启。之后继续补跑真正的 KVM 与默认 CET 配置验收。
[宿主与安装包记录](host-update.json) · [安装结果](update-install-result.json)

QEMU 11.1.0 搭配 Ubuntu 6.8、保留默认 CET 时，可以启动并通过小型影子栈启用/返回测试；
运行约 563 秒后，PID 1 出现异常码 44，随后内核 panic。
[控制台](whpx-cet-panic.log.gz)和 [QEMU 错误](whpx-cet-stderr.log.gz)已保留。
在该 WHPX 环境中，`cet-ss=off,cet-ibt=off` CPU 参数也未移除 `user_shstk`。

另外用 Ubuntu HWE `7.0.0-42-generic` 做了对照：保留 CET，100 次显式影子栈测试通过，
但原生验收出现 syscall 结果遗漏、延迟 TLS 发现失败，独立采集脚本也缺少一个 exec 锚点。
因此本轮没有采用这个内核作为替代环境。[完整实验记录](hwe-experiment.tar.gz)同时保留成功与失败项，
项目采集代码没有为这次实验修改事件规则。

最终功能复测仍使用 Ubuntu `6.8.0-139-generic`、QEMU 11.1.0/WHPX，
只在一次性磁盘副本中加入 `nousershstk`。
该参数关闭 guest 用户态影子栈，见 [Linux 内核说明](https://docs.kernel.org/next/x86/shstk.html)。
原始虚拟机磁盘、宿主安全设置和 ARM64 对象均未改动。24 小时持续验收按此前约定暂不进行。

[SHA256SUMS](SHA256SUMS)包含本目录文件的校验值，清单自身除外。
