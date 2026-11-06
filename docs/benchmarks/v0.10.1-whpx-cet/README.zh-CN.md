# v0.10.1 WHPX CPU 配置修复与 CET 验收

[English](README.md) | 中文

验收时间为北京时间 2026-11-06 至 07 日。**使用 `-cpu max` 后，已复现的 WHPX guest 崩溃得到解决，CET 保持开启。**
Windows 仍为 `26300.9818`，QEMU 仍为原版 11.1.0，guest 内核仍为 Ubuntu `6.8.0-139-generic`。
本轮没有使用 `nousershstk`，也没有修改宿主安全设置。

## 原因与修复配置

[此前对照实验](../v0.10.1-kvm-postreboot/README.zh-CN.md)没有显式选择 CPU 模型。
Guest 暴露了 `user_shstk`，启动日志却显示 `x87 FPU will use FXSAVE`。
FXSAVE 不保存 CET 任务状态，启用影子栈后再切换任务，会影响其他任务的执行，甚至导致 PID 1 崩溃。
因此，短暂的启用、返回、关闭检查可以通过，持续切换任务才暴露出问题。

QEMU 11.1.0 的 [WHPX CPUID 实现](https://github.com/qemu/qemu/blob/v11.1.0/target/i386/whpx/whpx-all.c)
在处理 CPU 模型之后，又用虚拟化平台返回的结果覆盖 CET 标志。
这也解释了此前设置 `cet-ss=off` 后，guest 仍能看到 `user_shstk`。
修复方式是选择能力匹配的 CPU 模型，再冷启动虚拟机：

```text
qemu-system-x86_64.exe -accel whpx -cpu max ...
```

修改后，guest 同时暴露 `xsave`、`xsaves` 和 `user_shstk`。
启动日志包含 XSAVE 功能 `0x800`（`Control-flow User registers`），并采用紧凑格式保存状态。
CPUID 的 `0xD` 叶、子叶 1 在 XSS 掩码中报告了 CET 状态支持。
4 个辅助进程运行期间，`/proc/<pid>/status` 均显示 `x86_Thread_features: shstk`，
对应内核提供的[线程影子栈状态](https://docs.kernel.org/arch/x86/shstk.html)。
[环境记录](max-environment.txt) · [CPUID 与运行中线程状态](max-cpuid-and-active-cet.txt)

## 验收结果

第一次冷启动禁用采集器、K3s 和 Docker，重复此前的对照场景。
第二次冷启动恢复常驻服务，再执行采集验收。两次均使用修复后的 CPU 配置，保留 CET。

| 检查项 | 结果 | 证据 |
| --- | --- | --- |
| 单进程开启 CET，运行 120 秒 | 107,166 次嵌套函数返回、CPU 迁移、让出调度与休眠循环，无错误 | [日志](max-context-single.log) |
| 4 个进程开启 CET，各运行 240 秒 | 每个进程完成超过 215,000 次循环，退出时成功关闭 CET | [日志](max-context-parallel.log) |
| 原生探针 | 14 个顶层测试及 8 种 TLS 发现模式全部通过，无跳过 | [日志](native.log) |
| CPU 预检与签名回放测试 | 10/10 项通过 | [日志](guest-tests.log) |
| 独立系统调用、DNS、C/OpenSSL 与 Go 检查 | 62/62 项通过 | [报告](sensor-live.json) |
| systemd 采集、签名导出与导入 | 20 条原生事件，原始图、签名和回放图校验通过 | [报告](guest-service.json) |
| K3s 归属与删除 | 107 条原生事件、12 条绑定关闭，图校验通过 | [报告](guest-k3s.json) |
| 容器 TLS 重建 | 30/30 项通过 | [报告](container-tls.json) |
| 迟到绑定、崩溃恢复与去重 | 13/13 项通过，未报告内核丢弃计数 | [报告](node-capture.json) |
| Daemon 就绪与存储故障 | 11/11 项通过 | [报告](daemon-readiness.json) |
| 服务重启 | Run 事件数保持为 27 和 114，服务恢复 active、ready | [报告](service-restart.json) |
| 常驻服务运行时的 CET 检查 | 4 个进程各运行 300 秒，全部正常完成 | [日志](service-context-parallel.log) |
| 第二次启动持续观察超过 600 秒 | 采集器 ready，显式 CET 检查通过，未记录内核崩溃或段错误 | [报告](final-check.json) |

这套 QEMU CPU 模型启动时仍有一条 `misordered xstate` 警告，原始日志中已保留。
上述上下文切换和采集检查均在这条警告存在的情况下通过。
此前暂缓的 24 小时长跑仍未执行。

## 防止再次使用错误配置

`scripts/accept_kvm_guest.py` 现在会在执行工作负载前检查每个 x86 CPU。
如果暴露了 `user_shstk`，却缺少 `xsave` 或 `xsaves`，脚本会停止验收，指出缺失能力并给出冷启动配置。
报告会保留 CPU 的共同标志，ARM guest 跳过这项 x86 检查。

CLI 与探针程序沿用此前验收版本，ARM64 对象保持原样。
[版本记录](source-identity.json)包含程序、更新后的验收脚本及 QEMU 可执行文件的校验值。
本地 WHPX 启动脚本已补上 `-cpu max`，旧版脚本已备份。

[原始集成证据](integration-evidence.tar.gz)包含完整日志、事件、JSON 报告、签名回放包与公钥。
本目录便于阅读的 JSON 副本省略了冗长的 stderr/diagnostics 字段，文本副本去除了行尾空白；原始文本保留在证据包中。
[CET 辅助程序](cet-context-check.c)、[CPUID 检查](cpuid-state.c)、[集成入口](run-integration.sh)、
[重启检查](service-restart.py)与[最终检查](final-check.py)均已保留。
[对照控制台](control-console.log.gz)和[服务运行控制台](service-console.log.gz)记录两次启动。
[SHA256SUMS](SHA256SUMS)覆盖除自身以外的全部文件。
