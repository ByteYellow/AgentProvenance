# v0.10.1 Linux x86_64 验收

[English](README.md) | 中文

2026-11-06 从 `fix/v0.10.1-pr34-integration` 分支的 `45d1c00` 开始验收。
原便携包（源码 `4828cce`）及修正后的程序均在 Ubuntu 24.04.5、内核 `6.8.0-139-generic` 上通过。
本轮虚拟机使用 QEMU/WHPX，修正后的程序使用 Go 1.23.12 构建。
[源码与程序校验值](source-identity.json)记录了实际测试版本；ARM64 对象保持原样。

## 验收结果

| 检查 | 结果 |
| --- | --- |
| 原便携验收包 | 三组全部 PASS，无跳过。[原始日志](baseline-package) |
| 修正后的原生测试 | 14 个顶层测试全部通过，无失败、无跳过；覆盖系统调用结果、procfs 状态、OpenSSL 生命周期/并发/分块边界/真实丢失、Go TLS Read。[日志](native.log) |
| 短命 TLS 进程发现 | 八种模式全部通过，首个请求分别捕获 1/1、1/1、1/1、1/1、1/1、8/8、2/2、1/1；挂载延迟、CPU 和扫描次数保留在日志中。 |
| x86 系统调用、C/Go ABI、采集时间 | 62 项断言全部通过。[报告](sensor-live.json) |
| systemd 常驻采集与签名回放 | 记录 18 条工作负载原生事件，原始及导入后的图谱验证通过，签名验证通过。[报告](guest-service.json) |
| K3s 归属与 Pod 删除 | 记录 105 条工作负载原生事件，关闭 12 条绑定，图谱验证通过。[报告](guest-k3s.json) |
| Pod 迟到绑定、崩溃恢复与去重 | 13 项断言全部通过。[报告](node-capture.json) |
| Pod 重建后的容器 TLS 自动发现 | 30 项断言全部通过。[报告](container-tls.json) |
| daemon 就绪与存储故障 | 11 项断言全部通过。[报告](daemon-readiness.json) |
| 采集服务重启 | 两次执行的事件数保持 27 和 111，重启前后一致。[报告](service-restart.json) |

[完整 guest 证据包](guest-evidence.tar.gz)保留原始 JSON 报告、事件样本、诊断输出、签名回放包及公钥。
本目录的简版 JSON 去除了重复的能力输出；原始版本保存在证据包中。
[SHA256SUMS](SHA256SUMS) 包含本目录全部证据文件的校验值，校验清单自身除外。

## 修正内容与回归检查

命名系统调用 tracepoint 的 `__syscall_nr` 是 32 位整数，后面有对齐填充。
原代码按 64 位读取；WSL 6.18 内核中的非零填充进入调用号后，会让入口和返回匹配失败。
现在只使用有符号 32 位调用号，实机测试同时检查调用号是否与当前架构一致。
[原始诊断记录](wsl-syscall-diagnostic.log)保留了异常调用号。

探针生成参数补上 BPF ISA v3，满足 TLS 调用序号使用的原子递增指令要求。
本机重新生成及 `--check` 通过。amd64 CI 矩阵补入八种短命进程发现用例并上传指标。
虚拟机文档也已按 daemon 默认鉴权行为更新。

## 软件回归检查

全仓库 39 个包含测试的包均通过普通测试和 race 检查：

- `go test -count=1 -p 2 -timeout 10m ./...`：[普通测试日志](unit-tests.log)。
- `CGO_ENABLED=1 go test -race -count=1 -p 2 -timeout 20m ./...`：[race 日志](full-race.log)。

缓存排查的 [runner 堆栈](go-cache-diagnostic.log)单独保留。

`sensor`、`telemetry`、`producer`、`producer/k8sinformer`、`record` 的 race 测试全部通过，见[日志](targeted-race.log)。
`go vet ./...`、探针重新生成、签名 CLI 回放与篡改拒绝、上下文展示、Dashboard 工作区及静态阅读器检查也已通过。
文档检查覆盖 58 篇中文文档及本地链接、图片引用。

第一次全仓库运行耗在 Windows 挂载盘上的测试缓存计算。
Go runner 堆栈位于 `computeTestInputsID` / `search.InDir` / `filepath.EvalSymlinks`，当时测试子进程已退出；保留[初次部分日志](full-race-incomplete.log)。
最终两次全量验证均使用 `-count=1` 跳过测试结果缓存并通过，所有用例、断言和超时保持原样。

## 环境限制与后续事项

- **KVM 加速**：当前 Windows/WSL 主机加载 `kvm_amd` 仍报 `SVM not supported by CPU 0`，本轮使用 WHPX。嵌套虚拟化恢复后，还需在真正的 KVM 加速环境补跑。
- **WSL 直接采集**：内核 PID/TID 与发行版 `/proc` 的命名空间不一致，默认运行时的自动状态采样、事件驱动 TLS 发现验收失败。[原始日志](wsl-original)已保留。后续需补命名空间感知的进程查找和明确的覆盖报告；这台机器目前可使用已验证的 Linux guest 路径。
- **WHPX 下的 CET**：首次启动时，PID 1 在 libc 的返回指令处发生 `SIGSEGV`，页面异常码为 `44`，随后内核 panic。[控制台日志](whpx-first-boot.log.gz)已保留。最终验收只在测试副本中加入 `nousershstk` 后完成，见[环境记录](environment.json)。确切原因及开启 CET 时的兼容性还需独立复现；该参数见 [Linux 内核说明](https://docs.kernel.org/next/x86/shstk.html)。
- **长期运行**：按此前决定，暂不进行 24 小时持续验收。本轮覆盖功能与故障恢复。

本轮未放宽等待时间或采集上限，也未移除必需用例。验收完成后仍由维护者决定合并和正式发布。
