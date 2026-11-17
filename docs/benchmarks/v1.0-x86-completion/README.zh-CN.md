# v1.0 x86 收尾验收

[English](README.md)

更新于 2026-11-17，工作分支为 `feature/v1.0-portable-evidence`。
本轮 x86 实机案例、有界性能测试和候选安装包已整理好，供维护者审阅。
已确认的示例首页和阅读器已接入当前源码的正式构建，构建方式见
[本地阅读器](../../../previews/v1.0-reader/README.zh-CN.md)。
24 小时长测、安装包更新和发布按维护者安排暂缓。下表保留各次验收的实际版本；
后续界面调整沿用这些记录，采集时间与原始签名保持原样。

## 需求与结果

| 需求 | 验收结果 | 证据 |
| --- | --- | --- |
| C-01 | 通过鉴权的接收方 API 保留精确 Sentry 出生身份、命令采集水位；命令计数与容器累计计数分开保存 | [runsc 最终结果](runsc-final.json) |
| W-01 | 原生 Sensor 与真实 Claude MCP 完成 Inspect、Read、Edit、Write、Bash 和最终 Read；冲突、并发修改、重启查询、路径及代次检查通过，完成签名交付和断网阅读 | [Workspace 最终结果](workspace-final.json) |
| E-01/E-02 | 三种交付模式、生产者／导出者信任、未知密钥、错误角色和篡改检查通过；四个平台安装包来自同一源码，均包含独立验证器 | [候选包结果](candidate-packages.json) |
| R-01 | 沿用 native、K3s、gVisor、Firecracker 的已有证据，补验 runsc 与 Guest 平台身份绑定 | [已有平台矩阵](../v1.0-amd64/README.zh-CN.md)、[runsc](runsc-final.json)、[Kata](kata-final.json) |
| R-02 | 正常执行、接收端重连、接收端重启、执行器重启和取消共五组场景通过；覆盖重复提交／查询、响应丢失、显式重试和错误代次拒绝 | [runsc 最终结果](runsc-final.json) |
| R-03 | 九项检查通过：Guest 内核、单命令交付、并发隔离、故障恢复、运行时绑定、离线交付、独立验证、Pod 重建、真实 Workspace Harness | [Kata 最终结果](kata-final.json)、[版本锁](kata-versions.lock.json)、[四份离线阅读包](kata-offline-final.json) |
| B-01/B-02/B-03 | 并发 context/tab、重定向、iframe/worker、后台请求、下载、进程身份绑定、SIGKILL 恢复和查询不重复执行通过；选择性导出移除失去支撑的原生关联 | [Browser 最终结果](browser-final.json) |
| Q-01，本轮有界范围 | Sensor 压力、10 万事件摄入、资源和上下文／导出预算通过；原预算及此前失败记录均保留 | [性能最终结果](performance-final.json) |
| 阅读器历史验收 | 五组桌面案例、中英文移动端与断网阅读、真实 Workspace 选择性导出通过；图谱、Compare、搜索、正文和附件入口保留 | [预览结果](preview-final.json) |
| 完整 CI | `b9e6b8f` 上 15 项门禁全部通过，含 50 个 Go 测试包的 race 检查、历史包与数据库升级、双架构构建和 eBPF 绑定检查 | [CI 运行](https://github.com/ByteYellow/AgentProvenance/actions/runs/43997596391)、[完整结果](ci-final.json) |

## 测试版本

结果分别记录实际采集版本和导出版本：

- Workspace、runsc 和 Kata 的采集程序：干净源码 `d8a7b60`。
- Browser 启动辅助程序和最终 Kata 验收脚本：干净源码 `85dd7be`；采集二进制仍为 `d8a7b60`。
- 图存储改进和 Workspace/Browser 阅读副本：干净源码 `f3deb10`。
- 最终候选包：干净源码 `b9e6b8f`，内置本轮整理后的文档。
- 审计规则 v4：`e82f1a3`，包含真实 CI 失败记录的回归。
- 验收辅助脚本及性能比较规则：`4fb34ea`。

`f3deb10` 将图视图中重复的完整节点和边合并保存，36 组视图／查询对比结果一致，
历史阅读包继续可用。三项 Browser 导出体积都回到了原预算内；basic 案例从
2,447,919 字节降至 1,476,157 字节。原生 Sensor 和摄入代码未改动，沿用
`d8a7b60` 实测；上下文／导出性能和签名离线交付已使用 `f3deb10` 复测。

Kata 组合为 runtime-rs 4.3.1、QEMU 11.0.1、带 BTF 的 Guest 内核 6.18.56、
K3s 1.36.4+k3s1 和 containerd 2.3.4。版本锁保存程序、镜像、配置和二进制摘要。
两次 Guest 启动均通过身份拒绝、交付、并发隔离和恢复检查；第二次还完成了真实
Workspace Harness，并确认旧 Target 被拒绝。

通用 Kata 脚本还包含更广的后续矩阵，因此原报告总状态保留 `PENDING`；
本轮 `r03_status=PASS` 和九项必做结果原样保留。Kata 专属的 Browser、恢复／双克隆、
强制回收、迟到证据、兼容性及 24 小时检查仍在报告中列出。本轮相应共享契约
使用其他平台已记录的案例，长测继续暂缓。

## 性能与失败记录

[performance](performance) 目录保留原始报告、冻结预算和比较结果。
最终通过 18 项 Sensor 检查、5 项摄入检查和 68 项上下文检查。实测时长约为：
Sensor 矩阵 201 秒、满环形缓冲压力 24 秒、10 万事件摄入 52 秒、
最终上下文／导出测量 56 秒。

首次严格比较因虚拟机重启后 Linux `MemTotal` 相差 4 KiB 而失败。
后续比较显式记录这一页内存的差异，其他环境、输入、测量脚本和全部性能限额保持原样。
原始严格失败和三项导出体积超预算记录均保留。复现方法见[性能验收](../../zh-CN/performance-validation.md)。

Kata 前三轮的失败及原报告摘要分别保留：Guest 身份与 AppArmor 配置、环形缓冲压力、
任务专用 K3s 的 API／CoreDNS 绑定。修正后固定组合通过。
后续归档曾被宿主机 C 盘空间耗尽中断，恢复 WSL 和验收虚拟机后完成了最终导出检查。

收尾 CI 还暴露了一处短命进程漏关联：粗粒度审计时间窗口结束时，进程尚未启动。
v4 规则将已验证的 journal 接收时间用于进程候选，与已有系统调用规则保持一致。
真实 AppArmor/seccomp 失败记录、PID 重用及无效时钟回归见[审计结果](audit-final.json)。

Browser CLI 回归测试也已同步共享图格式（`b9e6b8f`），保留在线／离线关系逐项一致、
排除支撑记录和运行时数据后移除关联的断言。实际 CLI 与 race 回归结果见
[Browser 结果](browser-final.json)。

## 候选包与审阅入口

[候选包信息](candidate-packages.json)包含源码、工具链、程序哈希和归档大小。
[CANDIDATE_SHA256SUMS](CANDIDATE_SHA256SUMS)覆盖 Linux/macOS 的 amd64/arm64 四个包。
Linux amd64 在 `PATH` 中没有 Go 的环境下实跑通过：12 个签名示例、14 篇 Demo 指南、
20 篇使用指南、基础记录和独立验证器均可使用。其他包已交叉构建，
ARM/macOS 实测沿用此前的验收记录。

可从记录的源码使用 `scripts/build-release.py` 重建。安装包目前用于审阅，
本轮不打发布标签，也不部署 Pages。使用入口见[候选版本说明](../../zh-CN/releases/v1.0.0-preview.md)
和[预览重建说明](../../../previews/v1.0-reader/README.zh-CN.md)。

## 归档范围

[实机回放包](replays/README.zh-CN.md)包含七份离线阅读 ZIP 和六份保留原样的签名包，
覆盖真实 Claude Workspace、开启 Sensor 的 Browser、中断恢复及 Kata/QEMU。
随附清单列出 Run、采集／导出源码 SHA 和文件校验值。

`*-final.json` 是经过检查的机器可读汇总，包含原始报告摘要；性能 JSON 和 Kata
版本锁保留源文件字节。私钥、接口凭据和原始模型日志留在本地私有验收目录。
[SHA256SUMS](SHA256SUMS)覆盖此目录中的公开文件。

此前的 `workspace.json`、`browser.json`、`runsc-*.json` 和 `kata-startup.json`
作为历史结果保留原版本身份。已有的 [gVisor 接收、故障和双克隆原始结果](../v1.0-amd64/gvisor/summary.json)
及 [Firecracker/KVM/K3s 矩阵](../v1.0-amd64/README.zh-CN.md)继续保留。
