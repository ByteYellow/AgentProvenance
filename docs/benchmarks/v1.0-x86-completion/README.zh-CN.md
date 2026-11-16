# v1.0 x86 收尾验收记录

[English](README.md)

这里保存 11 月 16 日 x86 实机测试的机器可读汇总。下表按具体场景记录结果，
v1.0 尚未完成的项目列在文末。24 小时长测继续按维护者决定暂缓。

| 场景 | 结果 | 证据 |
| --- | --- | --- |
| Workspace 原生采集与真实 Claude MCP 调用 | 已通过：Inspect、Read、Edit、Write、Bash、最终读取，以及版本冲突、并发编辑、路径和 generation 检查 | [Workspace](workspace.json) |
| Workspace 签名交付与离线阅读 | 已通过：停用源数据目录后导入独立接收方，检查信任、未知密钥、错误角色和篡改；两个阅读包均无网络请求 | [Workspace](workspace.json) |
| Browser 原生采集与签名交付 | 已通过：并发 context/tab、重定向、iframe/worker、后台请求、下载、选择性导出及四个离线阅读包 | [Browser](browser.json) |
| Browser 强制退出后的恢复 | 已通过：对完成和中断的操作各查询三次，两种 HTTP 副作用均只发生一次；中断的 generation 保持未封存 | [Browser](browser.json) |
| runsc 受控命令启动 | 已在干净的 `45ce9ad` 源码上通过：启动前保存 Sentry 出生身份，回执保存失败时拒绝执行，取消后保留未知结果 | [runsc](runsc-controlled.json) |
| runsc 逐命令采集 | 已通过：成功及非零退出、原生子进程归属、持久化完成标记和原始事件身份 | [命令证据](runsc-command-capture.json) |
| runsc API 与故障恢复 | 已通过：响应丢失、重复提交／查询、显式重试、错误 generation、签名交付、接收端断连／重启、执行器重启和取消 | [故障矩阵](runsc-execution.json) |
| Kata/QEMU Guest | 未完成：Guest Sensor 及必需探针已就绪；命令准备阶段发现 SQLite 写入竞争，修复后仍需完成整轮复测 | [Kata 历次结果](kata-startup.json) |

## 源码与校验信息

Workspace 和 Browser 使用的 CLI 构建于本地提交 `cdfb7cb`，其完整 Git tree
与已推送的 `71d8625` 相同。汇总保留了二进制身份和原始报告摘要。这两次测试
的原始顶层报告没有记录脚本所在 checkout 的 SHA；最终候选验收会补齐脚本版本
记录，历史结果继续保留原有身份。

runsc 复测使用已推送的 `45ce9ad3179d55091073775af1893f805336e240` 干净源码，
重新构建 CLI 和测试程序，并创建独立测试容器。汇总包含程序摘要、进程出生
身份、保存失败和取消结果，以及测试日志摘要。

逐命令采集和 API 故障矩阵分别记录了干净的 CLI／脚本源码版本、程序摘要、原始
报告摘要和各场景的检查点。API 矩阵的五个场景全部通过，总耗时 82.98 秒。
其中 CLI 源码 `afe3f96` 与已推送的 `5fea599` 仅在
`scripts/accept_execution_runsc.py` 上有差异，应用代码相同；实际使用的验收脚本
另行固定为 `fbaebd3`，并记录文件摘要。此前三次脚本验收失败也一并保留。

公开 JSON 汇总保留各项检查结果、证据引用、采集计数、交付包摘要和原始报告
摘要。模型凭据、签名私钥和模型对话日志留在本地私有目录。
[SHA256SUMS](SHA256SUMS) 用于核对这里公开的文件。

## 后续收尾

- 完成 Kata 原生采集期间的命令准备、并发隔离、恢复、Pod 重建、旧 Target
  拒绝和真实 Workspace Harness 验收。
- 补齐其余边界复核、有时限的资源测试、最终安装包检查（含 runsc 回归），以及预览和文档审阅。

正式 Dashboard 接入、合并 main、打 tag、发布 Release 和部署 Pages 仍待维护者审阅。
