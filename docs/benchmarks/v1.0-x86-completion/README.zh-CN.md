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
| Kata/QEMU Guest 启动 | 未完成：平台身份和 BPF 前置检查已通过，原生采集器启动超过验收预算 | [Kata 历次结果](kata-startup.json) |

## 源码与校验信息

Workspace 和 Browser 使用的 CLI 构建于本地提交 `cdfb7cb`，其完整 Git tree
与已推送的 `71d8625` 相同。汇总保留了二进制身份和原始报告摘要。这两次测试
的原始顶层报告没有记录脚本所在 checkout 的 SHA；最终候选验收会补齐脚本版本
记录，历史结果继续保留原有身份。

runsc 复测使用已推送的 `45ce9ad3179d55091073775af1893f805336e240` 干净源码，
重新构建 CLI 和测试程序，并创建独立测试容器。汇总包含程序摘要、进程出生
身份、保存失败和取消结果，以及测试日志摘要。

公开 JSON 汇总保留各项检查结果、证据引用、采集计数、交付包摘要和原始报告
摘要。模型凭据、签名私钥和模型对话日志留在本地私有目录。
[SHA256SUMS](SHA256SUMS) 用于核对这里公开的文件。

## 后续收尾

- 完成 runsc 的命令及子进程归属、持久化采集确认，以及接收方和执行器的完整
  中断恢复验收。本次 runsc 结果覆盖启动身份绑定和执行放行流程。
- 解决 Kata Guest 启动问题，继续完成并发隔离、恢复、Pod 重建、旧 Target
  拒绝和真实 Workspace Harness 验收。
- 补齐其余边界复核、有时限的资源测试、最终安装包检查，以及预览和文档审阅。

正式 Dashboard 接入、合并 main、打 tag、发布 Release 和部署 Pages 仍待维护者审阅。
