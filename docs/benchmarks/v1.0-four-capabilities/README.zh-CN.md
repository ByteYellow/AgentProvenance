# v1.0 四项能力验收

[English](README.md) | 中文

固定验收源码：**`831e85426393bdbf7757d37ee221cd8f3f0fd9ff`**。
本摘要覆盖受控工作区、可移植证据交付、运行时适配和 Browser 分层证据。
[结果索引](report.json)记录该固定版本复测的命令、退出码、源码与构建状态、
可执行文件及报告哈希，以及跳过条件。

**UI 状态：**保留本地预览，暂不接入正式 Dashboard，现有视觉布局保持不变。

## 已实现范围

| 能力 | 代码范围 | 已具备的本地工作流 |
| --- | --- | --- |
| 受控工作区 | [workspace](../../../internal/workspace)、[stdio MCP bridge](../../../python/agentprov/workspace_mcp.py) | 单一远端权威工作区、Target generation 检查、版本/摘要冲突、输入/输出 manifest，以及 CLI/MCP 的 Read/Edit/Write/Bash 回执。 |
| 证据交付 | [derivedview](../../../internal/derivedview)、[viewverify](../../../internal/viewverify)、[独立验证器](../../../cmd/agentprov-verify) | 未签名阅读副本、导出者签名的选定阅读副本、完整 Run 的已登记原件；接收方控制信任，分别核验文件完整性、生产者/导出者签名与覆盖状态。 |
| 运行时适配 | [runtimeadapter](../../../internal/runtimeadapter)、[handoff](../../../internal/handoff)、[Kata 验收脚本](../../../scripts/acceptance/kata-qemu) | 分离平台、执行与采集契约；保留 native 默认路径，支持 Guest 绑定、固定容器 runsc 执行和有界平台/清理检查。 |
| Browser 证据 | [browserlink](../../../internal/browserlink)、[browsercustody](../../../internal/browsercustody)、[provenance](../../../internal/provenance)、[回执持久化](../../../python/agentprov/browser_receipts.py) | 持久 accept/result、重启后只查询不重执行、接收方核验、原生 ID 分层关系和显式进程生命周期映射。 |

`internal/capturemanifest` 已实现观测层与能力时间区间投影。本地验收入口包括
工作区契约/真实 Harness 检查、受控 Chrome 回执恢复、独立交付核验、离线阅读和
有界 daemon soak 采样。原生 Sensor-on 与具体平台组合分别进行实机验收。

配置和命令见[四项能力验收流程](../../zh-CN/validation/four-capabilities.md)、
[工作区指南](../../zh-CN/workspace.md)、[交付指南](../../zh-CN/derived-evidence.md)
和 [Browser 指南](../../browser-context.zh-CN.md)。

## 固定源码复测

运行时二进制由上述固定源码构建。验收脚本修订
`476ad41508a253b416e9d6689639e9760630d8f3` 仅将工作区任务写成明确的 JSON
字符串与末尾换行要求，并增加三项回归测试。运行时代码和最终文件 19 字节的精确
检查保持不变。首次 Harness 失败与随后通过的复测分别记录。

修订 `dcc30062c499f16fdca3520d2876a1ff73e350e6` 校正了导航验收：精确比较
在线与静态页面的链接集合，同时遍历全部导出的参考文档。原数量检查将仅从正文
链接进入的 Kata 指南计入首页导航。14 项中英文回归检查覆盖缺失、多余、同数量
替换和错误语言链接，产品代码与页面布局均保持不变。

| 验证项 | 结果记录 |
| --- | --- |
| 完整 Go 测试与 vet | 通过，覆盖 49 个带测试的包；命令、工具链和日志索引见 [report.json](report.json)。 |
| Race 回归 | 使用现有 CI 参数 `-race -p 2 -timeout 20m`，通过。 |
| Python 与运行时验收脚本测试 | Python 测试集 98 项通过、2 项跳过；工作区 37 项通过；Kata 验收脚本 51 项通过。 |
| CLI 交付与独立核验 | 21 项预期结果全部符合；三种交付模式和两份 Browser 证据库均通过离线阅读检查。 |
| 静态案例与阅读器回归 | 12 个回放、106 个双语页面、17,910 次查询对照及 7,324 次正文分页检查通过；在线/静态图谱控件与选择性下载也通过。 |

各项结果标明对应的源码或验收脚本版本。以下历史测量保留各自原有的源码与构建身份。

## 历史参照

| 既有证据 | 已记录结果 | 测试条件 |
| --- | --- | --- |
| ARM Linux 真实 daemon 短测 | 60.001 秒、30 次成功健康采样、6 个独立命令、12/12 兼容性检查通过；soak 与 daemon 退出码均为 0。 | 非 root 隔离 daemon，Sensor 关闭；CPU 均值 3.76%，RSS 从 46.500 到 57.875 MiB，健康请求延迟 p95 为 33.30 ms。 |
| 本地 UI 预览 | 259 项检查、13 张截图、Chrome 155.0.8059.85；浏览器错误和外部 HTTP 请求均为 0。 | 中英文桌面/移动端预览；Workspace 为示例，Browser 已保存回执和交付报告分别标明来源。 |

ARM 采样脚本 checkout 为 `4e367089eb9f768be4592b1268e93d05166097a8`，
已跟踪工作区 **dirty=true**；二进制内嵌源码为
`52c7200f1c3e382040f210a83d3af665d2396325`，**vcs.modified=true**。
UI 预览为未提交的本地产物；当时的 Git revision、进程退出码和 Chrome 可执行文件哈希
未记录。原始报告哈希及来源信息在[结果索引](report.json)中单独保留。

## 后续 x86 收尾

最终 [x86 结果](../v1.0-x86-completion/README.zh-CN.md)已完成此前的 runsc、
Workspace/Browser 原生采集和固定 Kata/QEMU 验收，并收录有界性能、
同源码候选安装包及保留的阅读器预览。24 小时长测由维护者暂缓。
上文历史测量继续保留原版本和环境条件。
