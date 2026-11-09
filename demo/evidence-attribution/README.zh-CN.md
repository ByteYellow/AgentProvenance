# 证据归因：检查与修复

[English](README.md) | 中文

这两份签名记录来自 2026 年 11 月 6 日在 Linux arm64 上运行的真实 DeepSeek 报表任务。
可以查看 v0.10.1 新增的工具级意图关联、AppArmor/seccomp 决策和 TLS 采集完整性详情。

```sh
agentprov demo evidence-attribution
```

两次执行一起加载，离线回放无需模型账号或 Linux 虚拟机。
打开**对比**，选择**证据归因 · 修复前**与**证据归因 · 修复后**。

## 已记录的过程

主 Agent 与审查子 Agent 检查一个本地报表程序。可选诊断尝试读取受限文件并建立网络连接，
随后 Agent 继续同一个原生会话，移除多余诊断，生成总额为 `42.00` 的报表。

| 采集阶段 | Run | 消息记录 | 工具调用 | 审计记录 |
| --- | --- | ---: | ---: | ---: |
| 修复前 | `run-2fd63df0ab9b` | 22 | 18 | 3 |
| 修复后 | `run-48baa3821074` | 54 | 51 | 0 |

第二次采集延续原生会话，包含已保留的历史对话。表中统计的是保存记录，
比较时应结合具体步骤区分历史内容与本次新增执行。

## 直接查看新版详情

1. [查看一条工具级意图关联](/?run=run-2fd63df0ab9b&lens=intent&detail=raw&live=0&selected=diff%2Fv2%2F4958f6486e058efd80454be9ea8e6b8306c9cfc69337419c20db7db94f45b96c#inspection)。
   选中记录列出具体工具调用、支持它的运行时事件及 `agentprov.intent_scope/v4` 规则。
2. [查看一段保留的 TLS 片段](/?run=run-2fd63df0ab9b&lens=agent-intent&detail=raw&live=0&selected=sha256%3A072f5b3948ca4c5693b882722815b3958815c72ba807706b926dc67001bbbb49#inspection)。
   记录提供采集上限、调用位置和原始字节数，规则为 `agentprov.tls_reassembly/v3`。
   阅读器分别展示保留片段与完整 HTTP 内容。
3. 打开**关联会话**查看审查者，通过**搜索**阅读工具结果和文件。
   在**对比**中检查配置、文件和审计变化，再沿证据引用进入图谱。

## 采集来源与完整性

[采集清单](capture-manifest.json)列出采集时间、平台、二进制哈希、Run 和证据包校验值。
压缩包、DSSE 签名与公钥均保留采集时的原始文件；导入时先检查签名和图完整性，再提供回放。

任务使用公开标记和本地回环服务，已记录的采集缺口在页面中保留。
另有[外传归因合成示例](../endpoint-attribution/README.zh-CN.md)，用于查看源读取存在多个候选的情况。

此前的[诊断修复示例](../investigation-workflow/README.zh-CN.md)继续保留原始证据与规则版本。
