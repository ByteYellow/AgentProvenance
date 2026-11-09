# 外传归因：合成示例

[English](README.md) | 中文

这是一份使用公开验证记录构建的签名合成示例。数据包含公开标记
`PUBLIC-ENDPOINT-FIXTURE-CANARY` 和路径 `/fixture/secret.txt`，没有向外部服务发送数据。
它用于展示：正文命中后，如果存在多条源读取候选，阅读器如何分别呈现三段证据。

```sh
agentprov demo endpoint-attribution
```

[直接打开归因记录](/?run=ui-endpoint-candidates&lens=data-flow-taint&detail=raw&live=0&selected=sha256%3A44fe36c9defe9293755c49b45c2223d11f6ba5ef32aba86b7f6f4b50fcef2768#inspection)。

## 三段证据分别看什么

| 问题 | 保存的结果 | 可以检查的依据 |
| --- | --- | --- |
| 外发正文中是否出现标记？ | 正文命中 | 采集正文及标记引用 |
| 内容来自哪次文件读取？ | 两条候选 | 精确路径、读取先于捕获的时间顺序及内容哈希 |
| 哪次执行完成了传输？ | 未知 | 已有作用域证据和缺少的身份字段 |

记录采用 `agentprov.endpoint_attribution/v2` 规则，两条读取候选都保留自己的证据引用。
点击候选可以打开对应记录；阅读器不会仅凭最近时间选择其中一条作为确定来源。

## 回放与校验

目录包含压缩证据包、DSSE 签名和公钥。导入时检查签名及图完整性。
示例库和本说明均标明其合成来源。

要查看真实采集的意图关联和 TLS 详情，请打开
[证据归因：检查与修复](../evidence-attribution/README.zh-CN.md)。
