# 证据交付与独立验证

[English](../derived-evidence.md)

需要把选定证据交给其他人查看时，可以导出签名阅读副本。接收方无需连接你的
AgentProvenance 数据库。导出者签署 `DerivedView/v1` 清单，覆盖阅读器页面、
选定记录、附件、选择规则和实现摘要。

`dashboard export` 默认仍生成未签名阅读副本，已有副本继续支持离线打开。
签名需要显式启用，沿用现有冻结快照和选择流程。

## 选择交付模式

| 模式 | 包含内容 | 适用场景 |
| --- | --- | --- |
| `reading` | 阅读器和选定证据，未签名。 | 快速离线查看。 |
| `derived` | 选定证据和导出者签署的清单。 | 分享经过检查的选择范围，排除项留在本地。 |
| `originals` | 阅读器、明确选中的签名 Bundle 及其签名、导出者清单。 | 交付完整证据版本，供接收方独立验证。 |

未指定 `--delivery` 时，配置了导出密钥便使用 `derived`，否则使用 `reading`。
也可以显式指定 `--delivery reading`。`derived` 沿用现有留存和排除规则，分享前
请检查所选正文；自动识别所有敏感字符串不属于该模式的功能。

### 交付完整原件

先生成签名 Bundle，记下返回的 `id`：

```sh
agentprov forensics export RUN_ID --sign-key producer.private.hex --json
agentprov dashboard export --run RUN_ID --output complete.zip \
  --delivery originals --original-bundle BUNDLE_ID --confirm-original-scope \
  --sign-key exporter.private.hex --exporter-id review-team
```

每个 Run 明确选择一个已登记的 Bundle。阅读内容从该版本生成，之后采集的新记录
留在原数据库。原件及其签名按原字节复制到 `originals/`。原件可能包含阅读器没有
展示的内容，确认参数用于确认这一完整范围。本模式拒绝会话筛选和排除项；需要
选择性披露时使用 `derived`。

单个原件须为带签名的 JSON Bundle，符合严格导入的 256 MiB 上限。原件总量上限
为 900 MiB，完整交付目录上限为 1280 MiB。超过限制时导出失败，证据不会被截断。

## 导出

首次使用时，在证据目录之外生成导出者密钥。私钥留在导出机器上，公钥通过可信渠道
交给接收方。请使用新文件名，`forensics keygen` 会写入指定的密钥文件。

```sh
agentprov forensics keygen --priv exporter.private.hex --pub exporter.public.hex
agentprov dashboard export --run RUN_ID --output selected.zip \
  --harness claude --session SESSION_ID \
  --sign-key exporter.private.hex --exporter-id review-team
```

原有 `--selection-file`、`--exclude-record`、`--exclude-category`、
`--exclude-attachment` 选项继续生效。被排除的正文和原始数据库不会随签名自动加入。
清单保存私有冻结来源的摘要，原始来源本身留在导出端。

通过本地 HTTP 接口导出时，在启动服务时配置导出者密钥：

```sh
agentprov dashboard serve --addr 127.0.0.1:7396 \
  --replay-sign-key exporter.private.hex --replay-exporter-id review-team
```

[导出接口](../replay-export-api.yaml) 返回 `signed`、导出者和密钥 ID。HTTP 请求
不能传入或更换密钥。ZIP 中新增 `manifest.json`、`manifest.signature`，冻结预览
也提供这两个文件供检查。
请求中的可选 `delivery` 对象支持相同模式，只接收已登记的 Bundle ID，
不接收文件系统路径。预览清单会逐项列出将交付的原件。

## 独立验证

从你信任的源码版本构建独立验证器：

```sh
go build -o agentprov-verify ./cmd/agentprov-verify
./agentprov-verify selected.zip
```

验证器直接读取 ZIP 或解压后的目录，不启动服务、不导入证据、不执行页面脚本，
也不请求网络。未配置可信密钥时，它校验可用摘要和签名，并将签名者标为未知密钥。

接收方在包外单独配置可信公钥和角色：

```json
{
  "schema_version": "agentprovenance.reader_trust/v1",
  "id": "review-team-keys",
  "keys": [{
    "key_id": "FIRST_16_HEX_OF_PUBLIC_KEY_SHA256",
    "public_key_hex": "ED25519_PUBLIC_KEY_HEX",
    "roles": ["exporter"]
  }]
}
```

`forensics keygen` 会输出密钥 ID，它是公钥 SHA256 的前 16 位十六进制字符。
请填入经可信渠道确认的公钥；包内提供的公钥不会自动获得授权。验证目录时，
信任配置文件必须放在该目录之外。

```sh
./agentprov-verify --trust-policy recipient-trust.json selected.zip
agentprov evidence verify-view selected.zip --trust-policy recipient-trust.json
```

独立命令输出 JSON，退出码如下：

| 退出码 | 含义 |
| --- | --- |
| 0 | 清单内文件全部匹配，导出者及已交付原件的签名在对应角色下有效且受信任。 |
| 1 | 验证失败，例如文件被修改、缺失、多余或路径不安全。 |
| 2 | 副本未签名，或接收方没有授权相应的导出者或原始签名者。 |
| 3 | 输入路径、策略、参数或输出发生错误。 |

集成 CLI 输出相同的 JSON；非零验证结果均作为命令错误返回。自动化处理时，
请保留 JSON 报告，按具体字段判断。

## 理解结果

报告分别列出文件完整性、导出者签名、来源签名、派生关系和声明的采集覆盖。
导出者签名用于认证其导出声明。`derivation: not_checked` 表示接收方尚未从原始
材料重新计算该视图。采集期间存在的缺口会继续保留。

验证器只使用接收方显式提供的策略和授权角色。包内密钥、策略文件都不能自行
授予信任；只有 `producer` 角色的密钥无法授权阅读副本的导出者签名。

验证 `originals` 时，在接收方策略中给原始签名者的公钥授予 `producer` 角色。
独立验证器核对原件字节及其 DSSE 签名，与导出者签名分别报告。阅读器文件被修改时，
报告仍保留原件的独立验证结果。单独交付的原件也可以继续用 `forensics verify` 校验。

采集覆盖声明来自本次保留的采集记录。清单中的缺口数量统计的是诊断记录，
而非推算的丢失事件数；具体计数在阅读器中保留原有 Run 或采集器范围。
已记录的采集缺口不会因命令成功或签名有效而消失。

## 复现实测

```sh
python3 scripts/accept_derived_view.py \
  --agentprov ./agentprov --verifier ./agentprov-verify --out /tmp/reader-check
```

脚本记录一次真实本地命令，导出签名和未签名副本，检查可信密钥、未知密钥、
角色不匹配、文件篡改和多余文件。它使用临时签名密钥，保留结果报告及公开验证材料，
不保留私钥。
脚本也会交付一个原件，单独验证原始签名者，并修改阅读器文件，检查报告是否仍保留
原件的有效验证结果。
