# 签名阅读副本

[English](../derived-evidence.md)

需要把选定证据交给其他人查看时，可以导出签名阅读副本。接收方无需连接你的
AgentProvenance 数据库。导出者签署 `DerivedView/v1` 清单，覆盖阅读器页面、
选定记录、附件、选择规则和实现摘要。

`dashboard export` 默认仍生成未签名阅读副本，已有副本继续支持离线打开。
签名需要显式启用，沿用现有冻结快照和选择流程。

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
| 0 | 清单内文件全部匹配，导出者签名有效且受信任。 |
| 1 | 验证失败，例如文件被修改、缺失、多余或路径不安全。 |
| 2 | 副本未签名，或接收方没有授权该导出者。 |
| 3 | 输入路径、策略、参数或输出发生错误。 |

集成 CLI 输出相同的 JSON；非零验证结果均作为命令错误返回。自动化处理时，
请保留 JSON 报告，按具体字段判断。

## 理解结果

报告分别列出文件完整性、导出者签名、来源签名、派生关系和声明的采集覆盖。
导出者签名用于认证其导出声明。`derivation: not_checked` 表示接收方尚未从原始
材料重新计算该视图。采集期间存在的缺口会继续保留。

验证器只使用接收方显式提供的策略和授权角色。包内密钥、策略文件都不能自行
授予信任；只有 `producer` 角色的密钥无法授权阅读副本的导出者签名。

单独交付的原始 Bundle 及其采集签名仍可用 `forensics verify` 校验。
将原件验证结果与阅读副本验证报告一起保存，便于区分两类签名。

## 复现实测

```sh
python3 scripts/accept_derived_view.py \
  --agentprov ./agentprov --verifier ./agentprov-verify --out /tmp/reader-check
```

脚本记录一次真实本地命令，导出签名和未签名副本，检查可信密钥、未知密钥、
角色不匹配、文件篡改和多余文件。它使用临时签名密钥，保留结果报告及公开验证材料，
不保留私钥。
