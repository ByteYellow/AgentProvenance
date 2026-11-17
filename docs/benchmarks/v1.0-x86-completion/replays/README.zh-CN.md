# x86 实机案例回放包

[English](README.md)

这里提供七个已完成验收的案例，供在线 Demo 接入。下载 `reading` ZIP，
解压后打开 `index.html` 即可离线阅读。

| 案例 | 阅读副本 | 保留的签名原包 | 验收记录 |
| --- | --- | --- | --- |
| 真实 Claude Workspace：Read、Edit、Write、Bash、文件版本和原生事件 | [harness-reading.zip](workspace/harness-reading.zip) | [harness-derived.zip](workspace/harness-derived.zip) | [Workspace](../workspace-final.json) |
| Browser 开启 Sensor：并发上下文、重启、回执、OS 关联和三份 HAR 附件 | [sensor-on-reading.zip](browser/sensor-on-reading.zip) | [sensor-on-derived.zip](browser/sensor-on-derived.zip) | [Browser](../browser-final.json) |
| Browser 中断恢复：前后两代会话、已保存的操作结果和原生事件 | [crash-recovery-reading.zip](browser/crash-recovery-reading.zip) | — | [Browser](../browser-final.json) |
| Kata/QEMU 真实 Claude Workspace | [harness-reading.zip](kata/harness-reading.zip) | [harness-derived.zip](kata/harness-derived.zip) | [Kata](../kata-final.json) |
| Kata/QEMU 首次启动 Guest | [boot-1-reading.zip](kata/boot-1-reading.zip) | [boot-1-derived.zip](kata/boot-1-derived.zip) | [离线交付](../kata-offline-final.json) |
| Kata/QEMU 重建后的 Guest | [boot-2-reading.zip](kata/boot-2-reading.zip) | [boot-2-derived.zip](kata/boot-2-derived.zip) | [离线交付](../kata-offline-final.json) |
| Kata/QEMU Workspace 契约验收 | [contract-reading.zip](kata/contract-reading.zip) | [contract-derived.zip](kata/contract-derived.zip) | [Kata](../kata-final.json) |

[manifest.json](manifest.json) 逐项列出文件名、Run、采集／导出源码完整 SHA 和文件 SHA-256。
[SHA256SUMS](SHA256SUMS) 覆盖本目录的交付文件；
[verification.json](verification.json) 保存七份阅读包的离线检查、六份原包的签名验证和解码后的隐私检查结果。

六份签名原包保持原样。对应的未签名阅读副本保留全部证据分片、目录和记录选择，
只调整交付说明与文件清单。可用 [make_reading_copy.py](make_reading_copy.py) 复现转换。

中断恢复包从已保存的 Sensor 数据和两代 Browser 日志导出。
第二代保留八份已验证回执和 1,322 条 OS 关联；被中断的第一代保留未封存状态，
未完成操作仍显示 `unknown`。该恢复用例采集时关闭了截图和 HAR；
正常运行案例保留了三份实录 HAR 附件。

API Key、私钥和登录凭据留在 x86 机器上。
随附的 `*-recipient-trust.json` 仅包含用于验证签名原包的导出者公钥。
校验示例：

```sh
sha256sum -c SHA256SUMS
agentprov-verify --trust-policy workspace/harness-recipient-trust.json workspace/harness-derived.zip
```
