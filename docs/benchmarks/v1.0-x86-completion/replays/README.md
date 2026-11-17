# x86 recorded replays

[简体中文](README.zh-CN.md)

Seven recorded cases are ready for the Demo library. Download a `reading` ZIP,
extract it, and open `index.html`. Each package works offline.

| Case | Reading copy | Preserved signed package | Acceptance |
| --- | --- | --- | --- |
| Real Claude Workspace: Read, Edit, Write, Bash, file versions and native events | [harness-reading.zip](workspace/harness-reading.zip) | [harness-derived.zip](workspace/harness-derived.zip) | [Workspace](../workspace-final.json) |
| Browser with Sensor: parallel contexts, restart, receipts, OS links and three HAR attachments | [sensor-on-reading.zip](browser/sensor-on-reading.zip) | [sensor-on-derived.zip](browser/sensor-on-derived.zip) | [Browser](../browser-final.json) |
| Browser interrupted-operation recovery: both generations, saved outcomes and native events | [crash-recovery-reading.zip](browser/crash-recovery-reading.zip) | — | [Browser](../browser-final.json) |
| Kata/QEMU real Claude Workspace | [harness-reading.zip](kata/harness-reading.zip) | [harness-derived.zip](kata/harness-derived.zip) | [Kata](../kata-final.json) |
| Kata/QEMU first Guest boot | [boot-1-reading.zip](kata/boot-1-reading.zip) | [boot-1-derived.zip](kata/boot-1-derived.zip) | [Offline delivery](../kata-offline-final.json) |
| Kata/QEMU rebuilt Guest | [boot-2-reading.zip](kata/boot-2-reading.zip) | [boot-2-derived.zip](kata/boot-2-derived.zip) | [Offline delivery](../kata-offline-final.json) |
| Kata/QEMU Workspace contract | [contract-reading.zip](kata/contract-reading.zip) | [contract-derived.zip](kata/contract-derived.zip) | [Kata](../kata-final.json) |

[manifest.json](manifest.json) lists each filename, Run, full capture/export source
SHA and file SHA-256. [SHA256SUMS](SHA256SUMS) covers the complete handoff.
[verification.json](verification.json) records seven offline reader checks, six
signature checks and the decoded-content privacy review.

The six signed packages retain their original bytes. Their unsigned reading
copies preserve the evidence shards, catalog and record selection; only the
delivery banner and file inventory change. The conversion is reproducible with
[make_reading_copy.py](make_reading_copy.py).

The recovery reader was exported from the saved Sensor store and both existing
Browser transcripts. Its second generation has eight verified receipts and
1,322 OS relations. The interrupted first generation remains unsealed; its
unfinished operation remains `unknown`. This fixture disabled screenshots and
HAR capture. The Sensor-on case supplies its three recorded HAR attachments.

API keys, private keys and login credentials stay on the x86 machine. Public
`*-recipient-trust.json` files contain exporter public keys for the preserved
signed readers. To verify one:

```sh
sha256sum -c SHA256SUMS
agentprov-verify --trust-policy workspace/harness-recipient-trust.json workspace/harness-derived.zip
```
