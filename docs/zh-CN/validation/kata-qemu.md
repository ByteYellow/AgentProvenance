# Kata/QEMU x86 验收

[English](../../validation/kata-qemu.md)

本目录交付 R-03/Q-01 的 **Kubernetes + `kata-qemu-runtime-rs`、Linux x86_64** 验收脚本。
脚本复用现有 Guest executor、原生 Sensor、execution handoff 和签名交付协议。
请在选定的 Kubernetes 节点上运行，使用已获授权的专用验收 namespace。
当前 ARM 开发 VM 没有 `/dev/kvm`，硬件矩阵初始状态均为 `PENDING`。

## 版本锁

[锁文件模板](../../../scripts/acceptance/kata-qemu/versions.lock.json)接受**实测、已安装的
runtime-rs/QEMU 组合**，生效版本和摘要由操作者核对后填写。
`candidate_reference` 仅记录研究基线：Kata **4.3.1**、上游提交
`03cf2ec06a5d302f23af811744f6bcea49988bfb`、QEMU **11.0.1**、Guest kernel **6.18.56**，
无需为匹配候选版本重装现有部署。
选型依据为官方 [RuntimeClass 指南](https://kata-containers.github.io/kata-containers/kata-deploy-runtimeclasses/)
及[固定提交的版本清单](https://github.com/kata-containers/kata-containers/blob/03cf2ec06a5d302f23af811744f6bcea49988bfb/versions.yaml)。

将模板复制为私有 `versions.local.json`，补全必填项。
脚本不会下载发布包、自动认可节点文件摘要或选择 `latest`。
版本、路径与摘要必须对应同一个经过核对的组合。其他已安装版本及自定义 BTF Guest
构建在精确固定项、CRI、QEMU 和 Guest 能力检查通过后即可使用。
固定组合始终为 `kata-qemu-runtime-rs` 与 QEMU。

如果特权测试容器内尚未挂载 tracefs，可以显式添加 `--mount-guest-tracefs`。
节点脚本核对实际 Pod、容器和 Guest 启动身份后，在该测试容器内挂载 tracefs，
再发布绑定回执。每阶段会记录挂载信息和 Guest boot ID。默认流程仍只检查前提条件；
这个选项只处理本次创建的 Guest 测试容器。

| 锁字段 | 需要固定的证据 |
| --- | --- |
| `artifacts.kata` | runtime-rs shim 版本、上游 revision、安装路径及 SHA-256 |
| `artifacts.qemu` | QEMU 版本、安装路径及 SHA-256 |
| `artifacts.guest_kernel` | 内核版本、精确 `uname -r`、启动内核摘要、Guest `/sys/kernel/btf/vmlinux` 摘要 |
| `artifacts.guest_image` | Guest image 的实际构建标识、安装路径及 SHA-256 |
| `artifacts.kata_config` | 已安装 runtime-rs QEMU TOML 路径、版本及 SHA-256 |
| `sensor` | 嵌入式 Sensor/CLI 构建版本、完整源码提交及可执行文件摘要 |
| `kubernetes` / `containerd` | API server、kubelet、运行中 CRI 的精确版本 |
| `workload_image` | 已预载的测试容器镜像，必须使用不可变 `@sha256:` 引用 |
| `verifier` | 指定 `--verifier` 时必填：独立验证器版本、完整源码提交及可执行文件摘要 |

对核对后的产物执行 `sha256sum FILE`。BTF 摘要和精确内核 release 从对应 Guest
构建或操作者自己的检查会话获取。构建时设置 `internal/buildinfo.Version` 和
`internal/buildinfo.Commit`；实测 Sensor producer 必须与锁一致。
本 profile 使用 `agentprov` 内嵌 Sensor，所以 collector 和 CLI 使用同一个二进制摘要，
不会另起一个 raw Sensor 进程。

测试容器镜像需要预装 Python 3.11+、`bpftool`、`sleep`、`true`，以及所选 `agentprov`
二进制所需的动态加载器和库。Pod 使用 `imagePullPolicy: Never`。
镜像构建、宿主及 Guest 配置由操作者显式完成。

## 前置条件

- 选定节点上的 root 权限、Python 3.11+、`kubectl`、`crictl`、Git 和确定版本的 Linux amd64 `agentprov`。
- `/dev/kvm` 可用，Kubernetes context 有效，明确指定本机 containerd CRI socket。
- 已存在 `kata-qemu-runtime-rs` RuntimeClass/handler，且 `runtimePath`、`ConfigPath` 与锁一致。
- 该 CRI handler 已设置 `privileged_without_host_devices=true`。
- 专用 namespace 的既有准入策略允许本次特权测试 Pod 和三个限定目录的 `hostPath` 卷：只读 fixture 输入、只读绑定配置、可写证据目录。
- Guest 提供 BTF、BPF kprobe/tracepoint 程序、ring/hash map、可见 tracefs 和可写委派 cgroup v2。

handler 检查读取**运行中 CRI 的 `info`**，再按 Pod UID 检查 `inspectp` 的
`runtimeHandler`。创建 Pod 前会比对节点 boot ID、节点/API 版本、运行时版本、配置路径和
产物摘要。相关字段依据固定版本的 [kata-deploy containerd 实现](https://github.com/kata-containers/kata-containers/blob/03cf2ec06a5d302f23af811744f6bcea49988bfb/tools/packaging/kata-deploy/binary/src/runtime/containerd.rs)
和 [Kubernetes RuntimeClass 契约](https://kubernetes.io/docs/concepts/containers/runtime-class/)。

## 平台身份绑定

节点端操作者创建 Pod 后核对 UID 与 RuntimeClass，通过 CRI 定位运行中的 sandbox。
容器检查必须同时匹配原始 container ID 与 sandbox ID。随后通过操作者的 `kubectl exec`
读取 Guest boot ID，并在发布绑定前再次核对 Pod/container 和 RuntimeClass。
节点与 Guest 的 boot ID 必须不同。

脚本生成 `binding-N/execution.json`、签名密钥和
`agentprovenance.kata_binding_receipt/v1` 格式的 `receipt.json`。
这些 root 所有的普通文件以只读方式挂载到 `/binding`。回执记录 API/CRI 身份、
完整 executor Target、配置/二进制/锁摘要及公钥摘要。
该回执是由文件所有权和挂载边界保护的操作者启动声明；label 仅用于辅助清理检查。

生成的配置使用已实现的执行后端：

```json
{
  "target": {
    "producer_id": "kata-acceptance-fixture",
    "instance_id": "<observed-pod-uid>",
    "generation": "<fresh-operator-assigned-generation>"
  },
  "backend": {
    "mode": "guest",
    "guest": {
      "runtime_class": "kata-qemu-runtime-rs",
      "runtime_handler": "kata-qemu-runtime-rs",
      "pod_uid": "<observed-pod-uid>",
      "container_id": "<raw-64-hex-cri-container-id>",
      "guest_boot_id": "<observed-guest-boot-uuid>"
    }
  },
  "capture": {"mode": "native", "placement": "guest_kernel"}
}
```

此示例省略了同时生成的 caller、concurrency 和 delivery 配置。
Guest 在启动 daemon 前核对可信回执，daemon 还会读取实际内核 boot ID 进行校验。
每份 checkpoint 的 `platform_binding` 和 `runtime_report.execution.binding`
必须保持相同绑定；签名交付导入离线 store 后再次校验。
本地测试拒绝错配 Pod/boot 身份与 Target generation；实测还要求错误 Target instance、
generation，以及重建前的 Target 返回 HTTP 403。generation 由操作者独立分配，
不直接复用 Pod UID。

## 执行入口

以下命令在仓库根目录运行。data 与 output 必须是两个互不嵌套的新目录；
`preflight` 不创建 data 目录。需要保留源码 checkout，以记录源码 SHA 及复用脚本的字节摘要。

```sh
python3 scripts/acceptance/kata-qemu/run.py preflight --dry-run \
  --binary /srv/agentprov/agentprov \
  --lock /srv/agentprov/versions.local.json \
  --data-dir /var/tmp/ap-kata-data-001 \
  --output /var/tmp/ap-kata-plan-001 \
  --context lab-x86 --namespace agentprov-acceptance --node x86-01 \
  --cri-endpoint unix:///run/containerd/containerd.sock
```

dry-run 只计算本地输入摘要，生成 `pod-plan.json`、供审核的 RuntimeClass JSON、锁副本
和 `report.json`。它不执行二进制、不连接 Kubernetes/CRI、不探测 KVM。
锁完整时结果是 `PENDING`，缺失固定项时是 `BLOCKED` 并列出字段；硬件矩阵保留待执行。

去掉 `--dry-run` 并换一个新 output 目录，可执行真实节点 `preflight`。
随后使用显式特权 Pod 开关运行有时限的验收：

```sh
sudo python3 scripts/acceptance/kata-qemu/run.py run \
  --binary /srv/agentprov/agentprov \
  --lock /srv/agentprov/versions.local.json \
  --data-dir /var/tmp/ap-kata-data-001 \
  --output /var/tmp/ap-kata-run-001 \
  --context lab-x86 --namespace agentprov-acceptance --node x86-01 \
  --cri-endpoint unix:///run/containerd/containerd.sock \
  --allow-privileged-guest
```

确认执行用户具有预期 kubeconfig/context。脚本不输出 kubeconfig，也不请求 Secrets。
生成的 RuntimeClass JSON 仅供审核，不会自动 apply。

## 实测步骤

| 步骤 | `PASS` 所需证据 |
| --- | --- |
| Guest 预检 | 精确 kernel/BTF、`bpftool feature probe kernel`、内核配置、tracepoint、namespace、权限和本次独占的可写 cgroup 父目录 |
| 单命令 | 复用 `accept_execution_delivery.py`：合成 CSV 结果、签名传输、回执重试、原生 sealed scope、图和产物正文校验 |
| 并发隔离 | 复用 `accept_execution_handoff.py`：source/scope/原生文件事件隔离及幂等；额外核对不同 cgroup 内不同 marker 的输出和产物 |
| 恢复 | 仅 SIGKILL 本次 daemon，重启其内嵌 collector，保留 `unknown` 输出和 `incomplete` 采集；原请求重投后再用 `previous_attempt_id` 显式重试 |
| 平台身份 | API/CRI 绑定回执、实际 `backend.guest` 配置、两处 checkpoint 投影、错配 Pod/generation 拒绝及签名导入的 checkpoint |
| 离线交付 | 停止本次 daemon、`seal-executions`、保留包、移走源 store，使用操作者选定的公钥导入新 store，再验图、输出及平台绑定 |
| Pod 重建 | 删除本次 Pod 后同名重建，核对新 UID/container ID/Guest boot ID，并验证旧 Target 返回 HTTP 403 |
| 可选 reader 验证 | 签名 `--delivery derived` 导出；独立验证器接受接收方信任策略，拒绝未知密钥、错误角色和被篡改的 reader |

单命令 fixture 在原有 CSV 任务前加入两秒等待，为原生进程状态采样留出观测窗口。
原脚本文件保持不变，报告的 `delivery_task_prelude` 记录这一调用细节。

Guest 步骤总时限 600 秒，Pod active deadline 为 720 秒；节点等待、CRI 调用及清理均有时限。
进程操作只使用本次启动句柄。删除 Pod 先检查 label/UID，再提交带 UID 前置条件的原子删除。
脚本不使用宽泛选择器或 `pkill`，不删除 namespace，不重启宿主服务，不 mount、sysctl、
重载策略、修改 RuntimeClass 或安装软件。

需要执行 reader 验证时，增加 `--verifier /srv/agentprov/agentprov-verify` 并填写
`lock.verifier`。脚本对独立导入的 run 执行
`dashboard export --delivery derived --sign-key KEY --exporter-id ID`，随后运行
`agentprov-verify --trust-policy FILE ZIP`。接收方策略在包外单独提供，并授权 `exporter`
角色。未指定验证器时，`derived_verifier` 保留待验收。

## 可选 Workspace 案例

在同一节点命令中加入 `--workspace-case contract --verifier /srv/agentprov/agentprov-verify`，
即可在**重建后的第二个 Guest** 内复用 `scripts/accept_workspace.py` 的 stdio MCP fixture。
省略该选项时，原两次启动流程不变；只写 `--workspace-case` 时默认选择 `contract`。
填写 `lock.verifier`，并将
`lock.workspace.mcp_version` 固定为工作负载镜像内已经安装的 MCP 包版本。
runner 复制并校验现有 Python MCP bridge 和 SDK 模块摘要，不安装依赖。

Workspace 使用与 `execution.json` 相同的操作者授权 Target，由只读
`/binding/workspace-target.json` 传入。各案例只修改自身副本来测试过期 generation 拒绝，
不修改操作者文件。每个案例的 Read、Edit、Write、Bash 使用同一个 remote-authoritative root。
输入/输出 revision、manifest 和实际 record attempt 由内容寻址的 workspace 证据核对，
签名导入后再次检查。

现有 handoff collector 停止后才启动 workspace capture。Workspace fixture 在自身 store
上运行 `sensor stream --placement guest_kernel`，等待必需探针 attached，结束时停止并
排空 collector 后再导出。同 run、record attempt 必须在其非零 owned cgroup 中有原生
exec/file 观察。接受的 correlation method 为 `cgroup_time_window:*` 或
`kernel_process_instance:*`，且每条所选事件的 cgroup 必须与该作用域相同。
scope-only 事件保留空 tool ID，以 `owned_record_cgroup` 报告，不升级为工具级归属。
Sensor build、placement、Guest boot 和 collector 生命周期与锁和操作者绑定核对。
环境前提缺失保留 `BLOCKED`/退出码 2。

MCP fixture 完成后，使用已有签名 `forensics export` 和固定公钥导入到新 store，
比较导入前后的 workspace/native-event 证据，再执行签名 derived-reader 导出和独立验证器。
报告和交付包保留在 `boot-2/workspace/{contract,harness}-delivery/`；
`kata-workspace.json` 记录模式、Target 和验证结果。

`contract` 是真实 CLI/MCP 契约测试，不调用模型 provider；通过后记录契约结果，完整
`workspace_case` 矩阵行仍为 `PENDING`。真实 Harness 模式选择 `--workspace-case harness`，
并将 `lock.workspace.harness.path` 和 `.sha256` 固定为 **Guest 容器内已有且已认证的 Claude
入口**。同一 fixture 复用已有 `--claude` 路径，检查实际受控 MCP tool call。
认证由操作者的既有部署提供，凭据不得写入镜像、lock、入口脚本、Pod plan 或证据。
runner 不复制凭据、不增加 Secret 挂载、不登录，也不通过 MCP 工具参数转发 provider 凭据；
入口缺失时报告缺项，不自动部署。Harness 日志保持私有并脱敏。

只有真实 native Guest Harness 案例及签名交付全部通过，才设置 `workspace_case=PASS`。
本地 Sensor-off CLI/MCP、dry-run 和 contract-only 模式均保留该行待实跑。
原 Guest 600 秒、节点 stage 690 秒、Pod 720 秒时限不变，可选案例共享这一预算。
案例子进程另外限定为 contract 150 秒、含既有有界 Harness 流程的模式 400 秒。
此接线不需要 UI 改动。

## 产物与隐私

`report.json` 记录当前源码 SHA/dirty 状态、二进制及 fixture 摘要、锁摘要、节点/运行时身份、
各次 Guest 结果与发布矩阵。`data-dir/assets` 保存送入 Pod 的确切输入，
`data-dir/binding-N` 保留 root 所有的配置、回执及密钥。
每个 `data-dir/boot-N` 保留报告、脱敏 daemon 日志、执行/采集数据、签名包、公钥、
receiver/offline store 及产物摘要索引。失败后也保留所有证据目录。

输出采用 umask `077`。合成验收私钥和 daemon token 留在私有 data 目录，不进入摘要索引。
输出诊断和 daemon 日志会移除已知 token、Bearer header、凭据赋值和 URL 密码。
分享前检查路径、原始证据和附件，不要发布整个 data 树。可移交的单命令包位于
`boot-N/portable/`，其公钥需要通过可信渠道传给接收者。

本地内部报告放到已忽略的 `scripts/acceptance/kata-qemu/.local/` 或仓库之外。
公共变更仅包含脚本、未填写摘要的模板与双语文档。

## 验收状态

本 fixture 在 **Kata Guest 内的特权容器**中启动 native executor，Sensor 观察该 Guest
内核，并记录容器 namespace。普通非特权业务容器的部署，以及超出本 fixture 范围的
Guest 全局采集，需要单独验证部署与采集配置。

本地配置及拒绝契约测试可在无 KVM 的环境运行。R-03 实机验收保持 **x86 `PENDING`**，
等待硬件执行。`runtimeadapter_binding` 已作为实际断言接入，没有无条件阻断项。
两次启动的实测全部通过后设置 `r03_status=PASS`；其余发布矩阵项尚未完成时，
Q-01 及报告整体状态继续保持 `PENDING`。

退出码 **2** 表示固定项、能力、权限或绑定缺失或不匹配；**1** 表示测试/运行失败；
**0** 表示请求阶段执行完成，具体范围见 `r03_status`、`q01_status` 与矩阵。
dry-run 和仅节点 preflight 均保留所有硬件验收行为待执行。

Q-01 还保留以下 `PENDING` 项：晚到证据、强制回收、受支持的 restore/clone、24 小时 soak、
旧数据兼容及 Browser 案例。Workspace 行在可选 native Harness 案例完成前继续待实跑。
这里的恢复同时重启 collector 和所属 daemon。其他 attempt 的最终包继续保留，等待回执对账；
验收脚本不授权删除证据。

## 本地验证

```sh
python3 -B -m unittest discover -s scripts/acceptance/kata-qemu -p 'test_*.py' -v
python3 -m compileall -q scripts/acceptance/kata-qemu
go test ./scripts/acceptance/kata-qemu
```

测试覆盖锁缺失、实测版本、handler/config 不匹配、Pod UID 清理约束、操作者回执、
绑定拒绝及两处 checkpoint 投影、进程超时清理、脱敏、Unknown/Incomplete 恢复和
无外部副作用的 dry-run。Go 测试将 Python 生成的配置交给实际 handoff 解析器及
runtimeadapter 校验器。
macOS 可另外运行不带 `--native` 的 `scripts/accept_execution_seal.py`，验证真实
CLI、回执及离线协议；该结果单独归档。复用协议见现有[执行交接文档](../execution-handoff.md)。

已有独立导入的 run 时，还可单独执行真实 reader 导出及验证器契约，无需 Kubernetes：

```sh
python3 scripts/acceptance/kata-qemu/reader.py \
  --binary /srv/agentprov/agentprov --verifier /srv/agentprov/agentprov-verify \
  --data-dir /srv/agentprov/imported-store --run RUN_ID \
  --output /var/tmp/ap-reader-contract-001
```
