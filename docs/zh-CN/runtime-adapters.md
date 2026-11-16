# 运行时适配

运行时适配将平台身份、命令执行和证据采集分开配置。接收命令、记录执行尝试、取消、查询、恢复和交付继续使用现有执行交接协议及持久化记录。

## 当前验收边界

| 模式 | 执行 | 采集 | 本阶段验收对象 |
| --- | --- | --- | --- |
| 默认 / `native` | 复用本机执行、策略、快照、作用域与恢复 | 原生 Sensor | 保持现有默认行为 |
| `guest` | 在虚拟机内部运行同一执行器 | 位于 Guest 内核的原生 Sensor | 保存平台身份与 Guest 证据 |
| `runsc` | 在一个固定容器中通过 `runsc exec` 执行 | 独立 SecCheck 接收器 | 保存操作回执和容器/Sentry 范围的观测 |

当前 runsc 路径尚未建立逐命令事件关联，因此命令成功时采集状态仍可为 `capture=incomplete`，并保留 `shared_call_identity_unavailable` 和 `command_capture_watermark_unavailable`。接收器事件与命令回执分别保存在独立 Run 中，调查时需同时读取。该路径及新增 Kata/QEMU 组合的实机验证见文末命令。

## Native 与 Guest 配置

入口仍为 `agentprov daemon serve --execution-config PATH`。省略 `backend` 或使用 `{"backend":{"mode":"native"}}` 保留 native 默认行为，包括非 root 开发配置和现有默认并发。

Guest 配置在原 handoff 文件上增加：

```json
{
  "target": {"producer_id":"node-a","instance_id":"pod-uid","generation":"operator-generation-1"},
  "caller": {"principal_id":"router","producer_id":"source","namespace":"lab"},
  "concurrency": 2,
  "backend": {
    "mode":"guest",
    "guest": {
      "runtime_class":"kata-qemu",
      "runtime_handler":"kata-qemu-runtime-rs",
      "pod_uid":"pod-uid",
      "container_id":"raw-cri-container-id",
      "guest_boot_id":"actual-guest-kernel-boot-id"
    }
  },
  "capture": {"mode":"native","placement":"guest_kernel"}
}
```

已有 Guest 部署可省略 `backend.guest`；填写时五个字段必须齐全。可信平台 launcher 先从控制面和 CRI 核对 RuntimeClass/handler、Pod UID、container ID，再按 operator receipt 生成配置，不从工作负载 label 分配身份。daemon 另行读取 `/proc/sys/kernel/random/boot_id`，与 `guest_boot_id` 比较。

Guest/runsc 配置文件及全部父目录须为 root 所有、禁止 group/other 写入且不含符号链接。投射卷内容需经校验后复制到真实的 root-owned 只读绑定目录。executor store、runsc state、二进制和 PID 临时目录应位于工作负载可写挂载之外。

完整映射保存到 `checkpoint.platform_binding`，Guest 同时写入 `checkpoint.runtime_report.execution.binding`，原 native Sensor 边界仍在 `checkpoint.capture_report`。Guest 的执行和恢复沿用原 native scope 路径。同一 Target 重启后发现映射变化会拒绝启动；restore/clone 的新 generation 由外部可信 launcher 分配，包括 Guest boot ID 随快照复制的场景。

## 固定 Runsc 入口

协议固定为 `release-20261109.0`，上游 commit 为 `a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`。这是兼容版本约束，部署主机仍需运行实机验收。

```json
{
  "target": {"producer_id":"node-a","instance_id":"sandbox-1","generation":"generation-1"},
  "caller": {"principal_id":"router","producer_id":"source","namespace":"lab"},
  "concurrency": 1,
  "backend": {
    "mode":"runsc",
    "runsc": {
      "binary":"/usr/local/bin/runsc",
      "root":"/run/runsc",
      "container_id":"container-1",
      "state_created":"2026-11-16T00:00:00Z",
      "runtime_release":"release-20261109.0",
      "workdir":"/workspace",
      "allow_uncorrelated":true
    },
    "seccheck": {
      "status_file":"/run/agentprov/receiver-status.jsonl",
      "target": {
        "run_id":"sentry-container-run",
        "socket_path":"/run/agentprov/events.sock",
        "registration": {
          "namespace":"node-a","instance_id":"sandbox-1","generation":"generation-1",
          "sandbox_id":"sandbox-1","container_id":"container-1","peer_uid":0
        }
      }
    }
  }
}
```

`state_created` 必须取自实际 `runsc --root=ROOT state CONTAINER` 返回值。每次执行前校验该值、容器 ID、running 状态与二进制版本。替换/恢复容器前，可信 launcher 需先退役旧绑定。路径使用绝对路径；`workdir` 固定为容器内部路径。请求需设置 `command.disable_snapshot=true`，`command.workdir` 留空或严格等于配置值。容器工作区不使用宿主快照和宿主路径解析。

执行命令固定为：

```text
runsc --root=ROOT exec --new-pidns --internal-pid-file=PRIVATE_FILE --cwd=WORKDIR CONTAINER ARGV...
```

请求不能选择 runtime flags、容器 ID 或 receiver 身份。Shell interpreter 受既有 `--record-allow-shell` 策略控制；transport 只获得最小宿主环境。`--record-timeout` 与持久化 stop 请求会取消并回收本地 transport。

可选 `seccheck` 指向原有独立 receiver。registration 的 namespace、instance、generation 必须分别匹配 Target 的 producer、instance、generation，并匹配配置容器。两个进程由 root 分别管理：

```sh
agentprov --data-dir /var/lib/agentprov-sentry telemetry receive-seccheck \
  --config /run/agentprov/receiver.json --json --status-interval 100ms \
  > /run/agentprov/receiver-status.jsonl
agentprov --data-dir /var/lib/agentprov-executor daemon serve \
  --execution-config /run/agentprov/execution.json --record-timeout 30s
```

配置了 receiver 时，执行前要求其已连接。状态缺失、过期、断连或身份不符均拒绝该命令。省略 receiver 是明确的 execution-only 配置，保留 `receiver_not_configured`。必须填写的 `allow_uncorrelated=true` 表示接受当前操作与 Sentry 事件之间的关联缺口。

checkpoint 只保留选中 receiver 的状态，省略 `node_spool`。collector ID、connection ID 及累计接收/丢失/身份缺口计数均属于容器 receiver 范围，不按单条命令计数。collector 重启、重连和损失变化分别记录 gap。

## 状态与恢复

沿用 `/v1/executions` 的准入、查询、stop API；adapter 结果位于 `checkpoint.runtime_report.execution` 与 `.capture`。重复提交和查询不调用第二次 `runsc exec`。

- runsc 正常返回且读取到内部 PID 回执时，记录执行成功。
- dispatch 前失败记录 Failed。dispatch 后非零返回与 runtime/control error 共用退出通道，保留 Unknown。
- 超时、取消、结果丢失或 executor 重启后，未确认的工作负载结果为 Unknown，退出码为空。
- 同一 Target 的 unresolved attempt 会通过 Ledger 阻止后续执行，重启后仍有效。继续执行前，由可信 launcher 回收旧工作负载并分配新 generation。
- `concurrency=1` 约束本 executor；容器外部执行保留 `external_container_execution_untracked`。

## PID 与出生身份

固定版本的 [`exec` 实现](https://github.com/google/gvisor/blob/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/runsc/cmd/exec.go#L189) 写入内部 PID，未返回出生时间；[进程创建路径](https://github.com/google/gvisor/blob/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/pkg/sentry/kernel/kernel.go#L1523) 返回根 namespace 的 thread-group ID。[SecCheck ContextData](https://github.com/google/gvisor/blob/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/pkg/sentry/seccheck/points/common.proto#L78) 另有精确 thread/group birth time 和 exec-session 标识。

当前缺少把调用与出生身份原子绑定的回执。实现不使用 host PID、取整后的 `ps` 时间、argv 或事件到达时间补造该关系。同 PID 样本保留为待核对候选；后续需要解决 PID 复用、晚到事件、重连和生命周期绑定后再建立逐命令关联。

## 验证与 X86 交接

本地回归和 Linux 构建：

```sh
go test ./internal/runtimeadapter ./internal/handoff ./internal/record ./internal/daemon
go test ./internal/cli -run 'TestExecutionBackend|TestExecutionCapture|TestRecord|TestDaemon'
go test -race ./internal/runtimeadapter ./internal/handoff
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/agentprov ./cmd/agentprov-sensor
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/runtimeadapter-amd64.test ./internal/runtimeadapter
```

在隔离的 Linux x86 主机准备固定版本、root-owned 的 runsc，以及含 `/bin/true`、`/bin/sleep` 的测试 rootfs。以 root 执行，输出路径保持较短以满足 Unix socket 限制：

```sh
AGENTPROV_TEST_RUNSC=/usr/local/bin/runsc \
AGENTPROV_TEST_GVISOR_ROOTFS=/opt/agentprov-test/rootfs \
AGENTPROV_TEST_RUNTIME_ADAPTER_OUTPUT=/root/ap-r02 \
go test ./internal/runtimeadapter -run '^TestRunscLiveExecutionIdentityEvidence$' -count=1 -v
```

测试自行创建并删除一次性容器，产物保存在新建的 `run-*` 目录：`runtime-state.json`、成功/取消操作回执、`acceptance-boundary.json`、`sentry-identity-records.json`。身份样本保留精确 protobuf `time_ns`、thread ID/birth、group ID/birth、container ID、parent group ID、`is_exec_session`，以及 registration、connection、sequence、packet digest/header 和 loss delta。64 位 protobuf 值使用十进制字符串，避免浮点精度损失；不保留凭据、argv、环境。transport peer PID 单独标识。

该探针覆盖真实 runtime 入口及 receiver 身份字段。完整集成验收还需对已配置 daemon 调用现有认证 handoff API，检查重复提交/查询不重执行、错代拒绝、receiver 重启/断连、executor 重启，并分别收集命令和容器 Run 的证据。native/Guest 继续使用原实机测试：

```sh
AGENTPROV_TEST_EXECUTION_CAPTURE=1 go test ./internal/handoff -run '^TestLiveExecutorSealsNativeCapture$' -count=1 -v
AGENTPROV_TEST_REQUIRE_CGROUP=1 go test ./internal/handoff -run '^TestExecutorRecoversLiveScope$' -count=1 -v
```

验收记录需包含 commit、架构、runsc 摘要、kernel/rootfs 版本、配置摘要及产物。真实 x86 运行、完整 R-02 故障矩阵、Kata/QEMU 平台验收待采集这些产物后确认。
