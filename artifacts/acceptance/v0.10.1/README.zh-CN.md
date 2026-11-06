# Linux x86_64 验收包

[English](README.md) | 中文

本目录提供预先构建的 Linux x86_64 程序和测试材料，便于在另一台机器验收 v0.10.1 候选版本。这是验收产物，尚未作为正式版本发布。

- 源码：[`4828cce10f0b53630d0a298affc760d5b1d6682c`](https://github.com/ByteYellow/AgentProvenance/tree/4828cce10f0b53630d0a298affc760d5b1d6682c)。
- 构建：Go 1.23.0，`linux/amd64`，`CGO_ENABLED=0`。
- [下载 ZIP](AgentProvenance-v0.10.1-x86-acceptance-4828cce.zip?raw=true)，约 68 MiB。
- [压缩包校验值](SHA256SUMS)；包内另附逐文件校验值。
- ARM64 验收已完成，x86 实机验收待执行。

## 环境要求

准备一台 x86_64 Linux 测试主机，具有 root 权限、eBPF/uprobe 支持和可读的 `/sys/kernel/btf/vmlinux`。需要 Bash、curl、unzip、`sha256sum`、C 编译器、`ldd`、OpenSSL 3 开发头文件及 Go 1.23.x。

测试会临时加载探针并访问本地 HTTPS 服务，应在测试主机执行。脚本不会自动安装依赖，也不会调用模型服务。

## 下载并执行

在独立工作目录运行：

```sh
set -eu
base='https://raw.githubusercontent.com/ByteYellow/AgentProvenance/fix/v0.10.1-pr34-integration/artifacts/acceptance/v0.10.1'
archive='AgentProvenance-v0.10.1-x86-acceptance-4828cce.zip'
curl -fL "$base/$archive" -o "$archive"
curl -fL "$base/SHA256SUMS" -o SHA256SUMS
sha256sum -c SHA256SUMS
unzip "$archive"
cd "${archive%.zip}"
sha256sum -c SHA256SUMS
sudo bash ./run-x86.sh
```

脚本依次检查原生 syscall 结果与访问控制状态、OpenSSL 采集与短命进程发现、Go TLS 并发读取。完成后回传生成的 `results-*` 目录，保留 `summary.tsv`、环境、源码、校验结果和全部测试日志。

跳过的测试标为 `BLOCKED`，失败结果保留用于排查。上传产物的提交晚于源码提交；包内程序始终对应 `4828cce`。
