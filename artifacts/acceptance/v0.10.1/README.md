# Linux x86_64 Acceptance Package

English | [中文](README.zh-CN.md)

This package provides the prebuilt Linux x86_64 programs and fixtures for
validating the v0.10.1 candidate on another machine. It is an acceptance
artifact, not a published release.

- Source: [`4828cce10f0b53630d0a298affc760d5b1d6682c`](https://github.com/ByteYellow/AgentProvenance/tree/4828cce10f0b53630d0a298affc760d5b1d6682c).
- Build: Go 1.23.0, `linux/amd64`, `CGO_ENABLED=0`.
- [Download ZIP](AgentProvenance-v0.10.1-x86-acceptance-4828cce.zip?raw=true) (about 68 MiB).
- [Archive checksum](SHA256SUMS); individual file checksums are inside the ZIP.
- ARM64 acceptance is complete; x86 live acceptance is pending.

## Requirements

Use an x86_64 Linux test host with root access, eBPF/uprobe support, readable
`/sys/kernel/btf/vmlinux`, Bash, curl, unzip, `sha256sum`, a C compiler, `ldd`,
OpenSSL 3 development headers, and Go 1.23.x. The tests load temporary probes
and make local HTTPS requests. Run them on a test host, not a production node.
The runner does not install dependencies or contact a model provider.

## Download and Run

In a dedicated working directory:

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

The runner records native syscall/access-state checks, OpenSSL capture and
short-lived target discovery, and Go TLS concurrent reads. Return the generated
`results-*` directory, including `summary.tsv`, environment, source, checksums,
and all test logs. Skipped tests are recorded as `BLOCKED`. Keep failed results
for diagnosis. The package's source identity stays at `4828cce` even when a later
commit uploads these artifacts.
