# 贡献指南

[English](CONTRIBUTING.md) | 简体中文

## 构建产物和验收记录

本地构建、冒烟测试数据和私有实录不提交到 Git。临时产物放在 `output/`，
长期保留的验收资料可放在仓库外。清理 `output/` 时保留其中已跟踪的 `go.mod`；
它让根目录的 `go test ./...` 和 `go vet ./...` 跳过本地生成的 Go 程序。
冒烟脚本默认向 `output/` 写入数据，原有的 `*_DATA_DIR` 环境变量仍有效。
请指定可清理的目录，不要指向验收原件。

运行 `python3 scripts/check_repository_artifacts.py` 可检查暂存区。
CI 还会检查本次推送或 PR 中间提交过、后来又删除的文件。
本地检查同一范围时，可以加 `--since origin/main`，并将分支名换成实际开发基线。

新建或修改的单个 Git 文件最大为 10 MiB。离线测试依赖的小样本可以随源码提交。
经过公开审查的大型验收包应作为
[Release 附件](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github#distributing-large-binaries)
分发，在仓库中记录源码提交、固定版本的下载地址、字节数和 SHA-256。私有实录保存在有访问控制的存储中。

现有大型样本按路径和 Git 对象 ID 保留。迁移前先下载并核对新附件，再更新引用，
实测示例站点构建和离线阅读。需要跟随源码一起版本化的大文件可以考虑 Git LFS，
前提是构建和离线打包都能取到并校验文件原文。迁移文件只改变以后的检出内容；
是否重写已发布的历史，由维护者另行决定。
