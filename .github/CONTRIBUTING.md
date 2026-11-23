# Contributing

English | [简体中文](CONTRIBUTING.zh-CN.md)

## Build output and evidence

Keep local builds, smoke-test stores and private recordings out of Git. Use
`output/` for disposable products or a directory outside the checkout for
long-lived evidence. The tracked `output/go.mod` keeps generated Go packages
out of `go test ./...` and `go vet ./...`. Preserve it when clearing that folder.
Smoke scripts use `output/` by default; their existing `*_DATA_DIR` overrides
still apply. Point them at a disposable directory, not at an evidence archive.

Run `python3 scripts/check_repository_artifacts.py` to check the staged files.
CI also checks intermediate commits, including files removed later in a pull
request. To check that range locally, add `--since origin/main`, substituting
the branch you actually based the change on.

New or changed Git blobs must be at most 10 MiB. Keep small fixtures used by
offline tests in the repository. Distribute larger approved public bundles as
[release assets](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github#distributing-large-binaries);
record the source commit, versioned download URL, byte count and SHA-256 in the
repository. Keep private evidence in access-controlled storage.

Existing large fixtures are pinned by path and Git object ID. Before moving
one, download and verify the replacement, update its consumers, and test the
published demo build and offline reader. Git LFS is an option for inputs
versioned alongside code once build and offline packaging can fetch and verify
the actual bytes. Moving a file changes future checkouts; rewriting published
history is a separate maintainer decision.
