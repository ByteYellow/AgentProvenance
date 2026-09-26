# AgentProvenance

English | [简体中文](zh-CN/release-start.md)

From this extracted directory:

```sh
./agentprov --version
./agentprov demo
./agentprov demo --list
./agentprov demo multiagent-provenance
```

The CLI embeds all six signed captures and all demo guides. Replay is offline,
read-only, and uses a temporary store removed on Ctrl-C. The browser opens
on a loopback address. Use `--no-browser` on a headless machine.

Choose Open replay to view evidence, or Read guide for a formatted guide with
a section outline, images, tables and code-copy buttons. Both use the dashboard
theme. The gallery and guides follow your browser language on first visit, with
English as the fallback. Use the English / 中文 switch to save a choice.
Guide content is embedded; additional repository/external links require
a network connection when followed.

The `demo/` directory contains every existing example, its original signatures,
public keys, scripts and documentation. Replaying never executes captured commands.
LLM Judge and Jev are optional Python examples, not prerecorded verdicts:

```sh
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline
```

Jev needs Python 3.9+ and separate live credentials/raw-evidence consent; see
`demo/jev-judge/README.md`. Its commands use this archive's absolute
`agentprov` path; Go is needed only for an optional source build. Reopening a completed Jev
study is offline. Live capture scripts have additional requirements in their guides.

Linux archives include the optional sensor; its kernel and privilege requirements
still apply. macOS supports replay and application recording, not Linux eBPF.
Windows users should use the matching Linux archive inside WSL.

SHA256SUMS and per-archive .sha256 files verify download integrity; they are not
publisher signatures. The CLI verifies example evidence using the bundled public
keys. This proves evidence integrity, not capture completeness or causal certainty.

These CLI binaries are not Apple Developer ID signed or notarized.
