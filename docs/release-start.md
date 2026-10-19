# Start with a recorded execution

English | [简体中文](zh-CN/release-start.md)

[Open the online demo](https://ByteYellow.github.io/AgentProvenance/) to try the
graph, Agent session and saved files without installing anything. The same site includes the full project overview, capture and deployment guides,
analysis commands, integration references and release history.

For offline replay, open the demo library from the extracted archive:

```sh
./agentprov demo
```

Choose **Open replay** to explore a signed execution or **Read guide** for its
illustrated walkthrough. Nine replays and eleven guides are included. No Go,
Docker, agent account or API key is needed for replay.

## Investigate, repair and compare

```sh
./agentprov demo investigation-workflow
```

A real DeepSeek session delegates code review, runs seven tests and encounters
denied optional diagnostics. It then continues the same session, disables those
diagnostics and successfully produces the report. Both signed runs load together.

In **Compare**, set A to **Diagnostic repair: before** and B to
**Diagnostic repair: after**. Read `settings.json` and the reports under
**File evidence**; **Configuration** shows Harness settings.

Open **Related sessions** to inspect delegation and continuation. Search the
recorded error, inspect AppArmor/seccomp decisions, compare the saved files, then
export selected evidence as a read-only page. Task, configuration and collection
details remain available from the overview.

The CLI checks the evidence signature and imports into a temporary store.
Replay works offline and never runs the recorded commands. Ctrl-C closes the
server and removes its temporary data.

## More examples

```sh
./agentprov demo --list
./agentprov demo deepseek-context
./agentprov demo multiagent-provenance
./agentprov demo k8s-cross-pod-a2a
./agentprov demo --no-browser
```

`--no-browser` prints a local URL. For a remote machine, forward that local port
to your browser. The `demo/` directory contains the original bundles, public
keys, scripts and guides. Live capture requirements are listed in each guide.

LLM Judge and Jev are optional Python integrations. Opening their guides does
not call a model. To try the LLM Judge integration with preset offline results:

```sh
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline
```

Jev requires Python 3.9+; live evaluation needs credentials and permission to send
selected evidence. Follow `demo/jev-judge/README.md`. Completed studies can be
reopened offline.

## Language

Web pages follow the browser language on first visit, falling back to English.
The English / 中文 switch saves your choice. CLI output defaults to English;
commands, paths, IDs, JSON and original evidence keep their original text.
The existing `--lang zh-CN` option selects Chinese help and supported output,
and opens web pages in Chinese.

## Platforms and verification

- Linux archives include the optional native sensor. Kernel capture needs the
  appropriate kernel, cgroup access and BPF/perf permissions.
- macOS supports application recording and replay. The CLI is not Apple
  Developer ID signed or notarized.
- On Windows, use the Linux archive inside WSL.
- `SHA256SUMS` and `.sha256` files check download integrity. The example public
  keys verify evidence signatures. Collection status separately describes what
  the original recording captured.

Embedded guides and their images work offline. Following external links requires
network access.
