# Dashboard / demo screenshots

English | [简体中文](README.zh-CN.md)

The current README uses desktop screenshots from the locally built demo website.
Each view has an English and a `-zh-CN` image. Run IDs refer to the original public recordings.

| Image | What is open |
| --- | --- |
| `demo-gallery.png` | Four featured investigations on the source homepage |
| `workbench-compare.png` | Both saved versions of `output/diagnostics.json`, before and after repair |
| `workbench-session.png` | DeepSeek's Bash result with seven tests in `run-dbc2adf273d4` |
| `workbench-team.png` | The orchestration graph for `run-double-attempt` |
| `workbench-placement.png` | Recorded workload and cgroup identities in `a2a-demo` |

To refresh, serve a [local website build](../../previews/v1.0-home/README.md#approved-website-build)
and run `node previews/v1.0-home/capture-readme.cjs http://127.0.0.1:58730/ docs/img` from the repository root.
The script checks the selected runs and displayed evidence before taking each screenshot.

## Recorded Agent Context

The v0.9.0 interface screenshots were captured on 2026-10-08 from the signed
DeepSeek run `run-dbc2adf273d4`. They show the v0.9 viewer over the original
2026-09-28 evidence, not a new model run. Each has an English and a `-zh-CN` version.
The images live with the [DeepSeek guide](../../demo/deepseek-context/README.md)
so the CLI can embed and display them offline.

| File in `demo/deepseek-context/` | Subject |
|---|---|
| `dashboard-session.png` / `dashboard-session-zh-CN.png` | Test command and returned output in Conversation & tools |
| `dashboard-configuration.png` / `dashboard-configuration-zh-CN.png` | Permission preset, sandbox mode and approval policy |
| `dashboard-tests.png` / `dashboard-tests-zh-CN.png` | Seven-test output in the expanded saved-content viewer |
| `dashboard-file.png` / `dashboard-file-zh-CN.png` | Saved final `test_report.py` text with Agent session collapsed |
| `dashboard-coverage.png` / `dashboard-coverage-zh-CN.png` | Separate session capture, tool association and runtime completeness |

Capture at a 1440 x 1060 viewport. Use the Agent session panel's own scroll area
and tabs; the test command is source record #56 and its result is #57 on page 2.
For the file view, choose File / Artifact, expand the source group and select
`test_report.py`. Do not modify evidence or hide coverage warnings for a screenshot.

## Gallery and Evidence Graphs

These older guide screenshots and playback clips retain their original UI and evidence.

| File | What to capture |
|------|-----------------|
| `demo-guide.png` | Formatted LLM Judge guide at `/demos/docs/llm-judge`, including section navigation and code-copy controls. |
| `dashboard-graph-explorer-taint.png` | Graph Explorer with the **Data-flow · taint** lens selected on `run-snake-supervised`; the red dashed `possible_sensitive_data_flow` edges visible. |
| `dashboard-side-panel-preview.png` | A node selected so the **Side Panel** shows Evidence + the artifact Preview (e.g. `workspace_file/snake.py`). |
| `demo-snake-taint-replay.png` | The taint lens mid **time-scrub** (▶): secret-read nodes shown, the metadata-IP egress about to appear. |
| `demo-snake-taint-replay.gif` | Short animated replay of the taint lens / time scrubber for README embedding. |
| `demo-multiagent-overview.png` | Dashboard overview for `run-double-attempt`: signed graph status, run overview, risk groups, and first timeline page. |
| `demo-multiagent-orchestration.png` | Multi-agent orchestration lens: lead agent, sub-agents, peer message, tool calls, and syscall attribution. |
| `demo-multiagent-agent-network.gif` | README animation captured from the dashboard's native play button in the orchestration lens. |
| `demo-multiagent-agent-network-01-start.png` | Source frame before native playback starts. |
| `demo-multiagent-agent-network-02-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-03-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-04-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-05-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-06-play.png` | Native playback source frame. |
| `demo-multiagent-agent-network-07-play.png` | Native playback source frame. |
| `demo-multiagent-risk-path.png` | Focused risk selection: metadata-IP risk plus focused evidence table. |
| `demo-multiagent-network-egress.png` | Network / egress lens for the multi-agent run, focused on outbound evidence. |
| `demo-k8s-a2a-substrate-dashboard.png` | K8s cross-pod A2A substrate lens: one node sensor, two pod cgroups, Alice -> Bob influence edge, and pod-level risk attribution. |

To regenerate the gallery/reader, run `./agentprov demo`, open the printed URL,
and capture the gallery and LLM Judge guide at a 1440-pixel desktop viewport.
These are real UI screenshots, not generated illustrations.

To regenerate evidence screenshots: replay the captured run and open the dashboard —

```sh
./agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub
./agentprov --data-dir /tmp/snake-replay dashboard serve   # http://127.0.0.1:7396
```

Chinese UI screenshots use the `-zh-CN.png` suffix. The Chinese index lists their
subjects and capture settings. Original commands, paths and evidence retain their
recorded text; translated screenshots do not modify the signed demo bundles.

## Chinese replay clips

`demo-multiagent-agent-network-zh-CN.gif` and `demo-snake-taint-replay-zh-CN.gif` are captured from the Chinese Dashboard using its playback control. Matching PNG files contain their final frames. See the [Chinese asset index](README.zh-CN.md) for the full list.
