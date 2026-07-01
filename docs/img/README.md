# Dashboard / demo screenshots

Screenshots and short replay media referenced from the top-level `README.md`.
They are generated from the portable `demo/snake-supply-chain` forensics bundle.

| File | What to capture |
|------|-----------------|
| `dashboard-graph-explorer-taint.png` | Graph Explorer with the **Data-flow · taint** lens selected on `run-snake-agent`; the red dashed `possible_sensitive_data_flow` edges visible. |
| `dashboard-side-panel-preview.png` | A node selected so the **Side Panel** shows Evidence + the artifact Preview (e.g. `workspace_file/snake.py`). |
| `demo-snake-taint-replay.png` | The taint lens mid **time-scrub** (▶): secret-read nodes shown, the metadata-IP egress about to appear. |
| `demo-snake-taint-replay.gif` | Short animated replay of the taint lens / time scrubber for README embedding. |

To regenerate them: replay the captured run and open the dashboard —

```sh
./agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-agent.forensics.json \
  --pub-key demo/snake-supply-chain/attestation.pub
./agentprov --data-dir /tmp/snake-replay dashboard serve   # http://127.0.0.1:7396
```
