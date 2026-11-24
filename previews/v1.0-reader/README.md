# v1.0 reader builder

[中文](README.zh-CN.md)

This directory builds the standalone v1.0 reading workbenches (task investigation,
cross-environment execution, Workspace, Browser, and Notebook) from packaged
unsigned reading copies. The unified Evidence Workbench is shared directly with
the formal Dashboard and offline exports through `internal/dashboard/workbench.js`,
`workbench.css`, and pure engine modules in `reader.js`.

## Build and open

Python 3.12 or newer is sufficient to build. Run from the repository root on
Linux or macOS, choosing a new output directory:

```sh
python3 previews/v1.0-reader/build.py --output /tmp/agentprov-v1-reader
python3 -m http.server 47920 --bind 127.0.0.1 --directory /tmp/agentprov-v1-reader
```

Open <http://127.0.0.1:47920/>. Each example also opens directly through its
`index.html` using `file://`.

## Fixtures and composition

- The investigation, execution, and Browser samples reuse the reviewed candidate
  ZIPs in `docs/benchmarks/v1.0-candidate/replays`.
- `fixtures/notebook-attachments.zip` preserves a synthetic Jupyter acceptance
  capture with a static chart and kernel restart.
- `fixtures/workspace-contract.zip` is an unsigned reading copy of the Linux x86
  Workspace contract case (SHA-256 `4dc4230ee69e8e0f28d86e1671e584201fdb5799a82ee5cf0c34ae7526a2136a`).
- `compose.py` and `graph_navigation.py` refresh the embedded workbench assets,
  strip retired legacy scripts, refresh archived graph projections, and
  regenerate `export-inventory.json` without mutating saved evidence records.

## Verification

The formal Dashboard embeds the same workbench assets. The website build uses
`--production` to link back to the demo library; downloaded copies hide site
navigation when opened via `file://` and keep graph, search, comparison, and
content controls. End-to-end checks run through `scripts/accept_demo_site.py`
and `previews/v1.0-home/check-redesign.cjs`. Historical acceptance records are
preserved in [preview-final.json](../../docs/benchmarks/v1.0-x86-completion/preview-final.json).
