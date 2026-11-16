# v1.0 reader review

[中文](README.zh-CN.md)

This candidate preserves the current Dashboard and adds a folded execution
handoff panel, a Browser / Notebook session tab, saved capture observations,
attachment reading, and recovery guidance. It reads the existing public APIs
through the offline replay adapter. It is **not enabled in the formal Dashboard**.

On 2026-11-16 the maintainer requested that this code and its instructions remain
available for review after the other v1.0 work is finished. Layout approval and
formal integration are deferred to that review.

## Build and open

Python 3.12 or newer is sufficient to build. Run from the repository root on
Linux or macOS, choosing a new output directory:

```sh
python3 previews/v1.0-reader/build.py --output /tmp/agentprov-v1-reader
python3 -m http.server 47920 --bind 127.0.0.1 --directory /tmp/agentprov-v1-reader
```

Open <http://127.0.0.1:47920/>. The top navigation selects task investigation,
cross-environment execution, Browser, or Notebook. The original language switch
and browser-language default remain available. Each example also opens through
its `index.html` using `file://`.

## What to review

- The graph remains above the collapsed Agent session. Existing graph views,
  Compare, timeline, and saved-file reading remain present.
- Execution links navigate in both directions and locate the recorded source
  tool call. Execution and capture status belong to the saved package. Its
  delivery status is labeled **at packaging**; a saved receipt appears separately.
- Browser / Notebook records expose native identities, saved bodies, screenshots,
  static images, and HAR. Images and archives are loaded only after a click.
- Collection status retains observed capability changes, their times, scoped
  counters, and unknown values. Recovery guidance distinguishes resending an
  existing delivery from creating another execution attempt.

The investigation, execution, and Browser samples reuse the reviewed candidate
ZIPs in `docs/benchmarks/v1.0-candidate/replays`. The Notebook sample is a synthetic
Jupyter acceptance capture with a static chart and a kernel restart. Its full
reading copy is preserved in `fixtures/notebook-attachments.zip`; the earlier
Claude Notebook sample remains unchanged in the candidate directory.

The builder preserves the evidence records, adds preview assets to a new copy,
and regenerates the reading-copy file inventory. `review.json` records the
selected examples. Each inventory records the original ZIP hash and pending
approval. These remain unsigned reading copies.

The reader refreshes the archived graph projections: model messages no longer
count as artifacts, standalone calls and artifacts remain inspectable, and
investigation counts follow the selected session. Saved evidence and attribution
edges are unchanged. Capture details distinguish missing AppArmor/seccomp state
snapshots from event loss and pending ingestion, using the saved execution scope.

## Check interactions

With Node.js, Playwright, and its Chromium browser installed:

```sh
AGENTPROV_PREVIEW_URL=http://127.0.0.1:47920 \
  node previews/v1.0-reader/check.cjs /tmp/agentprov-v1-reader-check
```

The check covers nonzero graph drilldowns across runs and sessions, capture
details, both directions of execution navigation, the exact source
command, collapsed sessions, existing Compare, Browser and Notebook body/image
reading, script errors, and unexpected network requests. Screenshots and a JSON
report are written under the chosen check directory.

Before formal integration, move the approved design into the shared Dashboard
assets, remove the preview-only wrapper around session navigation, and add the
new elements to live, static, and selective-export regression coverage. The
preview currently keeps a separate bounded content dialog; the final placement
of this reader is part of the pending design decision.
