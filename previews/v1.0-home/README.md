# Demo homepage preview

English | [中文](README.zh-CN.md)

This directory holds the shared homepage assets and a retained local review build.
It preserves four illustrated entry cards and groups the remaining cases by
their actual tasks. Report-repair links open Compare with an explicit A/B pair.
The October and November reproductions remain separate. Headings omit final
periods; descriptive text retains punctuation.

## Build

Use Node.js, Python 3, Playwright Chromium and a current source build of `agentprov`.
The commands below only read bundled public recordings and build local files.

```sh
go build -o /tmp/agentprov-review ./cmd/agentprov
/tmp/agentprov-review demo export --output output/home-review-archive
npm ci --prefix previews/v1.0-home
previews/v1.0-home/node_modules/.bin/playwright install chromium
python3 previews/v1.0-home/build.py \
  --archive output/home-review-archive \
  --output output/home-review
python3 -m http.server 58729 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/home-review
```

Open `http://127.0.0.1:58729/?lang=en`. Use new output directories for a rebuild
and choose another port if occupied. Existing previews and signed evidence
are preserved. The build refreshes unsigned reading-copy inventories and
renders Mermaid locally; the resulting pages need no external diagram service.

## Review

```sh
node previews/v1.0-home/check.cjs http://127.0.0.1:58729/ output/playwright/home-review output/home-review
```

The check covers both languages, desktop/mobile layouts, each archive chapter,
guide links, per-link icons, heading punctuation, paired comparisons, restored
reader state, diagram zoom and downloaded replay bytes. The optional last
argument enables offline `file://` checks. Invalid pairs and other Compare
behavior have a separate regression in `scripts/test_dashboard_compare_completeness.mjs`.

`media/` contains screenshots of the saved recordings, not generated task data.
To recapture them, run `capture-thumbnails.cjs` with the preview URL and a new
image directory. An optional `--screenshots` directory supplies larger reader
screenshots in the case dialogs. Opening these cases does not run an Agent or
call a model API.

The [refined homepage](refined/README.md) and reader were approved for integration
on 2026-11-17. This earlier design remains available for comparison.

## Approved website build

The release workflow validates the signed static catalog first, then composes
the approved homepage and current readers into the artifact supplied to Pages.
These commands build and check the same artifact locally; they do not deploy:

```sh
export NODE_PATH="$PWD/previews/v1.0-home/node_modules"
python3 scripts/accept_static_demo.py --binary /tmp/agentprov-review --site output/site-base
python3 scripts/build_demo_site.py --archive output/site-base --output output/site
python3 scripts/accept_demo_site.py --archive output/site-base --site output/site
python3 -m http.server 58730 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/site
```

Open `http://127.0.0.1:58730/`. Existing `/en/` and `/zh-CN/` reader, guide and
download paths remain valid. The previous full catalog is available as
`en/library.html` or `zh-CN/library.html`. New reading downloads carry the current
reader and updated inventories under `downloads/reading/`; original downloads
remain byte-identical. The five current example readers and three supplemental
recordings share the embedded Dashboard assets. No public API or database format
changes are required for this integration.

The acceptance script checks both languages at four widths, archive dialogs,
links, diagrams, comparisons, graph drilldowns, attachments and an actual downloaded
Workspace copy opened offline. Set `PLAYWRIGHT_CHANNEL=chrome` to use installed
Chrome instead of Playwright Chromium. Existing output directories are preserved;
choose a new path for every build.
