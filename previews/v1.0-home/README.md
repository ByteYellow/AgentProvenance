# Demo homepage preview

English | [中文](README.zh-CN.md)

This is a local review build, separate from the formal gallery and reader.
It preserves four illustrated entry cards and groups the remaining cases by
their actual tasks. Report-repair links open Compare with an explicit A/B pair.
The October and November reproductions remain separate. Headings omit final
periods; descriptive text retains punctuation.

## Build

Use Node.js, Python 3, Chrome and a current source build of `agentprov`.
The commands below only read bundled public recordings and build local files.

```sh
go build -o /tmp/agentprov-review ./cmd/agentprov
/tmp/agentprov-review demo export --output output/home-review-archive
npm ci --prefix previews/v1.0-home
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

Review approval is still pending. This build does not replace the formal
Dashboard, publish a release or deploy GitHub Pages.
