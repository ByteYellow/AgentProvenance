# Page Tour Preview

[中文](README.zh-CN.md)

A first-visit invitation to explore the current demo library and recorded-run
reader. A small floating hint points to Page tour without dimming or blocking the
page. Clicking Page tour starts the spotlight tour, which highlights one region
at a time with a floating explanation and
Back, Next and Skip all controls. The original layout, dropdowns, evidence,
graph controls and investigation entries remain in place.

## Behavior

- The library and reader have separate first-visit hints. The full tour starts
  only after the visitor clicks Page tour. Dismissing a hint remembers that page type.
- Skip all suppresses future automatic hints across both pages in this browser origin.
- Page tour in the header restarts the current tour. `?tour=1` shows the invitation again.
- Escape closes the current hint or tour. Only the full spotlight tour confines keyboard focus.
- Closing restores the scroll position, previously focused control and session
  disclosure. It leaves the selected Run, graph view and evidence unchanged.
- A comparison deep link has priority, including while it is still loading. After
  the visitor closes the comparison with X or Escape, the reader invitation appears.
  Other dialogs temporarily hide the hint. It returns when the dialog is closed
  and the header is in view, without changing the visitor's scroll position.
- The reader tour covers scope and session relationships; search and comparison;
  graph views, playback, zoom and file content; risk and access control; session
  configuration, coverage, Workspace and Browser/Notebook; export, delivery and
  auxiliary views. Execution handoffs appear when that section is available.
- Chinese and English follow the current page language. Narrow screens use a
  compact header button and wrapping reader shortcuts.
- The library tour points directly to Documentation, or Quick start on mobile,
  and explains how to find deployment and integration guidance.
- Featured screenshots use inset spacing, a fine edge and a subtle shadow.
  Their existing links are unchanged, with no additional labels or panels.

This remains a separate preview, alongside `previews/v1.0-guided`. It is not
connected to the production build or published site. Original evidence downloads
remain unchanged; the tour is included only in the web preview. It does not run
commands or activate the highlighted controls.

## Build and Check

Start from an approved site built with the [demo site instructions](../v1.0-home/README.md),
not the earlier guidance preview. Use a fresh output directory.

```sh
npm ci --prefix previews/v1.0-tour --ignore-scripts
python3 previews/v1.0-tour/build.py --site output/site --output output/tour-review
python3 -m http.server 58732 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/tour-review
NODE_PATH=previews/v1.0-home/node_modules PLAYWRIGHT_CHANNEL=chrome \
  node previews/v1.0-tour/check.cjs http://127.0.0.1:58732/ output/playwright/tour
```

The build copies the site, updates unsigned reading-copy inventories and bundles
[Driver.js](https://driverjs.com/docs/installation) locally at the locked version.
Its MIT license is retained as `tour-assets/driver-LICENSE.txt`. No CDN is required
to display the tour. Playwright uses the existing preview test dependency.

The browser check covers both languages on desktop and mobile, every tour step,
invitation and explicit start, skip and restart, keyboard focus, first-visit
persistence, state restoration, delayed comparison loading and closing, and the
existing search controls. It writes
screenshots and a JSON report to the selected output directory.
