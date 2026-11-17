# Page Tour Preview

[中文](README.zh-CN.md)

A first-visit, spotlight-style tour of the current demo library and recorded-run
reader. It highlights one region at a time with a floating explanation and
Back, Next and Skip all controls. The original layout, dropdowns, evidence,
graph controls and investigation entries remain in place.

## Behavior

- The library and reader have separate tours. Each starts once on first visit.
- Skip all suppresses automatic tours across both pages in this browser origin.
- Page tour in the header restarts the current tour. `?tour=1` also starts it.
- Escape closes the current tour. Keyboard focus stays within the tour while open.
- Closing restores the scroll position, previously focused control and session
  disclosure. It leaves the selected Run, graph view and evidence unchanged.
- An open comparison or other dialog takes precedence over automatic guidance.
- Chinese and English follow the current page language. Narrow screens use a
  compact header button and wrapping reader shortcuts.

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
skip and restart, keyboard focus, first-visit persistence, state restoration,
the direct comparison entry and the existing search controls. It writes
screenshots and a JSON report to the selected output directory.
