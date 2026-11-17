# Case Guidance Preview

[中文](README.zh-CN.md)

A local review of the existing four-card demo library and evidence reader.
It keeps the graph, search, comparison, export and original records. Each case
offers a short investigation question and direct steps into its saved evidence.
The additional investigation views remain available in a disclosure; risk and
capture summaries remain visible. Workspace receipt details retain their original
JSON under an expandable section.

This design is separate from the approved site build. The 24-hour soak and package
refresh are deferred. The newer x86 Harness, Sensor-on Browser/recovery and Kata
readers can be integrated when their selected public archives are supplied;
the current cases retain their original sources and scope.

```sh
python3 previews/v1.0-guided/build.py --site output/site --output output/guided-review
python3 -m http.server 58731 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/guided-review
NODE_PATH=previews/v1.0-home/node_modules PLAYWRIGHT_CHANNEL=chrome \
  node previews/v1.0-guided/check.cjs http://127.0.0.1:58731/ output/playwright/guided
```

Build `output/site` using the [existing demo site instructions](../v1.0-home/README.md).
The preview copies that site to a new directory; it does not overwrite the source
site or change the original evidence downloads. Downloaded archives retain the
approved reader; the proposed case guide is for web review only.
