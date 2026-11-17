# 案例阅读引导预览

[English](README.md)

在现有四张主卡和阅读器上补充案例引导。保留图谱、搜索、对比、导出及原始记录，
每个案例先呈现要调查的问题，再通过直接入口阅读对应证据。
其他调查视图收在可展开区域中，风险和采集摘要仍然可见。
工作区回执优先展示结果，原始 JSON 按需展开。

本次设计独立于已确认的正式构建。24 小时长测和安装包更新暂缓；最新 x86 Harness、
开启 Sensor 的 Browser／恢复案例和 Kata 阅读包待提供选定的公开原包后接入。
当前展示的案例保留各自的原始来源和采集范围。

```sh
python3 previews/v1.0-guided/build.py --site output/site --output output/guided-review
python3 -m http.server 58731 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/guided-review
NODE_PATH=previews/v1.0-home/node_modules PLAYWRIGHT_CHANNEL=chrome \
  node previews/v1.0-guided/check.cjs http://127.0.0.1:58731/ output/playwright/guided
```

`output/site` 的构建方式见[示例站点说明](../v1.0-home/README.zh-CN.md)。
预览复制到新目录，保留源站点和原始证据下载。下载包继续使用已确认的阅读器，
本次案例引导先供网页审阅。
