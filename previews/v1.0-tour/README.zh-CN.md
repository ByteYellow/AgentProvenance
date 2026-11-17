# 页面导览预览

[English](README.md)

在现有示例库和执行记录页上增加首次访问导览。每一步高亮一个区域，用悬浮说明
介绍它的用途，提供“上一步”“下一步”和“跳过全部”。保留现有布局、下拉菜单、
图谱操作、证据正文和调查入口。

## 交互规则

- 示例首页和记录页分别导览，首次访问各自动出现一次。
- “跳过全部”关闭当前导览，并停止当前浏览器站点下两种页面的自动导览。
- 右上角“页面导览”可重新开始；链接添加 `?tour=1` 也可以直接体验。
- Esc 关闭当前导览；导览期间，键盘焦点留在浮层中。
- 结束后恢复滚动位置、原焦点和会话区展开状态，保持 Run、图谱视图和已选证据。
- 已经打开对比或其他弹窗时，自动导览让位于当前操作。
- 中英文跟随页面语言。手机使用紧凑入口，记录页的快捷按钮自动换行。

这版仍是独立预览，与 `previews/v1.0-guided` 并存，尚未接入正式构建或线上站点。
原始下载包保持不变，导览仅用于网页预览；导览不会执行命令或触发高亮控件的业务操作。

## 构建与检查

先按[示例站点说明](../v1.0-home/README.md)构建已确认的站点，使用新的输出目录。
输入应为正式站点构建结果，而不是上一版案例引导预览。

```sh
npm ci --prefix previews/v1.0-tour --ignore-scripts
python3 previews/v1.0-tour/build.py --site output/site --output output/tour-review
python3 -m http.server 58732 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/tour-review
NODE_PATH=previews/v1.0-home/node_modules PLAYWRIGHT_CHANNEL=chrome \
  node previews/v1.0-tour/check.cjs http://127.0.0.1:58732/ output/playwright/tour
```

构建会复制站点，刷新未签名阅读副本的文件清单，并将锁定版本的
[Driver.js](https://driverjs.com/docs/installation) 打包到本地。
MIT 许可证保存在 `tour-assets/driver-LICENSE.txt`；显示导览无需访问 CDN。
浏览器检查复用现有预览的 Playwright 依赖。

检查覆盖桌面和手机的中英文逐步导览、跳过与重开、键盘焦点、首次访问记忆、
阅读状态恢复、对比直达和搜索入口，并输出截图与 JSON 报告。
