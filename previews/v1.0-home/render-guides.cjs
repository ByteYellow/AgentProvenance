const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require('playwright');
const { parseHTML } = require('linkedom');

const output = path.resolve(process.argv[2]);
const production = process.argv.includes('--production');
const archive = production ? output : path.join(output, 'archive');
const home = production ? '../../' : '../../../';
const evidence = [];
const digest = text => crypto.createHash('sha256').update(text).digest('hex');

const assets = path.join(archive, 'diagram-assets');
fs.mkdirSync(assets, { recursive: true });

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHANNEL ? {channel: process.env.PLAYWRIGHT_CHANNEL} : {}) });
  try {
    const page = await browser.newPage();
    await page.setContent('<!doctype html><html><body></body></html>');
    await page.addScriptTag({ path: path.join(path.dirname(require.resolve('mermaid')), 'mermaid.min.js') });
    await page.evaluate(() => mermaid.initialize({
      startOnLoad: false, securityLevel: 'strict', theme: 'base', htmlLabels: false,
      fontFamily: '-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif',
      themeVariables: { primaryColor: '#eef5ff', primaryTextColor: '#1d1d1f', primaryBorderColor: '#b8cbe5', lineColor: '#8794a5', clusterBkg: '#f8f9fb', clusterBorder: '#d7dce4', tertiaryColor: '#f6f8fc' },
      flowchart: { htmlLabels: false, useMaxWidth: false, nodeSpacing: 28, rankSpacing: 40, wrappingWidth: 220 }
    }));
    for (const language of ['zh-CN', 'en']) {
      for (const section of ['guides', 'demos']) for (const filename of fs.readdirSync(path.join(archive, language, section))) {
        if (!filename.endsWith('.html')) continue;
        const input = fs.readFileSync(path.join(archive, language, section, filename), 'utf8');
        const { document } = parseHTML(input);
        for (const a of document.querySelectorAll('a[href="../index.html"]')) a.setAttribute('href', home + '?lang=' + language);
        const blocks = [...document.querySelectorAll('pre > code.language-mermaid')];
        for (const [index, code] of blocks.entries()) {
          const original = code.textContent;
          const id = 'architecture-' + language + '-' + index;
          const svg = await page.evaluate(async ({ id, code }) => {
            const {svg} = await mermaid.render(id, code.replaceAll('<cmd>', '#lt;cmd#gt;').replaceAll('\\n', '<br/>'));
            const container = document.createElement('div');
            container.innerHTML = svg;
            const element = container.querySelector('svg');
            if (element.querySelector('foreignObject')) throw new Error('Diagram requires portable SVG text labels');
            // Normalize Mermaid's escaped plain-text labels without introducing HTML into the SVG.
            for (const span of element.querySelectorAll('.text-inner-tspan')) {
              const decoder = document.createElement('textarea');
              decoder.innerHTML = span.textContent;
              span.textContent = decoder.value;
            }
            if (code.includes('<cmd>') && !element.textContent.includes('<cmd>')) throw new Error('Command placeholder was lost');
            return new XMLSerializer().serializeToString(element);
          }, { id, code: original });
          const { document: svgDocument } = parseHTML(svg);
          if (!svgDocument.querySelector('svg .node')) throw new Error('Empty diagram: ' + id);
          const name = filename.replace('.html', '') + '-' + language + '-' + index + '.svg';
          fs.writeFileSync(path.join(assets, name), svg);
          const zh = language === 'zh-CN';
          const figure = document.createElement('figure');
          figure.className = 'rendered-diagram';
          figure.innerHTML = `<div class="diagram-bar"><span>${zh ? '系统架构' : 'System architecture'}</span><button type="button" data-diagram-open aria-label="${zh ? '放大查看架构图' : 'Expand architecture diagram'}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M3 3l6 6m12-6-6 6M3 21l6-6m12 6-6-6"/></svg>${zh ? '放大查看' : 'Expand'}</button></div><a class="diagram-overview" href="../../diagram-assets/${name}" target="_blank" rel="noopener"><img src="../../diagram-assets/${name}" alt="${zh ? 'AgentProvenance 系统架构：采集入口、接收层、证据核心与查询和安全分析' : 'AgentProvenance architecture: collection, ingestion, evidence core, queries and security analysis'}"></a><details class="diagram-source"><summary>${zh ? '查看 Mermaid 源码' : 'View Mermaid source'}</summary></details>`;
          const pre = code.parentElement;
          pre.replaceWith(figure);
          figure.querySelector('.diagram-source').append(pre);
          evidence.push({ language, page: filename, sourceSHA256: digest(original), svgSHA256: digest(svg), nodes: svgDocument.querySelectorAll('svg .node').length, svg: name });
        }
        if (blocks.length) {
          const css = document.createElement('link');
          css.rel = 'stylesheet'; css.href = home + 'diagrams.css?v=1'; document.head.append(css);
          const js = document.createElement('script');
          js.src = home + 'diagrams.js?v=1'; js.defer = true; document.head.append(js);
        }
        fs.writeFileSync(path.join(archive, language, section, filename), document.toString());
      }
    }
    fs.writeFileSync(path.join(output, 'diagram-build.json'), JSON.stringify({ mermaid: require('./package.json').devDependencies.mermaid, evidence }, null, 2) + '\n');
    console.log(JSON.stringify(evidence, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
