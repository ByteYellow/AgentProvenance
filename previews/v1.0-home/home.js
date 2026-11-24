'use strict';
(() => {
  const root = document.querySelector('#app');
  const dialog = document.querySelector('#case-dialog');
  const url = new URL(location.href);
  let preferred = '';
  try { preferred = localStorage.getItem('agentprov_language') || ''; } catch {}
  const pathLang = /\/(en|zh-CN)\/(?:index\.html)?$/.exec(url.pathname)?.[1];
  let lang = url.searchParams.get('lang') || pathLang || preferred || (navigator.language.startsWith('zh') ? 'zh-CN' : 'en');
  lang = lang === 'en' ? 'en' : 'zh-CN';
  let activeCase = null;

  const t = (zh, en) => (lang === 'zh-CN' ? zh : en);
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const ICONS = {
    shield: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
    compare: '<path d="m16 3 4 4-4 4M4 7h16M8 21l-4-4 4-4m12 4H4"/>',
    play: '<path d="m8 5 11 7-11 7Z"/>',
    chevron: '<path d="m9 6 6 6-6 6"/>',
    back: '<path d="m15 6-6 6 6 6"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8m-8 4h5"/>',
    terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m5 0h5"/>',
    browser: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01M13 6.5h.01"/>',
    team: '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4m-7 4v-4h14v4"/>',
    layers: '<path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 17l10 5 10-5"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 1v3m6-3v3M9 20v3m6-3v3M20 9h3m-3 6h3M1 9h3m-3 6h3"/>'
  };
  const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;

  const catalogBase = document.body.dataset.catalogBase;
  const catalog = file => `${catalogBase}${lang}/${file}`;
  const guide = id => catalog(`guides/${id}.html`);
  const demoDoc = id => catalog(`demos/${id}.html`);
  const reader = (kind, params) => `current/${kind}/${lang}/index.html?${new URLSearchParams({ live: '0', detail: 'summary', ...params })}`;
  const x86Reader = id => `recordings/x86-${id}/${lang}/index.html?live=0`;
  const notebookReader = preset => `recordings/notebook-${preset}/${lang}/index.html?live=0&view=native`;
  const historical = (run, lens = 'default', params = {}) => catalog('replay.html') + '?' +
    new URLSearchParams({ run, lens, live: '0', detail: 'summary', ...params });
  const historicalPair = (before, after) => historical(after, 'default', {
    compare_a: before, compare_b: after, compare_dim: 'files'
  });

  const { investigation: investigationCard, workspace: workspaceCard, browser: browserCard, team: teamCard } =
    JSON.parse(document.getElementById('featured-card-data').textContent);
  const number = value => value.toLocaleString(lang);
  const investigationCompareURL = () => reader('investigation', {
    run: investigationCard.after.run,
    compare_a: investigationCard.before.run,
    compare_b: investigationCard.after.run,
    compare_dim: 'files'
  });
  const investigationBeforeURL = () => reader('investigation', { run: investigationCard.before.run });
  const investigationAfterURL = () => reader('investigation', { run: investigationCard.after.run });
  const workspaceURL = () => reader('workspace', { run: workspaceCard.run, lens: 'file-artifact', view: 'workspace' });
  const handoffURL = () => reader('execution', { run: 'run-ce9d7ca0a2af', view: 'handoff' });
  const browserURL = () => reader('browser', { run: browserCard.run, view: 'native' });
  const teamURL = () => historical(teamCard.run, 'orchestration');

  function x86List() {
    return [
      ['workspace-harness', t('Claude 受控工作区实录', 'Claude controlled workspace'), t('沿 Read / Edit / Write / Bash 核对输入版本、版本递增与最终产物。', 'Follow Read, Edit, Write and Bash through revisions and final output.')],
      ['kata-harness', 'Kata / QEMU · Claude ' + t('工作区', 'workspace'), t('同类 Claude 工作区任务在 Kata 虚拟化 Guest 中的完整取证。', 'Separate Claude workspace run recorded inside a Kata/QEMU guest.')],
      ['kata-boot-1', t('Kata 首次启动 Guest 身份', 'First Kata guest boot'), t('首次启动 Guest 身份、代次与执行记录。', 'Identity, generation and execution of the first Kata guest boot.')],
      ['kata-boot-2', t('Kata 重建后 Guest 身份', 'Rebuilt Kata guest'), t('重建后形成独立 Guest 代次，与首次启动隔离。', 'Distinct guest generation after rebuild.')],
      ['kata-contract', t('Kata 工作区版本与回执', 'Kata workspace contract'), t('受控任务在 Kata 内的工作区版本操作与回执。', 'Controlled workspace operations and revision receipts inside Kata.')],
      ['browser-sensor-on', t('Browser + 原生内核 Sensor', 'Browser with native OS sensor'), t('并发页面操作、OS 进程归属关联与 3 份保存的 HAR。', 'Concurrent pages, OS process attribution and 3 saved HAR archives.')],
      ['browser-crash-recovery', t('Browser 中断恢复两代会话', 'Browser crash & recovery'), t('对比中断前后两代浏览器会话，未完成操作诚实保留为 unknown。', 'Two browser generations; interrupted action stays unknown.')]
    ];
  }

  function workspaceSteps() {
    return workspaceCard.rows.map(r => {
      const rev = r.error || ('rev ' + r.before + '→' + r.after);
      const detail = r.error ? (r.next === 'reread' ? t('请重新读取 (reread)', 'Next action: reread') : r.next || '') :
        r.path + ' · ' + (r.kind === 'added' ? r.kind + ' (' + r.size + ' B)' : r.outcome);
      return `<div class="ws-step${r.error ? ' conflict' : ''}" data-tool-call="${esc(r.call)}">
        <span class="ws-rev">${r.error ? '⚠ ' : ''}${esc(rev)}</span><span class="ws-op">${esc(r.tool)}</span><span class="ws-detail">${esc(detail)}</span>
        ${!r.error && r.kind === 'added' ? '<span class="ws-hash">' + esc(r.digest.slice(0, 8)) + '…</span>' : ''}
      </div>`;
    }).join('');
  }

  function renderCards() {
    const {before, after, settings} = investigationCard;
    const diagnosticStat = row => row.records > 0 && row.denied === row.records
      ? t(number(row.denied) + ' 条权限错误', number(row.denied) + (row.denied === 1 ? ' permission error' : ' permission errors'))
      : t(number(row.records) + ' 条诊断记录', number(row.records) + (row.records === 1 ? ' diagnostic entry' : ' diagnostic entries'));
    return `
      <article class="card" data-case="investigation">
        <div class="card-top">
          <div class="card-meta">
            <span class="card-icon">${icon('file')}</span>
            <span>${t('任务调查与修复', 'Investigate & compare')}</span>
            <span class="badge">${t('DeepSeek · 两次执行', 'DeepSeek · 2 runs')}</span>
          </div>
          <h3>${t('测试全过，为什么诊断还是触发了受限访问？', 'Tests passed. Why did diagnostics hit restricted access?')}</h3>
          <p class="card-desc">${t('从任务指令与子 Agent 审阅追到受限诊断与外联，一键对比修复前后的真实文件变更。', 'Trace from task prompt and subagent review to denied diagnostics, then diff the exact repair files.')}</p>
        </div>
        <a class="stage-link" href="${esc(investigationCompareURL())}">
          <div class="stage diff-stage">
            <div class="diff-row" data-event="${esc(before.event)}"><span class="diff-pill before">${t('修复前', 'Before')}</span><span class="diff-file">${esc(before.path)}</span><span class="diff-stat">${esc(diagnosticStat(before))}</span></div>
            <div class="diff-row" data-event="${esc(settings.event)}"><span class="diff-pill edit">${t('配置', 'Settings')}</span><span class="diff-file">${esc(settings.path)}</span><span class="diff-stat">${t(number(settings.disabled) + ' 项关闭', number(settings.disabled) + ' off')}</span></div>
            <div class="diff-row" data-event="${esc(after.event)}"><span class="diff-pill after">${t('修复后', 'After')}</span><span class="diff-file">${esc(after.path)}</span><span class="diff-stat">${esc(diagnosticStat(after))}</span></div>
          </div>
        </a>
        <div class="card-foot">
          <div class="actions-row">
            <a class="btn primary" href="${esc(investigationCompareURL())}">${icon('compare')}<span>${t('对比修复前后文件', 'Compare repair files')}</span></a>
            <a class="btn" href="${esc(investigationAfterURL())}">${icon('play')}<span>${t('打开证据图', 'Open graph')}</span></a>
            <button type="button" class="text-btn" data-story="investigation">${t('案例经过', 'Details')}${icon('chevron')}</button>
          </div>
          <div class="sub-links">
            <span>${t('直达：', 'Jump to:')}</span>
            <a href="${esc(investigationBeforeURL())}">${t('修复前实录', 'Before repair')}</a>
            <a href="${esc(reader('investigation', { run: after.run, view: 'compliance' }))}">${t('合规评估', 'Compliance')}</a>
            <a href="${esc(reader('investigation', { run: after.run, view: 'risk' }))}">${t('访问控制', 'Access control')}</a>
            <a href="${esc(guide('graph'))}">${t('文档说明', 'Docs')}</a>
          </div>
        </div>
      </article>

      <article class="card" data-case="remote">
        <div class="card-top">
          <div class="card-meta">
            <span class="card-icon">${icon('terminal')}</span>
            <span>${t('受控工作区与跨环境执行', 'Workspace & remote handoff')}</span>
            <span class="badge new">${t('v1.0 新增', 'New in v1.0')}</span>
          </div>
          <h3>${t('远端改文件、遇冲突，每一步有回执', 'Revisions, conflicts & operation receipts')}</h3>
          <p class="card-desc">${t('核对 Read / Edit / Write / Bash 的版本链和冲突拒绝原因，并追踪跨环境调用交接。', 'Inspect file revisions, rejected conflict writes and cross-sandbox execution handoffs.')}</p>
        </div>
        <a class="stage-link" href="${esc(workspaceURL())}">
          <div class="stage ws-stage">
            ${workspaceSteps()}
          </div>
        </a>
        <div class="card-foot">
          <div class="actions-row">
            <a class="btn primary" href="${esc(workspaceURL())}">${icon('play')}<span>${t('打开工作区视图', 'Open workspace')}</span></a>
            <a class="btn" href="${esc(handoffURL())}">${t('跨环境交接', 'Handoffs')}</a>
            <button type="button" class="text-btn" data-story="remote">${t('案例经过', 'Details')}${icon('chevron')}</button>
          </div>
          <div class="sub-links">
            <span>${t('Linux x86 & 文档：', 'Linux x86 & Docs:')}</span>
            <a href="${esc(x86Reader('workspace-harness'))}">${t('Claude 工作区', 'Claude workspace')}</a>
            <a href="${esc(x86Reader('kata-harness'))}">Kata / QEMU</a>
            <a href="${esc(guide('workspace'))}">${t('工作区文档', 'Workspace docs')}</a>
            <a href="${esc(guide('execution-handoff'))}">${t('交接文档', 'Handoff docs')}</a>
          </div>
        </div>
      </article>

      <article class="card" data-case="native">
        <div class="card-top">
          <div class="card-meta">
            <span class="card-icon">${icon('browser')}</span>
            <span>${t('Browser 与 Notebook 原生记录', 'Browser & Notebook context')}</span>
            <span class="badge new">${t('v1.0 新增', 'New in v1.0')}</span>
          </div>
          <h3>${t('网页操作、截图与 HAR 直接联查', 'Actions, screenshots & HAR in one view')}</h3>
          <p class="card-desc">${t('保留页面、请求、截图与 Jupyter 单元格原生身份，在工作台里直接预览附件与正文。', 'Inspect native page, request, screenshot, HAR and Jupyter records right inside the workbench.')}</p>
        </div>
        <a class="stage-link" href="${esc(browserURL())}">
          <div class="stage browser-stage">
            <div class="br-trail">
              <div class="br-item" data-entry="${esc(browserCard.navigation.entry)}"><span class="br-tag">${esc(browserCard.navigation.op)}</span><span class="br-val">${esc(browserCard.navigation.path)}</span></div>
              <div class="br-item" data-entry="${esc(browserCard.read.entry)}"><span class="br-tag">${esc(browserCard.read.op)}</span><span class="br-val">${esc(browserCard.read.text)}</span></div>
              <div class="br-item br-attachments">${['har','png'].map(key => `<span class="br-size" data-ref="${esc(browserCard[key].ref)}"><span class="br-tag har">${key.toUpperCase()}</span> ${number(browserCard[key].bytes)} B</span>`).join('')}</div>
            </div>
            <div class="br-shot">
              <div class="br-shot-bar"><span class="br-dot"></span><span class="br-dot"></span><span class="br-dot"></span><span>${t('已保存截图', 'Saved screenshot')} · PNG</span></div>
              <img src="${esc(browserCard.png.asset)}" alt="${esc(t('实录中的页面截图', 'Screenshot from the recording'))}" loading="eager">
            </div>
          </div>
        </a>
        <div class="card-foot">
          <div class="actions-row">
            <a class="btn primary" href="${esc(browserURL())}">${icon('play')}<span>${t('打开 Browser 视图', 'Open Browser')}</span></a>
            <a class="btn" href="${esc(notebookReader('detailed'))}">Notebook</a>
            <button type="button" class="text-btn" data-story="native">${t('案例经过', 'Details')}${icon('chevron')}</button>
          </div>
          <div class="sub-links">
            <span>${t('Linux x86 & 文档：', 'Linux x86 & Docs:')}</span>
            <a href="${esc(x86Reader('browser-sensor-on'))}">${t('Browser + 原生 Sensor', 'Browser with Sensor')}</a>
            <a href="${esc(x86Reader('browser-crash-recovery'))}">${t('中断恢复', 'Crash recovery')}</a>
            <a href="${esc(guide('browser-context'))}">${t('Browser 文档', 'Browser docs')}</a>
            <a href="${esc(guide('notebook-context'))}">${t('Notebook 文档', 'Notebook docs')}</a>
          </div>
        </div>
      </article>

      <article class="card" data-case="team">
        <div class="card-top">
          <div class="card-meta">
            <span class="card-icon">${icon('team')}</span>
            <span>${t('多 Agent 协作与安全溯源', 'Multi-agent & security lineage')}</span>
            <span class="badge">${t('经典实录 · ' + number(teamCard.events) + ' 个事件', 'Classic · ' + number(teamCard.events) + ' events')}</span>
          </div>
          <h3>${t('谁发起委派、谁触发了风险，一图看清', 'Trace delegation, refusal & risky execution')}</h3>
          <p class="card-desc">${t('沿 Alice 与 Bob 的委派消息、模型拒绝与依赖安装，直达敏感文件访问与外联证据。', 'Follow Alice and Bob through peer messages, a refusal, dependency install and runtime risk signals.')}</p>
        </div>
        <a class="stage-link" href="${esc(teamURL())}">
          <div class="stage graph-stage">
            <div class="graph-frame">
              <img src="refined-media/team-${lang}.png" alt="${esc(t('Alice 与 Bob 协作关系证据图', 'Alice and Bob collaboration graph'))}" loading="lazy">
            </div>
          </div>
        </a>
        <div class="card-foot">
          <div class="actions-row">
            <a class="btn primary" href="${esc(teamURL())}">${icon('play')}<span>${t('打开协作证据图', 'Open team graph')}</span></a>
            <a class="btn" href="${esc(historical('a2a-demo', 'orchestration'))}">${t('跨 Pod A2A', 'Cross-Pod A2A')}</a>
            <button type="button" class="text-btn" data-story="team">${t('案例经过', 'Details')}${icon('chevron')}</button>
          </div>
          <div class="sub-links">
            <span>${t('相关实录 & 文档：', 'Related & Docs:')}</span>
            <a href="${esc(historical('claude-demo', 'substrate'))}">${t('Kubernetes 部署归属', 'K8s placement')}</a>
            <a href="${esc(demoDoc('multiagent-provenance'))}">${t('文档说明', 'Guide & docs')}</a>
            <a href="${esc(demoDoc('k8s-cross-pod-a2a'))}">${t('跨 Pod 文档', 'Cross-Pod docs')}</a>
          </div>
        </div>
      </article>
    `;
  }

  function renderArchiveChapters() {
    const chapters = [
      ['x86', 'cpu', 'blue', t('Linux x86 实录合集', 'Linux x86 recordings'), t('Claude 受控工作区、Kata / QEMU 虚拟化 Guest、Browser + 原生 Sensor 与中断恢复（含离线 ZIP 下载）。', 'Claude workspace, Kata/QEMU guest runs, Browser with native sensor and crash recovery (with offline ZIPs).'), t('7 份实录', '7 runs')],
      ['earlier', 'file', 'orange', t('历史报表修复对比', 'Historical report repair comparisons'), t('2026 年 10 月与 11 月的两次复现实录，各自保留修复前后的配对对比与归因证据。', 'October and November reproductions, each with its own before-and-after comparison pair.'), t('2 组对比', '2 pairs')],
      ['development', 'terminal', '', t('DeepSeek 完整开发任务', 'DeepSeek full development task'), t('从用户指令一路追踪到工具输入输出、7 项测试通过与最终保存文件正文。', 'Trace task prompt, tool outputs, 7 passing tests and final saved file contents.'), t('1 份实录', '1 run')],
      ['grok', 'clock', 'red', t('Grok 历史外发调查', 'Grok historical outbound investigations'), t('带采集日期的历史签名实录：代码库外发路径与三类外发面区分（原场景已无法重跑）。', 'Dated historical captures separating model inference, telemetry and third-party analytics.'), t('2 份实录', '2 runs')],
      ['presets', 'layers', 'purple', t('采集档位与 Jupyter 附件样本', 'Capture presets & Jupyter attachments'), t('对比 Browser / Notebook 的 basic 轻量档与 detailed 留存档，以及图表附件与 Kernel 重启样本。', 'Compare basic vs detailed retention presets plus Jupyter chart attachments and kernel restart.'), t('3 份样本', '3 examples')]
    ];
    return `
      <div class="archive-group">
        ${chapters.map(([key, ic, tone, title, desc, cnt]) => `
          <button type="button" class="chapter-btn" data-story="${key}">
            <span class="chapter-ic ${tone}">${icon(ic)}</span>
            <span class="chapter-body">
              <strong class="chapter-title">${esc(title)}</strong>
              <span class="chapter-desc">${esc(desc)}</span>
            </span>
            <span class="chapter-count">${esc(cnt)}</span>
            <span class="chapter-chev">${icon('chevron')}</span>
          </button>
        `).join('')}
      </div>
    `;
  }

  function render() {
    try { localStorage.setItem('agentprov_language', lang); } catch {}
    document.documentElement.lang = lang;
    document.title = `${t('交互示例库', 'Interactive Demos')} · AgentProvenance v1.0`;
    const copyCmd = './agentprov doctor -- claude\n./agentprov launch --file-diff -- claude\n./agentprov dashboard serve';

    root.innerHTML = `
      <header class="topbar">
        <a class="brand" href="?lang=${lang}"><span><b>Agent</b>Provenance</span><span class="version-pill">v1.0</span></a>
        <nav class="top-nav" aria-label="${esc(t('主导航', 'Main navigation'))}">
          <a href="#featured" aria-current="page">${t('精选实录', 'Featured')}</a>
          <a href="#archive">${t('案例档案', 'Archive')}</a>
          <a href="#capture">${t('本地录制', 'Quickstart')}</a>
          <a href="${esc(guide('start'))}">${t('文档', 'Docs')}</a>
          <a href="https://github.com/ByteYellow/AgentProvenance" target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
        <span class="spacer"></span>
        <button hidden id="page-tour-start" type="button" aria-label="${t('页面导览','Page tour')}" title="${t('页面导览','Page tour')}"><span aria-hidden="true" class="tour-icon">?</span><span class="tour-label">${t('页面导览','Page tour')}</span></button>
        <nav class="languages" aria-label="${esc(t('语言', 'Language'))}">
          <button type="button" data-lang="en" aria-pressed="${lang === 'en'}">English</button>
          <button type="button" data-lang="zh-CN" aria-pressed="${lang === 'zh-CN'}">中文</button>
        </nav>
      </header>
      <div data-tour-slot hidden></div>

      <section class="hero-band">
        <div class="hero-inner hero-copy">
          <h1>${t('看清 Agent 到底做了什么', 'See what your AI agent actually did')}</h1>
          <p class="hero-sub">${t('<span class="hero-clause">把模型对话、工具调用与进程、文件、网络事实，</span><span class="hero-clause">连成一张可回放、可验证的因果证据图。</span>', 'Connect agent conversations and tool calls to OS processes, files and network facts in one verifiable provenance graph.')}</p>
          <div class="hero-actions">
            <a class="btn primary" href="${esc(investigationCompareURL())}">${icon('compare')}<span>${t('体验修复前后对比', 'Try before/after compare')}</span></a>
            <a class="btn" href="#archive">${t('浏览分类案例档案', 'Browse case archive')}</a>
          </div>
          <p class="hero-note">${t('只读回放 · 读取时校验内容哈希 · 无需 API Key', 'Read-only replays · Content hashes checked on read · No API key')}</p>
          <div class="hero-flow" aria-label="${esc(t('三层证据关联', 'Three-layer evidence model'))}">
            <button type="button" class="flow-chip" data-jump="investigation">
              <span class="flow-ic blue">${icon('terminal')}</span>
              <span class="flow-text">
                <span class="flow-title">${t('会话与工具意图', 'Session & tool intent')}</span>
                <span class="flow-sub">${t('对话上下文、子 Agent 审阅与工具调用', 'Prompts, subagent reviews & tool calls')}</span>
              </span>
              <span class="flow-go" aria-hidden="true">${icon('chevron')}</span>
            </button>
            <button type="button" class="flow-chip" data-jump="team">
              <span class="flow-ic green">${icon('cpu')}</span>
              <span class="flow-text">
                <span class="flow-title">${t('进程 · 文件 · 网络', 'OS & network facts')}</span>
                <span class="flow-sub">${t('内核观测文件变更、访问控制与外联', 'Kernel-observed files, audit & egress')}</span>
              </span>
              <span class="flow-go" aria-hidden="true">${icon('chevron')}</span>
            </button>
            <button type="button" class="flow-chip" data-jump="remote">
              <span class="flow-ic purple">${icon('shield')}</span>
              <span class="flow-text">
                <span class="flow-title">${t('SHA-256 离线回放包', 'Verifiable reading copy')}</span>
                <span class="flow-sub">${t('离线读正文，按需核验原件签名', 'Read offline; verify signed originals separately')}</span>
              </span>
              <span class="flow-go" aria-hidden="true">${icon('chevron')}</span>
            </button>
          </div>
        </div>
      </section>

      <main>
        <section id="featured">
          <div class="section-head">
            <h2>${t('精选交互实录', 'Featured interactive recordings')}</h2>
            <p>${t('点击卡片直接进入证据工作台，支持图谱钻取、合规评估、正文阅读与前后对比', 'Open directly into the evidence workbench with graph drilldown, compliance & compare')}</p>
          </div>
          <div class="grid">${renderCards()}</div>
        </section>

        <section id="topics" class="band">
          <div class="section-head">
            <h2>${t('专题调查与评估集成', 'Focused investigations & evaluators')}</h2>
            <p>${t('按具体安全问题深入，或接入外部评审器', 'Drill into a specific security question or evaluator workflow')}</p>
          </div>
          <div class="topic-grid">
            <article class="topic-card">
              <span class="topic-kicker"><span class="topic-ic teal">${icon('shield')}</span>${t('供应链安全', 'Supply chain')}</span>
              <h3>${t('依赖安装中的异常凭据读取', 'Suspicious install-hook exfiltration')}</h3>
              <p>${t('追踪被投毒的依赖包如何在安装阶段读取测试密钥、尝试外联并污染产物。', 'Follow a poisoned package reading planted test credentials and attempting egress.')}</p>
              <div class="topic-links">
                <a href="${esc(historical('run-snake-supervised'))}">${t('打开实录 →', 'Open recording →')}</a>
                <a href="${esc(demoDoc('snake-supply-chain'))}">${t('复现说明', 'Guide')}</a>
              </div>
            </article>
            <article class="topic-card">
              <span class="topic-kicker"><span class="topic-ic indigo">${icon('layers')}</span>${t('关联依据 · 合成样本', 'Attribution · Synthetic')}</span>
              <h3>${t('一条推断关联的依据是什么？', 'What backs a derived edge?')}</h3>
              <p>${t('清晰区分已观测事实与推断关联：查看正文命中、候选源文件与未消解归属。', 'Inspect body matches, candidate source reads and unresolved execution identity honestly.')}</p>
              <div class="topic-links">
                <a href="${esc(historical('ui-endpoint-candidates', 'data-flow-taint'))}">${t('查看样本 →', 'Explore example →')}</a>
                <a href="${esc(demoDoc('endpoint-attribution'))}">${t('关联方法', 'Methodology')}</a>
              </div>
            </article>
            <article class="topic-card">
              <span class="topic-kicker"><span class="topic-ic purple">${icon('terminal')}</span>${t('外部评测', 'Evaluators')}</span>
              <h3>${t('让 LLM / Jev 沿着证据打分', 'Feed evidence to LLM Judge & Jev')}</h3>
              <p>${t('通过 JSON / Python / MCP 将可验证轨迹交给外部评测器，把评分与证据引用写回同一张图。', 'Score recorded trajectories via JSON, Python or MCP with verifiable evidence refs.')}</p>
              <div class="topic-links">
                <a href="${esc(demoDoc('llm-judge'))}">${t('LLM Judge 指南', 'LLM Judge')}</a>
                <a href="${esc(demoDoc('jev-judge'))}">${t('Jev 评审指南', 'Jev evaluator')}</a>
              </div>
            </article>
          </div>
        </section>

        <section id="archive" class="band">
          <div class="section-head">
            <h2>${t('案例档案', 'Case archive')}</h2>
            <p>${t('按主题分类收纳其余 15 份 Linux x86、历史复现、安全调查与采集档位实录', '15 additional Linux x86, historical, security and preset recordings organized by chapter')}</p>
          </div>
          ${renderArchiveChapters()}
        </section>

        <section id="capture" class="quickstart-card">
          <div>
            <h2>${t('录下自己的 Agent 任务', 'Record your own agent task')}</h2>
            <p>${t('零外部依赖、本地 SQLite 存储 + 内置离线 Dashboard，录制完成后即可在浏览器里回放与对比。', 'Local SQLite + embedded Dashboard with zero external services. Replay and compare right in your browser.')}</p>
            <div class="harness-pills">
              <span>Claude Code</span>
              <span>Codex</span>
              <span>DeepSeek Harness</span>
              <span>Browser / Jupyter</span>
            </div>
            <div class="rec-links" style="margin-top:0">
              <a href="${esc(guide('quickstart'))}">${t('快速开始文档 →', 'Quickstart docs →')}</a>
              <a href="${esc(guide('execution-handoff'))}">${t('远端执行', 'Handoff')}</a>
              <a href="${esc(guide('browser-context'))}">Browser</a>
              <a href="${esc(guide('notebook-context'))}">Notebook</a>
            </div>
          </div>
          <div class="terminal">
            <div class="term-dots" aria-hidden="true"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i></div>
            <button type="button" class="copy-btn" id="copy-cmd">${t('复制命令', 'Copy')}</button>
            <div><span class="dim">$ </span><span class="cmd-bin">./agentprov</span> doctor <span class="cmd-flag">--</span> claude</div>
            <div><span class="dim">$ </span><span class="cmd-bin">./agentprov</span> launch <span class="cmd-flag">--file-diff --</span> claude</div>
            <div><span class="dim">$ </span><span class="cmd-bin">./agentprov</span> dashboard serve</div>
          </div>
        </section>

        <footer class="page-footer">
          <span>AgentProvenance · ${t('交互示例库', 'Interactive demo library')}</span>
          <nav>
            <a href="${esc(catalog(catalogBase ? 'index.html' : 'library.html'))}">${t('全部命令行示例', 'CLI demo catalog')}</a>
            <a href="${esc(guide('demo-library'))}">${t('案例指南', 'Demo guide')}</a>
            <a href="https://github.com/ByteYellow/AgentProvenance/releases/latest" target="_blank" rel="noopener noreferrer">${t('下载 CLI', 'Download CLI')}</a>
          </nav>
        </footer>
      </main>
    `;

    root.querySelector('#copy-cmd')?.addEventListener('click', async e => {
      const btn = e.currentTarget;
      let ok = false;
      try {
        if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(copyCmd); ok = true; }
      } catch {}
      if (!ok) {
        try {
          const ta = document.createElement('textarea');
          ta.value = copyCmd; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.append(ta); ta.select(); ok = document.execCommand('copy'); ta.remove();
        } catch {}
      }
      btn.textContent = ok ? t('已复制', 'Copied') : t('请手动复制', 'Select to copy');
      setTimeout(() => { btn.textContent = t('复制命令', 'Copy'); }, 1500);
    });
    document.dispatchEvent(new Event('agentprov:tour-ready'));
  }

  function rec(title, tag, desc, links, meta = '') {
    return `<div class="rec-item"><div class="rec-top"><h3>${title}</h3><span class="badge">${tag}</span></div><p>${desc}</p><div class="rec-links">${links}</div>${meta ? `<small>${esc(meta)}</small>` : ''}</div>`;
  }

  function caseBody(id) {
    const open = (href, txt) => `<a class="btn primary sm" href="${esc(href)}">${txt}</a>`;
    const dl = file => `<a href="downloads/reading/${esc(file)}" download>${t('下载离线阅读包', 'Download offline ZIP')}</a>`;
    if (id === 'archive') return {
      title: t('案例档案分类', 'Case archive chapters'),
      html: `<p class="dlg-intro">${t('按主题分类浏览全部 15 份历史实录、Linux x86 录制与采集档位样本。', 'Browse all 15 Linux x86, historical, security and preset recordings by topic.')}</p>` + renderArchiveChapters()
    };
    if (id === 'investigation') return {
      title: t('任务调查与修复', 'Task investigation & repair'),
      html: `<p class="dlg-intro">${t('DeepSeek 在配置修复前后分别执行报表流水线检查。你可以直接对比两次执行的文件变化，或进入任一执行查看图谱、工具输出、合规评估与访问控制记录。', 'DeepSeek ran the reporting pipeline before and after disabling two optional diagnostic switches. Compare changed files directly or inspect either execution in the workbench.')}</p>
        <ol class="steps">
          <li><strong>1. ${t('看差异', 'Inspect the diff')}</strong>${t('直接定位 settings.json、diagnostics.json 与 review.md 的内容变化并阅读正文。', 'See exact changes across settings.json, diagnostics.json and review.md with full body preview.')}</li>
          <li><strong>2. ${t('读会话与工具', 'Read session & tools')}</strong>${t('查看主会话与子 Agent 审阅过程及完整工具输出。', 'Read the main session, subagent review and tool outputs.')}</li>
          <li><strong>3. ${t('核对合规与访问控制', 'Check compliance & audit')}</strong>${t('查看合规控制映射、AppArmor/seccomp 状态与网络外联。', 'Inspect compliance mappings, AppArmor/seccomp states and egress records.')}</li>
        </ol>`
        + rec(t('修复前后配对对比', 'Paired before & after'), t('执行实录', 'Recorded'), t('直接打开「文件证据」差异，跳过实例元数据噪音，并支持直接阅读正文。', 'Opens directly to File evidence diffs with body preview.'),
          open(investigationCompareURL(), t('对比修复前后文件', 'Compare files')) + `<a href="${esc(investigationBeforeURL())}">${t('修复前', 'Before')}</a><a href="${esc(investigationAfterURL())}">${t('修复后', 'After')}</a><a href="${esc(guide('graph'))}">${t('追溯与比较文档', 'Graph & compare docs')}</a>` + dl('task-investigation.zip'), investigationCard.before.run + ' → ' + investigationCard.after.run)
    };
    if (id === 'remote') return {
      title: t('受控工作区与跨环境执行', 'Workspace revisions & remote handoff'),
      html: `<p class="dlg-intro">${t('工作区实录展示了版本递增、冲突拒绝（conflict → reread）与最终文件产物；跨环境交接展示了 2 个 Claude 会话与 3 次远端执行尝试及回执恢复。', 'The workspace run captures revision chains, a rejected conflict write and final artifact; the handoff run captures 2 Claude sessions, 3 remote attempts and receipt recovery.')}</p>`
        + rec(t('远端工作区：读、改、冲突、产物', 'Remote workspace: read, edit, conflict, output'), 'Linux x86', t('原生 Sensor + 工作区版本链，包含 conflict 拒绝回执。', 'Native sensor + workspace revisions including a conflict rejection.'), open(workspaceURL(), t('打开工作区视图', 'Open workspace')) + `<a href="${esc(guide('workspace'))}">${t('工作区文档', 'Workspace docs')}</a>` + dl('workspace-contract.zip'), workspaceCard.run)
        + rec(t('跨环境：调用交接与恢复', 'Cross-environment handoff & recovery'), t('执行实录', 'Recorded'), t('两个 Claude 会话、三次远端执行尝试与回执丢失恢复。', 'Two Claude sessions, three remote attempts and receipt recovery.'), open(handoffURL(), t('打开交接实录', 'Open handoff')) + `<a href="${esc(guide('execution-handoff'))}">${t('交接文档', 'Handoff docs')}</a>` + dl('native-matrix.zip'), 'run-ce9d7ca0a2af')
    };
    if (id === 'native') return {
      title: t('Browser 与 Notebook 原生记录', 'Browser & Notebook native records'),
      html: `<p class="dlg-intro">${t('在工作台的 Browser / Notebook 顶层视图中直接阅读操作、请求身份、内联截图预览与格式化 HAR。', 'Inspect browser actions, request identities, inline screenshots and formatted HAR directly in the top-level Browser / Notebook view.')}</p>`
        + rec('Browser · detailed', t('执行实录', 'Recorded'), t('网页导航、点击、文本读取、PNG 截图与 HAR 网络记录。', 'Navigation, clicks, text reads, PNG screenshot and HAR capture.'), open(browserURL(), t('打开 Browser 视图', 'Open Browser')) + `<a href="${esc(guide('browser-context'))}">${t('Browser 文档', 'Browser docs')}</a>` + dl('browser-detailed.zip'), browserCard.run)
        + rec('Notebook · detailed', t('执行实录', 'Recorded'), t('真实 Claude 任务中的 Jupyter 单元格输入与执行输出。', 'Jupyter cells and outputs from a real Claude task.'), open(notebookReader('detailed'), t('打开 Notebook 视图', 'Open Notebook')) + `<a href="${esc(guide('notebook-context'))}">${t('Notebook 文档', 'Notebook docs')}</a>` + dl('notebook-detailed.zip'))
    };
    if (id === 'team') return {
      title: t('多 Agent 协作与 Kubernetes 归属', 'Multi-agent collaboration & placement'),
      html: `<p class="dlg-intro">${t('追踪 Alice 与 Bob 的委派、拒绝与风险执行，并可对比 Kubernetes 跨 Pod A2A 与工作负载位置记录。', 'Follow Alice & Bob delegation, refusal and risk execution, alongside Kubernetes cross-Pod A2A and workload placement.')}</p>`
        + rec(t('Alice / Bob 团队协作', 'Alice / Bob collaboration'), t('历史实录', 'Historical'), t('含委派、同伴消息、模型拒绝与投毒依赖安装。', 'Delegation, peer messages, refusal and poisoned package install.'), open(teamURL(), t('打开协作图', 'Open graph')) + `<a href="${esc(demoDoc('multiagent-provenance'))}">${t('调查指南', 'Guide')}</a>`, teamCard.run + ' · 2026-07-13')
        + rec(t('跨 Pod A2A 协作', 'Cross-Pod A2A'), t('混合来源', 'Mixed'), t('单节点 Sensor 捕获两个 Pod 的跨 Pod 通信。', 'Single node sensor attributing two Pods.'), open(historical('a2a-demo', 'orchestration'), t('打开实录', 'Open')) + `<a href="${esc(demoDoc('k8s-cross-pod-a2a'))}">${t('来源说明', 'Details')}</a>`)
        + rec(t('Kubernetes 运行位置', 'Kubernetes placement'), t('历史实录', 'Historical'), t('Pod、容器与 cgroup 执行范围对应。', 'Pod, container and cgroup attribution.'), open(historical('claude-demo', 'substrate'), t('打开实录', 'Open')))
    };
    if (id === 'x86') return {
      title: t('Linux x86 实录合集（7 份）', 'Linux x86 recordings (7)'),
      chapter: true,
      html: `<p class="dlg-intro">${t('在 Linux x86 原生内核 Sensor 与 Kata / QEMU 环境中录制的 7 份独立实录，均提供离线只读 ZIP 下载。', '7 standalone runs recorded on Linux x86 with native kernel sensor and Kata/QEMU, each with an offline ZIP.')}</p>`
        + x86List().map(([xid, name, copy]) =>
          rec(name, 'Linux x86', copy, open(x86Reader(xid), t('打开工作台', 'Open')) + `<a href="downloads/x86-${xid}.zip" download>${t('下载离线包', 'Download ZIP')}</a>`, `x86-${xid}`)
        ).join('')
    };
    if (id === 'earlier') return {
      title: t('历史报表修复对比（10 月 / 11 月复现）', 'Historical report repair comparisons'),
      chapter: true,
      html: `<p class="dlg-intro">${t('同类报表修复任务在不同日期的两次独立复现，每组均保留修复前后的配对对比与调查指南。', 'Two independent reproductions of the reporting pipeline repair on different dates, each with its paired comparison.')}</p>`
        + rec(t('11 月复现：工具与外联归因', 'November reproduction: tool & egress attribution'), t('历史实录', 'Historical'), t('追到具体工具调用、访问控制决策与 TLS 片段。', 'Tool-scoped intent, audit decisions and TLS fragments.'), open(historicalPair('run-2fd63df0ab9b', 'run-48baa3821074'), t('对比修复前后', 'Compare')) + `<a href="${esc(historical('run-2fd63df0ab9b'))}">${t('修复前', 'Before')}</a><a href="${esc(historical('run-48baa3821074'))}">${t('修复后', 'After')}</a><a href="${esc(demoDoc('evidence-attribution'))}">${t('案例指南', 'Guide')}</a>`, '2026-11-06')
        + rec(t('10 月复现：拒绝与配置修改', 'October reproduction: subagent review & config diff'), t('历史实录', 'Historical'), t('子 Agent 审阅、被拒诊断与 settings.json 修改。', 'Subagent review, denied diagnostics and settings.json diff.'), open(historicalPair('run-e9c3f452461a', 'run-2267309eda57'), t('对比修复前后', 'Compare')) + `<a href="${esc(historical('run-e9c3f452461a'))}">${t('修复前', 'Before')}</a><a href="${esc(historical('run-2267309eda57'))}">${t('修复后', 'After')}</a><a href="${esc(demoDoc('investigation-workflow'))}">${t('案例指南', 'Guide')}</a>`, '2026-10-19')
    };
    if (id === 'development') return {
      title: t('DeepSeek 完整开发任务', 'DeepSeek full development task'),
      chapter: true,
      html: `<p class="dlg-intro">${t('一次从头到尾的完整开发任务历史实录，适合沿时间线阅读 Agent 的完整工作流。', 'A complete end-to-end development task recording from user instructions to final files.')}</p>`
        + rec(t('任务、7 项测试与最终文件', 'Task, 7 tests & final files'), t('历史实录', 'Historical'), t('从用户指令一路追踪到工具结果、测试通过与最终文件正文。', 'Follow instructions, tool results, 7 passing tests and final files.'), open(historical('run-dbc2adf273d4'), t('打开工作台', 'Open')) + `<a href="${esc(demoDoc('deepseek-context'))}">${t('案例说明', 'Guide')}</a>`, 'run-dbc2adf273d4 · 2026-09-28')
    };
    if (id === 'grok') return {
      title: t('Grok 历史外发调查', 'Grok historical outbound investigations'),
      chapter: true,
      html: `<p class="dlg-intro">${t('带采集日期的历史实录，原线上场景已无法复现，完整保留原始签名证据供调查。', 'Dated historical captures retained with original signed evidence.')}</p>`
        + rec(t('代码库外发路径', 'Codebase outbound data'), t('历史实录', 'Historical'), t('阅读原始外发行为及保存正文。', 'Inspect recorded outbound behavior and saved content.'), open(historical('run-grok-exfil'), t('打开工作台', 'Open')) + `<a href="${esc(demoDoc('grok-codebase-exfil'))}">${t('调查指南', 'Guide')}</a>`, 'run-grok-exfil · 2026-07-14')
        + rec(t('三类外发路径', 'Three outbound routes'), t('历史实录', 'Historical'), t('区分模型推理请求、厂商遥测与第三方分析。', 'Separate model requests, vendor telemetry and third-party analytics.'), open(historical('run-grok-3routes'), t('打开工作台', 'Open')) + `<a href="${esc(demoDoc('grok-3routes'))}">${t('调查指南', 'Guide')}</a>`, 'run-grok-3routes · 2026-07-15')
    };
    if (id === 'presets') return {
      title: t('采集档位与 Jupyter 附件样本', 'Capture presets & Jupyter attachments'),
      chapter: true,
      html: `<p class="dlg-intro">${t('对比 basic 轻量元数据留存与 detailed 完整正文/附件留存，以及 Jupyter 图表附件与 Kernel 重启身份。', 'Compare basic vs detailed capture retention presets and inspect Jupyter chart attachments.')}</p>`
        + rec('Browser · basic / detailed', t('执行实录', 'Recorded'), t('对比仅留存元数据的轻量档与完整截图/HAR 档。', 'Compare lightweight metadata retention vs detailed PNG/HAR capture.'), open(`recordings/browser-basic/${lang}/index.html?live=0&view=native`, t('打开 basic', 'Open basic')) + `<a href="${esc(browserURL())}">${t('打开 detailed', 'Open detailed')}</a>` + dl('browser-basic.zip'))
        + rec('Notebook · basic / detailed', t('执行实录', 'Recorded'), t('Jupyter 请求、单元格代码与输出留存。', 'Jupyter requests, code and output retention.'), open(notebookReader('basic'), t('打开 basic', 'Open basic')) + `<a href="${esc(notebookReader('detailed'))}">${t('打开 detailed', 'Open detailed')}</a>` + dl('notebook-basic.zip'))
        + rec(t('Jupyter 图表与 Kernel 重启', 'Jupyter chart & kernel restart'), t('合成样本', 'Synthetic'), t('展示 PNG 图表附件、父消息引用与重启前后 Kernel 身份。', 'PNG chart attachments, parent-message refs and restarted kernel identity.'), open(reader('notebook', { run: 'notebook-detailed', view: 'native' }), t('打开样本', 'Open example')))
    };
    return null;
  }

  function openCase(id) {
    const info = caseBody(id);
    if (!info) return;
    activeCase = id;
    document.querySelector('#case-eyebrow').textContent = info.chapter ? t('案例档案', 'CASE ARCHIVE') : t('案例经过与实录入口', 'CASE STORY & RECORDINGS');
    document.querySelector('#case-title').textContent = info.title;
    const back = info.chapter ? `<button type="button" class="back-btn" data-story="archive">${icon('back')}${t('返回全部分类', 'All archive chapters')}</button>` : '';
    document.querySelector('#case-body').innerHTML = back + info.html;
    if (!dialog.open) dialog.showModal();
    document.querySelector('#case-body').scrollTop = 0;
  }

  root.addEventListener('click', e => {
    const story = e.target.closest('[data-story]');
    if (story) return openCase(story.dataset.story);
    const jump = e.target.closest('[data-jump]');
    if (jump) {
      const card = root.querySelector(`.card[data-case="${jump.dataset.jump}"]`);
      card?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      card?.animate([{ boxShadow: '0 0 0 3px rgba(0,113,227,0.35)' }, { boxShadow: 'none' }], { duration: 900 });
      return;
    }
    const lb = e.target.closest('[data-lang]');
    if (lb && lb.dataset.lang !== lang) {
      lang = lb.dataset.lang;
      const next = new URL(location.href);
      next.searchParams.set('lang', lang);
      history.replaceState({}, '', next);
      render();
      if (activeCase) openCase(activeCase);
    }
  });
  dialog.addEventListener('click', e => {
    if (e.target === dialog) return dialog.close();
    const story = e.target.closest('[data-story]');
    if (story) openCase(story.dataset.story);
  });
  document.querySelector('#close-dialog').onclick = () => dialog.close();
  dialog.addEventListener('close', () => { activeCase = null; });

  render();
  if (url.searchParams.has('case')) openCase(url.searchParams.get('case'));

  const updateActiveNav = () => {
    const ids = ['featured', 'archive', 'capture'];
    let cur = 'featured';
    for (const id of ids) {
      const el = document.getElementById(id);
      if (el && el.getBoundingClientRect().top <= 160) cur = id;
    }
    root.querySelectorAll('.top-nav a[href^="#"]').forEach(a => {
      if (a.getAttribute('href') === '#' + cur) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  };
  addEventListener('scroll', updateActiveNav, { passive: true });
})();
