'use strict';
const root = document.querySelector('#app');
const dialog = document.querySelector('#case-dialog');
const url = new URL(location.href);
const production = document.body.dataset.site === 'production';
const archivePrefix = production ? '' : 'archive/';
let preferredLanguage = '';
try { preferredLanguage = localStorage.getItem('agentprov_language') || ''; } catch {}
const pathLanguage = /\/(en|zh-CN)\/(?:index\.html)?$/.exec(url.pathname)?.[1];
let lang = url.searchParams.get('lang') || (production ? pathLanguage || preferredLanguage || (navigator.language.startsWith('zh') ? 'zh-CN' : 'en') : 'zh-CN');
lang = lang === 'en' ? 'en' : 'zh-CN';
let activeStory = null;
const t = (zh, en) => lang === 'zh-CN' ? zh : en;
const escapeHTML = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const icons = {
  arrow:'<path d="M5 12h14m-5-5 5 5-5 5"/>',
  chevron:'<path d="m9 5 7 7-7 7"/>',
  play:'<path d="m8 5 11 7-11 7Z"/>',
  compare:'<path d="m16 3 4 4-4 4M4 7h16M8 21l-4-4 4-4m12 4H4"/>',
  file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8m-8 4h5"/>',
  command:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 8 4 4-4 4m6 0h4"/>',
  browser:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01M13 6.5h.01"/>',
  team:'<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4m-7 4v-4h14v4"/>',
  shield:'<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  archive:'<rect x="3" y="3" width="18" height="4" rx="1"/><path d="M5 7v13h14V7M10 11h4"/>',
  layers:'<path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 17l10 5 10-5"/>'
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name]}</svg>`;
const link = (href, label, cls = '', extra = '') => `<a href="${escapeHTML(production && href.startsWith('#') ? location.pathname + location.search + href : href)}" class="${cls}" ${extra}>${label}</a>`;
const guideLink = (href, label) => link(href, icon('file') + '<span>' + label + '</span>');
const guide = id => `${archivePrefix}${lang}/guides/${id}.html`;
const originalGuide = id => `${archivePrefix}${lang}/demos/${id}.html`;
const historical = (run, lens = 'default') => `${archivePrefix}${lang}/replay.html?${new URLSearchParams({run,lens,live:'0',detail:'summary'})}`;
const current = (kind, run, lens = 'default') => `current/${kind}/${lang}/index.html?${new URLSearchParams({run,lens,live:'0',detail:'summary'})}`;
const realNotebook = preset => `recordings/notebook-${preset}/${lang}/index.html?live=0`;
const primary = (href, text) => link(href, icon('play') + text, 'button primary');
const compareLink = href => link(href, icon('compare') + t('对比修复前后','Compare before & after'), 'button primary compare-action');
const currentInvestigation = () => current('investigation','run-3bfc6838a9c6');
const workspace = () => current('workspace','run-w01-445a3a164ae14723b82f90634cff96f5','file-artifact');
const browser = () => current('browser','run-da25e015ca1f');
const team = () => historical('run-double-attempt','orchestration');
const comparison = (href, a, b) => {
  const target = new URL(href, document.baseURI);
  target.searchParams.set('compare_a', a);
  target.searchParams.set('compare_b', b);
  return target.href;
};
const investigationCompare = () => comparison(currentInvestigation(), 'run-860466af8a9a', 'run-3bfc6838a9c6');
const historicalCompare = (a, b) => comparison(historical(a), a, b);

function stories() {
  return [
    {id:'investigation',icon:'file',kicker:t('任务调查与修复','Investigate & compare'),badge:t('执行实录','Recorded'),title:t('读懂一次任务的执行','Understand an agent run'),description:t('从 DeepSeek 的任务与工具结果，追到文件、网络证据，再比较修复前后的变化。','From the DeepSeek task to its tools, files and network activity. Compare what changed after the repair.'),href:currentInvestigation(),caption:t('文件与产物 · 保存的证据图','Files & artifacts · Recorded graph'),actions:compareLink(investigationCompare()),foot:t('DeepSeek · 两次执行','DeepSeek · Two executions')},
    {id:'remote',icon:'command',kicker:t('工作区与跨环境执行','Workspace & remote execution'),badge:t('v1.0 新增','New in v1.0'),fresh:true,title:t('远端执行，有据可查','Follow execution across environments'),description:t('核对工作区的输入、修改和最终文件；从跨环境记录继续查看调用交接与恢复回执。','Inspect workspace inputs, edits and output files. Follow handoffs and recovered receipts in a companion recording.'),href:workspace(),caption:t('工作区操作 · 输入与输出版本','Workspace operation · Input & output revisions'),actions:primary(workspace(),t('查看工作区','Open workspace')),foot:t('Linux x86 实录 · 含独立交接案例','Linux x86 recording · Separate handoff case')},
    {id:'native',icon:'browser',kicker:t('Browser 与 Notebook','Browser & Notebook'),badge:t('v1.0 新增','New in v1.0'),fresh:true,title:t('从操作，看到真实结果','From an action to its result'),description:t('查看网页操作、请求与截图，阅读 Notebook 代码和输出。每条记录保留原生身份。','Inspect browser actions, requests and screenshots, or notebook code and output, with native record identities.'),href:browser(),caption:t('浏览器任务 · 会话与工具记录','Browser task · Session & tool records'),actions:primary(browser(),'Browser')+link(realNotebook('detailed'),'Notebook','button'),foot:t('真实 Agent 任务 · 应用上下文','Real agent tasks · Application context')},
    {id:'team',icon:'team',kicker:t('多 Agent 协作','Multi-agent collaboration'),badge:t('经典实录','Historical'),title:t('协作的来龙去脉，一路追踪','Follow the work between agents'),description:t('沿着 Alice 与 Bob 的消息、委派和工具调用，查看谁发起任务、谁实际执行。','Follow Alice and Bob through messages, delegation and tool calls to see who initiated the work and who executed it.'),href:team(),caption:t('Agent 协作 · 消息与调用关系','Agent collaboration · Messages & calls'),actions:primary(team(),t('查看协作图','Open team graph')),foot:t('保留原始采集日期与证据引用','Original capture dates & evidence references')}
  ];
}

function topic(symbol, label, title, description, actions, guides) {
  return `<article class="topic-card"><div class="topic-label">${icon(symbol)}<span>${label}</span></div><h3>${title}</h3><p>${description}</p><div class="topic-footer">${actions?`<div class="links topic-action">${actions}</div>`:''}<div class="topic-guides"><div class="links">${guides}</div></div></div></article>`;
}

function render() {
  if(production) { try { localStorage.setItem('agentprov_language',lang); } catch {} }
  document.documentElement.lang = lang;
  document.title = `${t('示例库','Demo library')} · AgentProvenance`;
  document.querySelector('#close-dialog').ariaLabel = t('关闭案例详情','Close case details');
  root.innerHTML = `<header class="topbar">
    ${link('?lang='+lang,'<b>Agent</b>Provenance','brand')}
    <span class="brand-description">${t('Agent 执行观测与证据验证','Verifiable agent observability')}</span><span class="header-divider" aria-hidden="true"></span>
    <nav class="top-nav" aria-label="${t('主导航','Main navigation')}">${link('#featured',t('示例','Demos'),'','aria-current="page"')}${link(guide('start'),t('文档','Documentation'))}${link('https://github.com/ByteYellow/AgentProvenance','GitHub','','target="_blank" rel="noopener noreferrer"')}</nav>
    <span class="spacer"></span><span class="saved-status">${icon('clock')}${t('只读回放','Read-only replay')}</span><nav class="languages" aria-label="${t('语言','Language')}"><button data-lang="en" aria-pressed="${lang==='en'}">English</button><button data-lang="zh-CN" aria-pressed="${lang==='zh-CN'}">中文</button></nav>
  </header><main>
    <section class="intro"><div><p class="eyebrow">AgentProvenance <span>1.0</span></p><h1>${t('示例库','Demo library')}</h1><p>${t('看见 Agent 的真实执行，从一次调用到跨环境协作。','Explore what agents actually did, from a single call to work across environments.')}</p></div><div class="intro-note"><strong>${icon('shield')}${t('打开记录，沿证据探索','Open a recording, follow its evidence')}</strong>${t('无需安装，无需模型 API Key','No installation or model API key required')}</div></section>
    <nav class="section-nav" aria-label="${t('页面章节','Page sections')}">${link('#featured',t('精选案例','Featured cases'))}${link('#topics',t('专题与集成','Topics & integrations'))}${link('#history',t('历史记录','Archive'))}${link('#capture',t('采集自己的任务','Capture your own task')+icon('arrow'),'end')}</nav>
    <section id="featured"><div class="section-head"><h2>${t('精选执行案例','Featured executions')}</h2><p>${t('先读经过，再打开完整记录','Read the story. Explore the complete record.')}</p></div><div class="grid">${stories().map(s=>`<article class="story" data-case="${s.id}"><div class="story-copy"><div class="story-head"><span class="story-icon">${icon(s.icon)}</span><span class="kicker">${s.kicker}</span><span class="tag ${s.fresh?'new':''}">${s.badge}</span></div><h3>${s.title}</h3><p class="description">${s.description}</p></div><figure class="story-preview">${link(s.href,`<img src="media/${s.id}-${lang}.png" width="1024" height="380" alt="${escapeHTML(s.caption)}" decoding="async" loading="${s.id==='investigation'||s.id==='remote'?'eager':'lazy'}">`,'preview-link')}<figcaption>${s.caption}</figcaption></figure><div class="story-actions"><div class="story-bottom">${s.actions}<button class="text-button" data-story="${s.id}">${t('案例经过','Case details')}${icon('chevron')}</button></div><div class="story-foot">${s.foot}</div></div></article>`).join('')}</div></section>
    <section class="band" id="topics"><div class="section-head"><h2>${t('专题与集成','Topics & integrations')}</h2><p>${t('选一个问题，继续深入','Choose a question. Go a little deeper.')}</p></div><div class="topic-grid">
      ${topic('shield',t('安全调查','Security investigation'),t('依赖安装中的异常行为','Suspicious dependency installation'),t('沿安装钩子，追踪测试凭据读取、外联尝试与产物变化。','Follow an install hook through test-credential reads, network attempts and changed artifacts.'),link(historical('run-snake-supervised'),t('查看实录','Open recording')+icon('arrow')),guideLink(originalGuide('snake-supply-chain'),t('案例说明与复现','Case guide & reproduction')))}
      ${topic('layers',t('关联方法','Evidence relationships'),t('一条关联，依据是什么？','What supports a relationship?'),t('用合成样本读懂正文命中、源读取候选和执行归属。','Use a synthetic example to inspect content matches, source-read candidates and execution identity.'),link(historical('ui-endpoint-candidates','data-flow-taint'),t('查看关联样本','Explore the example')+icon('arrow')),guideLink(originalGuide('endpoint-attribution'),t('三段证据与关联方法','Evidence layers & relationships')))}
      ${topic('command',t('AI 研判','AI analysis'),t('让 AI 沿着证据分析','Analyze evidence with AI'),t('LLM 分析执行轨迹，Jev 完成结构化判断。指南包含配置、调用和人工复核流程。','Use an LLM to analyze a trace or Jev for structured judgments. Follow the guides for setup, invocation and human review.'),'',guideLink(originalGuide('llm-judge'),t('LLM 接入指南','LLM integration guide'))+guideLink(originalGuide('jev-judge'),t('Jev 接入与评审指南','Jev integration & review')))}
    </div></section>
    <section class="archive-strip" id="history" aria-labelledby="archive-heading"><div class="archive-mark">${icon('archive')}</div><div class="archive-copy"><h2 id="archive-heading">${t('案例档案','The case archive')}</h2><p>${t('报表修复前后对比、DeepSeek 开发任务、Grok 外发调查与采集示例。','Report repairs, a DeepSeek development task, Grok outbound investigations and capture examples.')}</p></div><button class="button archive-open" data-story="archive">${t('浏览档案','Browse archive')}${icon('arrow')}</button></section>
    <section class="start" id="capture"><div><h2>${t('换成你自己的 Agent 任务','Bring your own agent task')}</h2><p>${t('从本地采集开始，按需接入远端执行、Browser 或 Notebook。','Start with local capture, then add remote execution, Browser or Notebook as needed.')}</p></div><div class="links">${link(guide('quickstart'),t('快速开始','Quick start'),'button')}${link(guide('execution-handoff'),t('远端执行','Remote execution'))}${link(guide('browser-context'),'Browser')}${link(guide('notebook-context'),'Notebook')}</div></section>
    <footer class="page-footer"><span>${t('v1.0 发布后首页预览 · 本地审核','v1.0 release homepage preview · Local review')}</span><span>${link('archive/'+lang+'/index.html',t('原版示例库','Original demo library'))}</span></footer>
  </main>`;
  syncSectionLinks();
}

function syncSectionLinks() {
  const section = ['#featured','#topics','#history','#capture'].includes(location.hash) ? location.hash : '#featured';
  root.querySelectorAll('.section-nav a').forEach(anchor => {
    if(anchor.hash === section) anchor.setAttribute('aria-current','location');
    else anchor.removeAttribute('aria-current');
  });
}

function record(title, kind, description, actions, metadata = '') {
  return `<section class="recording"><div class="recording-top"><h3>${title}</h3><span class="tag">${kind}</span></div><p>${description}</p><div class="links">${actions}</div>${metadata?'<small>'+escapeHTML(metadata)+'</small>':''}</section>`;
}

function description(intro, steps) {
  return `<p class="dialog-intro">${intro}</p><ol class="reading-steps">${steps.map(([title,text])=>`<li><strong>${title}</strong>${text}</li>`).join('')}</ol>`;
}

function screenshot(id) {
  return `<details class="image-disclosure"><summary>${t('展开阅读界面截图','Show the reader screenshot')}</summary><img src="screenshots/${id}.png" alt="${t('已保存案例的阅读界面','Reader for the saved case')}" loading="lazy"></details>`;
}

function caseContent(id) {
  const recorded = t('执行实录','Recorded execution');
  const historic = t('历史实录','Historical recording');
  const open = href => link(href,t('打开记录','Open recording'),'button primary');
  const download = file => link('downloads/'+(production?'reading/':'')+file,t('下载只读回放','Download replay'),'','download');
  const nativeNote = `<p class="source-note">${t('本组 Browser / Notebook 实录采集应用上下文，原生 Sensor 关闭。basic 与 detailed 来自分别执行的任务。','These Browser / Notebook recordings capture application context with the native Sensor off. Basic and detailed are separate task executions.')}</p>`;
  if(id==='archive') return {
    title:t('案例档案','The case archive'),
    content:`<p class="dialog-intro">${t('按你想调查的问题选择案例。报表修复可以直接打开前后对比，开发任务可以查看工具输出和最终文件。','Choose a case by the question you want to investigate. Compare report repairs directly, or inspect tool output and final files from a development task.')}</p><div class="archive-chapters">${[
      ['earlier','file',t('测试通过，为什么报表仍然失败？','Tests passed. Why did the report fail?'),t('关闭多余诊断后，报表恢复生成。两次历史复现实录，各自保留修复前后对比。','Disabling unnecessary diagnostics restored the report. Two historical reproductions, each with its own before-and-after pair.')],
      ['development','command',t('DeepSeek 如何完成一次开发任务','How DeepSeek completed a development task'),t('阅读任务、工具输入输出、7 项测试记录和最终文件。','Read the task, tool inputs and outputs, seven recorded tests and the final files.')],
      ['grok','clock','Grok',t('两份历史调查，阅读代码库外发与三类外发路径。原场景已无法重跑。','Two historical investigations into codebase data and outbound routes. The original scenario cannot be rerun.')],
      ['presets','layers',t('采集档位与附件','Capture presets & attachments'),t('Browser / Notebook 的 basic 与 detailed 实录，以及 Jupyter 图表样本。','Basic and detailed Browser / Notebook recordings, plus a Jupyter chart example.')]
    ].map(([key,symbol,title,copy])=>`<button class="archive-chapter" data-story="${key}"><span class="chapter-icon">${icon(symbol)}</span><span><strong>${title}</strong><small>${copy}</small></span>${icon('chevron')}</button>`).join('')}</div>`
  };
  if(id==='investigation') return {
    title:t('任务调查与修复','Task investigation & repair'),
    content:description(t('DeepSeek 在配置修复前后分别执行调查任务。先读清任务和工具输出，再检查两次运行的配置、文件及网络记录。','DeepSeek performs an investigation before and after a configuration repair. Read the task and tool output, then inspect configuration, files and network records across both runs.'),[
      [t('读任务','Read the task'),t('展开 Agent 会话，查看指令和工具结果。','Open the agent session to read instructions and tool results.')],
      [t('追证据','Follow evidence'),t('从文件或网络记录进入图谱与保存正文。','Open file or network evidence, its graph and saved content.')],
      [t('看变化','Compare changes'),t('直接对比已配对的修复前、修复后记录。','Open the matched before-and-after recordings in Compare.')]
    ])+screenshot('investigation')+record(t('配置修复前后','Before & after configuration repair'),recorded,t('同一个阅读副本包含两次执行，保留原始调用、采集状态和支持证据。','One reading copy contains both executions, their original calls, capture status and supporting evidence.'),compareLink(investigationCompare())+link(currentInvestigation(),t('修复前记录','Before repair'))+link(current('investigation','run-860466af8a9a'),t('修复后记录','After repair'))+download('task-investigation.zip'),'run-3bfc6838a9c6 / run-860466af8a9a')
  };
  if(id==='remote') return {
    title:t('工作区版本与跨环境执行','Workspace revisions & remote execution'),
    content:description(t('这条阅读路线包含两组独立实录：先核对远端工作区中的输入、修改和产物，再看来源 Tool Call 如何交接到目标执行。','This route contains two separate recordings: first inspect workspace inputs, edits and outputs, then follow a source Tool Call into a target execution.'),[
      [t('文件一致性','File consistency'),t('核对输入与输出版本，阅读 result.txt。','Inspect input and output revisions and read result.txt.')],
      [t('执行交接','Execution handoff'),t('沿调用跳到目标 Run，检查执行尝试和回执。','Follow a call to its target Run, attempt and receipt.')],
      [t('交付记录','Delivery records'),t('分别查看执行、采集及封包时交付状态。','Inspect execution, capture and sealed delivery status separately.')]
    ])+screenshot('workspace')+record(t('远端工作区：读、改、跑','Remote workspace: read, edit, run'),t('Linux x86 实录','Linux x86 recording'),t('启用原生 Sensor 的受控工作区任务，保留文件版本、操作回执及最终文件正文。','A controlled workspace task with the native Sensor enabled, file revisions, operation receipts and saved output content.'),open(workspace())+download('workspace-contract.zip'),'run-w01-445a3a164ae14723b82f90634cff96f5')+record(t('跨环境：调用交接与恢复','Cross-environment handoff & recovery'),recorded,t('两个 Claude 会话、三个远端执行尝试，包含回执响应丢失后的查询恢复。','Two Claude sessions and three remote execution attempts, including query recovery after a receipt response is lost.'),open(current('execution','run-ce9d7ca0a2af'))+download('native-matrix.zip'))+`<p class="source-note">${t('下载项为只读阅读副本。工作区及调用交接来自各自的采集记录；原始签名与派生交付在阅读器中分别展示。','Downloads are read-only reading copies. Workspace and handoff cases retain their separate capture records; the reader distinguishes original signatures from derived delivery.')}</p>`
  };
  if(id==='native') return {
    title:t('Browser 与 Notebook 原生记录','Browser & Notebook native records'),
    content:description(t('从 Agent 的一次调用进入浏览器或 Jupyter 的原生操作记录。正文、输出与附件在对应操作下阅读。','Follow an agent call into a native browser or Jupyter record. Read the content, outputs and attachments associated with that operation.'),[
      [t('定位调用','Locate the call'),t('从会话中选择 Browser / Notebook。','Select Browser / Notebook in the session.')],
      [t('阅读原生结果','Read native results'),t('打开请求身份、操作结果及保存正文。','Inspect request identities, results and saved content.')],
      [t('打开附件','Open attachments'),t('按需查看截图或已保存的输出。','Open screenshots or saved output on demand.')]
    ])+screenshot('browser')+record('Browser · detailed',recorded,t('网页任务的操作、请求及截图。','Operations, requests and screenshots from a browser task.'),open(browser())+download('browser-detailed.zip'),'run-da25e015ca1f')+record('Notebook · detailed',recorded,t('真实 Claude 任务中的 Jupyter 请求、代码和结果。','Jupyter requests, code and results from a real Claude task.'),open(realNotebook('detailed'))+download('notebook-detailed.zip'))+nativeNote
  };
  if(id==='team') return {
    title:t('多 Agent 协作与执行位置','Multi-agent collaboration & placement'),
    content:description(t('先看 Alice 与 Bob 之间的委派、拒绝和后续执行。Kubernetes 的两份历史记录则从部署位置与跨 Pod 通信补充另一个观察角度。','Begin with delegation, refusal and subsequent execution between Alice and Bob. Two Kubernetes recordings provide separate perspectives on placement and cross-Pod communication.'),[
      [t('谁发起','Who initiated?'),t('读取消息与关联会话。','Read messages and related sessions.')],
      [t('谁执行','Who executed?'),t('沿工具调用追到执行证据。','Follow tool calls to execution evidence.')],
      [t('在哪里','Where did it run?'),t('从独立 K8s 案例查看工作负载位置。','Inspect placement in the separate Kubernetes cases.')]
    ])+record(t('Alice / Bob 协作','Alice / Bob collaboration'),historic,t('保留委派、消息、拒绝与后续操作的原始记录。','Original records of delegation, messages, refusal and subsequent actions.'),open(team())+link(originalGuide('multiagent-provenance'),t('案例说明与签名包','Guide & signed bundle')),'run-double-attempt · 2026-07-13')+record(t('跨 Pod 协作','Cross-Pod collaboration'),t('混合来源','Mixed sources'),t('回放的应用 hooks 与当次采集的内核事件，按来源分别呈现。','Replayed application hooks and captured kernel events, identified by source.'),open(historical('a2a-demo','orchestration'))+link(originalGuide('k8s-cross-pod-a2a'),t('来源说明','Source details')))+record(t('Kubernetes 运行环境','Kubernetes placement'),historic,t('查看 Pod、容器与执行范围的对应。','Inspect Pod, container and execution-scope associations.'),open(historical('claude-demo','substrate')))
  };
  if(id==='grok') return {
    title:t('Grok 历史调查','Grok historical investigations'),
    content:`<p class="dialog-intro">${t('原场景当前无法重新执行。两份原始实录保留各自的 Run、采集日期和签名证据，供继续调查。','The original scenario can no longer be rerun. Both recordings retain their own Runs, dates and signed evidence for investigation.')}</p>`+record(t('代码库外发路径','Outbound codebase data'),historic,t('阅读原始外发行为及其保存内容。','Inspect the recorded outbound behavior and saved content.'),open(historical('run-grok-exfil'))+link(originalGuide('grok-codebase-exfil'),t('指南与原始签名包','Guide & original signed bundle')),'2026-07-14')+record(t('三类外发路径','Three outbound routes'),historic,t('分别查看模型请求、厂商遥测和第三方分析请求。','Inspect model requests, vendor telemetry and third-party analytics separately.'),open(historical('run-grok-3routes'))+link(originalGuide('grok-3routes'),t('指南与原始签名包','Guide & original signed bundle')),'2026-07-15')
  };
  if(id==='earlier') return {
    title:t('测试通过，为什么报表仍然失败？','Tests passed. Why did the report fail?'),
    content:description(t('计算测试通过，但可选诊断尝试读取受限文件、访问外部地址，导致报表失败。DeepSeek 关闭多余诊断，保留报表计算和原有测试。以下是同类任务在不同日期的两次复现，每组单独对比。','The calculation tests passed, but optional diagnostics tried to read a restricted file and reach an external address, causing the report to fail. DeepSeek disabled those diagnostics while preserving the report and its tests. These are two reproductions of that workflow on different dates, each compared separately.'),[
      [t('修复前','Before'),t('定位失败的诊断调用及其访问控制记录。','Locate the failed diagnostic calls and access-control records.')],
      [t('修改了什么','What changed'),t('查看配置文件中的两项诊断开关。','Inspect the two diagnostic switches in the configuration file.')],
      [t('修复后','After'),t('报表正常生成，总额仍为 42.00。','The report completes with the total still at 42.00.')]
    ])+record(t('11 月复现：追到具体工具与外联','November: trace tools and outbound activity'),historic,t('重点看哪次工具调用触发了文件访问与外联，以及修复后留下哪些记录。','Focus on the tool calls behind file access and outbound activity, and the records left after repair.'),compareLink(historicalCompare('run-2fd63df0ab9b','run-48baa3821074'))+link(historical('run-2fd63df0ab9b'),t('修复前','Before'))+link(historical('run-48baa3821074'),t('修复后','After'))+link(originalGuide('evidence-attribution'),t('任务经过与证据','Story & evidence')),'2026-11-06')+record(t('10 月复现：查看拒绝与配置修改','October: inspect denials and configuration changes'),historic,t('重点看子 Agent 的审阅、被拒绝的诊断，以及 settings.json 中关闭诊断的修改。','Focus on the subagent review, denied diagnostics and changes disabling diagnostics in settings.json.'),compareLink(historicalCompare('run-e9c3f452461a','run-2267309eda57'))+link(historical('run-e9c3f452461a'),t('修复前','Before'))+link(historical('run-2267309eda57'),t('修复后','After'))+link(originalGuide('investigation-workflow'),t('任务经过与证据','Story & evidence')),'2026-10-19')
  };
  if(id==='development') return {
    title:t('DeepSeek 如何完成一次开发任务','How DeepSeek completed a development task'),
    content:`<p class="dialog-intro">${t('这是一次完整开发任务的历史记录，适合从头阅读 Agent 的工作过程。','This historical recording follows a complete development task, from the instructions to the final files.')}</p>`+record(t('任务、测试与最终文件','Task, tests and final files'),historic,t('从用户任务开始，逐次查看工具输入输出，检查 7 项已记录的测试结果，再打开最终文件正文。','Start with the user task, follow each tool input and output, inspect seven recorded test results and read the final files.'),open(historical('run-dbc2adf273d4'))+link(originalGuide('deepseek-context'),t('案例说明','Case guide')),'2026-09-28')
  };
  if(id==='presets') return {
    title:t('采集档位与附件示例','Capture presets & attachment example'),
    content:`<p class="dialog-intro">${t('basic 保留轻量上下文，detailed 额外留存可阅读正文。这里分别打开独立采集的记录。','Basic retains lightweight context; detailed retains additional readable content. These links open independently captured runs.')}</p>`+record('Browser · basic / detailed',recorded,t('查看两次网页任务的应用上下文。','Inspect application context from two browser tasks.'),open('recordings/browser-basic/'+lang+'/index.html?live=0')+link(browser(),'detailed'))+record('Notebook · basic / detailed',recorded,t('查看两次 Jupyter 任务的代码与结果留存。','Inspect captured code and output from two Jupyter tasks.'),open(realNotebook('basic'))+link(realNotebook('detailed'),'detailed'))+record(t('Jupyter 图表与 kernel 重启','Jupyter chart & kernel restart'),t('合成样本','Synthetic example'),t('专门展示图片附件、父消息引用和重启前后的 kernel 身份。','An example for image attachments, parent-message references and kernel identity before and after restart.'),open(current('notebook','notebook-detailed')))+nativeNote
  };
  return null;
}

function openStory(id, updateURL = true) {
  const content = caseContent(id);
  if (!content) return;
  activeStory = id;
  document.querySelector('#case-eyebrow').textContent = t('案例经过与记录','STORY & RECORDINGS');
  document.querySelector('#case-title').textContent = content.title;
  const isArchiveChapter = ['grok','earlier','development','presets'].includes(id);
  document.querySelector('#case-body').innerHTML = (isArchiveChapter?`<button class="text-button back-to-archive" data-story="archive">${icon('arrow')}${t('全部档案','All archive chapters')}</button>`:'')+content.content;
  if(!dialog.open) dialog.showModal();
  document.querySelector('#case-body').scrollTop = 0;
  if(updateURL) {
    const next = new URL(location.href);
    next.searchParams.set('case',id);
    history.replaceState({},'',next);
  }
}

root.addEventListener('click', event => {
  const story = event.target.closest('[data-story]');
  if(story) return openStory(story.dataset.story);
  const language = event.target.closest('[data-lang]');
  if(language) {
    const bodyScroll = document.querySelector('#case-body').scrollTop;
    const pageScroll = scrollY;
    lang = language.dataset.lang;
    const next = new URL(location.href);
    next.searchParams.set('lang',lang);
    history.replaceState({},'',next);
    render();
    if(activeStory) {
      openStory(activeStory,false);
      document.querySelector('#case-body').scrollTop = bodyScroll;
    }
    scrollTo(0,pageScroll);
    root.querySelector(`[data-lang="${lang}"]`).focus({preventScroll:true});
  }
});
dialog.addEventListener('click',event=>{
  const story = event.target.closest('[data-story]');
  if(story) openStory(story.dataset.story);
});
document.querySelector('#close-dialog').addEventListener('click',()=>dialog.close());
dialog.addEventListener('click',event=>{if(event.target===dialog){const rect=dialog.getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom) dialog.close();}});
dialog.addEventListener('close',()=>{
  const trigger = root.querySelector(`[data-story="${activeStory}"]`) || root.querySelector('[data-story="archive"]');
  activeStory = null;
  const next = new URL(location.href);
  next.searchParams.delete('case');
  history.replaceState({},'',next);
  trigger?.focus({preventScroll:true});
});
render();
window.addEventListener('hashchange',syncSectionLinks);
if(['#featured','#topics','#history','#capture'].includes(location.hash)) {
  requestAnimationFrame(()=>document.getElementById(location.hash.slice(1))?.scrollIntoView({behavior:'instant'}));
}
if(url.searchParams.has('case')) openStory(url.searchParams.get('case'),false);
