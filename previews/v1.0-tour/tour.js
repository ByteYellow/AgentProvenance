/* Hosted demo tour. The recorded evidence and underlying layout stay intact. */
(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  // Keep the original key so returning visitors retain their tour preferences.
  const key = 'agentprov.onboarding.preview/v2';
  const isHome = Boolean($('#app'));
  if (!isHome && !$('#runoverview')) return;
  const pageKind = isHome ? 'library' : 'recording';
  const t = (cn, en) => document.documentElement.lang.startsWith('zh') ? cn : en;
  const initialParams = new URLSearchParams(location.search);
  let memory = {seen: {}, skipped: false}, tour = null, invite = null, saved = null, inviteTimer;
  let forceInvite = initialParams.get('tour') === '1';
  let waitingForCompare = initialParams.has('compare_a') || initialParams.has('compare_b');
  function preferences() {
    try {
      const value = JSON.parse(localStorage.getItem(key));
      if (value && value.seen && typeof value.seen === 'object') memory = value;
    } catch (_) { /* The tour remains usable without browser storage. */ }
    return memory;
  }
  function remember(skip = false) {
    const value = preferences();
    value.seen[pageKind] = true;
    if (skip) value.skipped = true;
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* Optional preference. */ }
    forceInvite = false;
    const url = new URL(location.href);
    if (url.searchParams.has('tour')) { url.searchParams.delete('tour'); history.replaceState(history.state, '', url); }
  }
  function step(element, cn, en, bodyCN, bodyEN, options = {}) {
    return {element, popover: {title: t(cn, en), description: t(bodyCN, bodyEN), side: 'bottom', align: 'start'}, ...options};
  }
  function steps() {
    if (isHome) return [
      step('[data-case="investigation"] .story-copy', '从一个真实案例开始', 'Start with a real case',
        '这里的四个案例分别介绍任务调查、远端工作区、浏览器和多 Agent 协作。先选一个与你的问题接近的案例。',
        'These four cases cover task investigation, remote workspaces, browsers and agent collaboration. Choose the one closest to your question.'),
      step('[data-case="investigation"] .story-bottom', '先看经过，或直接看证据', 'Read the story or open the evidence',
        '“案例经过”说明当时发生了什么。左侧主按钮直接打开对应记录；修复案例会预选修复前后的两次执行。',
        'Case details explains what happened. The primary button opens the records; the repair case opens its before-and-after comparison.'),
      step('.section-nav', '按用途找到入口', 'Find the right section',
        '精选案例用于体验完整调查；专题与集成介绍具体方法；历史记录保留过去的案例。',
        'Featured cases walk through investigations. Topics cover specific methods and integrations. The archive keeps earlier recordings.'),
      step('#topics .section-head', '需要深入时，看专题和指南', 'Explore methods and integrations',
        '这里集中放安全调查、关联方法和 AI 研判。每个专题都提供相应的实录或接入文档。',
        'Find security investigations, evidence relationships and AI analysis here, with their recordings or integration guides.'),
      step('#history', '旧案例仍然可以查看', 'Earlier cases remain available',
        '历史报表修复、DeepSeek 开发任务和 Grok 调查都在案例档案中，保留各自的采集时间。',
        'The archive includes earlier report repairs, DeepSeek development tasks and Grok investigations, with their original capture dates.'),
      step('#capture', '接下来，记录自己的任务', 'Next, record your own task',
        '体验完案例后，从“快速开始”进入本地采集。远端执行、Browser 和 Notebook 的指南也在这里。右上角可随时重新打开导览。',
        'After exploring a case, use Quick start to record a local task. Remote execution, Browser and Notebook guides are here too. Reopen this tour from the header anytime.'),
      step(matchMedia('(max-width:600px)').matches ? '#capture .links a:first-child' : '.top-nav a:nth-child(2)',
        '用文档把 Demo 变成自己的工作流', 'Use the docs to build your own workflow',
        '这个入口打开使用文档。第一次安装先看“快速开始”；随后按文档侧栏查找采集与部署、分析与追溯、接入与集成。遇到配置或命令问题时，可以回到这里查完整说明。',
        'This opens the documentation. Start with Quick start, then use the sidebar for capture and deployment, investigation, and integrations. Return here for configuration and command details.')
    ];
    const group = (cn, en, items) => items.map(item => ({...item, data: {section: t(cn, en)}}));
    const inSession = {onHighlightStarted: () => { $('#context-fold').open = true; }};
    return [
      ...group('范围与调查入口', 'Scope and investigation', [
      step('#runsel', '先确认你正在查看哪次执行', 'Choose the execution to inspect',
        '这里切换 Run，也就是一次执行记录。图谱、会话和正文都会随所选 Run 更新。',
        'A Run is one recorded execution. This selector changes the graph, sessions and saved content together.'),
      step('#session-directory-open', '看清这次执行由谁组成', 'See the sessions behind the run',
        '打开会话目录，查看参与的 Agent 和来源。选择一个会话后，图谱与对话会聚焦到该会话，也可以返回整个 Run。',
        'Open the session directory to see participating agents and sources. Selecting a session focuses its graph and conversation; you can return to the whole Run.'),
      step('#session-relations-open', '追踪会话之间的协作', 'Trace relationships between sessions',
        '这里查看已记录的父子、fork 和委派关系。展开关系可查看来源依据，并跳转到相关会话。',
        'Inspect recorded parent, fork and delegation relationships. Expand a relationship to see its source evidence and open the related session.'),
      step('#askgrid .qbtn', '从你要调查的问题入手', 'Start with an investigation question',
        '这组入口分别聚焦风险、协作、工具调用、文件和网络。比如点这里，可以查看触发风险的行为及支持证据。',
        'These entries focus on risks, collaboration, tool calls, files or network activity. This one opens risk-related behavior and its supporting evidence.'),
      step('[data-investigation="search"]', '用关键词找到原始证据', 'Find evidence by keyword',
        '搜索已保存的消息、工具输入输出和配置。命中后可以阅读上下文，再定位到对应记录或图谱。',
        'Search saved messages, tool inputs, outputs and configuration. Read a match in context, then locate its record or graph evidence.'),
      step('[data-investigation="compare"]', '解释两次执行有什么变化', 'Inspect changes between two Runs',
        '选择基线 A 和目标 B，对照配置、文件、网络和访问控制。可交换两侧、只看差异；关闭后回到当前记录。',
        'Choose a baseline A and target B to compare configuration, files, network and access control. Swap sides or show only differences; closing returns to this record.')
      ]),
      ...group('图谱与证据', 'Graph and evidence', [
      step('#graphcard>h2', '图谱用来追踪关联', 'Follow relationships in the graph',
        '左侧下拉切换协作、进程、文件和网络等视图；右侧选择摘要、展开或原始记录。点击节点后，统一详情区会展示它的关联依据。',
        'The left selector switches between collaboration, process, file and network views. The right selector changes summary, expanded and raw detail. Select a node to inspect its evidence.'),
      step('#scrub', '按时间阅读执行过程', 'Read the execution over time',
        '播放按钮和时间滑条用于查看已保存事件的先后顺序。拖动滑条可以停在某一时刻，观察当时出现的节点和关系。',
        'The play button and time slider navigate saved events in order. Move the slider to a point in time to inspect the nodes and relationships shown there.'),
      step('.zoombar', '把大图调整到合适尺度', 'Adjust the graph to a useful scale',
        '使用加减按钮缩放，“适应宽度”重新收拢整张图。图很大时，先选择会话或调查问题，再查看局部。',
        'Use plus and minus to zoom, or Fit to bring the graph back into view. For large graphs, first select a session or investigation question.'),
      step('#context-nav-files', '阅读正文，而不只是看节点', 'Read content, not just nodes',
        '文件证据进入统一详情区，区分摘要、关联事件和已保存正文。正文有多份时可用下拉选择，长内容可以分页或放大阅读。',
        'File evidence opens the shared reader for summaries, related events and saved content. Use the content selector for multiple versions, or paginate and expand long text.'),
      step('.card.side>h2', '重要风险集中在这里', 'Find important risk signals here',
        '这里汇总风险线索。点选一项可以继续定位相关记录，再结合原文和关联依据判断。',
        'This area collects risk signals. Select one to locate the related records, then inspect their content and association basis.'),
      step('.access-bar', '查看 AppArmor 与 seccomp 证据', 'Inspect AppArmor and seccomp evidence',
        '这里分别展示审计记录、实际状态、配置声明和审计采集情况。点开一类查看原始记录，再核对执行结果。',
        'Audit records, observed state, configuration declarations and audit collection are separate entries. Open a category to inspect its records alongside execution results.')
      ]),
      ...group('会话与执行细节', 'Sessions and execution details', [
      step('#agentcontext .context-toolbar', '阅读完整的对话与工具调用', 'Read the conversation and tool calls',
        '会话区保留任务、模型消息和工具输入输出。右侧下拉选择来源会话；较长记录可以在区块底部分页。',
        'The session area contains tasks, model messages and tool inputs and outputs. Select a source session on the right and use the pager for longer records.', inSession),
      step('#context-tab-configuration', '核对当时的权限与配置', 'Inspect recorded permissions and configuration',
        '这里查看 Harness 配置、声明的工具权限和相关上下文。配置内容与上面的实际审计、执行结果分开保存。',
        'Inspect harness configuration, declared tool permissions and related context. Configuration records are separate from audit observations and execution outcomes.', inSession),
      step('#context-tab-coverage', '确认记录覆盖了哪些内容', 'Check what was captured',
        '查看采集来源、basic／detailed 留存档位、主动省略与采集缺口。任务结果、采集覆盖与证据验证各有独立状态。',
        'Check capture sources, basic or detailed retention, intentional omissions and collection gaps. Task outcome, capture coverage and verification have separate states.', inSession),
      step('#portable-workspace-tab', '查看工作区版本与操作回执', 'Inspect workspace versions and receipts',
        'Workspace 记录 Read、Edit、Write 和 Bash 的输入输出版本。打开“版本与回执”，查看修改前后内容、冲突及对应执行。',
        'Workspace records input and output versions for Read, Edit, Write and Bash. Open Versions and receipt to inspect changes, conflicts and the linked execution.', inSession),
      step('#portable-native-tab', '阅读 Browser 与 Notebook 原生记录', 'Read Browser and Notebook records',
        'Browser 可查看操作、请求、下载和已保存附件；Notebook 可查看单元格、输出和图表。每条记录保留原生身份与关联依据。',
        'Browser records include operations, requests, downloads and retained attachments. Notebook records include cells, outputs and charts, with native identities and association evidence.', inSession),
      step('#portable-executions:not([hidden])>details>summary', '追踪跨环境执行交接', 'Trace execution across environments',
        '展开后分别查看执行、采集和交付状态。可以跳转到远端执行，也能返回来源工具调用，继续阅读同一次交接的证据。',
        'Expand to inspect execution, capture and delivery separately. Open the remote execution or return to its source tool call to follow the same handoff.')
      ]),
      ...group('交付与进一步调查', 'Sharing and further investigation', [
      step('[data-investigation="export"]', '选择要分享的证据', 'Choose evidence to share',
        '导出入口展示分享范围和记录选择。本地证据库可以生成离线阅读包；在线示例提供已有下载或说明所需的本地操作。',
        'The export entry shows sharing scope and record selection. A local store can create an offline reader; online examples offer saved downloads or explain the local export workflow.'),
      step('#portable-delivery-details', '了解这份副本如何验证', 'Understand verification of this copy',
        '交付说明区分阅读副本、导出者签名副本和原件交付。文件完整性、签名信任及采集覆盖分别核对，签名由接收方自己的信任配置验证。',
        'Delivery details distinguishes reading copies, exporter-signed copies and originals. File integrity, signer trust and capture coverage are checked separately using recipient-controlled trust.'),
      step('#profile-fold>summary', '需要时核对执行范围', 'Check the execution scope',
        '展开这里查看运行环境、采集来源及边界。调查跨容器、沙箱或 Guest 的行为时，可以先确认这些身份信息。',
        'Expand this section for the runtime environment, capture sources and boundaries. Check these identities when investigating activity across containers, sandboxes or guests.'),
      step('#timeline-fold>summary', '继续深入时间线与系统行为', 'Explore the timeline and system activity',
        '下方按需展开时间线、进程树、外联明细和合规信息。它们补充整次 Run 的细节；右上角“页面导览”随时可以重新打开。',
        'Expand the timeline, process tree, network and compliance sections below for whole-Run detail. Page tour in the header remains available whenever you need it.')
      ])
    ];
  }
  function restore() {
    const state = saved;
    saved = null;
    if (!state) return;
    if (state.fold) state.fold.open = state.foldOpen;
    requestAnimationFrame(() => {
      window.scrollTo({left: state.x, top: state.y, behavior: 'instant'});
      const target = state.focus?.isConnected && state.focus !== document.body ? state.focus : $('#page-tour-start');
      target?.focus({preventScroll: true});
    });
  }
  function start() {
    if (tour?.isActive() || $('dialog[open]')) return;
    invite?.destroy();
    const fold = $('#context-fold');
    saved = {x: scrollX, y: scrollY, focus: document.activeElement, fold, foldOpen: fold?.open};
    const selected = steps().filter(item => $(item.element));
    remember();
    tour = window.driver.js.driver({
      steps: selected,
      animate: !matchMedia('(prefers-reduced-motion: reduce)').matches,
      duration: 180, smoothScroll: false, overlayColor: '#18202b', overlayOpacity: 0.48,
      stagePadding: 7, stageRadius: 8, popoverOffset: 14,
      disableActiveInteraction: true, overlayClickBehavior: 'none', focus: 'popover',
      showButtons: ['previous', 'next'], showProgress: true,
      progressText: '{{current}} / {{total}}',
      nextBtnText: t('下一步', 'Next'), prevBtnText: t('上一步', 'Back'), doneBtnText: t('开始探索', 'Start exploring'),
      popoverClass: 'agentprov-tour',
      onPopoverRender(popover, opts) {
        const caption = document.createElement('div'); caption.className = 'tour-caption';
        const current = selected[opts.index];
        popover.wrapper.dataset.tourTarget = current.element;
        const label = document.createElement('span'); label.textContent = current.data?.section || t('认识示例库', 'DEMO LIBRARY TOUR');
        caption.append(label, popover.progress); popover.title.before(caption);
        const meter = document.createElement('div'); meter.className = 'tour-meter'; meter.setAttribute('aria-hidden', 'true');
        const bar = document.createElement('span'); bar.style.width = ((opts.index + 1) / selected.length * 100) + '%'; meter.append(bar); caption.after(meter);
        const skip = document.createElement('button'); skip.type = 'button'; skip.className = 'tour-skip'; skip.textContent = t('跳过全部', 'Skip all');
        skip.onclick = () => { remember(true); tour.destroy(); };
        popover.footer.prepend(skip);
      },
      onDestroyed: restore
    });
    tour.drive();
  }
  function ready() {
    return isHome ? Boolean($('[data-case="investigation"] .story-bottom')) : Boolean($('#runsel')?.options.length && $('#askgrid .qbtn'));
  }
  function offerTour() {
    clearTimeout(inviteTimer);
    inviteTimer = setTimeout(() => {
      const button = $('#page-tour-start'), pref = preferences();
      if (!button || waitingForCompare || $('dialog[open]')) { invite?.destroy(); return; }
      if (tour?.isActive() || (!forceInvite && (pref.skipped || pref.seen[pageKind]))) return;
      const rect = button.getBoundingClientRect();
      if (rect.top < 0 || rect.bottom > innerHeight) { invite?.destroy(); return; }
      if (invite?.isActive()) return;
      const headerBottom = button.closest('header')?.getBoundingClientRect().bottom ?? rect.bottom;
      button.classList.add('tour-invited');
      invite = window.driver.js.driver({
        animate: false, overlayOpacity: 0, allowPageInteraction: true, focus: 'none',
        scrollIntoView: false, overlayClickBehavior: 'none', showButtons: ['close'],
        popoverClass: 'agentprov-tour-invite', stagePadding: 5,
        popoverOffset: Math.max(15, Math.ceil(headerBottom - rect.bottom) + 12),
        closeBtnLabel: t('关闭导览提示', 'Dismiss tour hint'),
        onPopoverRender(popover) {
          popover.wrapper.id = 'page-tour-invite';
          popover.wrapper.setAttribute('role', 'region');
          popover.wrapper.removeAttribute('aria-modal');
          popover.wrapper.setAttribute('aria-live', 'polite');
        },
        onDestroyed(_, __, opts) {
          button.classList.remove('tour-invited');
          invite = null;
          if (opts.reason === 'close' || opts.reason === 'escape') remember();
        }
      });
      invite.highlight({element: button, popover: {
        title: t(isHome ? '从这里认识示例库' : '从这里认识执行记录', isHome ? 'Get to know the demo library' : 'Get to know this recording'),
        description: t('点击上方“页面导览”，逐步了解各个区域和常用操作。', 'Click Page tour above to learn about each area and the main actions.'),
        side: 'bottom', align: 'end', showButtons: ['close']
      }});
    }, 300);
  }
  function install() {
    if (!ready()) return;
    const anchor = isHome ? $('.languages') : $('.language-switch');
    if (anchor && !$('#page-tour-start')) {
      const button = document.createElement('button'); button.id = 'page-tour-start'; button.type = 'button';
      button.innerHTML = '<span class="tour-help-icon" aria-hidden="true">?</span><span class="tour-help-label"></span>';
      button.onclick = start; anchor.before(button);
    }
    const button = $('#page-tour-start');
    if (button) { button.querySelector('.tour-help-label').textContent = t('页面导览', 'Page tour'); button.title = button.ariaLabel = t('打开页面导览', 'Open the page tour'); }
    if (invite && !invite.getActiveElement()?.isConnected) invite.destroy();
    offerTour();
  }
  function boot() {
    if (!window.driver?.js?.driver) return;
    install();
    const host = isHome ? $('#app') : $('#askgrid');
    new MutationObserver(install).observe(host, {childList: true});
    // Compare deep links open asynchronously. Keep their entire modal session first.
    document.addEventListener('close', event => {
      if (event.target.id === 'compare-dialog') waitingForCompare = false;
      offerTour();
    }, true);
    new MutationObserver(() => { if ($('dialog[open]')) invite?.destroy(); offerTour(); })
      .observe(document.body, {subtree: true, attributes: true, attributeFilter: ['open']});
    window.addEventListener('scroll', offerTour, {passive: true});
    window.addEventListener('resize', () => { invite?.destroy(); offerTour(); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, {once: true});
  else boot();
})();
