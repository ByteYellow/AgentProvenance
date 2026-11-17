/* Review-only page tour. The recorded evidence and underlying layout stay intact. */
(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const key = 'agentprov.onboarding.preview/v1';
  const isHome = Boolean($('#app'));
  if (!isHome && !$('#runoverview')) return;
  const pageKind = isHome ? 'library' : 'recording';
  const t = (cn, en) => document.documentElement.lang.startsWith('zh') ? cn : en;
  let memory = {seen: {}, skipped: false}, tour = null, saved = null, automaticScheduled = false;
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
        'After exploring a case, use Quick start to record a local task. Remote execution, Browser and Notebook guides are here too. Reopen this tour from the header anytime.')
    ];
    return [
      step('#runsel', '先确认你正在查看哪次执行', 'Choose the execution to inspect',
        '这里切换 Run，也就是一次执行记录。图谱、会话和正文都会随所选 Run 更新。',
        'A Run is one recorded execution. This selector changes the graph, sessions and saved content together.'),
      step('#session-composition', '看清这次执行由谁组成', 'See the sessions behind the run',
        '“会话与来源”列出参与的会话；“关联会话”展示已记录的父子、委派或其他关联。',
        'Sessions & sources lists the participating sessions. Related sessions shows recorded parent, delegation and other relationships.'),
      step('#askgrid .qbtn', '从你要调查的问题入手', 'Start with an investigation question',
        '这组入口分别聚焦风险、协作、工具调用、文件和网络。比如点这里，可以查看触发风险的行为及支持证据。',
        'These entries focus on risks, collaboration, tool calls, files or network activity. This one opens risk-related behavior and its supporting evidence.'),
      step('#graphcard>h2', '图谱用来追踪关联', 'Follow relationships in the graph',
        '节点表示 Agent、调用、进程、文件等记录，连线展示它们的关系。点击节点查看依据；这里可以切换观察角度和细节级别。',
        'Nodes represent agents, calls, processes, files and other records. Edges show their relationships. Select a node for evidence; use these controls to change the view and detail.'),
      step('#inspection:not([hidden]) .inspection-tabs, #context-nav-files', '正文和原始记录在同一处阅读', 'Read content and its supporting records',
        '选择文件或工具记录后，详情区会显示摘要、关联事件和已保存正文。这里也能直接进入文件证据。',
        'Select a file or tool record to inspect its summary, related events and saved content in one reader. This shortcut also opens file evidence.'),
      step('#agentcontext .context-toolbar', '阅读任务、调用和配置', 'Read the task, calls and configuration',
        '会话区保留对话和工具输入输出；权限与配置、采集情况分开查看。有对应记录时，还会提供工作区、Browser 或 Notebook 视图。',
        'The session area contains messages and tool inputs and outputs. Permissions, configuration and collection status have separate tabs. Workspace, Browser or Notebook views appear when records are available.',
        {onHighlightStarted: () => { $('#context-fold').open = true; }}),
      step('.card.side>h2', '重要风险集中在这里', 'Find important risk signals here',
        '这里汇总风险线索。点选一项可以继续定位相关记录，再结合原文和关联依据判断。',
        'This area collects risk signals. Select one to locate the related records, then inspect their content and association basis.'),
      step('[data-context-open="coverage"]', '确认记录覆盖了哪些内容', 'Check what was captured',
        '采集情况说明已保存、主动省略和存在缺口的内容。任务结果、采集覆盖与证据验证各自有独立状态。',
        'Collection status shows retained content, intentional omissions and capture gaps. Task results, capture coverage and evidence verification have separate states.'),
      step('.investigation-actions', '搜索、比较、分享', 'Search, compare and share',
        '从左到右：搜索已保存的原文；对照两次 Run；选择需要分享的记录并导出离线回放。',
        'From left to right: search saved text, compare two Runs, and select records to export as an offline replay.'),
      step('#profile-fold>summary', '更多细节，按需展开', 'Expand the details you need',
        '执行范围与采集来源放在这里。页面下方还保留时间线、进程树、网络和合规信息。先完成当前调查，再按需要深入。',
        'Execution scope and capture sources are here. Timeline, process tree, network and compliance details remain below. Expand them when your investigation needs them.')
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
    const fold = $('#context-fold');
    saved = {x: scrollX, y: scrollY, focus: document.activeElement, fold, foldOpen: fold?.open};
    const selected = steps().filter(item => $(item.element));
    remember();
    const url = new URL(location.href);
    if (url.searchParams.has('tour')) { url.searchParams.delete('tour'); history.replaceState(null, '', url); }
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
        const label = document.createElement('span'); label.textContent = t(isHome ? '认识示例库' : '认识执行记录', isHome ? 'DEMO LIBRARY TOUR' : 'RECORDING TOUR');
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
  function install() {
    if (!ready()) return;
    const anchor = isHome ? $('.languages') : $('.language-switch');
    if (anchor && !$('#page-tour-start')) {
      const button = document.createElement('button'); button.id = 'page-tour-start'; button.type = 'button';
      button.innerHTML = '<span class="tour-help-icon" aria-hidden="true">?</span><span class="tour-help-label"></span>';
      button.onclick = start; anchor.before(button);
    }
    const button = $('#page-tour-start');
    if (button) { button.querySelector('.tour-help-label').textContent = t('页面导览', 'Page tour'); button.title = button.ariaLabel = t('重新打开页面导览', 'Reopen the page tour'); }
    if (automaticScheduled) return;
    automaticScheduled = true;
    setTimeout(() => {
      const pref = preferences(), force = new URL(location.href).searchParams.get('tour') === '1';
      if (force || !pref.skipped && !pref.seen[pageKind]) start();
    }, 450);
  }
  function boot() {
    if (!window.driver?.js?.driver) return;
    install();
    const host = isHome ? $('#app') : $('#askgrid');
    new MutationObserver(install).observe(host, {childList: true});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, {once: true});
  else boot();
})();
