// The page owns its markup and readiness; the tour only highlights existing controls.
(() => {
  'use strict';
  const $ = s => document.querySelector(s);
  const t = (zh, en) => document.documentElement.lang.startsWith('zh') ? zh : en;
  const key = 'agentprov.onboarding.preview/v2';
  let prefs = {seen:{}, skipped:false}, guide, trigger, forced = new URLSearchParams(location.search).get('tour') === '1';
  try { const p = JSON.parse(localStorage.getItem(key)); if (p?.seen) prefs = p; } catch {}
  const kind = () => document.body.dataset.tourPage;
  function remember(skip = false) {
    prefs.seen[kind()] = true;
    if (skip) prefs.skipped = true;
    try {localStorage.setItem(key, JSON.stringify(prefs));} catch {}
    if (forced) {
      forced = false;
      const u = new URL(location.href); u.searchParams.delete('tour');
      history.replaceState(history.state, '', u);
    }
  }
  function steps() {
    const out = [];
    function add(selector, zh, en, descZh, descEn) {
      const el = $(selector);
      if (el?.getClientRects().length && !el.disabled) {
        out.push({element:el, popover:{title:t(zh,en),description:t(descZh,descEn),side:'bottom',align:'start'}});
      }
    }
    if (kind() === 'library') {
      add('.hero-actions a', '先看一次修复前后对比', 'Start with a before/after comparison', '这里直接打开两次执行的文件差异，先看发生了什么变化。', 'This opens both runs on their file differences. Start with what changed.');
      add('[data-case="investigation"] .actions-row', '从故事进入证据', 'From a case to its evidence', '主按钮进入实录；“案例经过”介绍任务背景、调查顺序和相关记录。', 'The main button opens the recording. Case details gives you the task, investigation path and related records.');
      add('[data-case="remote"] .sub-links', '查看相关实录和指南', 'Find related recordings and guides', '每张卡片下方都有与该案例相关的文档或实录。这里可以打开 Claude 或 Kata 的工作区记录。', 'Each card links to relevant guides and runs. Here you can open the Claude or Kata workspace recording.');
      add('#topics .section-head', '按问题找专题', 'Explore by topic', '从这里找安全调查、关联方法和 AI 研判的实录与接入说明。', 'Find recordings and guides for security investigations, evidence relationships and AI evaluation.');
      add('#archive .chapter-btn', '查找其他案例', 'Browse the archive', '按分类查看 Linux x86、历史调查和采集档位，打开具体记录或下载可用的离线包。', 'Browse Linux x86, historical cases and capture presets. Open a recording or download an available offline copy.');
      add('#capture h2', '录一次自己的任务', 'Record your own task', '快速开始给出本地命令。录制完成后可以用相同的工作台查看自己的证据。', 'The quick start shows the local commands. Then use the workbench to explore your own evidence.');
      add(matchMedia('(max-width:600px)').matches ? '#capture a[href*="/guides/quickstart."]' : '.top-nav a[href*="/guides/start."]', '从这里看文档', 'Find the documentation', '从快速开始、部署到接入指南，文档按任务组织。随时可以从页首重新打开导览。', 'Find setup, deployment and integration guides by task. Reopen the tour from the header anytime.');
      return out;
    }
    add('#wb-runsel','先确认执行记录','Choose the run','切换这里会换掉整份证据。先核对任务和运行，再看具体事件。','This selects the whole evidence set. Check the run before investigating individual events.');
    add('#wb-scopesel','按会话缩小范围','Choose a session','在有多个会话的执行中，可只看其中一个，也可以随时回到整个 Run。','In a multi-session run, narrow the scope to a session or return to the whole run.');
    add('.wb-tabs','选择调查视图','Choose an investigation view','图谱、会话、风险、合规和时间线分别回答不同问题。工作区与 Browser 等视图按实录内容出现。','Graph, sessions, risk, compliance and timeline answer different questions. Extra views appear when their records are available.');
    add('#wb-lens-strip','换个角度看图','Choose a graph lens','按文件、网络或协作关系聚焦；视角的数字描述当前记录。','Focus on files, network activity or collaboration using the available lenses.');
    add('.wb-graph-tools .wb-seg','选择图谱详细程度','Choose graph detail','摘要用于看全貌；展开或原始视图便于追踪节点和时间。','Start with the summary. Expanded and raw views help trace nodes and time.');
    add('#wb-inspector','点节点读证据','Inspect a graph node','选中节点后，在这里核对关联来源、事件和保存的内容。','Select a node to inspect its sources, events and retained content here.');
    add('#ws-list .wb-row-btn.on','选择一次工作区操作','Select a workspace operation','每一行是一条工具结果。冲突、成功回执和文件变更分别展示。','Each row is a tool result. Rejected operations, successful receipts and file changes are shown separately.');
    add('#ws-detail h3','核对版本与实际产物','Check revisions and file changes','这里显示所选调用的回执；比较输入输出版本、文件哈希和原始结果。','Inspect this call’s receipt, its input and output revisions, file hashes and the saved result.');
    add('#nat-list .wb-row-btn.on','选择原生记录','Choose a native record','从操作、导航或 Notebook 消息进入详情。附件数量是已保存的数量。','Select an operation, navigation or notebook message. The attachment count describes what was saved.');
    add('#nat-detail h3','读取正文和附件','Read content and attachments','读取附件时会核对 SHA-256；当前记录保留的正文也在这里。','SHA-256 is checked when an attachment is read. Retained content for the selected record appears here.');
    add('#handoff-body > :first-child','追踪跨环境交接','Trace a handoff','分别核对来源调用、执行实例和证据交付状态。','Inspect the source call, execution instance and evidence delivery separately.');
    add('[data-mode="session"]','回看对话与工具','Inspect sessions and tools','在这里核对 Agent 收到的任务、工具输入输出，以及保存了哪些内容。','Use this view for task messages, tool inputs and outputs, and retention details.');
    add('[data-mode="risk"]','核对风险和访问控制','Inspect risk and access control','这里既有风险线索，也有实际访问控制记录，分别阅读。','Investigate risk signals alongside the recorded access-control decisions.');
    add('[data-mode="compliance"]','查看合规映射','Review compliance mappings','查看规则映射与本次执行记录到的证据。','Inspect the control mappings and the supporting evidence in this run.');
    add('[data-mode="timeline"]','按时间追踪','Follow the timeline','从时间线继续追查进程和记录到的系统事件。','Use the timeline to follow processes and recorded system events.');
    add('#wb-btn-search','搜已保存的原文','Search saved evidence','按关键词找消息、输出和文件证据，再返回当前现场。','Search messages, output and file evidence by keyword, then return to the current view.');
    add('#wb-btn-compare','比较两次执行','Compare two runs','选定 A 和 B 后可以按文件、配置或网络查看差异。','Select A and B to compare files, configuration or network evidence.');
    add('#wb-verify','查看校验范围','Check what was verified','这里说明图完整性、阅读副本与签名信任。点击页首按钮可随时重看导览。','See graph integrity, copy type and signer trust separately. Use the header to reopen the tour anytime.');
    return out;
  }

  function hideInvitation() {
    const slot=$('[data-tour-slot]');
    if (slot) {slot.hidden=true; slot.replaceChildren();}
    trigger?.classList.remove('tour-invited');
  }
  function alignInvitation() {
    const tip=$('#page-tour-invite');
    if (!tip || !trigger) return;
    tip.style.marginLeft='0px';
    const slot=tip.parentElement.getBoundingClientRect(), btn=trigger.getBoundingClientRect();
    const center=(btn.left+btn.right)/2-slot.left, width=tip.offsetWidth;
    const left=Math.max(8,Math.min(slot.width-width-8,center-width+28));
    tip.style.marginLeft=left+'px';
    tip.style.setProperty('--tour-arrow', Math.max(12, Math.min(width-16,center-left))+'px');
  }
  function offer() {
    if (!trigger?.isConnected || guide || $('dialog[open]') || (!forced && (prefs.skipped || prefs.seen[kind()]))) {hideInvitation();return;}
    const slot=$('[data-tour-slot]');
    if (!slot || !slot.hidden || scrollY>16) return;
    const tip=document.createElement('aside'); tip.id='page-tour-invite';
    tip.setAttribute('aria-label',t('页面导览提示','Page tour hint'));
    const message=document.createElement('span');
    message.textContent=t('初次来到这里？点击「页面导览」逐步认识界面。','New here? Select Page tour for a walkthrough.');
    const close=document.createElement('button'); close.type='button'; close.textContent='×';
    close.setAttribute('aria-label',t('关闭导览提示','Dismiss tour hint'));
    close.onclick=()=>{remember();hideInvitation();trigger.focus({preventScroll:true});};
    tip.append(message, close);slot.append(tip);slot.hidden=false;
    trigger.classList.add('tour-invited');alignInvitation();
  }
  function start() {
    if (guide || $('dialog[open]')) return;
    const choices=steps(); if(!choices.length) return;
    const focus=document.activeElement; hideInvitation();remember();
    const positions=[document.scrollingElement,...document.querySelectorAll('.wb-subbar,.wb-lens-strip,.wb-inspector,.wb-list-scroll,.wb-detail-col,.wb-scroll-page,.top-nav')]
      .filter(Boolean).map(el=>[el,el.scrollLeft,el.scrollTop]);
    guide=window.driver.js.driver({
      steps:choices, animate:!matchMedia('(prefers-reduced-motion: reduce)').matches, smoothScroll:false,
      disableActiveInteraction:true, overlayClickBehavior:'none', overlayColor:'#18202b',overlayOpacity:0.45,
      focus:'popover',stagePadding:5,stageRadius:8,popoverOffset:12,
      showButtons:['previous','next'],showProgress:true,progressText:'{{current}} / {{total}}',
      popoverClass:'agentprov-tour',nextBtnText:t('下一步','Next'),prevBtnText:t('上一步','Back'),doneBtnText:t('开始探索','Start exploring'),
      onPopoverRender(popover) {
        const skip=document.createElement('button');skip.type='button';skip.className='tour-skip';skip.textContent=t('跳过全部','Skip all');
        skip.onclick=()=>{remember(true);guide.destroy();};popover.footer.prepend(skip);
      },
      onDestroyed() {
        guide=null;
        requestAnimationFrame(()=>{
          for(const [el,x,y] of positions) if(el.isConnected) el.scrollTo({left:x,top:y,behavior:'instant'});
          (focus?.isConnected && focus!==document.body ? focus : trigger)?.focus({preventScroll:true});
        });
      }
    });
    guide.drive();
  }
  function ready() {
    if (!kind() || !window.driver?.js?.driver) return;
    const button=$('#page-tour-start');
    if (!button) return;
    trigger=button; button.onclick=start; button.hidden=false;
    offer();
  }
  // Native dialogs always win, including a comparison opened during initial load.
  const modalObserver=new MutationObserver(offer);
  function bind() {
    document.querySelectorAll('dialog').forEach(d=>modalObserver.observe(d,{attributes:true,attributeFilter:['open']}));
    ready();
  }
  document.addEventListener('agentprov:tour-ready',bind);
  document.addEventListener('close',offer,true);
  addEventListener('resize',alignInvitation);
  if (document.readyState==='loading') document.addEventListener('DOMContentLoaded',bind,{once:true}); else bind();
})();
