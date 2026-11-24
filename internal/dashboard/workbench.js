'use strict';
(() => {
  const $ = s => document.querySelector(s);
  const { t: i18nLookup, locale: LANG } = window.AgentProvI18n || { t: s => s, locale: 'zh-CN' };
  const ZH = LANG === 'zh-CN';
  const L = (zh, en) => (ZH ? zh : en);
  const tr = s => {
    const v = i18nLookup(s);
    return v !== s ? v : s;
  };
  const tx = (s, vals) => tr(s).replace(/\{(\w+)\}/g, (m, k) => (Object.hasOwn(vals, k) ? String(vals[k]) : m));
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtTime = s => (s || '').replace('T', ' ').replace(/\.\d+Z?$/, '');
  const fmtBytes = n => { if (!n && n !== 0) return ''; const u = ['B', 'KB', 'MB', 'GB']; let i = 0, v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return (i ? v.toFixed(1) : v) + ' ' + u[i]; };
  const shortID = id => (id && id.length > 26 ? id.slice(0, 14) + '…' + id.slice(-8) : id || '');

  const EDGE_LABEL = {
    llm_call: tr('request→response'), llm_intent_caused: tr('intent→action'),
    llm_request: tr('request'), llm_response: tr('response'), llm_caused: tr('caused syscall'),
    before_tool_call: tr('before tool call'), after_tool_call: tr('after tool call'),
    agent_spawn: tr('spawns (delegation)'), agent_message: tr('sends (peer)'),
    agent_tool_call: tr('runs'), agent_syscall: tr('→ syscall'),
    pod_influences_pod: tr('A2A call →'), runtime_event_policy_decision: tr('→ policy'),
    policy_decision_risk_signal: tr('→ risk'), risk_signal_response_action: tr('→ response'),
    runtime_tool_call_event: tr('tool→event'), runtime_process_event: tr('proc→event'),
    possible_sensitive_data_flow: tr('data flow'), runtime_process_parent: tr('parent→child'),
    policy_decision_session: tr('→ session'), refused_intent: tr('⊘ blocked')
  };
  const CAPTURE_STATUS = {
    ok: L('正常采集', 'Captured'), complete: L('采集完整', 'Complete'),
    partial: L('部分采集', 'Partial'), incomplete: L('有采集缺口', 'Incomplete'),
    disabled: L('未启用', 'Disabled'), no_input: L('无输入', 'No input'),
    legacy_not_recorded: L('历史未记录', 'Historical (not recorded)'),
    not_recorded: L('未记录', 'Not recorded')
  };
  const CHANNEL_LABEL = {
    model_inference: tr('Model inference'), artifact_storage: tr('Artifact storage'),
    telemetry_service: tr('Telemetry service'), product_analytics: tr('Product analytics'),
    external_api: tr('External API'), database: tr('Database'),
    tool_service: tr('Tool service'), unknown_egress: tr('Unknown egress')
  };
  const DATA_LABEL = {
    secret: tr('secret'), source_code: tr('source code'), conversation: tr('conversation'),
    behavioral_metadata: tr('behavioral metadata'), unknown: tr('unknown data')
  };
  const EVIDENCE_LABEL = {
    payload_observed: tr('payload observed'), connection_observed: tr('connection observed'),
    dns_only: tr('DNS only'), documented: tr('documented')
  };
  const CMP_OP_NAMES = {
    recorded_configuration: L('已记录配置', 'Recorded configuration'),
    configuration_unavailable: L('配置不可用', 'Configuration unavailable'),
    saved_file_version: L('已保存文件版本', 'Saved file version'),
    recorded_file_change: L('已记录文件内容变更', 'Recorded content change'),
    file_snapshot_removed: L('快照间被移除', 'File removed between snapshots'),
    file_open: L('文件打开尝试', 'File open attempt'),
    file_write: L('文件写入尝试', 'File write attempt'),
    secret_path: L('敏感路径访问', 'Sensitive path access'),
    connection_attempt: L('连接尝试', 'Connection attempt'),
    dns_lookup: L('DNS 查询', 'DNS lookup'),
    audit_decision: L('安全机制判定', 'Mechanism decision'),
    state_snapshot: L('进程安全状态快照', 'Observed task state'),
    configuration_declaration: L('安全策略配置声明', 'Configuration declaration'),
    collection_status: L('审计采集状态', 'Audit collection')
  };
  const AC_KINDS = [
    ['access_control', L('审计记录', 'Audit records')],
    ['access_control_state', L('实际状态', 'Observed task state')],
    ['access_control_config', L('配置声明', 'Configuration declarations')],
    ['access_control_collection', L('审计采集', 'Audit collection')]
  ];
  const AC_FIELD_NAMES = {
    mechanism: 'Mechanism', decision: 'Recorded decision', profile: 'Profile', profile_namespace: 'Profile namespace',
    label: 'Label', class: 'Class', operation: 'Operation', target: 'Target', requested_mask: 'Requested access',
    denied_mask: 'Denied access', arch: 'Architecture', abi: 'ABI', syscall_name: 'System call',
    syscall_number: 'System call number', status: 'Status', reason: 'Reason', source: 'Source', mode: 'Mode',
    filter_count: 'Filter count', no_new_privs: 'No new privileges', profile_type: 'Profile type',
    observed_at: 'State observed at', coverage_scope: 'Coverage scope', upstream_loss: 'Upstream loss',
    read: 'Records read', ingested: 'Saved', duplicates: 'Duplicates', skipped: 'Skipped', failed: 'Failed',
    syscall_result: 'Return value', syscall_outcome: 'Observed outcome'
  };
  const CONTROL_DESC = {
    ASI01: tr('An attacker steers the agent off its intended goal via crafted prompts or instructions.'),
    ASI02: tr('The agent invokes its tools in harmful or unintended ways.'),
    ASI03: tr('The agent acquires or abuses credentials/privileges beyond its scope.'),
    ASI04: tr('Compromised dependencies, templates, or artifacts enter the run.'),
    ASI05: tr('The agent runs unexpected code or spawns unexpected processes.'),
    ASI06: tr("The agent's memory or working state is tampered with (poisoned)."),
    ASI07: tr('Untrusted agent-to-agent messages (only applies to multi-agent runs).'),
    ASI08: tr('One failure cascades across agents or exhausts shared resources.'),
    ASI09: tr("A human is misled into over-trusting the agent's output."),
    ASI10: tr('An agent drifts outside its normal (baseline) behaviour.'),
    TRACE: tr('Every action can be independently reconstructed and verified.'),
    Q1: tr('What security threats/risks did this run actually exhibit?'),
    Q2: tr('Which technical controls were enforced during the run?'),
    Q3: tr("How is the run's activity detected and assessed?"),
    Q4: tr('Was the deployment environment constrained and monitored?'),
    Q5: tr('Operational artifacts for broader, cross-discipline review.')
  };

  function captureStatusLabel(st) { return CAPTURE_STATUS[st] || (st ? tr(st) : L('应用层 / 历史记录', 'App / historical')); }
  function formatSignalTitle(raw) {
    const s = String(raw || '');
    const m = /^(.+) \(detect-only; would ([\w-]+)\)$/.exec(s);
    return m ? tx('{reason} (detect-only; would {action})', { reason: tr(m[1]), action: tr(m[2]) }) : tr(s);
  }
  function sevRank(s) { return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[String(s || '').toLowerCase()] || 0; }
  function isLoopbackHost(h) { h = String(h || '').replace(/^\[|\]$/g, ''); return h === 'localhost' || h === '::1' || h.startsWith('127.'); }
  function groupRiskSignals(rawArr) {
    const arr = rawArr || [];
    if (arr[0] && Array.isArray(arr[0].refs)) return arr;
    const groups = new Map();
    for (const s of arr) {
      if (!s) continue;
      let p = {}; try { p = JSON.parse(s.payload || '{}') || {}; } catch {}
      if ((p.rule_id === 'private_cidr_access' || s.reference === 'private CIDR access') && isLoopbackHost(p.dst_ip || p.host || '')) continue;
      const isSec = (s.dimension || '').toLowerCase() === 'security' || !!s.recommended_action || sevRank(s.severity) > sevRank('low');
      if (!isSec) continue;
      const rule = p.rule_id || p.rule || s.reference || s.type || 'risk';
      const action = s.recommended_action || p.decision || p.action || '';
      const key = [rule, s.type || '', action].join('|');
      let g = groups.get(key);
      if (!g) {
        g = { title: s.reference || rule, type: s.type || s.dimension || 'risk', action, severity: s.severity || 'medium', count: 0, refs: [], focus: '', sample: '' };
        groups.set(key, g);
      }
      g.count++;
      if (sevRank(s.severity) > sevRank(g.severity)) g.severity = s.severity;
      const ref = s.event_id ? `runtime_event/${s.event_id}` : (s.graph_ref_kind === 'event' && s.graph_ref_id ? (s.graph_ref_id.startsWith('runtime_event/') ? s.graph_ref_id : `runtime_event/${s.graph_ref_id}`) : '');
      if (ref && !g.refs.includes(ref)) g.refs.push(ref);
      if (!g.focus) g.focus = ref || (s.graph_ref_id ? (s.graph_ref_kind === 'risk' ? `risk_signal/${s.graph_ref_id}` : s.graph_ref_id) : '');
      if (!g.sample && p.rule_id !== 'secret_path_access' && p.event_type !== 'secret_path') g.sample = p.path || p.dst_ip || p.host || '';
    }
    return [...groups.values()].sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.count - a.count || a.title.localeCompare(b.title));
  }
  function nodeLabel(n) {
    const orig = String(n.label || n.id || '');
    if (!ZH) return orig;
    const d = n.data || {}, kind = n.kind;
    if (kind === 'overview_group') {
      const m = {
        tool_calls: () => tx('Tool calls: {count}', { count: d.count || 0 }),
        processes: () => tx('Process groups: {count} pids', { count: d.runtime_processes || 0 }),
        files: () => tx('File changes: {count}', { count: d.count || 0 }),
        egress: () => tx('Egress: {risky} risky / {total} total', { risky: d.risky || 0, total: d.total || 0 }),
        risks: () => tx('Risks: {high} high / {total} total', { high: d.high || 0, total: d.total || 0 }),
        agent_network: () => tx('Agent network: {agents} agents / {messages} peer msgs', { agents: d.agents || 0, messages: d.messages || 0 }),
        llm_intent: () => tx('LLM intent: {count} evidence nodes', { count: d.count || 0 }),
        artifacts: () => tx('Artifacts: {count}', { count: d.count || 0 })
      };
      if (orig === 'Process overview') return tr(orig);
      return m[n.subtype] ? m[n.subtype]() : tr(orig);
    }
    if (kind === 'risk_signal') return formatSignalTitle(orig);
    if (kind === 'policy_decision' && orig.startsWith('policy: ')) return tx('policy: {decision}', { decision: tr(d.decision || orig.slice(8)) });
    if (kind === 'response_action' && orig.startsWith('response: ')) return tx('response: {action}', { action: tr(d.action || orig.slice(10)) });
    if (kind === 'message' || kind === 'relay') return orig.replace(/^(peer|delegate) (.*?) -> (.*)$/, (_, act, from, to) => tx(act === 'peer' ? 'peer {from} -> {to}' : 'delegate {from} -> {to}', { from, to }));
    if (['file_group', 'egress_group', 'risk_group', 'trust_group', 'boundary_group'].includes(kind)) {
      const lbl = orig.replace(/^(.+?): (\d+)/, (_, cat, cnt) => tr(kind === 'file_group' && n.subtype === 'source' ? 'source files' : n.subtype || cat) + ': ' + cnt);
      return kind === 'risk_group' ? lbl.replace(/ -> (.*)$/, (_, dec) => ' → ' + tr(dec)) : lbl;
    }
    if (kind === 'process_group') {
      const m = orig.match(/^process group: (\d+) pids$/);
      if (m) return tx('process group: {count} pids', { count: m[1] });
    }
    if (kind === 'event_burst') {
      const m = orig.match(/^(\d+) exec \/ (\d+) proc \/ (\d+) risk$/);
      if (m) return tx('{exec} exec / {proc} proc / {risk} risk', { exec: m[1], proc: m[2], risk: m[3] });
      if (d.count !== undefined) return tr(n.subtype || d.event_type) + ': ' + d.count;
    }
    if (kind === 'runtime_event' || kind === 'event') {
      const st = orig.match(/^[①②③④] /)?.[0] || '', lbl = orig.slice(st.length);
      if (lbl === n.subtype) return st + tr(lbl);
      if (n.subtype && lbl.startsWith(n.subtype + ' ')) return st + tr(n.subtype) + lbl.slice(n.subtype.length);
    }
    return tr(orig);
  }
  function nodeSubtype(n) {
    const sub = n.subtype || n.kind;
    if (!ZH) return sub;
    const pid = sub.match(/^pid (\d+)$/); if (pid) return tx('pid {id}', { id: pid[1] });
    return tr(sub);
  }
  function renderDiffOrCode(txt, isDiff, maxH = '460px') {
    if (!isDiff) return `<pre class="code-box" style="max-height:${maxH}">${esc(txt)}</pre>`;
    return `<pre class="code-box" style="max-height:${maxH}">${txt.split('\n').map(line => {
      const cls = line.startsWith('+') ? 'diff-add' : line.startsWith('-') ? 'diff-del' : line.startsWith('@@') ? 'diff-hunk' : '';
      return cls ? `<span class="${cls}">${esc(line)}</span>` : esc(line);
    }).join('\n')}</pre>`;
  }

  const RUN_TITLES = {
    'run-3bfc6838a9c6': L('修复后 · 关闭可选诊断', 'After repair · Diagnostics disabled'),
    'run-860466af8a9a': L('修复前 · 诊断触发受限访问', 'Before repair · Diagnostics blocked'),
    'run-w01-445a3a164ae14723b82f90634cff96f5': L('受控工作区 · 读/改/冲突/产物', 'Controlled workspace · Revisions & conflict'),
    'run-da25e015ca1f': L('Browser 任务 · 操作/截图/HAR', 'Browser task · Actions, PNG & HAR'),
    'run-ce9d7ca0a2af': L('跨环境交接 · Claude 会话与回执', 'Cross-environment handoff · Claude'),
    'notebook-detailed': L('Notebook · 单元格与图表附件', 'Notebook · Cells & chart attachments'),
    'run-double-attempt': L('Agent 团队协作 (Alice & Bob)', 'Agent team (Alice & Bob)'),
    'run-snake-supervised': L('供应链投毒外联 (Snake)', 'Supply-chain exfil (Snake)'),
    'run-dbc2adf273d4': L('DeepSeek 完整开发任务', 'DeepSeek development task'),
    'run-2fd63df0ab9b': L('11 月复现 · 修复前', 'Nov reproduction · Before'),
    'run-48baa3821074': L('11 月复现 · 修复后', 'Nov reproduction · After'),
    'run-e9c3f452461a': L('10 月复现 · 修复前', 'Oct reproduction · Before'),
    'run-2267309eda57': L('10 月复现 · 修复后', 'Oct reproduction · After'),
    'run-grok-exfil': L('Grok 历史 · 代码库外发', 'Grok · Outbound codebase'),
    'run-grok-3routes': L('Grok 历史 · 三类外发路径', 'Grok · Three outbound routes'),
    'a2a-demo': L('Kubernetes 跨 Pod A2A', 'Kubernetes cross-Pod A2A'),
    'claude-demo': L('Kubernetes 部署归属', 'Kubernetes placement'),
    'ui-endpoint-candidates': L('关联依据 · 合成外联样本', 'Attribution · Synthetic outbound')
  };
  const runTitle = id => RUN_TITLES[id] || (window.RUN_LABELS?.[id] ? tr(window.RUN_LABELS[id]) : shortID(id));

  const STORY_BRIEFS = {
    'run-3bfc6838a9c6': {
      title: L('故事主线：配置修复后的复跑', 'Story: Re-run after configuration repair'),
      body: L('DeepSeek 修改 settings.json 关闭了两项会触发外部/受限访问的可选诊断，保留原有 7 项测试并更新 diagnostics.json 与 review.md。', 'DeepSeek updated settings.json to disable two optional diagnostic switches while keeping all 7 tests green and updating diagnostics.json and review.md.'),
      actions: [
        { label: L('对比修复前后文件', 'Compare before & after files'), fn: () => openCompare('run-860466af8a9a', 'run-3bfc6838a9c6', 'files') },
        { label: L('看合规框架评估', 'Open Compliance'), fn: () => setMode('compliance') },
        { label: L('看访问控制证据', 'Access control'), fn: () => setMode('risk') }
      ]
    },
    'run-860466af8a9a': {
      title: L('故事主线：修复前为什么触碰受限访问？', 'Story: Why diagnostics hit restricted access before repair'),
      body: L('7 项计算测试与报表计算完成，但可选诊断触发了受限路径读取与外联尝试并被拒。点下面直接对比修复后的文件改动。', 'Calculation tests and report generation ran, yet optional diagnostics attempted restricted reads and egress. Compare directly with the repaired run.'),
      actions: [
        { label: L('对比修复后文件', 'Compare with repaired run'), fn: () => openCompare('run-860466af8a9a', 'run-3bfc6838a9c6', 'files') },
        { label: L('查看安全风险图', 'Security lens'), fn: () => setLens('security') },
        { label: L('看合规框架评估', 'Open Compliance'), fn: () => setMode('compliance') }
      ]
    },
    'run-w01-445a3a164ae14723b82f90634cff96f5': {
      title: L('故事主线：受控工作区版本链与冲突拒绝', 'Story: Workspace revisions & conflict rejection'),
      body: L('包含 14 次受控工作区调用：先修改 input.txt，随后一次过期版本的 workspace_write 被明确以 conflict 拒绝并提示 reread，最终写入 result.txt。', '14 controlled workspace calls: an edit to input.txt, a stale workspace_write rejected with conflict (next_action: reread), and final output result.txt.'),
      actions: [
        { label: L('直达冲突回执 (conflict)', 'Inspect conflict receipt'), fn: () => { setMode('workspace'); selectWorkspaceBy('conflict'); } },
        { label: L('直达最终产物 result.txt', 'Inspect result.txt'), fn: () => setLens('file-artifact', 'raw') }
      ]
    },
    'run-da25e015ca1f': {
      title: L('故事主线：Browser 原生操作与附件取证', 'Story: Native Browser actions & verified attachments'),
      body: L('记录了 navigate → click → read_text 完整网页任务，并离线保存经 SHA-256 校验的 PNG 截图与 HAR 网络档案。', 'Captures navigate → click → read_text alongside SHA-256 verified PNG screenshot and HAR archive.'),
      actions: [
        { label: L('查看截图与 HAR', 'Open Browser & PNG'), fn: () => setMode('native') },
        { label: L('查看会话对话', 'Open session'), fn: () => setMode('session') }
      ]
    },
    'run-double-attempt': {
      title: L('故事主线：多 Agent 委派、拒绝与风险外联', 'Story: Delegation, refusal & risky execution'),
      body: L('Alice 委派 Bob 执行任务；其中一次提议被模型拒绝，随后同伴消息驱动 Bob 执行 pip 安装，触发敏感文件读取与云元数据地址访问。', 'Alice delegates to Bob; an early proposal is refused, then a peer message triggers pip install, secret file reads and metadata IP egress.'),
      actions: [
        { label: L('展开协作细节', 'Expanded orchestration'), fn: () => setLens('orchestration', 'expanded') },
        { label: L('查看合规映射', 'Compliance mapping'), fn: () => setMode('compliance') },
        { label: L('查看风险与外发', 'Risks & egress'), fn: () => setMode('risk') }
      ]
    }
  };

  const KIND_COLOR = {
    runtime_event: 'var(--event)', event: 'var(--event)', intent: 'var(--intent)',
    tool_call: 'var(--toolcall)', process: 'var(--process)', runtime_process: 'var(--process)',
    artifact: 'var(--artifact)', file: 'var(--file)', egress_group: 'var(--egress)',
    run: 'var(--acc)', overview_group: 'var(--group)', process_group: 'var(--process)',
    event_burst: 'var(--event)', file_group: 'var(--file)', risk_group: 'var(--risk)',
    intent_group: 'var(--intent)', intent_stage: 'var(--intent)', trust_group: 'var(--group)',
    boundary_group: 'var(--snapshot)', policy_decision: 'var(--policy)', policy: 'var(--policy)',
    risk_signal: 'var(--risk)', risk: 'var(--risk)', response_action: 'var(--response)',
    response: 'var(--response)', snapshot: 'var(--snapshot)', attempt: 'var(--snapshot)',
    session: 'var(--toolcall)', agent: 'var(--acc)', message: '#c026d3', relay: '#0891b2',
    refused: 'var(--risk)', llm_call: '#6366f1', llm_prompt: '#818cf8', llm_completion: '#a78bfa',
    intent_diff: '#ea580c', unknown: '#94a3b8', other: '#64748b'
  };
  const LENS_NAMES = {
    'default': L('因果总览', 'Causality'),
    'security': L('安全风险', 'Security'),
    'file-artifact': L('文件与产物', 'Files & artifacts'),
    'process': L('进程树', 'Processes'),
    'network-egress': L('网络外联', 'Network egress'),
    'orchestration': L('Agent 协作', 'Orchestration'),
    'agent-intent': L('模型意图', 'Model intent'),
    'intent': L('意图一致性', 'Conformance'),
    'data-flow-taint': L('敏感数据流', 'Data flow'),
    'substrate': L('运行环境', 'Substrate'),
    'trust-origin': L('信任来源', 'Trust origin'),
    'sandbox-boundary': L('沙箱边界', 'Boundary')
  };

  async function api(path, opts = {}) {
    if (window.AgentProvReplay) return window.AgentProvReplay.query(path, opts);
    const res = await fetch(path, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
    return res.json();
  }
  window.j = api;

  const INIT = new URLSearchParams(location.search);
  const VALID_MODES = new Set(['graph', 'workspace', 'native', 'handoff', 'session', 'risk', 'compliance', 'timeline']);
  const S = {
    runs: [],
    run: INIT.get('run') || '',
    mode: VALID_MODES.has(INIT.get('view')) ? INIT.get('view') : 'graph',
    scope: INIT.get('session') && INIT.get('harness') ? { harness: INIT.get('harness'), session_id: INIT.get('session') } : null,
    lens: INIT.get('lens') || 'default',
    detail: ['summary', 'expanded', 'raw'].includes(INIT.get('detail')) ? INIT.get('detail') : 'summary',
    focus: INIT.get('focus') || '',
    sel: INIT.get('selected') || INIT.get('focus') || null,
    compare: null,
    expandMode: 'lineage',
    overlays: new Set(),
    zoom: 1,
    fit: true,
    exactFit: false,
    times: [],
    tcur: null,
    playing: null,
    graph: null,
    lensManifest: null,
    overviewLens: null,
    overview: null,
    contextOverview: null,
    entries: [],
    entriesCursor: '',
    sessionSourceFilter: '',
    captureManifest: [],
    captureCursor: '',
    wsItems: [],
    wsSelected: 0,
    nativeItems: [],
    nativeSelected: 0,
    handoffs: [],
    outbound: [],
    egress: [],
    processes: [],
    timeline: { events: [], total: 0, offset: 0, limit: 50 },
    acCounts: {},
    acKind: 'access_control_state',
    acPage: { events: [], total: 0, offset: 0, limit: 25 },
    frameworks: [],
    frameworkId: '',
    compliance: null,
    compGrp: { detected: true, enforced: true, not_triggered: false, no_rule: false },
    compOpen: new Set(),
    insTab: 'summary',
    insContentMode: 'body',
    insContentNode: '',
    sessionTab: 'conversation',
    graphView: null,
    layout: null,
    layoutKey: '',
    gsig: '',
    reqEpoch: 0
  };

  const IS_REPLAY = !!window.AgentProvReplay;
  const IS_OFFLINE = !!window.AgentProvOffline;
  const HAS_GALLERY_LINK = !!document.querySelector('.offline-replay-bar [data-site-navigation], .public-demo-bar');

  function homeHref() {
    const navLink = document.querySelector('.offline-replay-bar [data-site-navigation], .public-demo-bar a');
    if (navLink) return navLink.getAttribute('href');
    const isNested = /\/(current|recordings)\//.test(location.pathname);
    return isNested ? `../../../?lang=${LANG}` : `../?lang=${LANG}`;
  }
  function altLangHref(targetLang) {
    const u = new URL(location.href);
    if (/\/(en|zh-CN)\//.test(u.pathname)) {
      u.pathname = u.pathname.replace(/\/(en|zh-CN)\//, `/${targetLang}/`);
      u.searchParams.delete('lang');
    } else {
      u.searchParams.set('lang', targetLang);
    }
    if (S.run) u.searchParams.set('run', S.run);
    u.searchParams.set('lens', S.lens);
    u.searchParams.set('detail', S.detail);
    if (S.mode !== 'graph') u.searchParams.set('view', S.mode); else u.searchParams.delete('view');
    if (S.focus && !S.compare) u.searchParams.set('focus', S.focus); else u.searchParams.delete('focus');
    return u.href;
  }
  function syncURL() {
    try {
      const u = new URL(location.href);
      if (S.run) u.searchParams.set('run', S.run);
      u.searchParams.set('lens', S.lens);
      u.searchParams.set('detail', S.detail);
      if (S.mode !== 'graph') u.searchParams.set('view', S.mode); else u.searchParams.delete('view');
      if (S.focus && !S.compare) u.searchParams.set('focus', S.focus); else u.searchParams.delete('focus');
      if (S.sel && S.sel !== S.focus && !S.compare) u.searchParams.set('selected', S.sel); else u.searchParams.delete('selected');
      for (const key of ['a', 'b', 'dim']) {
        if (S.compare) u.searchParams.set('compare_' + key, S.compare[key]);
        else u.searchParams.delete('compare_' + key);
      }
      if (S.scope) {
        u.searchParams.set('session', S.scope.session_id); u.searchParams.set('harness', S.scope.harness);
      } else { u.searchParams.delete('session'); u.searchParams.delete('harness'); }
      history.replaceState(null, '', u);
    } catch {}
    document.querySelectorAll('.wb-lang a').forEach(a => { a.href = altLangHref(a.lang || (a.textContent === 'EN' ? 'en' : 'zh-CN')); });
  }

  function buildShell() {
    document.title = `${L('证据工作台', 'Evidence Workbench')} · AgentProvenance`;
    const mount = document.getElementById('wb-root') || (() => {
      const d = document.createElement('div'); d.id = 'wb-root'; document.body.appendChild(d); return d;
    })();
    const showBack = HAS_GALLERY_LINK || (IS_REPLAY && !IS_OFFLINE);
    const liveRefreshBtn = !IS_REPLAY ? `<button type="button" id="wb-refresh" class="wb-btn" title="${esc(L('刷新本地数据', 'Refresh local store'))}">↻ ${L('刷新', 'Refresh')}</button>` : '';
    mount.innerHTML = `
      <div class="wb-shell">
        <header class="wb-topbar">
          ${showBack ? `<a class="wb-back" href="${esc(homeHref())}">
            <svg viewBox="0 0 24 24"><path d="M19 12H5m6-6-6 6 6 6"/></svg>
            <span>${L('示例库', 'Demos')}</span>
          </a>` : ''}
          <span class="wb-brand"><b>Agent</b>Provenance</span>
          <span class="wb-div"></span>
          <select id="wb-runsel" class="wb-runsel" aria-label="${esc(L('选择执行记录', 'Select run'))}"></select>
          <span class="wb-spacer"></span>
          <button type="button" id="wb-verify" class="wb-verify">…</button>
          <div class="wb-actions">
            ${liveRefreshBtn}
            <button type="button" id="wb-btn-search" class="wb-btn">
              <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
              <span>${L('搜索', 'Search')}</span><span class="wb-kbd">⌘K</span>
            </button>
            <button type="button" id="wb-btn-compare" class="wb-btn">
              <svg viewBox="0 0 24 24"><path d="m16 3 4 4-4 4M4 7h16M8 21l-4-4 4-4m12 4H4"/></svg>
              <span>${L('对比', 'Compare')}</span>
            </button>
          </div>
          <button hidden type="button" id="page-tour-start" aria-label="${L('页面导览','Page tour')}" title="${L('页面导览','Page tour')}"><span aria-hidden="true" class="tour-icon">?</span><span class="tour-label">${L('页面导览','Page tour')}</span></button>
          <nav class="wb-lang language-switch" aria-label="${esc(L('语言', 'Language'))}">
            <a href="${esc(altLangHref('en'))}" lang="en" ${LANG === 'en' ? 'aria-current="true"' : ''}>EN</a>
            <a href="${esc(altLangHref('zh-CN'))}" lang="zh-CN" ${LANG === 'zh-CN' ? 'aria-current="true"' : ''}>中文</a>
          </nav>
        </header>
        <div data-tour-slot hidden></div>

        <nav class="wb-subbar" aria-label="${esc(L('工作台视图', 'Workbench views'))}">
          <div class="wb-tabs" role="tablist">
            <button type="button" class="wb-tab" role="tab" data-mode="graph" aria-selected="true">${L('证据图', 'Graph')}</button>
            <button type="button" class="wb-tab" role="tab" data-mode="workspace" hidden>${L('工作区', 'Workspace')} <span class="wb-count" id="cnt-ws">0</span></button>
            <button type="button" class="wb-tab" role="tab" data-mode="native" hidden>Browser / Notebook <span class="wb-count accent" id="cnt-native">0</span></button>
            <button type="button" class="wb-tab" role="tab" data-mode="handoff" hidden>${L('跨环境交接', 'Handoffs')} <span class="wb-count accent" id="cnt-handoff">0</span></button>
            <button type="button" class="wb-tab" role="tab" data-mode="session">${L('会话与工具', 'Session & tools')} <span class="wb-count" id="cnt-session">…</span></button>
            <button type="button" class="wb-tab" role="tab" data-mode="risk">${L('风险与访问控制', 'Risk & egress')} <span class="wb-count" id="cnt-risk">0</span></button>
            <button type="button" class="wb-tab" role="tab" data-mode="compliance">${L('合规评估', 'Compliance')} <span class="wb-count" id="cnt-comp">…</span></button>
            <button type="button" class="wb-tab" role="tab" data-mode="timeline">${L('时间线与进程', 'Timeline & procs')} <span class="wb-count" id="cnt-tl">…</span></button>
          </div>
          <div class="wb-scope-bar" id="wb-scope-wrap" hidden>
            <span>${L('会话范围:', 'Session:')}</span>
            <select id="wb-scopesel" aria-label="${esc(L('按会话筛选', 'Filter by session'))}"></select>
          </div>
        </nav>

        <div class="wb-stage">
          <!-- 1. Graph Split View -->
          <section class="wb-view" data-view="graph">
            <div class="wb-graph-split">
              <div class="wb-canvas-col">
                <div class="wb-lens-strip" id="wb-lens-strip"></div>
                <div class="wb-focus-bar" id="wb-focus-bar" hidden>
                  <span>${L('当前聚焦节点：', 'Focused node:')}</span>
                  <code id="wb-focus-code"></code>
                  <button type="button" id="wb-focus-clear">${L('× 清除聚焦并返回全图', '× Clear focus')}</button>
                </div>
                <div class="wb-graph-tools">
                  <div class="wb-seg" role="group" aria-label="${esc(L('图谱详细程度', 'Detail level'))}">
                    <button type="button" data-detail="summary">${L('摘要', 'Summary')}</button>
                    <button type="button" data-detail="expanded">${L('展开', 'Expanded')}</button>
                    <button type="button" data-detail="raw">${L('原始', 'Raw')}</button>
                  </div>
                  <button type="button" class="wb-chip risk" data-ov="risk">${L('风险高亮', 'Risk')}</button>
                  <button type="button" class="wb-chip trust" data-ov="trust">${L('信任来源', 'Trust')}</button>
                  <div class="wb-scrub" id="wb-scrub">
                    <button type="button" id="wb-play" title="${esc(L('按时间播放', 'Play'))}">▶</button>
                    <input type="range" id="wb-slider" min="0" max="0" value="0">
                    <span class="wb-scrub-lbl" id="wb-scrub-lbl"></span>
                    <button type="button" class="wb-scrub-hint" id="wb-scrub-hint" hidden>${L('摘要无时间轴 · 切到展开回放', 'Switch to Expanded for timeline')}</button>
                  </div>
                  <div class="wb-find">
                    <input id="wb-find" type="search" placeholder="${esc(L('查找节点…', 'Find node…'))}" aria-label="${esc(L('查找图中节点', 'Find graph node'))}">
                    <output id="wb-matches" for="wb-find"></output>
                    <button type="button" id="wb-next" disabled title="${esc(L('下一个匹配', 'Next match'))}">↓</button>
                  </div>
                  <div class="wb-zoom">
                    <button type="button" id="wb-zout" title="${esc(L('缩小', 'Zoom out'))}">−</button>
                    <button type="button" id="wb-zfit">${L('全图', 'Fit width')}</button>
                    <button type="button" id="wb-zin" title="${esc(L('放大', 'Zoom in'))}">+</button>
                  </div>
                </div>
                <div class="wb-dag-wrap">
                  <div id="dag"></div>
                  <div class="wb-canvas-foot">
                    <div class="wb-legend" id="wb-legend"></div>
                    <div class="wb-stats" id="wb-stats"></div>
                  </div>
                </div>
              </div>
              <aside class="wb-inspector" id="wb-inspector"></aside>
            </div>
          </section>

          <!-- 2. Workspace View -->
          <section class="wb-view" data-view="workspace" hidden>
            <div class="wb-split-2">
              <div class="wb-list-col">
                <div class="wb-list-head"><strong id="ws-list-title">${L('工作区操作与版本链', 'Workspace operations')}</strong><span class="pill-tag" id="ws-conflict-pill" hidden></span></div>
                <div id="ws-reasons" hidden></div>
                <div class="wb-list-scroll" id="ws-list"></div>
              </div>
              <div class="wb-detail-col" id="ws-detail"></div>
            </div>
          </section>

          <!-- 3. Browser / Notebook View -->
          <section class="wb-view" data-view="native" hidden>
            <div class="wb-split-2">
              <div class="wb-list-col">
                <div class="wb-list-head"><strong>Browser / Notebook ${L('原生记录', 'native records')}</strong><span class="pill-tag acc" id="nat-att-pill" hidden></span></div>
                <div class="wb-list-scroll" id="nat-list"></div>
              </div>
              <div class="wb-detail-col" id="nat-detail"></div>
            </div>
          </section>

          <!-- 4. Handoffs View -->
          <section class="wb-view" data-view="handoff" hidden>
            <div class="wb-scroll-page" id="handoff-body"></div>
          </section>

          <!-- 5. Session & Tools View -->
          <section class="wb-view" data-view="session" hidden>
            <div class="wb-scroll-page" id="session-body"></div>
          </section>

          <!-- 6. Risk, Outbound, Egress & Access Control View -->
          <section class="wb-view" data-view="risk" hidden>
            <div class="wb-scroll-page" id="risk-body"></div>
          </section>

          <!-- 7. Compliance View -->
          <section class="wb-view" data-view="compliance" hidden>
            <div class="wb-scroll-page" id="compliance-body"></div>
          </section>

          <!-- 8. Timeline, Process Tree & Producer Profile View -->
          <section class="wb-view" data-view="timeline" hidden>
            <div class="wb-scroll-page" id="timeline-body"></div>
          </section>
        </div>
      </div>

      <!-- Compare Dialog -->
      <dialog id="wb-compare-dlg" class="wb-dlg" aria-labelledby="wb-cmp-title">
        <div class="wb-dlg-head">
          <h2 id="wb-cmp-title">${L('对比两次执行', 'Compare two runs')}</h2>
          <button type="button" class="wb-dlg-close" data-close="wb-compare-dlg" aria-label="${esc(L('关闭', 'Close'))}">×</button>
        </div>
        <div class="wb-dlg-body" id="wb-cmp-body"></div>
      </dialog>

      <!-- Search Dialog -->
      <dialog id="wb-search-dlg" class="wb-dlg" aria-labelledby="wb-srch-title">
        <div class="wb-dlg-head">
          <h2 id="wb-srch-title">${L('搜索已保存证据', 'Search saved evidence')}</h2>
          <button type="button" class="wb-dlg-close" data-close="wb-search-dlg" aria-label="${esc(L('关闭', 'Close'))}">×</button>
        </div>
        <div class="wb-dlg-body" id="wb-srch-body"></div>
      </dialog>

      <!-- Delivery / Content Lightbox Dialog -->
      <dialog id="wb-info-dlg" class="wb-dlg" aria-labelledby="wb-info-title">
        <div class="wb-dlg-head">
          <h2 id="wb-info-title"></h2>
          <button type="button" class="wb-dlg-close" data-close="wb-info-dlg" aria-label="${esc(L('关闭', 'Close'))}">×</button>
        </div>
        <div class="wb-dlg-body" id="wb-info-body"></div>
      </dialog>
    `;

    function closeSheet(dialog) {
      if (dialog.id === 'wb-compare-dlg') { S.compare = null; syncURL(); }
      dialog.close();
    }
    document.querySelectorAll('[data-close]').forEach(b => { b.onclick = () => closeSheet($(`#${b.dataset.close}`)); });
    $('#wb-compare-dlg').addEventListener('cancel', e => { e.preventDefault(); closeSheet(e.currentTarget); });
    $('#wb-compare-dlg').addEventListener('close', () => {
      if (!$('#wb-compare-dlg').open) { S.compare = null; syncURL(); }
    });
    document.querySelectorAll('dialog.wb-dlg').forEach(d => d.addEventListener('click', e => { if (e.target === d) closeSheet(d); }));
    document.querySelectorAll('.wb-tab').forEach(b => { b.onclick = () => setMode(b.dataset.mode); });
    document.querySelectorAll('[data-detail]').forEach(b => { b.onclick = () => setLens(S.lens, b.dataset.detail, S.focus); });
    document.querySelectorAll('.wb-chip[data-ov]').forEach(b => {
      b.onclick = () => {
        const k = b.dataset.ov;
        if (S.overlays.has(k)) S.overlays.delete(k); else S.overlays.add(k);
        b.classList.toggle('on', S.overlays.has(k));
        loadGraph();
      };
    });
    $('#wb-focus-clear').onclick = () => setLens(S.lens, S.detail, '');
    $('#wb-zout').onclick = () => setZoom(0.8);
    $('#wb-zin').onclick = () => setZoom(1.25);
    $('#wb-zfit').onclick = () => { S.fit = true; S.exactFit = !S.exactFit; S.graphView?.resize(); renderGraph(); };
    $('#wb-play').onclick = togglePlay;
    $('#wb-slider').oninput = () => { stopPlay(); setScrub(+$('#wb-slider').value); };
    $('#wb-scrub-hint').onclick = () => setLens(S.lens, 'expanded', S.focus);
    $('#wb-runsel').onchange = () => loadRun($('#wb-runsel').value);
    $('#wb-scopesel').onchange = () => {
      const v = $('#wb-scopesel').value;
      S.scope = v ? JSON.parse(v) : null;
      S.sel = null; S.focus = '';
      loadGraph();
    };
    $('#wb-btn-compare').onclick = () => openCompare();
    $('#wb-btn-search').onclick = () => openSearch();
    $('#wb-verify').onclick = () => openDeliveryModal();
    window.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openSearch(); }
    });
  }

  function setMode(mode) {
    S.mode = mode;
    document.querySelectorAll('.wb-tab').forEach(b => b.setAttribute('aria-selected', String(b.dataset.mode === mode)));
    document.querySelectorAll('.wb-view').forEach(v => { v.hidden = v.dataset.view !== mode; });
    syncURL();
    if (mode === 'graph') S.graphView?.resize();
    if (mode === 'workspace') renderWorkspaceView();
    if (mode === 'native') renderNativeView();
    if (mode === 'handoff') renderHandoffsView();
    if (mode === 'session') renderSessionView();
    if (mode === 'risk') renderRiskView();
    if (mode === 'compliance') renderComplianceView();
    if (mode === 'timeline') renderTimelineView();
  }

  function setLens(lens, detail = S.detail, focus = '') {
    S.lens = lens || 'default';
    S.detail = detail || 'summary';
    S.focus = focus || '';
    S.sel = S.focus || null;
    S.insContentMode = 'body';
    S.insContentNode = '';
    S.fit = true;
    S.exactFit = false;
    stopPlay();
    if (S.mode !== 'graph') setMode('graph'); else syncURL();
    loadGraph();
  }

  // --- Graph Layout & Rendering ---
  function textW(str, sz = 13) { let w = 0; for (const c of String(str)) w += c.codePointAt(0) > 255 ? sz : sz * 0.54; return w; }
  function clipText(str, maxW, sz = 13) {
    if (textW(str, sz) <= maxW) return str;
    let out = '';
    for (const c of String(str)) { if (textW(out + c + '…', sz) > maxW) break; out += c; }
    return out + '…';
  }
  function adaptLens(m) {
    const nodes = (m.nodes || []).map(n => ({ id: n.id, label: n.label || n.id, kind: n.kind, subtype: n.subtype || '', risk: n.risk || '', trust_origin: n.trust_origin || '', data: n.data || {} }));
    const norm = (e, d) => ({ from: e.from_id, to: e.to_id, type: e.edge_type, t: e.created_at || '', derived: !!d, confidence: e.confidence ?? null, rule: e.derivation_rule || '', evidence: e.evidence_refs || [] });
    const edges = (m.edges || []).map(e => norm(e, false)).concat((m.derived_edges || []).map(e => norm(e, true)));
    const nodeT = {};
    nodes.forEach(n => { if (n.data?.created_at) nodeT[n.id] = n.data.created_at; });
    edges.forEach(e => { if (e.t) [e.from, e.to].forEach(id => { if (nodeT[id] === undefined || e.t < nodeT[id]) nodeT[id] = e.t; }); });
    return { nodes, edges, nodeT, meta: m };
  }
  function computeLayout(nodes, edges) {
    const byId = {}, adj = {};
    nodes.forEach(n => { byId[n.id] = n; adj[n.id] = []; });
    edges.forEach(e => { if (byId[e.from] && byId[e.to]) adj[e.from].push(e.to); });
    const color = {}, back = new Set(), order = [];
    const dfs = root => {
      const st = [[root, 0]];
      while (st.length) {
        const fr = st[st.length - 1], u = fr[0];
        if (fr[1] === 0) color[u] = 1;
        const kids = adj[u];
        if (fr[1] < kids.length) {
          const v = kids[fr[1]++];
          if (color[v] === 1) back.add(u + '\0' + v);
          else if (!color[v]) st.push([v, 0]);
        } else { color[u] = 2; order.push(u); st.pop(); }
      }
    };
    nodes.forEach(n => { if (!color[n.id]) dfs(n.id); });
    const layer = {}; nodes.forEach(n => { layer[n.id] = 0; });
    order.slice().reverse().forEach(u => adj[u].forEach(v => { if (!back.has(u + '\0' + v) && layer[v] < layer[u] + 1) layer[v] = layer[u] + 1; }));
    const cols = {}; nodes.forEach(n => (cols[layer[n.id]] = cols[layer[n.id]] || []).push(n));
    const idx = {}, nUp = {}, nDn = {};
    Object.keys(cols).forEach(k => cols[k].forEach((n, i) => { idx[n.id] = i; }));
    nodes.forEach(n => { nUp[n.id] = []; nDn[n.id] = []; });
    edges.forEach(e => {
      if (!byId[e.from] || !byId[e.to]) return;
      const lf = layer[e.from], lt = layer[e.to];
      if (lt === lf + 1) { nDn[e.from].push(e.to); nUp[e.to].push(e.from); }
      else if (lf === lt + 1) { nDn[e.to].push(e.from); nUp[e.from].push(e.to); }
    });
    const nums = Object.keys(cols).map(Number).sort((a, b) => a - b);
    const bary = (id, ns, i) => ns.length ? ns.reduce((s, x) => s + idx[x], 0) / ns.length : i;
    for (let sw = 0; sw < 4; sw++) {
      const down = sw % 2 === 0;
      (down ? nums : nums.slice().reverse()).forEach(k => {
        cols[k] = cols[k].map((n, i) => ({ n, i, v: bary(n.id, down ? nUp[n.id] : nDn[n.id], i) })).sort((a, b) => a.v - b.v || a.i - b.i).map(x => x.n);
        cols[k].forEach((n, i) => { idx[n.id] = i; });
      });
    }
    const ROWH = 80, NW = 166, NH = 52, PADX = 28, PADY = 26;
    const pos = {}; let x = PADX, right = PADX + NW;
    for (const k of nums) {
      let widest = NW;
      cols[k].forEach((n, i) => {
        const w = Math.max(NW, Math.min(320, 38 + Math.ceil(textW(nodeLabel(n)))));
        pos[n.id] = { x, y: PADY + i * ROWH, w, h: NH };
        widest = Math.max(widest, w);
      });
      right = x + widest; x += Math.max(260, widest + 42);
    }
    const maxRows = Math.max(1, ...Object.values(cols).map(c => c.length));
    return { pos, W: right + PADX, H: PADY * 2 + (maxRows - 1) * ROWH + NH };
  }
  function localScope(g, sel, mode) {
    if (!sel) return null;
    const out = {}, inc = {};
    g.edges.forEach((e, i) => { (out[e.from] = out[e.from] || []).push([e.to, i]); (inc[e.to] = inc[e.to] || []).push([e.from, i]); });
    const nodes = new Set([sel]), edges = new Set();
    const walk = (id, adj) => (adj[id] || []).forEach(([nx, i]) => { edges.add(i); if (!nodes.has(nx)) { nodes.add(nx); walk(nx, adj); } });
    if (mode === 'children') (out[sel] || []).forEach(([nx, i]) => { edges.add(i); nodes.add(nx); });
    else if (mode === 'upstream') walk(sel, inc);
    else if (mode === 'downstream') walk(sel, out);
    else { walk(sel, out); walk(sel, inc); }
    return { nodes, edges };
  }
  function graphZoom(W) {
    if (S.fit) {
      const el = $('#dag');
      const cw = (el && el.clientWidth) || W;
      const raw = Math.min(1, (cw - 12) / W);
      if (S.exactFit) return raw;
      return S.lens === 'orchestration' && matchMedia('(min-width: 981px)').matches ? 1.1 : Math.max(0.62, raw);
    }
    return S.zoom;
  }
  function setZoom(m) {
    if (S.fit && S.layout) S.zoom = graphZoom(S.layout.W);
    S.fit = false; S.exactFit = false; S.zoom = Math.max(0.25, Math.min(3, S.zoom * m));
    S.graphView?.resize(); updateFitButton();
  }
  function updateFitButton() {
    const fit = $('#wb-zfit');
    fit.textContent = S.exactFit ? L('阅读比例', 'Reading size') : L('全图', 'Fit width');
    fit.title = S.exactFit ? L('恢复默认阅读字号', 'Restore default reading size') : L('按宽度查看整张图', 'Fit the entire graph width');
  }
  function stopPlay() { if (S.playing) { clearInterval(S.playing); S.playing = null; } $('#wb-play').textContent = '▶'; }
  function togglePlay() {
    if (S.playing) return stopPlay();
    if (!S.times.length) return;
    const sl = $('#wb-slider');
    if (+sl.value >= S.times.length) sl.value = 0;
    setScrub(+sl.value);
    $('#wb-play').textContent = '⏸';
    S.playing = setInterval(() => {
      const v = +sl.value + 1; sl.value = v; setScrub(v);
      if (v >= S.times.length) stopPlay();
    }, 700);
  }
  function setScrub(idx) {
    S.tcur = idx >= S.times.length ? null : S.times[idx];
    updateScrubLabel();
    renderGraph();
  }
  function updateScrubLabel() {
    const has = S.times.length > 0;
    $('#wb-play').hidden = $('#wb-slider').hidden = !has;
    $('#wb-scrub-lbl').hidden = !has;
    $('#wb-scrub-hint').hidden = has || S.detail !== 'summary';
    if (!has) return;
    const idx = +$('#wb-slider').value;
    $('#wb-scrub-lbl').textContent = S.tcur === null ? `${S.times.length} ${L('时间点', 'steps')}` : `${idx + 1}/${S.times.length} · ${fmtTime(S.tcur).slice(11)}`;
  }

  function renderLensStrip() {
    const avail = S.lensManifest?.available_lenses || ['default'];
    const ovNodes = {};
    (S.overviewLens?.nodes || []).forEach(n => { ovNodes[n.id] = n.data || {}; });
    const cRisk = ovNodes['overview/risks']?.total || 0;
    const cFiles = ovNodes['overview/files']?.count || 0;
    const cProc = ovNodes['overview/processes']?.runtime_processes || 0;
    const cEgress = ovNodes['overview/egress']?.total || 0;
    const cAgents = ovNodes['overview/agent_network']?.agents || 0;
    const cIntent = ovNodes['overview/llm_intent']?.count || 0;

    const candidates = [
      { id: 'default', count: null },
      { id: 'security', count: cRisk, risk: cRisk > 0 },
      { id: 'file-artifact', count: cFiles },
      { id: 'orchestration', count: cAgents > 1 ? cAgents : 0 },
      { id: 'network-egress', count: cEgress },
      { id: 'process', count: cProc },
      { id: 'agent-intent', count: cIntent }
    ].filter(x => avail.includes(x.id) && (x.id === 'default' || x.id === S.lens || (x.count && x.count > 0)));
    const shown = new Set(candidates.map(c => c.id));
    if (!shown.has(S.lens) && avail.includes(S.lens)) candidates.push({ id: S.lens, count: null });

    const strip = $('#wb-lens-strip');
    strip.innerHTML = candidates.map(c => `
      <button type="button" class="wb-lens-pill ${c.risk ? 'risk-pill' : ''} ${S.lens === c.id ? 'on' : ''}" data-lens="${esc(c.id)}">
        <span>${esc(LENS_NAMES[c.id] || c.id)}</span>${c.count ? `<span class="n">${c.count}</span>` : ''}
      </button>
    `).join('') + `
      <select class="wb-lens-more" id="wb-lens-select" aria-label="${esc(L('全部视角', 'All lenses'))}">
        ${avail.map(id => `<option value="${esc(id)}" ${id === S.lens ? 'selected' : ''}>${esc(LENS_NAMES[id] || id)}</option>`).join('')}
      </select>
    `;
    strip.querySelectorAll('[data-lens]').forEach(b => { b.onclick = () => setLens(b.dataset.lens, S.detail, ''); });
    $('#wb-lens-select').onchange = e => setLens(e.target.value, S.detail, '');
  }

  function renderGraph() {
    if (!S.graph) return;
    updateFitButton();
    const g = S.graph;
    const key = S.gsig;
    if (S.layoutKey !== key || !S.layout) {
      S.layout = computeLayout(g.nodes, g.edges);
      S.layoutKey = key;
    }
    S.graphView ??= window.AgentGraphView({
      host: $('#dag'), find: $('#wb-find'), next: $('#wb-next'), count: $('#wb-matches'),
      activate: selectNode, scale: graphZoom, zoomAt: setZoom, translate: tr
    });
    const focus = localScope(g, S.sel, S.expandMode);
    const nodeVis = id => S.tcur === null || g.nodeT[id] === undefined || g.nodeT[id] <= S.tcur;
    const edgeVis = e => !(S.tcur !== null && e.t && e.t > S.tcur) && nodeVis(e.from) && nodeVis(e.to);

    S.graphView.show({
      key, g, L: S.layout, sel: S.sel, focus, visible: nodeVis, edgeVisible: edgeVis,
      nodeStyle: (n, p) => {
        const lbl = nodeLabel(n), sub = nodeSubtype(n);
        const ovColor = n.kind === 'overview_group' ? ({
          'overview/agent_network': 'var(--acc)',
          'overview/artifacts': 'var(--artifact)',
          'overview/egress': 'var(--egress)',
          'overview/files': 'var(--file)',
          'overview/llm_intent': 'var(--intent)',
          'overview/processes': 'var(--process)',
          'overview/risks': (n.data?.total || 0) > 0 ? 'var(--risk)' : 'var(--group)',
          'overview/tool_calls': 'var(--toolcall)'
        }[n.id] || KIND_COLOR.overview_group) : (KIND_COLOR[n.kind] || KIND_COLOR.other);
        return {
          label: clipText(lbl, p.w - 36),
          sub: clipText(S.overlays.has('trust') && n.trust_origin ? tr(n.trust_origin) : sub, p.w - 25, 10.5),
          title: [lbl, sub, n.risk ? `risk: ${n.risk}` : '', n.id].filter(Boolean).join(' · '),
          risky: S.overlays.has('risk') && ['high', 'critical', 'tainted', 'medium'].includes(n.risk),
          color: ovColor
        };
      },
      edgeLabel: e => {
        const txt = (EDGE_LABEL[e.type] || tr(e.type)) + (e.derived && e.confidence != null ? ` · ${Number(e.confidence).toFixed(2)}` : '');
        return { text: txt, width: textW(txt, 10) + 16 };
      }
    });

    const fbar = $('#wb-focus-bar');
    fbar.hidden = !S.focus;
    if (S.focus) $('#wb-focus-code').textContent = S.focus;

    const kinds = [...new Set(g.nodes.map(n => n.kind))];
    $('#wb-legend').innerHTML = kinds.slice(0, 7).map(k => `<span><i style="background:${KIND_COLOR[k] || KIND_COLOR.other}"></i>${esc(tr(k))}</span>`).join('')
      + (g.edges.some(e => e.derived) ? `<span><i class="dash"></i>${L('推断关系', 'derived')}</span>` : '');
    const q = S.lensManifest?.query || {};
    $('#wb-stats').textContent = `${q.node_count ?? g.nodes.length} ${L('节点', 'nodes')} · ${(g.edges || []).length} ${L('关系', 'edges')} · ${q.raw_event_count ?? 0} ${L('事件', 'events')}`;
  }

  function selectNode(id) {
    const n = S.graph?.nodes.find(x => x.id === id);
    if (n?.data?.drilldown_lens) {
      return setLens(n.data.drilldown_lens, n.data.drilldown_detail || 'summary', n.data.drilldown_focus || '');
    }
    S.sel = S.sel === id ? null : id;
    S.expandMode = 'lineage';
    S.insTab = 'summary';
    S.insContentMode = 'body';
    S.insContentNode = '';
    syncURL();
    renderGraph();
    renderInspector();
  }

  // --- Right Contextual Inspector ---
  async function renderInspector() {
    const host = $('#wb-inspector');
    const n = S.sel ? S.graph?.nodes.find(x => x.id === S.sel) : null;
    if (!n) return renderOverviewInspector(host);

    const col = KIND_COLOR[n.kind] || KIND_COLOR.other;
    host.innerHTML = `
      <div class="wb-ins-head">
        <div>
          <h2><span style="color:${col}">●</span> ${esc(nodeLabel(n))}</h2>
          <div class="wb-ins-sub">
            <span class="pill-tag">${esc(tr(n.kind))}</span>
            ${n.risk ? `<span class="pill-tag risk">${esc(L('风险:', 'Risk:') + ' ' + tr(n.risk))}</span>` : ''}
            ${n.trust_origin ? `<span class="pill-tag acc">${esc(tr(n.trust_origin))}</span>` : ''}
          </div>
        </div>
        <button type="button" class="wb-dlg-close" id="ins-clear" title="${esc(L('返回概览', 'Back to overview'))}">×</button>
      </div>
      <div class="wb-ins-tabs">
        <button type="button" class="wb-ins-tab ${S.insTab === 'summary' ? 'on' : ''}" data-instab="summary">${L('摘要与字段', 'Summary')}</button>
        <button type="button" class="wb-ins-tab ${S.insTab === 'events' ? 'on' : ''}" data-instab="events">${L('关联事件', 'Events')}</button>
        <button type="button" class="wb-ins-tab ${S.insTab === 'content' ? 'on' : ''}" data-instab="content">${L('保存正文', 'Saved content')}</button>
      </div>
      <div class="wb-ins-body" id="ins-pane"></div>
    `;
    $('#ins-clear').onclick = () => { if (S.focus) return setLens(S.lens, S.detail); S.sel = null; syncURL(); renderGraph(); renderInspector(); };
    host.querySelectorAll('[data-instab]').forEach(b => { b.onclick = () => { S.insTab = b.dataset.instab; renderInspector(); }; });

    const pane = $('#ins-pane');
    if (S.insTab === 'summary') {
      const d = n.data || {};
      const dv = (S.graph?.edges || []).find(e => e.derived && (e.from === n.id || e.to === n.id));
      const digest = /^sha256:([a-f0-9]{64})$/i.exec(n.id)?.[1];
      const storePath = digest && String(d.path || '').replaceAll('\\', '/').endsWith('/objects/sha256/' + digest.slice(0, 2) + '/' + digest + '.json');
      const storedObject = !!digest && d.hash === n.id;
      const logicalPath = String(d.source_id || '').match(/^workspace_file\/(.+)$/)?.[1];
      const fields = { ...d };
      if (storePath) delete fields.path;
      const rows = (storedObject && (storePath || !d.path) && logicalPath ? `<dt>${L('文件路径', 'File path')}</dt><dd>${esc(logicalPath)}</dd>` : '') +
        Object.entries(fields).filter(([, v]) => v !== '' && v != null && v !== false).map(([k, v]) => {
        let out = v;
        if (k === 'payload') { try { out = JSON.stringify(JSON.parse(v), null, 2); } catch {} }
        else if (typeof v === 'object') out = JSON.stringify(v, null, 2);
        const label = storedObject && k === 'hash' ? L('证据对象 SHA-256', 'Evidence object SHA-256')
          : storedObject && k === 'size_bytes' ? L('证据对象字节数', 'Evidence object bytes') : tr(k);
        return `<dt>${esc(label)}</dt><dd>${esc(out)}</dd>`;
      }).join('');
      pane.innerHTML = `
        <div class="scope-pills">
          ${[['lineage', L('完整链路', 'Lineage')], ['upstream', L('上游', 'Upstream')], ['downstream', L('下游', 'Downstream')], ['children', L('子节点', 'Children')]].map(([m, lbl]) =>
            `<button type="button" class="${S.expandMode === m ? 'on' : ''}" data-exp="${m}">${lbl}</button>`
          ).join('')}
        </div>
        ${dv ? `<div class="story-card"><h3>${L('推断关联依据', 'Derived edge basis')}</h3><p>${esc(dv.rule)} · ${L('置信度', 'conf')} ${dv.confidence ?? '?'}</p><div style="font-family:var(--mono);font-size:11px;color:#1e40af">${esc((dv.evidence || []).join('\n'))}</div></div>` : ''}
        <dl class="kv"><dt>node_id</dt><dd>${esc(n.id)}</dd>${rows}</dl>
      `;
      pane.querySelectorAll('[data-exp]').forEach(b => { b.onclick = () => { S.expandMode = b.dataset.exp; renderGraph(); renderInspector(); }; });
    } else if (S.insTab === 'events') {
      pane.innerHTML = `<div class="empty">${L('正在加载关联事件…', 'Loading related events…')}</div>`;
      try {
        const p = new URLSearchParams({ run: S.run, limit: '30', offset: '0', lens: S.lens, focus: n.id });
        if (S.scope) { p.set('harness', S.scope.harness); p.set('session', S.scope.session_id); }
        if (Array.isArray(n.data?.evidence_refs) && n.data.evidence_refs.length) p.set('refs', n.data.evidence_refs.slice(0, 50).join(','));
        const res = await api('/api/events?' + p.toString());
        if (S.sel !== n.id || S.insTab !== 'events') return;
        const evs = res.events || [];
        pane.innerHTML = evs.length ? `<p class="wb-ins-sub" style="margin-bottom:10px">${L('共', 'Total')} ${res.total} ${L('条事件', 'events')}</p>` + evs.map(ev => {
          let pl = ev.payload || '';
          try { pl = JSON.stringify(JSON.parse(pl), null, 2); } catch {}
          return `<details class="cmp-row"><summary><span style="font-weight:600;font-size:12px">${esc(tr(ev.event_type))}</span><span class="pill-tag">${esc(fmtTime(ev.created_at).slice(11))}</span></summary><div style="padding:8px 12px;border-top:1px solid var(--line)"><pre class="code-box">${esc(pl)}</pre></div></details>`;
        }).join('') : `<div class="empty">${L('此节点无直接关联的原始事件。', 'No direct raw events for this node.')}</div>`;
      } catch (err) { pane.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
    } else {
      pane.innerHTML = `<div class="empty">${L('正在读取保存正文…', 'Loading saved content…')}</div>`;
      try {
        const targetNode = S.insContentNode || n.id;
        const art = await api('/api/artifact?' + new URLSearchParams({ run: S.run, node: targetNode, mode: S.insContentMode, view_lang: LANG, offset: '0', limit: '65536' }));
        if (S.sel !== n.id || S.insTab !== 'content') return;
        const versions = art.versions || [];
        const versionSel = versions.length ? `
          <select id="ins-ver-sel" style="padding:3px 7px;border:1px solid var(--line-strong);border-radius:6px;font-size:11.5px;max-width:170px">
            <option value="${esc(n.id)}" ${targetNode === n.id ? 'selected' : ''}>${L('当前对象', 'Current')}</option>
            ${versions.map(v => `<option value="${esc(v.ref)}" ${targetNode === v.ref ? 'selected' : ''}>${L('版本', 'Ver')} · ${esc(v.ref.slice(7, 19))}</option>`).join('')}
          </select>
        ` : '';
        if (!art.content && art.kind !== 'text' && art.kind !== 'diff') {
          pane.innerHTML = `<div class="empty">${esc(tr(art.reason || L('此节点未保存文件正文。', 'No saved body for this node.')))}</div>`;
          return;
        }
        let body = art.content || '';
        const isDiff = art.kind === 'diff';
        if (!isDiff) { try { const j = JSON.parse(body); if (j && typeof j === 'object') body = JSON.stringify(j, null, 2); } catch {} }
        pane.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:6px;flex-wrap:wrap">
            <div class="wb-seg">
              <button type="button" class="${S.insContentMode === 'body' ? 'on' : ''}" data-cmode="body">${L('正文', 'Body')}</button>
              <button type="button" class="${S.insContentMode === 'raw' ? 'on' : ''}" data-cmode="raw">${L('原始对象', 'Raw')}</button>
            </div>
            ${versionSel}
            <button type="button" class="wb-btn sm" id="ins-expand-body" style="margin-left:auto">${L('全屏', 'Expand')}</button>
          </div>
          <div class="wb-ins-sub" style="font-family:var(--mono);margin-bottom:8px">${esc((art.sha256 || '').slice(0, 18))}… · ${art.total_bytes ?? body.length} B${art.redacted ? ' · ' + L('已脱敏', 'Redacted') : ''}</div>
          ${renderDiffOrCode(body, isDiff)}
        `;
        pane.querySelectorAll('[data-cmode]').forEach(b => { b.onclick = () => { S.insContentMode = b.dataset.cmode; renderInspector(); }; });
        $('#ins-ver-sel')?.addEventListener('change', e => { S.insContentNode = e.target.value; renderInspector(); });
        $('#ins-expand-body').onclick = () => openInfoModal(nodeLabel(n), renderDiffOrCode(body, isDiff, '72vh'));
      } catch (err) { pane.innerHTML = `<div class="empty">${esc(err.message)}</div>`; }
    }
  }

  function renderOverviewInspector(host) {
    const story = STORY_BRIEFS[S.run];
    const sigGroups = groupRiskSignals(S.overview?.signals?.signals);
    const sigTotal = sigGroups.reduce((n, g) => n + g.count, 0);
    const totalEvents = S.runs.find(r => r.run === S.run)?.events ?? S.timeline.total;
    const cap = S.contextOverview?.runtime_coverage?.capture;
    const capLabel = captureStatusLabel(cap?.status);
    const compSum = S.compliance?.summary;

    host.innerHTML = `
      <div class="wb-ins-head">
        <div>
          <h2>${esc(runTitle(S.run))}</h2>
          <div class="wb-ins-sub" style="font-family:var(--mono)">${esc(S.run)}</div>
        </div>
      </div>
      <div class="wb-ins-body">
        ${story ? `
          <div class="story-card">
            <h3>${esc(story.title)}</h3>
            <p>${esc(story.body)}</p>
            <div class="story-actions">${story.actions.map((a, i) => `<button type="button" class="story-btn" data-sact="${i}">${esc(a.label)}</button>`).join('')}</div>
          </div>
        ` : `<p class="wb-ins-sub" style="margin:0 0 14px">${L('点击左侧图谱中的任意节点，即可在此直接查看因果链路、关联事件与保存正文。', 'Click any node in the graph to inspect its lineage, related events and saved content right here.')}</p>`}

        <div class="ins-sec">
          <div class="ins-sec-title"><span>${L('关键指标', 'Key metrics')}</span></div>
          <div class="kpi-grid">
            <button type="button" class="kpi" data-jump-mode="timeline"><div class="k">${L('原始事件', 'Events')}</div><div class="v">${totalEvents}</div></button>
            <button type="button" class="kpi" data-jump-mode="risk"><div class="k">${L('风险线索', 'Risk groups')}</div><div class="v ${sigGroups.length ? 'risk' : ''}">${sigGroups.length}${sigTotal > sigGroups.length ? ` <small style="font-size:11px;font-weight:500;color:var(--muted)">(${sigTotal})</small>` : ''}</div></button>
            <button type="button" class="kpi" data-jump-mode="compliance"><div class="k">${L('合规评估', 'Compliance')}</div><div class="v" style="font-size:12.5px;font-family:var(--sans)">${compSum ? `${compSum.detected || 0} ${L('仅检测', 'detected')} / ${compSum.total || 0}` : '—'}</div></button>
            <button type="button" class="kpi" data-jump-mode="session"><div class="k">${L('运行时采集', 'Runtime capture')}</div><div class="v" style="font-size:12.5px;font-family:var(--sans)">${esc(capLabel)}</div></button>
          </div>
        </div>

        <div class="ins-sec">
          <div class="ins-sec-title"><span>${L('风险线索', 'Risk signals')}</span><span>${sigGroups.length ? `${sigGroups.length} ${L('类', 'groups')} · ${sigTotal} ${L('条', 'signals')}` : '0'}</span></div>
          ${sigGroups.length ? sigGroups.slice(0, 8).map((g, i) => `
            <button type="button" class="sig-item" data-sig-idx="${i}">
              <span class="sev ${esc((g.severity || 'low').toLowerCase())}">${esc(tr(g.severity || 'risk'))}</span>
              <div style="min-width:0;flex:1">
                <div style="font-weight:650;font-size:12.5px">${esc(formatSignalTitle(g.title))}</div>
                <div class="wb-ins-sub">${esc(tr(g.type || ''))} · ${g.count} ${L('条事件', 'events')}${g.sample ? ` · ${esc(g.sample)}` : ''}</div>
              </div>
            </button>
          `).join('') : `<div class="wb-ins-sub">${L('本次执行未记录高风险信号。', 'No risk signals recorded in this run.')}</div>`}
        </div>
      </div>
    `;

    if (story) host.querySelectorAll('[data-sact]').forEach(b => { b.onclick = () => story.actions[+b.dataset.sact].fn(); });
    host.querySelectorAll('[data-jump-mode]').forEach(b => { b.onclick = () => setMode(b.dataset.jumpMode); });
    host.querySelectorAll('[data-sig-idx]').forEach(b => {
      b.onclick = () => {
        const g = sigGroups[+b.dataset.sigIdx];
        const focus = g.focus || (g.refs?.[0]) || '';
        if (focus) setLens('security', 'summary', focus); else setMode('risk');
      };
    });
  }

  // --- First-Class Workspace View ---
  function rejection(v) { return v?.ok === false || v?.error ? String(v.error?.code || 'rejected') : ''; }
  function rejectLabel(code) {
    return ({ conflict: L('版本冲突', 'Revision conflict'), unsafe_path: L('路径越界', 'Path outside workspace'), rejected: L('原因未记录', 'Reason not recorded') })[code] || code;
  }
  function selectWorkspaceBy(kind) {
    const idx = S.wsItems.findIndex(w => rejection(w.parsed) === kind);
    if (idx >= 0) S.wsSelected = idx;
    renderWorkspaceView();
  }
  function renderWorkspaceView() {
    const list = $('#ws-list'), detail = $('#ws-detail');
    const counts = new Map();
    for (const { parsed } of S.wsItems) {
      const code = rejection(parsed);
      if (code) counts.set(code, (counts.get(code) || 0) + 1);
    }
    const rejected = [...counts.values()].reduce((a,b) => a+b, 0);
    const pill = $('#ws-conflict-pill'), reasons = $('#ws-reasons');
    pill.hidden = reasons.hidden = !rejected;
    pill.className = 'pill-tag risk';
    pill.textContent = rejected + ' ' + L('次拒绝', 'rejected');
    reasons.textContent = [...counts].map(([code, count]) => rejectLabel(code) + ' ' + count).join('  ·  ');
    if (!S.wsItems.length) {
      list.innerHTML = `<div class="empty">${L('当前执行没有受控工作区记录。', 'No controlled workspace results in this run.')}</div>`;
      detail.innerHTML = ''; return;
    }
    list.innerHTML = S.wsItems.map((item, i) => {
      const v = item.parsed, err = v?.ok === false || v?.error;
      const rc = v?.view?.last_receipt;
      const own = rc && rc.ref === v?.operation_ref && rc.tool_call_id === item.entry.tool_call_id;
      const path = own ? (rc.path || rc.changes?.[0]?.path || '') : '';
      const rev = own && rc.input_revision != null && rc.output_revision != null ? `rev ${rc.input_revision}→${rc.output_revision}` : (v?.view?.binding?.revision != null ? `rev ${v.view.binding.revision}` : '');
      return `
        <button type="button" class="wb-row-btn ${err ? 'conflict' : ''} ${i === S.wsSelected ? 'on' : ''}" data-ws-idx="${i}">
          <div class="wb-row-top">
            <span class="wb-row-title">${esc(item.entry.tool_name)}</span>
            ${err ? `<span class="pill-tag risk">⚠ ${esc(v?.error?.code || 'rejected')}</span>` : (rev ? `<span class="pill-tag ${own ? 'ok' : ''}">${esc(rev)}</span>` : '')}
          </div>
          <div class="wb-row-sub">${esc(path || (err ? v?.error?.message : item.entry.tool_call_id))} · ${esc(fmtTime(item.entry.recorded_at).slice(11))}</div>
        </button>
      `;
    }).join('');
    list.querySelectorAll('[data-ws-idx]').forEach(b => { b.onclick = () => { S.wsSelected = +b.dataset.wsIdx; renderWorkspaceView(); }; });

    const cur = S.wsItems[S.wsSelected] || S.wsItems[0];
    const v = cur.parsed, b = v?.view?.binding, rc = v?.view?.last_receipt;
    const own = rc && rc.ref === v?.operation_ref && rc.tool_call_id === cur.entry.tool_call_id;
    const err = v?.ok === false || v?.error;
    const changes = own && Array.isArray(rc.changes) ? rc.changes : [];
    const verText = x => x ? [(x.Hash || x.hash || '').slice(0, 12), x.SizeBytes ?? x.size_bytes].filter(y => y !== undefined).join(' · ') : '—';

    detail.innerHTML = `
      <div class="wb-detail-card">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
          <h3 style="margin:0;font-family:var(--mono)">${esc(cur.entry.tool_name)}</h3>
          ${err ? `<span class="pill-tag risk">${L('操作被拒绝', 'Operation rejected')}</span>` : v?.ok === true ? `<span class="pill-tag ok">${L('已记录回执', 'Recorded')}</span>` : `<span class="pill-tag">${L('结果未知', 'Outcome unknown')}</span>`}
          <span class="wb-ins-sub" style="margin-left:auto;font-family:var(--mono)">${esc(cur.entry.tool_call_id)}</span>
        </div>
        ${err ? `
          <div class="wb-alert">
            <h4>${esc(rejectLabel(rejection(v)))}</h4>
            <dl class="kv">
              <dt>${L('错误码', 'Error code')}</dt><dd>${esc(v?.error?.code || 'rejected')}</dd>
              <dt>${L('原因说明', 'Message')}</dt><dd>${esc(v?.error?.message || '')}</dd>
              <dt>${L('建议下一步', 'Next action')}</dt><dd>${esc(v?.error?.next_action || '')}</dd>
            </dl>
          </div>
        ` : ''}
        ${b ? `
          <dl class="kv" style="margin-bottom:14px">
            <dt>${L('工作区', 'Workspace')}</dt><dd>${esc(b.workspace_id)}</dd>
            <dt>${L('目标环境', 'Target')}</dt><dd>${esc(b.target?.instance_id || '')} (${esc(shortID(b.target?.generation))})</dd>
            <dt>${L('当前版本', 'Revision')}</dt><dd>${esc(b.revision)}</dd>
            ${own ? `<dt>${L('路径 / 结果', 'Path / outcome')}</dt><dd>${esc(rc.path || '—')} · ${esc(rc.outcome || '')}</dd><dt>${L('版本变迁', 'Rev transition')}</dt><dd>${esc(rc.input_revision)} → ${esc(rc.output_revision)}</dd>` : ''}
          </dl>
        ` : ''}
        ${changes.length ? `
          <h3>${L('文件变更明细', 'File changes')}</h3>
          <div class="wb-table-scroll" role="region" tabindex="0" aria-label="${esc(L('文件变更明细', 'File changes'))}"><table class="wb-table">
            <thead><tr><th>${L('路径', 'Path')}</th><th>${L('类型', 'Kind')}</th><th>${L('变更前', 'Before')}</th><th>${L('变更后', 'After')}</th></tr></thead>
            <tbody>${changes.map(c => `<tr><td class="mono">${esc(c.path)}</td><td><span class="pill-tag">${esc(c.kind)}</span></td><td class="mono">${esc(verText(c.before))}</td><td class="mono">${esc(verText(c.after))}</td></tr>`).join('')}</tbody>
          </table></div>
        ` : ''}
        <h3>${L('保存的原始结果（格式化 JSON）', 'Saved result (formatted JSON)')}</h3>
        <pre class="code-box">${esc(cur.pretty || cur.raw || L('正文未留存', 'Body not retained'))}</pre>
      </div>
    `;
  }

  // --- First-Class Browser / Notebook View ---
  async function loadAttachmentBytes(att, run) {
    const chunks = []; let offset = 0;
    while (offset < att.bytes) {
      const page = await api('/api/context/attachment?' + new URLSearchParams({ run, ref: att.ref, offset: String(offset), limit: '262144' }));
      const bytes = Uint8Array.from(atob(page.data), c => c.charCodeAt(0));
      if (!bytes.length || page.next_offset !== offset + bytes.length || page.next_offset > att.bytes) throw new Error(L('附件分页不完整', 'Incomplete attachment page'));
      chunks.push(bytes); offset = page.next_offset;
    }
    const all = new Uint8Array(att.bytes); let at = 0;
    for (const c of chunks) { all.set(c, at); at += c.length; }
    const digest = await window.agentProvSHA256(all);
    if (digest !== att.sha256) throw new Error(L('附件 SHA-256 校验失败', 'Attachment SHA-256 mismatch'));
    return all;
  }

  async function renderNativeView() {
    const list = $('#nat-list'), detail = $('#nat-detail');
    const run = S.run;
    const attCount = new Set(S.nativeItems.flatMap(x => (x.attachments || []).filter(a => a.state === 'stored' && a.ref).map(a => a.ref))).size;
    const pill = $('#nat-att-pill');
    pill.hidden = !attCount;
    pill.textContent = L('已保存 ' + attCount + ' 份附件', 'Saved attachments: ' + attCount);
    if (!S.nativeItems.length) {
      list.innerHTML = `<div class="empty">${L('当前执行没有 Browser / Notebook 原生记录。', 'No Browser or Notebook records in this run.')}</div>`;
      detail.innerHTML = ''; return;
    }

    list.innerHTML = S.nativeItems.map((x, i) => {
      const title = x.browser?.operation || x.browser?.kind || x.notebook?.message_type || x.tool_name || x.kind;
      const atts = (x.attachments || []).filter(a => a.state === 'stored');
      return `
        <button type="button" class="wb-row-btn ${i === S.nativeSelected ? 'on' : ''}" data-nat-idx="${i}">
          <div class="wb-row-top">
            <span class="wb-row-title">${esc(title)}</span>
            ${atts.map(a => `<span class="pill-tag acc">${a.media_type === 'image/png' ? '🖼 PNG' : '🌐 HAR'}</span>`).join('')}
          </div>
          <div class="wb-row-sub">${esc(x.source?.harness || '')} · ${esc(fmtTime(x.recorded_at).slice(11))}${x.browser?.target_id ? ' · ' + esc(shortID(x.browser.target_id)) : ''}</div>
        </button>
      `;
    }).join('');
    list.querySelectorAll('[data-nat-idx]').forEach(b => { b.onclick = () => { S.nativeSelected = +b.dataset.natIdx; renderNativeView(); }; });

    const cur = S.nativeItems[S.nativeSelected] || S.nativeItems[0];
    const b = cur.browser, nb = cur.notebook;
    const title = b?.operation || b?.kind || nb?.message_type || cur.tool_name || cur.kind;
    detail.innerHTML = `
      <div class="wb-detail-card">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
          <h3 style="margin:0;font-family:var(--mono)">${esc(title)}</h3>
          <span class="pill-tag">${esc(cur.source?.harness || '')}</span>
          <span class="wb-ins-sub" style="margin-left:auto">${esc(fmtTime(cur.recorded_at))}</span>
        </div>
        <div id="nat-inline-att"></div>
        <dl class="kv" style="margin-bottom:14px">
          ${b ? [
            [L('页面 / 目标', 'Target'), b.target_id], [L('目标类型', 'Type'), b.target_type],
            [L('操作 ID', 'Operation'), b.operation_id], [L('请求键', 'Request'), b.request_key],
            [L('页面框架', 'Frame'), b.frame_id], [L('关联依据', 'Association'), b.association]
          ].filter(([, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('') : ''}
          ${nb ? [
            [L('消息 ID', 'Message'), nb.message_id], [L('父消息', 'Parent msg'), nb.parent_message_id],
            [L('关联状态', 'Association'), nb.association]
          ].filter(([, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('') : ''}
        </dl>
        <h3>${L('保存的正文内容', 'Saved body')}</h3>
        <pre class="code-box" id="nat-body-pre">${L('正在读取…', 'Loading…')}</pre>
      </div>
    `;

    const bodyEl = $('#nat-body-pre');
    if (cur.content?.state === 'stored') {
      api('/api/context/content?' + new URLSearchParams({ run: S.run, ref: cur.content.ref, offset: '0', limit: '65536' }))
        .then(p => {
          let txt = p.content || '';
          try { const j = JSON.parse(txt); if (j && typeof j === 'object') txt = JSON.stringify(j, null, 2); } catch {}
          if (bodyEl.isConnected) bodyEl.textContent = txt;
        }).catch(err => { if (bodyEl.isConnected) bodyEl.textContent = err.message; });
    } else {
      bodyEl.textContent = L('此条目正文未留存。', 'Body not retained.');
    }

    const attHost = $('#nat-inline-att');
    for (const att of (cur.attachments || []).filter(a => a.state === 'stored')) {
      const box = document.createElement('div');
      box.innerHTML = `<div class="wb-ins-sub" style="margin-bottom:6px">${L('正在 SHA-256 校验并加载附件…', 'Verifying SHA-256 attachment…')}</div>`;
      attHost.append(box);
      try {
        if (!att.sha256) {
          box.textContent = L('附件未校验：未记录 SHA-256。', 'Attachment not verified: no SHA-256 was recorded.');
          continue;
        }
        const bytes = await loadAttachmentBytes(att, run);
        if (!box.isConnected || S.run !== run) return;
        if (att.media_type === 'image/png') {
          const url = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(new Blob([bytes], { type: 'image/png' })); });
          box.innerHTML = `
            <div class="wb-shot-frame">
              <div style="display:flex;justify-content:space-between;padding:6px 10px;background:var(--subtle);border-bottom:1px solid var(--line);font-size:11px;color:var(--muted)">
                <span>🖼 ${L('已校验页面截图 (SHA-256 通过)', 'Verified PNG screenshot (SHA-256 ok)')}</span>
                <span style="font-family:var(--mono)">${att.bytes} B</span>
              </div>
              <img src="${url}" alt="${esc(L('保存的截图', 'Saved screenshot'))}">
            </div>
          `;
          box.querySelector('img').onclick = () => openInfoModal(L('页面截图原图', 'Full screenshot'), `<img src="${url}" style="max-width:100%;border-radius:8px">`);
        } else {
          const har = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          const entries = har?.log?.entries || [];
          const fmtSize = sz => (typeof sz === 'number' && sz >= 0 ? `${sz} B` : '—');
          box.innerHTML = `
            <div class="wb-card" style="margin-bottom:14px">
              <div class="wb-card-h"><span>🌐 HAR ${L('网络档案（SHA-256 已校验）', 'archive (SHA-256 verified)')}</span><span class="pill-tag">${entries.length} ${L('个请求', 'requests')} · ${att.bytes} B</span></div>
              ${entries.length ? `<table class="wb-table"><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>${entries.slice(0, 30).map(e => `<tr><td class="mono">${esc(e.request?.method)}</td><td class="mono">${esc(e.request?.url)}</td><td><span class="pill-tag ok">${esc(e.response?.status)}</span></td><td class="mono">${esc(fmtSize(e.response?.bodySize))}</td></tr>`).join('')}</tbody></table>` : ''}
              <details style="padding:10px 12px"><summary style="cursor:pointer;font-size:12px;color:var(--acc)">${L('查看完整 HAR JSON', 'Inspect full HAR JSON')}</summary><pre class="code-box" style="margin-top:8px">${esc(JSON.stringify(har, null, 2))}</pre></details>
            </div>
          `;
        }
      } catch (err) { box.innerHTML = `<div class="wb-alert">${esc(err.message)}</div>`; }
    }
  }

  // --- Handoffs View (Full parity: capture details, source call, target run, guidance) ---
  function renderHandoffsView() {
    const host = $('#handoff-body');
    if (!S.handoffs.length) { host.innerHTML = `<div class="empty">${L('当前执行无跨环境交接记录。', 'No cross-environment handoffs.')}</div>`; return; }
    const lbl = s => tr({ succeeded: 'Succeeded', failed: 'Failed', running: 'Running', incomplete: 'Incomplete', complete: 'Complete', pending: 'Pending', draining: 'Draining', persisted: 'Receipt saved' }[s] || s || 'Not recorded');
    host.innerHTML = S.handoffs.map((h, i) => {
      const id = h.identity || {}, st = h.manifest?.state || h.checkpoint?.state || {};
      const receipt = h.receipt?.status === 'persisted';
      const issues = h.checkpoint?.capture_report?.issues || [];
      const stateGapOnly = issues.length === 1 && issues[0] === 'scope_state_sampling_gap';
      const capLabel = st.capture === 'incomplete' && stateGapOnly ? tr('Security state snapshots incomplete') : lbl(st.capture);
      const hints = [];
      if (st.execution === 'failed') hints.push(tr('The command failed. Read the saved output before deciding whether to create a new attempt.'));
      if (st.capture === 'incomplete') hints.push(tr('The saved package has capture gaps. Review the capture observations and use the retained evidence.'));
      hints.push(receipt ? tr('A receipt is saved. If the sender did not receive its ACK, resend the same receipt; keep the original attempt.') : tr('Collect the existing attempt again to retry delivery. An explicit reexecution creates a separate attempt.'));
      return `
        <div class="wb-card">
          <div class="wb-card-h">
            <span>${esc(id.source?.harness || '?')} → ${esc(id.target?.instance_id || '?')}</span>
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <span class="pill-tag ${st.execution === 'succeeded' ? 'ok' : st.execution === 'failed' ? 'risk' : ''}">${L('执行', 'Exec')}: ${esc(lbl(st.execution))}</span>
              <span class="pill-tag ${st.capture === 'complete' ? 'ok' : 'warn'}">${L('采集', 'Capture')}: ${esc(capLabel)}</span>
              <span class="pill-tag">${L('交付', 'Delivery')}: ${esc(lbl(st.delivery))}</span>
              ${receipt ? `<span class="pill-tag ok">${L('回执已保存', 'Receipt saved')}</span>` : ''}
            </div>
          </div>
          <div style="padding:14px 16px">
            <dl class="kv" style="margin-bottom:12px">
              <dt>${L('来源调用', 'Source call')}</dt><dd>${esc(id.source?.tool_call_id)}</dd>
              <dt>${L('执行尝试', 'Attempt')}</dt><dd>${esc(id.attempt_id)}</dd>
              <dt>${L('目标代次', 'Generation')}</dt><dd>${esc(id.target?.generation)}</dd>
              <dt>${L('目标 Run', 'Target Run')}</dt><dd>${esc(id.local_run_id)}</dd>
            </dl>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
              ${id.local_run_id && S.runs.some(r => r.run === id.local_run_id) ? `<button type="button" class="wb-btn primary" data-go-run="${esc(id.local_run_id)}">${L('切换到目标 Run', 'Open target Run')}</button>` : ''}
              ${id.source?.run_id && id.source?.tool_call_id ? `<button type="button" class="wb-btn" data-handoff-src="${i}">${L('查看来源调用', 'Open source call')}</button>` : ''}
              ${h.checkpoint?.capture_report ? `<button type="button" class="wb-btn" data-handoff-cap="${i}">${L('查看采集详情', 'Capture details')}</button>` : ''}
              <button type="button" class="wb-btn" data-handoff-raw="${i}">${L('查看原始 JSON', 'Raw JSON')}</button>
            </div>
            <details style="font-size:12px;color:var(--muted)"><summary style="cursor:pointer;font-weight:600">${L('接下来怎么处理', 'Next steps')}</summary>${hints.map(x => `<p style="margin:6px 0 0">${esc(x)}</p>`).join('')}</details>
          </div>
        </div>
      `;
    }).join('');
    host.querySelectorAll('[data-go-run]').forEach(b => { b.onclick = () => { setMode('graph'); loadRun(b.dataset.goRun); }; });
    host.querySelectorAll('[data-handoff-raw]').forEach(b => { b.onclick = () => openInfoModal(L('交接记录原始字段', 'Handoff record'), `<pre class="code-box" style="max-height:72vh">${esc(JSON.stringify(S.handoffs[+b.dataset.handoffRaw], null, 2))}</pre>`); });
    host.querySelectorAll('[data-handoff-cap]').forEach(b => {
      b.onclick = () => {
        const h = S.handoffs[+b.dataset.handoffCap];
        const rep = h.checkpoint.capture_report, p = rep.scope_progress || {};
        openInfoModal(L('采集详情', 'Capture details'), `
          <p class="wb-ins-sub" style="margin-bottom:12px">${esc(tr('These counts describe the sealed execution interval, not the entire node.'))}</p>
          <dl class="kv" style="margin-bottom:14px">
            <dt>${L('作用域事件', 'Scope events')}</dt><dd>${esc(p.events ?? 0)}</dd>
            <dt>${L('已入库', 'Ingested')}</dt><dd>${esc(p.ingested ?? 0)}</dd>
            <dt>${L('已报告丢失', 'Dropped')}</dt><dd>${esc(p.dropped ?? 0)}</dd>
            <dt>${L('失败', 'Failed')}</dt><dd>${esc(p.failed ?? 0)}</dd>
            <dt>${L('待处理事件', 'Pending')}</dt><dd>${esc(p.pending ?? 0)}</dd>
            <dt>${L('状态补采缺失', 'Sampling gaps')}</dt><dd>${esc(p.sampling_gaps ?? 0)}</dd>
          </dl>
          ${(rep.issues || []).length ? `<h4 style="margin:0 0 8px">${L('采集问题', 'Capture issues')}</h4>${rep.issues.map(iss => `<p style="margin:4px 0;font-size:12.5px">${esc(tr(iss))} <code style="font-family:var(--mono);font-size:11px;color:var(--muted)">${esc(iss)}</code></p>`).join('')}` : ''}
        `);
      };
    });
    host.querySelectorAll('[data-handoff-src]').forEach(b => {
      b.onclick = async () => {
        const src = S.handoffs[+b.dataset.handoffSrc]?.identity?.source;
        if (!src) return;
        openInfoModal(`${L('来源调用', 'Source call')} · ${src.tool_call_id}`, `<div class="empty">${L('正在读取…', 'Loading…')}</div>`);
        try {
          const page = await api('/api/context/entries?' + new URLSearchParams({ run: src.run_id, harness: src.harness || '', session: src.session_id || '', tool_call: src.tool_call_id, limit: '20' }));
          const ents = page.entries || [];
          if (!ents.length) { $('#wb-info-body').innerHTML = `<div class="empty">${L('来源调用未包含在当前副本中。', 'Source call not included in this copy.')}</div>`; return; }
          const blocks = await Promise.all(ents.map(async e => {
            let txt = L('正文未留存', 'Body not retained');
            if (e.content?.state === 'stored') {
              const c = await api('/api/context/content?' + new URLSearchParams({ run: src.run_id, ref: e.content.ref, offset: '0', limit: '65536' }));
              txt = c.content || '';
              try { const j = JSON.parse(txt); if (j && typeof j === 'object') txt = JSON.stringify(j, null, 2); } catch {}
            }
            return `<div class="wb-card"><div class="wb-card-h"><span>${esc(tr(e.kind))} · ${esc(e.tool_name || e.id)}</span><span class="wb-ins-sub">${esc(fmtTime(e.recorded_at))}</span></div><pre class="code-box" style="border:0;border-radius:0;max-height:300px">${esc(txt)}</pre></div>`;
          }));
          $('#wb-info-body').innerHTML = blocks.join('');
        } catch (err) { $('#wb-info-body').innerHTML = `<div class="wb-alert">${esc(err.message)}</div>`; }
      };
    });
  }

  function openSessionRelations(sessions) {
    const run = S.run;
    openInfoModal(tr('Related sessions'), `<label>${L('来源会话', 'Source session')}
      <select data-related-from>${sessions.map((s,i) => `<option value="${i}">${esc(s.harness)} · ${esc(s.session_id)}</option>`).join('')}</select></label>
      <div data-related-list aria-live="polite"></div>`);
    const select = $('#wb-info-body [data-related-from]'), list = $('#wb-info-body [data-related-list]');
    select.selectedIndex = Math.max(0, sessions.findIndex(s => S.sessionSourceFilter === s.harness+'|'+s.session_id));
    const kindNames = {same_session:'Same native session in another run', parent:'Recorded parent / child',
      delegation:'Recorded delegation', fork:'Recorded fork', message_request:'Message requested'};
    function endpoint(ref) {
      const label = esc(ref.harness)+' · '+esc(ref.session_id);
      const ids = [...new Set([ref.run_id, ...(ref.run_ids || [])].filter(Boolean))];
      return label + ids.map(id => {
        if (!ref.available || !S.runs.some(r => r.run === id)) return ' · '+esc(id);
        const dest = new URL(location.href);
        dest.search = new URLSearchParams({lang:LANG,run:id,harness:ref.harness,session:ref.session_id,view:'graph',live:'0'});
        return ` · <a href="${esc(dest.href)}">${esc(id)}</a>`;
      }).join('');
    }
    let epoch = 0;
    async function load(cursor = '') {
      const generation = ++epoch, group = sessions[select.selectedIndex];
      if (!cursor) list.replaceChildren();
      const status = document.createElement('p');
      status.textContent = L('正在读取关联…', 'Loading relationships…'); list.append(status);
      try {
        const q = new URLSearchParams({run,harness:group.harness,session:group.session_id,limit:'50'});
        if (cursor) q.set('cursor',cursor);
        const page = await api('/api/context/session-relations?'+q);
        if (!list.isConnected || generation !== epoch) return;
        for (const r of page.relations || []) {
          const item = document.createElement('article'); item.className = 'ac-card';
          item.innerHTML = `<strong>${esc(tr(kindNames[r.kind] || r.kind))}</strong><p>${endpoint(r.from)} ${r.kind === 'same_session' ? '↔' : '→'} ${endpoint(r.to)}</p>
            <details><summary>${tr('Source and evidence')}</summary><pre class="code-box">${esc(JSON.stringify({evidence:r.evidence,issues:r.issues},null,2))}</pre></details>`;
          list.insertBefore(item, status);
        }
        status.textContent = page.limited ? tr('Relationship discovery is limited; additional sources or records may exist.') :
          list.querySelector('article') ? '' : tr('No explicit session relationships found in saved records');
        if (page.has_more && page.next_cursor) {
          const more = document.createElement('button'); more.type='button'; more.className='wb-btn sm';
          more.textContent=tr('Load more'); more.onclick=()=>{more.remove();load(page.next_cursor);}; list.append(more);
        }
      } catch (err) { if (generation === epoch) status.textContent = tr('Session relationships unavailable')+' '+err.message; }
    }
    select.onchange = () => load(); load();
  }

  // --- Session, Tools, Config & Capture Manifest View ---
  function renderSessionView() {
    const host = $('#session-body');
    const directory = window.AgentDisplayHelpers.sessionDirectory(S.contextOverview);
    const known = directory.sessions.map(s => ({harness:s.harness, session_id:s.id}));
    for (const e of S.entries) {
      const s = e.source;
      if (s?.session_id && s.harness && !['launch','unknown'].includes(s.harness) &&
          !['runtime_correlation','discovery','processing'].includes(s.channel)) known.push(s);
    }
    const sources = [...new Map(known.map(s => [JSON.stringify([s.harness,s.session_id]),s])).values()];

    const filtered = S.entries.filter(e => {
      if (S.sessionSourceFilter && `${e.source?.harness}|${e.source?.session_id}` !== S.sessionSourceFilter) return false;
      if (S.sessionTab === 'configuration') return ['configuration', 'approval'].includes(e.kind);
      return ['message', 'tool_call', 'tool_result', 'task', 'session'].includes(e.kind);
    });

    host.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
        <div class="wb-seg">
          <button type="button" class="${S.sessionTab === 'conversation' ? 'on' : ''}" data-stab="conversation">${L('对话与工具', 'Conversation & tools')}</button>
          <button type="button" class="${S.sessionTab === 'configuration' ? 'on' : ''}" data-stab="configuration">${L('权限与配置', 'Permissions & config')}</button>
          <button type="button" class="${S.sessionTab === 'coverage' ? 'on' : ''}" data-stab="coverage">${L('采集覆盖与清单', 'Collection & manifest')} ${S.captureManifest.length ? `(${S.captureManifest.length})` : ''}</button>
        </div>
        ${sources.length > 1 && S.sessionTab !== 'coverage' ? `
          <select id="sess-src-sel" style="padding:4px 9px;border:1px solid var(--line-strong);border-radius:7px;font-size:12px;background:var(--surface)">
            <option value="">${L('全部会话来源', 'All sessions')} (${sources.length})</option>
            ${sources.map(s => `<option value="${esc(s.harness + '|' + s.session_id)}" ${S.sessionSourceFilter === s.harness + '|' + s.session_id ? 'selected' : ''}>${esc(s.harness)} · ${esc(shortID(s.session_id))}</option>`).join('')}
          </select>
        ` : ''}
        ${sources.length ? `<button class="wb-btn sm" type="button" id="wb-related">${tr('Related sessions')}</button>` : ''}
        <span class="wb-ins-sub">${L('已加载', 'Loaded')} ${S.entries.length} ${L('条记录', 'entries')}${S.entriesCursor ? ' · ' + L('还有更多', 'more available') : ''}</span>
      </div>
      <div id="session-list"></div>
    `;
    host.querySelectorAll('[data-stab]').forEach(b => { b.onclick = () => { S.sessionTab = b.dataset.stab; renderSessionView(); }; });
    $('#sess-src-sel')?.addEventListener('change', e => { S.sessionSourceFilter = e.target.value; renderSessionView(); });

    $('#wb-related')?.addEventListener('click', () => openSessionRelations(sources));
    const list = $('#session-list');
    const helpers = window.AgentDisplayHelpers;
    if (S.sessionTab === 'coverage') {
      const cov = S.contextOverview?.coverage || [];
      const cap = S.contextOverview?.runtime_coverage?.capture;
      const pol = S.contextOverview?.capture_policy;
      const sections = helpers?.coverageSections?.(S.contextOverview);
      const runtime = sections?.runtime;
      const retention = helpers?.retentionPresentation?.(pol);
      const retentionSummary = retention
        ? [tr(retention.label), ...retention.settings.filter(s => s.override || s.enabled === false).map(s => `${tr(s.label)}: ${tr(s.enabled === true ? 'Retained' : s.enabled === false ? 'Not retained' : 'Not recorded')}${s.override ? ' (' + tr('Override') + ')' : ''}`)].join(' · ')
        : (pol ? JSON.stringify(pol) : '');
      const statusText = runtime ? tr(runtime.label) : captureStatusLabel(cap?.status);
      const statusTone = runtime ? (runtime.state === 'ok' ? 'ok' : runtime.state === 'failed' ? 'bad' : 'warn') : (cap?.status === 'ok' ? 'ok' : 'warn');
      list.innerHTML = `
        <div class="wb-card">
          <div class="wb-card-h"><span>${L('运行时采集与留存策略', 'Runtime capture & retention policy')}</span><span class="pill-tag ${statusTone}">${esc(statusText)}</span></div>
          <div style="padding:12px 16px">
            <dl class="kv">
              <dt>${L('采集状态', 'Status')}</dt><dd>${esc(statusText)}${runtime?.message ? ` — ${esc(tr(runtime.message))}` : ''}</dd>
              ${cap?.started_at ? `<dt>${L('采集区间', 'Interval')}</dt><dd>${esc(fmtTime(cap.started_at))} → ${esc(fmtTime(cap.ended_at))}</dd>` : ''}
              ${retentionSummary ? `<dt>${L('留存档位', 'Retention')}</dt><dd>${esc(retentionSummary)}</dd>` : ''}
              ${(cap?.issues || []).length ? `<dt>${L('采集提示', 'Issues')}</dt><dd>${esc(cap.issues.join(' · '))}</dd>` : ''}
              ${(sections?.nativeLimits || []).length ? `<dt>${L('观测边界', 'Observation limits')}</dt><dd>${esc(sections.nativeLimits.map(l => `${l.mechanism}: ${l.detail}`).join(' · '))}</dd>` : ''}
            </dl>
          </div>
        </div>
        ${S.captureManifest.length ? `
          <div class="wb-card">
            <div class="wb-card-h"><span>${L('保存的采集观测记录 (Capture Manifest)', 'Saved capture observations')}</span><span class="pill-tag">${S.captureManifest.length}</span></div>
            <div style="padding:12px 16px">
              ${S.captureManifest.map(r => `
                <div class="ac-card">
                  <div class="ac-card-h">
                    <strong>${esc(r.source)}</strong>
                    <span class="pill-tag ${r.status === 'complete' || r.status === 'ok' ? 'ok' : 'warn'}">${esc(captureStatusLabel(r.status))}</span>
                    <span class="wb-ins-sub" style="margin-left:auto">${esc([r.started_at, r.ended_at].filter(Boolean).map(fmtTime).join(' → ') || fmtTime(r.observed_at))}</span>
                  </div>
                  <dl class="kv" style="margin-bottom:8px">
                    ${r.placement ? `<dt>${L('目标位置', 'Target')}</dt><dd>${esc(r.placement)}</dd>` : ''}
                    ${r.identity_domain ? `<dt>${L('范围域', 'Scope')}</dt><dd>${esc(r.identity_domain)}</dd>` : ''}
                    ${r.evidence_ref ? `<dt>evidence_ref</dt><dd>${esc(r.evidence_ref)}</dd>` : ''}
                  </dl>
                  ${(r.snapshots || []).length ? `<details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px;font-weight:600;color:var(--acc)">${L('采集能力快照', 'Capabilities')} (${r.snapshots.length})</summary><div style="padding-top:6px">${r.snapshots.map(sn => `<div style="margin-bottom:8px"><div class="wb-ins-sub">${esc(fmtTime(sn.observed_at))} · ${esc(sn.boundary)} · ${esc(captureStatusLabel(sn.status))}</div><dl class="kv">${(sn.features || []).map(f => `<dt>${esc(f.name)}</dt><dd>${esc([f.state, f.reason].filter(Boolean).join(' · '))}</dd>`).join('')}</dl></div>`).join('')}</div></details>` : ''}
                  ${(r.loss || []).length ? `<details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px;font-weight:600;color:var(--acc)">${L('丢失计数器', 'Loss counters')} (${r.loss.length})</summary><dl class="kv" style="padding-top:6px">${r.loss.map(c => `<dt>${esc(c.name)}</dt><dd>${esc(c.value === null ? L('未知', 'Unknown') : c.value)} · ${esc(c.scope)}${c.scope_id ? ' / ' + esc(c.scope_id) : ''}</dd>`).join('')}</dl></details>` : ''}
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}
        <div class="wb-card">
          <div class="wb-card-h"><span>${L('会话来源覆盖报告', 'Session coverage reports')}</span><span class="pill-tag">${cov.length}</span></div>
          <div style="padding:12px 16px">
            ${cov.length ? cov.map(c => `
              <div class="ac-card">
                <div class="ac-card-h"><strong>${esc(c.source?.harness || '')} · ${esc(c.source?.channel || '')}</strong><span class="pill-tag ${c.status === 'ok' ? 'ok' : 'warn'}">${esc(captureStatusLabel(c.status))}</span></div>
                <dl class="kv"><dt>source_id</dt><dd>${esc(c.source?.id || '')}</dd><dt>session_id</dt><dd>${esc(c.source?.session_id || '—')}</dd><dt>${L('缺失字段', 'Missing')}</dt><dd>${esc((c.missing_fields || []).join(', ') || L('无', 'None'))}</dd></dl>
              </div>
            `).join('') : `<div class="empty">${L('此执行未记录会话覆盖详情。', 'No session coverage reports.')}</div>`}
          </div>
        </div>
      `;
      return;
    }

    list.innerHTML = (filtered.length ? filtered.map((e, i) => `
      <div class="wb-card">
        <div class="wb-card-h">
          <span><span class="pill-tag acc" style="margin-right:6px">${esc(tr(e.kind))}</span>${esc(e.tool_name || e.role || e.source?.harness || '')}</span>
          <span class="wb-ins-sub">${esc(fmtTime(e.recorded_at))}</span>
        </div>
        <div style="padding:10px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
          <span class="wb-ins-sub" style="font-family:var(--mono)">${esc(e.tool_call_id || e.id)}</span>
          ${e.content?.state === 'stored' ? `<button type="button" class="wb-btn sm" data-read-entry="${i}">${L('阅读保存正文', 'Read body')}</button>` : `<span class="wb-ins-sub">${esc(helpers ? tr(helpers.contentReason(e.content)) : L('正文未留存', 'Not retained'))}</span>`}
        </div>
      </div>
    `).join('') : `<div class="empty">${L('此筛选条件下暂无原生会话条目。', 'No native session entries in this filter.')}</div>`)
      + (S.entriesCursor ? `<div style="text-align:center;margin-top:12px"><button type="button" class="wb-btn" id="sess-load-more">${L('加载更多会话记录', 'Load more entries')}</button></div>` : '');

    list.querySelectorAll('[data-read-entry]').forEach(b => {
      b.onclick = () => {
        const e = filtered[+b.dataset.readEntry];
        openInfoModal(`${tr(e.kind)} · ${e.tool_name || e.id}`, '<div data-session-reader></div>');
        mountEvidenceReader($('#wb-info-body [data-session-reader]'), S.run, {entry:e}, true);
      };
    });
    $('#sess-load-more')?.addEventListener('click', async e => {
      const btn = e.currentTarget; btn.disabled = true; btn.textContent = L('正在加载…', 'Loading…');
      try {
        const next = await api('/api/context/entries?' + new URLSearchParams({ run: S.run, limit: '200', cursor: S.entriesCursor }));
        S.entries.push(...(next.entries || []));
        S.entriesCursor = next.has_more ? (next.next_cursor || '') : '';
        $('#cnt-session').textContent = String(S.entries.length) + (S.entriesCursor ? '+' : '');
        renderSessionView();
      } catch { btn.disabled = false; }
    });
  }

  // --- Risk, Outbound Data Surfaces, Network Egress & Full 4-Kind Access Control ---
  async function loadAccessControlPage(kind, offset = 0) {
    S.acKind = kind;
    const runId = S.run;
    try {
      const res = await api('/api/events?' + new URLSearchParams({ run: runId, type: kind, offset: String(offset), limit: '25' }));
      if (S.run !== runId) return;
      S.acPage = { events: res.events || [], total: res.total || 0, offset: res.offset || 0, limit: res.limit || 25 };
      if (S.mode === 'risk') renderRiskView();
    } catch {}
  }

  function decodeACPayload(ev) {
    let val = {};
    try { val = typeof ev.payload === 'string' ? JSON.parse(ev.payload) : (ev.payload || {}); } catch { return {}; }
    for (let i = 0; i < 8 && val && typeof val === 'object' && !Array.isArray(val); i++) {
      if (val.payload && typeof val.payload === 'object') val = val.payload;
      else if (val.raw && typeof val.raw === 'object') val = val.raw;
      else break;
    }
    return val || {};
  }

  function renderRiskView() {
    const host = $('#risk-body');
    const sigs = groupRiskSignals(S.overview?.signals?.signals);
    const sigTotal = sigs.reduce((n, g) => n + g.count, 0);
    const acTotalAll = Object.values(S.acCounts).reduce((a, b) => a + b, 0);
    const acFrom = S.acPage.total ? S.acPage.offset + 1 : 0;
    const acTo = Math.min(S.acPage.offset + S.acPage.limit, S.acPage.total);

    host.innerHTML = `
      <div class="wb-card">
        <div class="wb-card-h"><span>${L('风险信号汇总', 'Risk signals')}</span><span class="pill-tag ${sigs.length ? 'risk' : 'ok'}">${sigs.length ? `${sigs.length} ${L('类', 'groups')} · ${sigTotal} ${L('条', 'signals')}` : '0'}</span></div>
        <div style="padding:12px 16px">
          ${sigs.length ? sigs.map((s, i) => `<button type="button" class="sig-item" data-risk-focus="${i}"><span class="sev ${esc((s.severity || 'low').toLowerCase())}">${esc(tr(s.severity || 'risk'))}</span><div style="flex:1;min-width:0"><div style="font-weight:650">${esc(formatSignalTitle(s.title))}</div><div class="wb-ins-sub">${esc(tr(s.type || ''))} · ${s.count} ${L('条事件', 'events')}${s.sample ? ` · ${esc(s.sample)}` : ''}</div></div></button>`).join('') : `<div class="wb-ins-sub">${L('无风险信号。', 'No risk signals.')}</div>`}
        </div>
      </div>

      <div class="wb-card">
        <div class="wb-card-h"><span>${L('数据外发面 (Outbound Data Surfaces)', 'Outbound data surfaces')}</span><span class="pill-tag">${S.outbound.length}</span></div>
        ${S.outbound.length ? `<div class="surface-grid">${S.outbound.map((o, i) => {
          const classes = (o.data_classes?.length ? o.data_classes : [o.data_class]).filter(Boolean).map(x => DATA_LABEL[x] || x).join(' + ');
          const isRisky = ['blocked', 'redacted'].includes(o.decision) || (o.data_classes || []).includes('secret');
          return `
            <button type="button" class="surface-card ${isRisky ? 'risk' : ''}" data-surf-idx="${i}">
              <div class="surface-top">
                <strong style="font-size:13px">${esc(CHANNEL_LABEL[o.channel_class] || o.channel_class)}</strong>
                <span class="pill-tag">${esc(EVIDENCE_LABEL[o.evidence_level] || o.evidence_level || '')}</span>
              </div>
              <div class="surface-flow">${esc(classes || '—')} → <b>${esc(tr(o.destination_owner || 'unknown'))}</b></div>
              <div class="surface-dest">${esc(o.destination || '')}${o.destinations?.length > 1 ? ` +${o.destinations.length - 1}` : ''}</div>
              <div style="display:flex;align-items:center;gap:8px;margin-top:2px;font-size:11.5px;color:var(--muted)">
                <span class="pill-tag ${o.decision === 'blocked' ? 'risk' : o.decision === 'allowed' ? 'ok' : ''}">${esc(tr(o.decision || 'observed'))}</span>
                <span>${o.request_count ?? 1} ${L('次请求', 'reqs')}${o.bytes ? ' · ' + fmtBytes(o.bytes) : ''}</span>
              </div>
            </button>
          `;
        }).join('')}</div>` : `<div style="padding:14px 16px" class="wb-ins-sub">${L('未观测到外发面。', 'No outbound surfaces observed.')}</div>`}
      </div>

      <div class="wb-card">
        <div class="wb-card-h"><span>${L('网络外联明细 (Egress)', 'Network egress destinations')}</span><span class="pill-tag">${S.egress.length}</span></div>
        ${S.egress.length ? `<div style="overflow-x:auto"><table class="wb-table"><thead><tr><th>${L('时间', 'Time')}</th><th>${L('类型', 'Type')}</th><th>${L('目标', 'Destination')}</th><th>${L('路径', 'Path')}</th><th>${L('端口', 'Port')}</th><th>${L('证据与判定', 'Evidence')}</th><th>${L('次数', 'Count')}</th><th>${L('进程', 'Process')}</th></tr></thead><tbody>${S.egress.map(e => `
          <tr class="${e.risk ? 'risk-row' : ''}">
            <td class="mono">${esc(fmtTime(e.time).slice(11))}</td>
            <td>${esc(tr(e.type || ''))}</td>
            <td class="mono">${e.domain ? `${esc(e.domain)} <span style="color:var(--muted)">${esc(e.dst || '')}</span>` : esc(e.dst || '')}</td>
            <td class="mono">${esc(e.path || '')}</td>
            <td class="mono">${esc(e.port || '')}</td>
            <td>${esc(tr(e.evidence || ''))}${e.decision && e.decision !== 'observed' ? ` · <span class="pill-tag">${esc(tr(e.decision))}</span>` : ''}</td>
            <td class="mono">${e.count || 1}</td>
            <td class="mono">${esc(e.comm || '')}</td>
          </tr>
        `).join('')}</tbody></table></div>` : `<div style="padding:14px 16px" class="wb-ins-sub">${L('未记录网络外联明细。', 'No outbound network records.')}</div>`}
      </div>

      <div class="wb-card">
        <div class="wb-card-h">
          <span>${L('访问控制证据 (AppArmor / seccomp)', 'Access control evidence (AppArmor / seccomp)')}</span>
          <div class="wb-seg">
            ${AC_KINDS.map(([k, lbl]) => `<button type="button" class="${S.acKind === k ? 'on' : ''}" data-ac-kind="${k}">${esc(lbl)} (${S.acCounts[k] ?? 0})</button>`).join('')}
          </div>
        </div>
        <div style="padding:12px 16px">
          ${S.acPage.events.length ? S.acPage.events.map(ev => {
            const d = decodeACPayload(ev);
            const entries = Object.entries(d).filter(([, v]) => v !== '' && v !== undefined).slice(0, 14);
            const aaMode = d.apparmor?.mode || d.apparmor?.status;
            const scMode = d.seccomp?.mode || d.seccomp?.status;
            const kindLabel = (AC_KINDS.find(([k]) => k === ev.event_type) || [])[1] || tr(ev.event_type);
            return `
              <div class="ac-card">
                <div class="ac-card-h">
                  <span class="pill-tag acc">${esc(d.mechanism || kindLabel)}</span>
                  ${d.decision ? `<span class="pill-tag ${d.decision === 'DENIED' || d.decision === 'ERRNO' ? 'risk' : 'ok'}">${esc(d.decision)}</span>` : ''}
                  ${aaMode ? `<span class="pill-tag">AppArmor: ${esc(aaMode)}</span>` : ''}
                  ${scMode ? `<span class="pill-tag">seccomp: ${esc(scMode)}</span>` : ''}
                  ${d.profile ? `<span style="font-family:var(--mono);font-size:12px;font-weight:600">${esc(d.profile)}</span>` : ''}
                  <span class="wb-ins-sub" style="margin-left:auto;font-family:var(--mono)">${ev.pid ? 'pid ' + ev.pid + ' · ' : ''}${esc(fmtTime(ev.created_at).slice(11))}</span>
                </div>
                <dl class="kv">${entries.map(([k, v]) => `<dt>${esc(tr(AC_FIELD_NAMES[k] || k))}</dt><dd>${esc(typeof v === 'object' ? JSON.stringify(v) : String(v))}</dd>`).join('')}</dl>
              </div>
            `;
          }).join('') : `<div class="wb-ins-sub">${acTotalAll ? L('当前分类下无记录，可切换上方访问控制分类标签。', 'No records in this category; try another tab above.') : L('本次执行无 AppArmor / seccomp 访问控制记录。', 'No AppArmor / seccomp records in this run.')}</div>`}
        </div>
        ${S.acPage.total > S.acPage.limit ? `
          <div class="wb-pager">
            <button type="button" class="wb-btn sm" id="ac-prev" ${S.acPage.offset <= 0 ? 'disabled' : ''}>‹ ${L('上一页', 'Prev')}</button>
            <span>${acFrom}–${acTo} / ${S.acPage.total}</span>
            <button type="button" class="wb-btn sm" id="ac-next" ${acTo >= S.acPage.total ? 'disabled' : ''}>${L('下一页', 'Next')} ›</button>
          </div>
        ` : ''}
      </div>
    `;

    host.querySelectorAll('[data-risk-focus]').forEach(b => {
      b.onclick = () => {
        const g = sigs[+b.dataset.riskFocus];
        const focus = g?.focus || g?.refs?.[0] || '';
        if (focus) setLens('security', 'summary', focus);
      };
    });
    host.querySelectorAll('[data-surf-idx]').forEach(b => {
      b.onclick = () => {
        const surf = S.outbound[+b.dataset.surfIdx];
        const ref = surf?.evidence_refs?.[0] || '';
        const lens = surf?.channel_class === 'model_inference' ? 'agent-intent' : 'network-egress';
        const avail = S.lensManifest?.available_lenses || [];
        setLens(avail.includes(lens) ? lens : 'default', 'raw', ref);
      };
    });
    host.querySelectorAll('[data-ac-kind]').forEach(b => { b.onclick = () => loadAccessControlPage(b.dataset.acKind, 0); });
    $('#ac-prev')?.addEventListener('click', () => loadAccessControlPage(S.acKind, Math.max(0, S.acPage.offset - S.acPage.limit)));
    $('#ac-next')?.addEventListener('click', () => loadAccessControlPage(S.acKind, S.acPage.offset + S.acPage.limit));
  }

  // --- Compliance Framework Assessment View (Restored in full!) ---
  async function loadComplianceForRun(runId) {
    try {
      if (!S.frameworks.length) {
        const fws = await api('/api/frameworks');
        S.frameworks = Array.isArray(fws) ? fws : [];
        if (S.frameworks.length && !S.frameworkId) S.frameworkId = S.frameworks[0].id;
      }
      if (!S.frameworkId) { S.compliance = null; updateComplianceBadge(); return; }
      const rep = await api('/api/compliance?' + new URLSearchParams({ run: runId, framework: S.frameworkId }));
      if (S.run !== runId) return;
      S.compliance = rep;
      updateComplianceBadge();
      if (S.mode === 'compliance') renderComplianceView();
      if (S.mode === 'graph' && !S.sel) renderInspector();
    } catch {
      if (S.run !== runId) return;
      S.compliance = null;
      updateComplianceBadge();
    }
  }
  function updateComplianceBadge() {
    const el = $('#cnt-comp');
    const sum = S.compliance?.summary;
    if (!sum) { el.textContent = '—'; el.className = 'wb-count'; return; }
    if (sum.detected > 0) {
      el.textContent = `${sum.detected} ⚠`;
      el.className = 'wb-count warn';
    } else {
      el.textContent = String(sum.total || 0);
      el.className = 'wb-count';
    }
  }
  function complianceLensFor(kind) {
    if (['risk_signal', 'policy_decision', 'response_action'].includes(kind)) return 'security';
    if (['process', 'runtime_process'].includes(kind)) return 'process';
    if (kind === 'tool_call') return 'agent-intent';
    if (['snapshot', 'taint'].includes(kind)) return 'data-flow-taint';
    return 'default';
  }
  function renderComplianceView() {
    const host = $('#compliance-body');
    const rep = S.compliance;
    const fwSelect = S.frameworks.length
      ? `<select id="comp-fw-sel" style="padding:5px 10px;border:1px solid var(--line-strong);border-radius:7px;font-size:12.5px;background:var(--surface)">${S.frameworks.map(f => `<option value="${esc(f.id)}" ${f.id === S.frameworkId ? 'selected' : ''}>${esc(tr(f.title))} (${f.controls})</option>`).join('')}</select>`
      : '';

    if (!rep || rep.error || !rep.summary) {
      host.innerHTML = `<div class="wb-card"><div class="wb-card-h"><span>${L('合规框架评估', 'Compliance assessment')}</span>${fwSelect}</div><div class="empty">${esc((rep && rep.error) || L('本次执行暂无合规映射数据。', 'No compliance mapping for this run.'))}</div></div>`;
      $('#comp-fw-sel')?.addEventListener('change', e => { S.frameworkId = e.target.value; loadComplianceForRun(S.run); });
      return;
    }

    const s = rep.summary, total = Math.max(1, s.total || 1);
    const pct = n => ((100 * (n || 0)) / total).toFixed(1) + '%';
    const meta = {
      detected: { icon: '🟠', label: tr('Detected only'), cls: 'warn' },
      enforced: { icon: '🟢', label: tr('Enforcement'), cls: 'ok' },
      not_triggered: { icon: '⚪', label: tr('Not triggered'), cls: 'acc' },
      no_rule: { icon: '⬚', label: tr('No rule'), cls: '' }
    };
    const items = rep.items || [];
    const groupsHTML = ['detected', 'enforced', 'not_triggered', 'no_rule'].map(stKey => {
      const arr = items.filter(i => (i.status || 'no_rule') === stKey);
      if (!arr.length) return '';
      const open = !!S.compGrp[stKey];
      const m = meta[stKey];
      const cards = open ? `<div class="comp-list-pad">${arr.map(it => {
        const desc = CONTROL_DESC[it.control_id] ? `<div class="comp-desc">${esc(CONTROL_DESC[it.control_id])}</div>` : '';
        const rules = (it.rules || []).length ? `<div class="comp-rules">${it.rules.map(r => {
          const modeTag = `<span class="pill-tag ${r.mode === 'detect' ? 'warn' : 'ok'}">${esc(tr(r.mode || 'enforce'))}</span>`;
          if (!r.fired) return `<div class="comp-rule"><span style="color:var(--muted)">○</span><code>${esc(r.id)}</code>${modeTag}<span class="wb-ins-sub">${esc(tr('not triggered'))}</span></div>`;
          return `<div class="comp-rule"><span>${r.enforced ? '✓' : '⚠'}</span><code>${esc(r.id)}</code>${modeTag}<span class="pill-tag ${r.enforced ? 'ok' : 'warn'}">${esc(tx('hits ×{count}', { count: r.fired }))}</span>${r.intended_decision ? `<span class="wb-ins-sub">· ${esc(tx('intended: {decision}', { decision: tr(r.intended_decision) }))}</span>` : ''}</div>`;
        }).join('')}</div>` : `<div class="wb-ins-sub">${esc(tr('no detection rule maps to this control yet'))}</div>`;

        const gap = (stKey === 'detected' || stKey === 'no_rule') && it.gap
          ? `<div class="comp-gap">⚠ ${esc(tr(it.gap))}${it.recommended_next_step ? ` → <span style="color:var(--acc)">${esc(tr(it.recommended_next_step))}</span>` : ''}</div>` : '';
        const hits = (it.rules || []).flatMap(r => (r.hits || []).map(h => ({ ...h, ruleId: r.id })));
        const hitsOpen = S.compOpen.has(it.control_id);
        const hitsHTML = hits.length ? `
          <div style="margin-top:8px">
            <button type="button" class="wb-btn sm" data-comp-ev="${esc(it.control_id)}">${hitsOpen ? '▾' : '▸'} ${esc(tx('rule hits ({count})', { count: hits.length }))}</button>
            ${hitsOpen ? `<div class="comp-hits">${hits.map(h => `
              <button type="button" class="comp-hit-btn" data-comp-ref="${esc(h.ref)}" data-comp-kind="policy_decision">
                <span style="font-family:var(--mono);color:var(--muted)">${esc(fmtTime(h.created_at).slice(11))}</span>
                <span class="pill-tag ${h.enforced ? 'ok' : 'warn'}">${esc(tx('Decision: {decision}', { decision: tr(h.decision) }))}</span>
                <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${esc(h.reason || h.ruleId)}</span>
                <span style="color:var(--acc);font-weight:600">${L('图中定位 →', 'Focus →')}</span>
              </button>
            `).join('')}</div>` : ''}
          </div>
        ` : '';

        return `
          <div class="comp-item st-${esc(stKey)}">
            <div class="comp-item-h">
              <span class="pill-tag ${m.cls}">${m.icon} ${esc(m.label)}</span>
              <strong style="font-size:13.5px">${esc(tr(it.title || it.control_id))}</strong>
              <span class="wb-ins-sub" style="font-family:var(--mono)">${esc(it.control_id)}</span>
            </div>
            ${desc}${rules}${gap}${hitsHTML}
          </div>
        `;
      }).join('')}</div>` : '';
      return `
        <div>
          <button type="button" class="comp-group-hdr" data-comp-grp="${stKey}">
            <span>${open ? '▾' : '▸'}</span><span>${m.icon} ${esc(m.label)}</span><span class="wb-count">${arr.length}</span>
          </button>
          ${cards}
        </div>
      `;
    }).join('');

    host.innerHTML = `
      <div class="wb-card">
        <div class="wb-card-h">
          <div>
            <span>${L('合规框架评估 (Compliance)', 'Compliance assessment')}</span>
            <div class="wb-ins-sub" style="font-weight:400">${L('逐项核对本次运行中是否触发检测规则，以及控制措施的判定状态（已执行 / 仅检测 / 未触发 / 无规则）。', 'Per control: did a mapped threat rule fire in this run, and what decision was recorded?')}</div>
          </div>
          ${fwSelect}
        </div>
        <div class="comp-bar-wrap">
          <div class="covbar">
            ${s.enforced ? `<i class="enforced" style="width:${pct(s.enforced)}"></i>` : ''}
            ${s.detected ? `<i class="detected" style="width:${pct(s.detected)}"></i>` : ''}
            ${s.not_triggered ? `<i class="not_triggered" style="width:${pct(s.not_triggered)}"></i>` : ''}
            ${s.no_rule ? `<i class="no_rule" style="width:${pct(s.no_rule)}"></i>` : ''}
          </div>
          <div class="covstats">
            <span>🟢 <b>${s.enforced || 0}</b> ${esc(tr('Enforcement'))}</span>
            <span>🟠 <b>${s.detected || 0}</b> ${esc(tr('detected only'))}</span>
            <span>⚪ <b>${s.not_triggered || 0}</b> ${esc(tr('not triggered'))}</span>
            <span>⬚ <b>${s.no_rule || 0}</b> ${esc(tr('no rule'))}</span>
            <span style="margin-left:auto">${esc(tx('{count} controls in total', { count: s.total || 0 }))}</span>
          </div>
        </div>
        ${groupsHTML || `<div class="empty">${L('无控制项。', 'No controls.')}</div>`}
        ${rep.disclaimer ? `<div class="comp-disclaimer">${esc(tr(rep.disclaimer))}</div>` : ''}
      </div>
    `;

    $('#comp-fw-sel')?.addEventListener('change', e => { S.frameworkId = e.target.value; loadComplianceForRun(S.run); });
    host.querySelectorAll('[data-comp-grp]').forEach(b => { b.onclick = () => { S.compGrp[b.dataset.compGrp] = !S.compGrp[b.dataset.compGrp]; renderComplianceView(); }; });
    host.querySelectorAll('[data-comp-ev]').forEach(b => {
      b.onclick = () => {
        const id = b.dataset.compEv;
        if (S.compOpen.has(id)) S.compOpen.delete(id); else S.compOpen.add(id);
        renderComplianceView();
      };
    });
    host.querySelectorAll('[data-comp-ref]').forEach(b => {
      b.onclick = () => {
        const ref = b.dataset.compRef, kind = b.dataset.compKind || 'policy_decision';
        const avail = S.lensManifest?.available_lenses || [];
        const lens = complianceLensFor(kind);
        setLens(avail.includes(lens) ? lens : 'default', 'raw', ref);
      };
    });
  }

  // --- Timeline (Paginated!), Hierarchical Process Tree & Producer Profile ---
  async function loadTimelinePage(offset = 0) {
    const runId = S.run;
    try {
      const res = await api('/api/timeline?' + new URLSearchParams({ run: runId, limit: '50', offset: String(offset) }));
      if (S.run !== runId) return;
      S.timeline = { events: res.events || [], total: res.total || 0, offset: res.offset || 0, limit: res.limit || 50 };
      if (S.mode === 'timeline') renderTimelineView();
    } catch {}
  }

  function buildProducerProfileHTML(evs) {
    if (!evs.length) return '';
    const sources = new Set(), scopes = new Set(), pods = [];
    let k8s = 0, kernel = 0, record = 0;
    evs.forEach(e => {
      if (e.source) sources.add(e.source);
      if (e.binding_source) scopes.add(e.binding_source);
      if (e.binding_source === 'k8s_cgroup' || e.pod_uid) k8s++;
      if ((e.correlation_class || '') === 'kernel_correlated') kernel++;
      if (e.self_launched || e.binding_source === 'record') record++;
      if (e.pod_name && !pods.some(p => p.pod_name === e.pod_name)) pods.push(e);
    });
    const tlsEvents = evs.filter(e => /^tls_/.test(e.event_type || '') || String(e.source || '').includes('tls'));
    const pids = [...new Set(evs.map(e => e.pid).filter(Boolean))];
    const cgroups = [...new Set(evs.map(e => e.cgroup_id).filter(Boolean))];
    const profile = k8s ? 'k8s-daemonset' : (kernel ? tr('local/VM sensor') : (record ? 'local-record' : tr('evidence import')));
    const scope = k8s ? tr('passive cgroup attribution') : (scopes.has('record') ? tr('record cgroup leaf') : (record ? tr('record logical scope') : tr('imported evidence')));
    const telemetry = kernel ? tx('{count}/{total} kernel-correlated', { count: kernel, total: evs.length }) : (record ? tx('{count}/{total} self-observed', { count: record, total: evs.length }) : tr('no runtime events in page'));
    const intent = tlsEvents.length ? tx('TLS records in page ({count})', { count: tlsEvents.length }) : tr('no model-intent TLS in page');
    return `
      <div class="profile-grid">
        <div class="pcard ${k8s ? 'acc' : kernel ? 'ok' : ''}"><div class="k">${esc(tr('Producer profile'))}</div><div class="v">${esc(profile)}</div><div class="d">${esc([...sources].slice(0, 3).map(tr).join(' · ') || tr('unknown source'))}</div></div>
        <div class="pcard ${k8s ? 'acc' : ''}"><div class="k">${esc(tr('Scope source'))}</div><div class="v">${esc(pods.length ? `${pods[0].namespace || '?'}/${pods[0].pod_name}` : scope)}</div><div class="d">${esc(cgroups.length ? `cgroup ${cgroups[0]}${cgroups.length > 1 ? ' +' + (cgroups.length - 1) : ''}` : tr('no cgroup id'))}</div></div>
        <div class="pcard ${kernel ? 'ok' : 'warn'}"><div class="k">${esc(tr('Runtime telemetry'))}</div><div class="v">${esc(telemetry)}</div><div class="d">${esc(pids.length ? tx('{count} pids observed', { count: pids.length }) : tr('no pid evidence'))}</div></div>
        <div class="pcard ${tlsEvents.length ? 'ok' : 'warn'}"><div class="k">${esc(tr('Model intent'))}</div><div class="v">${esc(intent)}</div><div class="d">${esc(tlsEvents.length ? tr('TLS body parsed when observable') : tr('app hooks / explicit events may still apply'))}</div></div>
      </div>
    `;
  }

  function buildProcessTreeHTML(procs) {
    if (!procs.length) return `<div class="empty">${L('未观测到进程记录。', 'No process events.')}</div>`;
    const byPid = {}, kids = {};
    procs.forEach(p => { if (!byPid[p.pid]) byPid[p.pid] = { pid: p.pid, ppid: p.ppid, command: p.command || p.comm || '?' }; });
    const pids = new Set(Object.keys(byPid).map(Number));
    Object.values(byPid).forEach(p => { (kids[p.ppid] = kids[p.ppid] || []).push(p); });
    const roots = Object.values(byPid).filter(p => !pids.has(p.ppid));
    const seen = new Set();
    const sig = c => (c.command || '').slice(0, 60);
    const isLeaf = c => !(kids[c.pid] || []).length;
    function renderList(list, depth) {
      let s = ''; const groups = {};
      list.forEach(c => { if (!seen.has(c.pid)) (groups[sig(c)] = groups[sig(c)] || []).push(c); });
      Object.values(groups).forEach(g => {
        const leaves = g.filter(isLeaf);
        const ind = '&nbsp;'.repeat(depth * 3);
        if (g.length >= 4 && leaves.length === g.length) {
          g.forEach(c => seen.add(c.pid));
          s += `<div class="ptree-row">${ind}${depth > 0 ? '└ ' : ''}<span class="ptree-cmd">${esc(g[0].command.slice(0, 90))}</span> <span class="pill-tag">×${g.length}</span></div>`;
        } else {
          g.forEach(c => {
            if (seen.has(c.pid) || depth > 30) return;
            seen.add(c.pid);
            s += `<div class="ptree-row">${ind}${depth > 0 ? '└ ' : ''}<span class="ptree-cmd">${esc(c.command.slice(0, 100))}</span> <span class="ptree-pid">[pid ${c.pid}]</span></div>`;
            s += renderList(kids[c.pid] || [], depth + 1);
          });
        }
      });
      return s;
    }
    return `<div class="ptree">${renderList(roots, 0) || `<div class="empty">${L('无根进程。', 'No root processes.')}</div>`}</div>`;
  }

  function renderTimelineView() {
    const host = $('#timeline-body');
    const evs = S.timeline.events || [];
    const from = S.timeline.total ? S.timeline.offset + 1 : 0;
    const to = Math.min(S.timeline.offset + S.timeline.limit, S.timeline.total);
    const slCount = evs.filter(e => e.self_launched).length;
    const kcCount = evs.filter(e => (e.correlation_class || '') === 'kernel_correlated').length;

    host.innerHTML = `
      ${buildProducerProfileHTML(evs)}
      <div class="wb-card">
        <div class="wb-card-h">
          <span>${L('执行时间线 (Run Timeline)', 'Run timeline')}</span>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span class="wb-ins-sub">${esc(tx('{started}/{total} self-launched · {kernel}/{total} kernel-correlated', { started: slCount, total: evs.length, kernel: kcCount }))}</span>
            <span class="pill-tag">${S.timeline.total} ${L('条事件', 'events')}</span>
          </div>
        </div>
        <div style="overflow-x:auto">
          <table class="wb-table">
            <thead><tr><th>${L('时间', 'Time')}</th><th>${L('事件', 'Event')}</th><th>${L('来源', 'Source')}</th><th>${L('关联类别', 'Correlation')}</th><th>${L('载荷（点击展开）', 'Payload (click to inspect)')}</th></tr></thead>
            <tbody>${evs.map((e, i) => `
              <tr>
                <td class="mono">${esc(fmtTime(e.created_at).slice(11))}</td>
                <td style="font-weight:600">${esc(tr(e.event_type))}</td>
                <td class="mono">${esc(e.source || '')}</td>
                <td><span class="pill-tag">${esc(tr(e.correlation_class || e.correlation_method || ''))}</span></td>
                <td class="mono">${e.payload ? `<button type="button" style="border:0;background:none;padding:0;text-align:left;color:var(--ink-2);font-family:var(--mono);font-size:11.5px;word-break:break-all" data-tl-pl="${i}">${esc(String(e.payload).slice(0, 120))}${String(e.payload).length > 120 ? '…' : ''}</button>` : '—'}</td>
              </tr>
            `).join('')}</tbody>
          </table>
        </div>
        ${S.timeline.total > S.timeline.limit ? `
          <div class="wb-pager">
            <button type="button" class="wb-btn sm" id="tl-prev" ${S.timeline.offset <= 0 ? 'disabled' : ''}>‹ ${L('上一页', 'Prev')}</button>
            <span>${from}–${to} / ${S.timeline.total}</span>
            <button type="button" class="wb-btn sm" id="tl-next" ${to >= S.timeline.total ? 'disabled' : ''}>${L('下一页', 'Next')} ›</button>
          </div>
        ` : ''}
      </div>
      <div class="wb-card">
        <div class="wb-card-h"><span>${L('进程树 (Process Tree)', 'Process tree')}</span><span class="pill-tag">${S.processes.length} ${L('条记录', 'records')}</span></div>
        ${buildProcessTreeHTML(S.processes)}
      </div>
    `;

    $('#tl-prev')?.addEventListener('click', () => loadTimelinePage(Math.max(0, S.timeline.offset - S.timeline.limit)));
    $('#tl-next')?.addEventListener('click', () => loadTimelinePage(S.timeline.offset + S.timeline.limit));
    host.querySelectorAll('[data-tl-pl]').forEach(b => {
      b.onclick = () => {
        const ev = evs[+b.dataset.tlPl];
        let txt = ev.payload || '';
        try { txt = JSON.stringify(JSON.parse(txt), null, 2); } catch {}
        openInfoModal(`${tr(ev.event_type)} · ${fmtTime(ev.created_at)}`, `<pre class="code-box" style="max-height:70vh">${esc(txt)}</pre>`);
      };
    });
  }

  // --- Compare Modal (With task text, capture metadata, body reader AND Locate-in-Graph!) ---
  const META_KEYS = /\/(id|createdAt|updatedAt|timestamp|delegationDepth|reason|sessionId|runId)$/i;
  const CACHE_FILE_RE = /(?:^|\/)__pycache__\/|\.(?:pyc|tmpdir)$|^\/home\/[^/]+\/\.local\//i;
  function mountEvidenceReader(host, run, evidence, expanded = false) {
    const entry = evidence?.entry?.content;
    const meta = entry || evidence?.content;
    if (meta?.state && !['reader', 'stored'].includes(meta.state)) {
      host.textContent = tr(meta.reason || meta.state); return;
    }
    const ref = entry?.state === 'stored' && entry.ref;
    if (!ref && !evidence?.node) {
      host.textContent = L('此记录没有保存正文引用。', 'No saved body reference in this record.'); return;
    }
    const offsets = [0];
    let request = 0;
    async function show() {
      const token = ++request, offset = offsets.at(-1);
      host.setAttribute('aria-busy', 'true'); host.textContent = L('正在读取正文…', 'Loading saved text…');
      const q = new URLSearchParams({run, offset: String(offset), limit: '65536'});
      if (ref) q.set('ref', ref);
      else { q.set('node', evidence.node); q.set('mode', 'body'); q.set('view_lang', LANG); }
      try {
        const page = await api((ref ? '/api/context/content?' : '/api/artifact?') + q);
        if (token !== request || !host.isConnected) return;
        const state = page.content_state || page.state;
        if ((state && state !== 'stored') || (!ref && !['text','diff'].includes(page.kind)) ||
            (typeof page.content !== 'string' && page.total_bytes !== 0)) {
          host.textContent = tr(page.reason || state || L('此记录没有可读正文。', 'No readable body in this record.')); return;
        }
        const txt = page.content ?? '', total = page.total_bytes;
        const next = page.next_offset, more = page.has_more === true && Number.isSafeInteger(next) && next > offset;
        const caption = [L('已保存正文', 'Saved text'), Number.isSafeInteger(total) ? total + ' B' : '',
          page.redacted ? L('已脱敏', 'Redacted') : '', (offset || page.has_more) ? offset + '–' + next + ' B' : ''].filter(Boolean).join(' · ');
        const projected = expanded && ref && offset === 0 && !page.has_more
          ? window.AgentDisplayHelpers.readableContent(txt, evidence.entry, L('其他已记录字段', 'Other recorded fields')) : null;
        host.innerHTML = renderDiffOrCode(projected ?? txt, page.kind === 'diff', expanded ? '65vh' : 'min(38vh, 370px)') +
          (projected != null && projected !== txt ? `<details><summary>${L('已保存原文', 'Original saved text')}</summary><pre class="code-box">${esc(txt)}</pre></details>` : '') +
          (expanded && page.sha256 ? `<div class="wb-ins-sub">SHA-256: <code>${esc(page.sha256)}</code></div>` : '') +
          `<div class="cmp-content-foot"><span>${esc(caption)}</span>${offsets.length > 1 ? `<button class="wb-btn sm" data-page="prev">${L('上一页', 'Previous')}</button>` : ''}${more ? `<button class="wb-btn sm" data-page="next">${L('下一页', 'Next')}</button>` : ''}</div>`;
        host.querySelector('[data-page=prev]')?.addEventListener('click', () => { offsets.pop(); show(); });
        host.querySelector('[data-page=next]')?.addEventListener('click', () => { offsets.push(next); show(); });
      } catch (err) {
        if (token === request && host.isConnected) host.textContent = L('读取失败：', 'Could not load: ') + err.message;
      } finally { if (token === request) host.removeAttribute('aria-busy'); }
    }
    show();
  }
  async function locateEvidenceInGraph(targetRun, evidence) {
    const dlg = $('#wb-compare-dlg');
    const sdlg = $('#wb-search-dlg');
    let nodeId = evidence?.node || evidence?.graph_node || '';
    if (!nodeId && evidence?.entry?.id) {
      const links = await api('/api/context/links?' + new URLSearchParams({ run: targetRun, entry: evidence.entry.id }));
      nodeId = links?.links?.[0]?.node_id || '';
    }
    if (!nodeId) {
      openInfoModal(L('定位提示', 'Graph link'), `<div class="empty">${L('该条目没有直接关联的图谱节点。', 'No direct graph node link for this record.')}</div>`);
      return;
    }
    const fromCompare = dlg.open;
    if (fromCompare) { S.compare = null; dlg.close(); }
    if (sdlg.open) sdlg.close();
    if (targetRun !== S.run) await loadRun(targetRun);
    if (fromCompare) { S.scope = null; $('#wb-scopesel').value = ''; }
    S.insTab = 'summary';
    setLens('default', 'raw', nodeId);
  }

  async function openCompare(runA, runB, preferDim) {
    const dlg = $('#wb-compare-dlg');
    const body = $('#wb-cmp-body');
    if (!dlg.open) dlg.showModal();
    if (S.runs.length < 2) {
      body.innerHTML = `<div class="empty">${L('当前回放包仅包含 1 次运行，无法对比。可前往示例库打开「任务调查与修复」体验双 Run 对比。', 'This replay contains only one run. Open "Task investigation" from Demos for paired comparison.')}</div>`;
      return;
    }
    const known = id => S.runs.some(r => r.run === id);
    const b = known(runB) ? runB : S.run;
    const a = known(runA) && runA !== b ? runA : S.runs.find(r => r.run !== b).run;
    let dim = ['files','configuration','network','access_control','outbound'].includes(preferDim) ? preferDim : 'auto';
    let showMeta = false;
    let showCacheFiles = false;
    let onlyDiff = true;
    let built = null;
    let tasks = { a: '', b: '' };

    async function runLoad(ra, rb) {
      const active = S.compare = { a: ra, b: rb, dim };
      syncURL();
      try {
        body.innerHTML = `<div class="empty">${L('正在扫描并对齐两次执行的保存证据…', 'Loading and diffing saved evidence…')}</div>`;
        const [da, db] = await Promise.all([
          window.AgentRunCompare.load({ run: ra, get: api }),
          window.AgentRunCompare.load({ run: rb, get: api })
        ]);
        if (!dlg.open || S.compare !== active) return;
        const pair = { a: da, b: db, ...window.AgentRunCompare.build(da, db) };
        const blurbs = { a: '', b: '' };
        await Promise.all(['a', 'b'].map(async side => {
          const trRec = window.AgentRunCompare.taskRecord(pair[side]);
          if (!trRec) return;
          try {
            const p = await api('/api/context/content?' + new URLSearchParams({ run: pair[side].run, ref: trRec.evidence.entry.content.ref, offset: '0', limit: '2048' }));
            let raw = p.content || '';
            try {
              const parsed = JSON.parse(raw);
              if (Array.isArray(parsed)) raw = parsed.map(x => (typeof x === 'string' ? x : x?.text || '')).filter(Boolean).join(' ');
              else if (parsed && typeof parsed === 'object') raw = parsed.text || parsed.prompt || parsed.content || raw;
            } catch {}
            const clean = String(raw).replace(/^#+\s*/, '').replace(/\s+/g, ' ').trim();
            blurbs[side] = clean.length > 136 ? clean.slice(0, 134).replace(/\s+\S*$/, '') + '…' : clean;
          } catch {}
        }));
        if (!dlg.open || S.compare !== active) return;
        built = pair; tasks = blurbs;
        if (dim === 'auto') {
          const cfgReal = built.rows.filter(r => r.dimension === 'configuration' && r.status !== 'common' && !META_KEYS.test(r.label));
          if (built.counts.files.differences > 0 && cfgReal.length === 0) dim = 'files';
          else dim = ['files', 'configuration', 'network', 'access_control', 'outbound'].find(d => built.counts[d]?.differences > 0) || 'files';
        }
        renderCmp(ra, rb);
      } catch (err) { if (dlg.open && S.compare === active) body.innerHTML = `<div class="wb-alert">${esc(err.message)}</div>`; }
    }

    function renderCmp(ra, rb) {
      S.compare.dim = dim; syncURL();
      const dims = [
        ['files', L('文件证据', 'File evidence')],
        ['configuration', L('配置', 'Configuration')],
        ['network', L('网络目标', 'Network')],
        ['access_control', L('访问控制', 'Access control')],
        ['outbound', L('外发类型', 'Outbound')]
      ];
      let rows = built.rows.filter(r => r.dimension === dim && (!onlyDiff || r.status !== 'common'));
      let hiddenMeta = 0;
      let hiddenCache = 0;
      if (dim === 'configuration' && !showMeta) {
        const filtered = rows.filter(r => !META_KEYS.test(r.label));
        hiddenMeta = rows.length - filtered.length;
        rows = filtered;
      }
      if (dim === 'files' && !showCacheFiles) {
        const filtered = rows.filter(r => !CACHE_FILE_RE.test(r.label));
        if (filtered.length > 0) {
          hiddenCache = rows.length - filtered.length;
          rows = filtered;
        }
      }
      const autoOpenIdx = rows.findIndex(r => r.status === 'different');

      const capSummary = side => captureStatusLabel(built[side].coverage?.runtime_coverage?.capture?.status);
      body.innerHTML = `
        <div class="cmp-bar">
          <label>A <select id="cmp-a">${S.runs.map(r => `<option value="${esc(r.run)}" ${r.run === ra ? 'selected' : ''} ${r.run === rb ? 'disabled' : ''}>${esc(runTitle(r.run))} (${r.events})</option>`).join('')}</select></label>
          <button type="button" class="wb-btn" id="cmp-swap" title="${esc(L('交换 A/B', 'Swap A/B'))}">⇄</button>
          <label>B <select id="cmp-b">${S.runs.map(r => `<option value="${esc(r.run)}" ${r.run === rb ? 'selected' : ''} ${r.run === ra ? 'disabled' : ''}>${esc(runTitle(r.run))} (${r.events})</option>`).join('')}</select></label>
          <label style="margin-left:auto;font-size:12px;color:var(--muted)"><input type="checkbox" id="cmp-only" ${onlyDiff ? 'checked' : ''}> ${L('只看差异', 'Differences only')}</label>
        </div>
        <div class="cmp-pair">
          <div class="cmp-side-hdr"><strong>A · ${esc(runTitle(ra))}</strong><small>${esc(ra)} · ${L('采集', 'Capture')}: ${esc(capSummary('a'))}</small>${tasks.a ? `<p class="cmp-task">${esc(tasks.a)}</p>` : ''}</div>
          <div class="cmp-side-hdr"><strong>B · ${esc(runTitle(rb))}</strong><small>${esc(rb)} · ${L('采集', 'Capture')}: ${esc(capSummary('b'))}</small>${tasks.b ? `<p class="cmp-task">${esc(tasks.b)}</p>` : ''}</div>
        </div>
        <div class="cmp-tabs">
          ${dims.map(([k, lbl]) => `<button type="button" class="cmp-tab ${dim === k ? 'on' : ''}" data-cdim="${k}">${lbl} (${built.counts[k]?.differences ?? 0})</button>`).join('')}
          ${dim === 'configuration' && (hiddenMeta > 0 || showMeta) ? `<button type="button" class="wb-btn sm" id="cmp-meta-toggle" style="margin-left:auto">${showMeta ? L('隐藏实例元数据', 'Hide metadata') : `${L('显示已折叠的实例元数据', 'Show folded metadata')} (${hiddenMeta})`}</button>` : ''}
          ${dim === 'files' && (hiddenCache > 0 || showCacheFiles) ? `<button type="button" class="wb-btn sm" id="cmp-cache-toggle" style="margin-left:auto">${showCacheFiles ? L('折叠缓存与会话文件', 'Hide cache & session files') : `${L('显示已折叠的缓存与会话文件', 'Show folded cache & session files')} (${hiddenCache})`}</button>` : ''}
        </div>
        <div>
          ${rows.length ? rows.slice(0, 80).map((r, rIdx) => {
            const st = { only_a: L('仅 A 记录', 'Only A'), only_b: L('仅 B 记录', 'Only B'), different: L('值不同', 'Different'), common: L('一致', 'Same'), unknown: L('不完整', 'Incomplete') }[r.status] || r.status;
            const stCls = r.status === 'different' ? 'acc' : r.status === 'only_a' ? 'warn' : r.status === 'only_b' ? 'ok' : '';
            const opLabel = CMP_OP_NAMES[r.operation] || CHANNEL_LABEL[r.operation] || tr(r.operation);
            const canRead = rec => !!(rec?.evidence?.entry?.content?.state === 'stored' || rec?.evidence?.node);
            const canGraph = rec => !!(rec?.evidence?.node || rec?.evidence?.graph_node || rec?.evidence?.entry?.id);
            const isFile = r.operation === 'saved_file_version';
            const sideVal = (side, rec) => {
              if (!rec) {
                const s = r.sides?.[side];
                const reason = !s?.enumerationComplete ? L('此侧扫描未完成', 'Scan incomplete on this side') : s?.reasons?.length ? s.reasons.map(tr).join(' · ') : L('此侧未记录', 'Not recorded on this side');
                return `<span class="wb-ins-sub">${esc(reason)}</span>`;
              }
              const pv = rec.value?.preview;
              if (!pv) return `<span class="wb-ins-sub">${L('值不可用', 'Unavailable')}</span>`;
              let parsed = null;
              try { parsed = JSON.parse(pv); } catch {}
              if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.values(parsed).every(v => v === null || typeof v !== 'object')) {
                const labels = { sha256: L('正文 SHA-256', 'Body SHA-256'), redacted: L('已脱敏', 'Redacted'), data_class: L('数据类型', 'Data class'), evidence_level: L('证据级别', 'Evidence level'), decision: L('判定', 'Decision'), status: L('状态', 'Status'), op: L('操作', 'Op'), mode: L('模式', 'Mode'), profile: L('策略', 'Profile') };
                const fmtVal = (k, v) => v === null ? 'null' : k === 'data_class' ? (DATA_LABEL[v] || String(v)) : k === 'evidence_level' ? (EVIDENCE_LABEL[v] || String(v)) : (k === 'channel' || k === 'channel_class') ? (CHANNEL_LABEL[v] || String(v)) : String(v);
                return `<dl class="kv">${Object.entries(parsed).map(([k, v]) => `<dt>${esc(labels[k] || tr(k))}</dt><dd>${esc(fmtVal(k, v))}</dd>`).join('')}</dl>`;
              }
              const txt = parsed && typeof parsed === 'object' ? JSON.stringify(parsed, null, 2) : pv;
              return `<pre class="code-box" style="max-height:220px">${esc(txt)}</pre>`;
            };
            const sideActs = (side, sideRun) => {
              const rec = (r[side] || [])[0];
              if (!rec) return '';
              return `<span class="cmp-box-acts">${canRead(rec) ? `<button type="button" class="wb-btn sm" data-cmp-read="${rIdx}:${side}" data-cmp-run="${esc(sideRun)}">${isFile ? L('放大正文', 'Expand text') : L('阅读记录', 'Read record')}</button>` : ''}${canGraph(rec) ? `<button type="button" class="wb-btn sm" data-cmp-graph="${rIdx}:${side}" data-cmp-run="${esc(sideRun)}">${L('图中定位', 'Graph')}</button>` : ''}</span>`;
            };
            const sidePanel = (side, run) => {
              const records = r[side] || [], rec = records[0];
              const contents = isFile && rec ? `
                ${records.length > 1 ? `<select class="cmp-version" data-version aria-label="${esc(L('选择已保存版本', 'Choose saved version'))}">${records.map((v,i)=>`<option value="${i}">${i+1}/${records.length} · ${esc(v.evidence?.recorded_at || v.evidence?.node || '')}</option>`).join('')}</select>` : ''}
                <div class="cmp-inline" data-inline-side="${side}"></div>
                <details class="cmp-meta"><summary>${L('证据字段', 'Evidence fields')}</summary>${records.map((v,i)=>`<div data-meta-version="${i}" ${i ? 'hidden' : ''}>${sideVal(side,v)}</div>`).join('')}</details>` : sideVal(side,rec);
              return `<div class="cmp-box"><h4><span>${side.toUpperCase()} · ${esc(runTitle(run))}</span>${sideActs(side,run)}</h4>${contents}</div>`;
            };
            const isOpen = rIdx === (autoOpenIdx >= 0 ? autoOpenIdx : 0) ? ' open' : '';
            return `
              <details class="cmp-row" data-row="${rIdx}"${isOpen}>
                <summary>
                  <div class="cmp-sum-main"><span class="cmp-chev" aria-hidden="true">›</span><div style="min-width:0;overflow-wrap:anywhere"><strong style="font-family:var(--mono);font-size:12.5px">${esc(r.label)}</strong> <span class="wb-ins-sub">${esc(opLabel)}</span></div></div>
                  <span class="pill-tag ${stCls}">${esc(st)}</span>
                </summary>
                <div class="cmp-sides">
                  ${sidePanel('a',ra)}${sidePanel('b',rb)}
                </div>
              </details>
            `;
          }).join('') : `<div class="empty">${L('此维度下无实质差异。', 'No substantive differences in this dimension.')}</div>`}
        </div>
        <details style="margin-top:12px;font-size:12px;color:var(--muted)"><summary style="cursor:pointer">${L('对照扫描统计与覆盖范围', 'Comparison scan stats & coverage')}</summary><p>A: ${built.a.sources} sources · ${built.a.records.length} records | B: ${built.b.sources} sources · ${built.b.records.length} records</p></details>
      `;

      body.querySelectorAll('[data-cdim]').forEach(btn => { btn.onclick = () => { dim = btn.dataset.cdim; renderCmp(ra, rb); }; });
      const versionIndex = box => Number(box.querySelector('[data-version]')?.value || 0);
      body.querySelectorAll('details[data-row]').forEach(el => {
        const row = rows[+el.dataset.row];
        function read(slot) {
          const side = slot.dataset.inlineSide, box = slot.closest('.cmp-box'), i = versionIndex(box);
          if (slot.dataset.loaded === String(i)) return;
          slot.dataset.loaded = String(i);
          box.querySelectorAll('[data-meta-version]').forEach(v => { v.hidden = +v.dataset.metaVersion !== i; });
          const reader = document.createElement('div');
          slot.replaceChildren(reader);
          mountEvidenceReader(reader, side === 'a' ? ra : rb, row[side][i]?.evidence);
        }
        const loadOpen = () => { if (el.open) el.querySelectorAll('[data-inline-side]').forEach(read); };
        el.addEventListener('toggle',loadOpen);
        el.querySelectorAll('[data-version]').forEach(s => { s.onchange = loadOpen; });
        loadOpen();
      });
      body.querySelectorAll('[data-cmp-read]').forEach(btn => {
        btn.onclick = () => {
          const [idxStr, side] = btn.dataset.cmpRead.split(':');
          const row = rows[+idxStr], rec = row?.[side]?.[versionIndex(btn.closest('.cmp-box'))], targetRun = btn.dataset.cmpRun;
          if (!rec?.evidence) return;
          openInfoModal(`${side.toUpperCase()} · ${runTitle(targetRun)} · ${row.label}`, '<div class="cmp-expanded"></div>');
          mountEvidenceReader($('#wb-info-body .cmp-expanded'),targetRun,rec.evidence,true);
        };
      });
      body.querySelectorAll('[data-cmp-graph]').forEach(btn => {
        btn.onclick = () => {
          const [idxStr, side] = btn.dataset.cmpGraph.split(':');
          const rec = rows[+idxStr]?.[side]?.[versionIndex(btn.closest('.cmp-box'))];
          locateEvidenceInGraph(btn.dataset.cmpRun, rec?.evidence);
        };
      });
      $('#cmp-only').onchange = e => { onlyDiff = e.target.checked; renderCmp(ra, rb); };
      $('#cmp-meta-toggle')?.addEventListener('click', () => { showMeta = !showMeta; renderCmp(ra, rb); });
      $('#cmp-cache-toggle')?.addEventListener('click', () => { showCacheFiles = !showCacheFiles; renderCmp(ra, rb); });
      $('#cmp-swap').onclick = () => runLoad(rb, ra);
      $('#cmp-a').onchange = $('#cmp-b').onchange = () => {
        const na = $('#cmp-a').value, nb = $('#cmp-b').value;
        if (na !== nb && known(na) && known(nb)) runLoad(na, nb);
        else { $('#cmp-a').value = ra; $('#cmp-b').value = rb; }
      };
    }

    await runLoad(a, b);
  }

  // --- Full Interactive Search Modal (Category filter + Pagination + Read body + Locate in Graph!) ---
  function openSearch() {
    const dlg = $('#wb-search-dlg'), body = $('#wb-srch-body');
    if (!dlg.open) dlg.showModal();
    let scanner = null, allHits = [], lastQ = '';
    const cats = [
      ['', L('全部保存内容', 'All saved content')],
      ['messages', L('消息', 'Messages')],
      ['tools', L('工具输入与输出', 'Tools')],
      ['configuration', L('配置', 'Configuration')],
      ['files', L('已保存文件', 'Saved files')],
      ['runtime', L('运行时记录', 'Runtime records')]
    ];
    body.innerHTML = `
      <form id="wb-srch-form" style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">
        <input id="wb-srch-q" type="search" required placeholder="${esc(L('输入关键词，搜索消息、工具输出、配置、文件内容…', 'Search messages, tool outputs, config, saved files…'))}" style="flex:1;min-width:200px;padding:7px 11px;border:1px solid var(--line-strong);border-radius:8px;font-size:13px">
        <select id="wb-srch-cat" style="padding:7px 10px;border:1px solid var(--line-strong);border-radius:8px;font-size:12.5px;background:var(--surface)">${cats.map(([v, lbl]) => `<option value="${v}">${esc(lbl)}</option>`).join('')}</select>
        <button type="submit" class="wb-btn primary">${L('搜索', 'Search')}</button>
      </form>
      <div id="wb-srch-res" class="wb-ins-sub">${L('按 Enter 在当前 Run 的离线证据分片中实时检索。', 'Press Enter to search across saved evidence shards in this run.')}</div>
    `;
    const input = $('#wb-srch-q');
    input.focus();

    const catLabel = Object.fromEntries(cats.filter(([v]) => v));
    function renderHits(stats, hasMore) {
      const resBox = $('#wb-srch-res');
      if (!allHits.length) { resBox.innerHTML = `<div class="empty">${L('未找到匹配内容。', 'No matches found.')}</div>`; return; }
      resBox.innerHTML = `
        <p class="wb-ins-sub" style="margin-bottom:10px">${L('找到', 'Found')} ${allHits.length} ${L('处命中', 'matches')} (${stats.scanned} ${L('个来源', 'sources')})</p>
        ${allHits.map((h, i) => `
          <div class="wb-card">
            <div class="wb-card-h">
              <span style="font-family:var(--mono);font-size:12px">${esc(h.source.label || h.source.id)}</span>
              <div style="display:flex;align-items:center;gap:6px">
                <span class="pill-tag">${esc(catLabel[h.source.category] || tr(h.source.category || ''))}</span>
                <button type="button" class="wb-btn sm" data-srch-read="${i}">${L('阅读正文', 'Read')}</button>
                <button type="button" class="wb-btn sm" data-srch-graph="${i}">${L('图中定位', 'Graph')}</button>
              </div>
            </div>
            <pre class="code-box" style="border:0;border-radius:0;max-height:150px" data-hl="1">${esc(h.excerpt.text)}</pre>
          </div>
        `).join('')}
        ${hasMore ? `<div style="text-align:center;margin-top:10px"><button type="button" class="wb-btn" id="srch-more">${L('搜索下一页', 'Search next page')}</button></div>` : ''}
      `;
      resBox.querySelectorAll('[data-hl]').forEach(el => window.AgentEvidenceSearch.highlight(el, lastQ));
      resBox.querySelectorAll('[data-srch-read]').forEach(b => {
        b.onclick = async () => {
          const src = allHits[+b.dataset.srchRead]?.source;
          if (!src) return;
          openInfoModal(src.label || src.id, `<div class="empty">${L('正在读取正文…', 'Loading…')}</div>`);
          try {
            let txt = '';
            if (src.entry?.content?.state === 'stored') {
              const p = await api('/api/context/content?' + new URLSearchParams({ run: S.run, ref: src.entry.content.ref, offset: '0', limit: '65536' }));
              txt = p.content || '';
            } else if (src.node) {
              const art = await api('/api/artifact?' + new URLSearchParams({ run: S.run, node: src.node, mode: 'body', offset: '0', limit: '65536', view_lang: LANG }));
              txt = art.content || '';
            }
            try { const j = JSON.parse(txt); if (j && typeof j === 'object') txt = JSON.stringify(j, null, 2); } catch {}
            $('#wb-info-body').innerHTML = `<pre class="code-box" style="max-height:70vh" id="srch-full-pre">${esc(txt || L('无正文', 'No content'))}</pre>`;
            window.AgentEvidenceSearch.highlight($('#srch-full-pre'), lastQ);
          } catch (err) { $('#wb-info-body').innerHTML = `<div class="wb-alert">${esc(err.message)}</div>`; }
        };
      });
      resBox.querySelectorAll('[data-srch-graph]').forEach(b => {
        b.onclick = () => locateEvidenceInGraph(S.run, allHits[+b.dataset.srchGraph]?.source);
      });
      $('#srch-more')?.addEventListener('click', async e => {
        const btn = e.currentTarget; btn.disabled = true; btn.textContent = L('正在检索…', 'Searching…');
        const out = await scanner.next();
        allHits.push(...(out.hits || []));
        renderHits(out.stats, out.has_more);
      });
    }

    $('#wb-srch-form').onsubmit = async e => {
      e.preventDefault();
      const q = input.value.trim(); if (!q) return;
      lastQ = q; allHits = [];
      const cat = $('#wb-srch-cat').value;
      $('#wb-srch-res').innerHTML = `<div class="empty">${L('正在检索…', 'Searching…')}</div>`;
      try {
        scanner = window.AgentEvidenceSearch.create({ query: q, category: cat, scope: { run: S.run, lang: LANG, ...(S.scope || {}) }, get: api });
        const out = await scanner.next();
        if (out.error) throw new Error(out.error);
        allHits = out.hits || [];
        renderHits(out.stats, out.has_more);
      } catch (err) { $('#wb-srch-res').innerHTML = `<div class="wb-alert">${esc(err.message)}</div>`; }
    };
  }

  function openInfoModal(title, html) {
    $('#wb-info-title').textContent = title;
    $('#wb-info-body').innerHTML = html;
    if (!$('#wb-info-dlg').open) $('#wb-info-dlg').showModal();
  }
  function graphVerification(v) {
    switch (v?.status) {
      case 'ok': return {label:L('图完整性通过', 'Graph integrity passed'), tone:'ok'};
      case 'failed': return {label:L('图完整性校验失败', 'Graph integrity check failed'), tone:'bad'};
      case 'subset': return {label:L('选定证据副本', 'Selected evidence only'), tone:'warn'};
      case 'deferred': return {label:L('图校验已延后', 'Graph check deferred'), tone:'neutral'};
      case 'unavailable': return {label:L('图校验结果不可用', 'Graph check unavailable'), tone:'neutral'};
      default: return {label:L('图完整性未校验', 'Graph integrity not verified'), tone:'neutral'};
    }
  }

  function showVerifyBadge(v) {
    const {label, tone} = graphVerification(v), button = $('#wb-verify');
    button.className = 'wb-verify ' + tone;
    const suffix = IS_REPLAY ? L(' · 阅读副本', ' · Reading copy') : L(' · 本地库', ' · Local store');
    button.textContent = (tone === 'ok' ? '✓ ' : '') + label + suffix;
  }

  function openDeliveryModal() {
    const v = S.overview?.verify;
    const counts = [[v?.error_count, L('错误', 'errors')], [v?.warning_count, L('警告', 'warnings')]]
      .filter(([n]) => Number.isInteger(n) && n >= 0).map(([n, label]) => n + ' ' + label);
    openInfoModal(L('图完整性与证据交付说明', 'Graph integrity & delivery details'), `
      <dl class="kv" style="margin-bottom:16px">
        <dt>${L('当前 Run', 'Current Run')}</dt><dd>${esc(S.run)}</dd>
        <dt>${L('图完整性校验', 'Graph integrity')}</dt><dd>${esc(graphVerification(v).label)}${counts.length ? ' (' + esc(counts.join(' · ')) + ')' : ''}</dd>
        <dt>${L('数据来源', 'Data source')}</dt><dd>${IS_REPLAY ? L('只读回放。浏览器在读取数据分片时核对 SHA-256。', 'Read-only replay. The browser checks SHA-256 as each data shard is read.') : L('本地数据库', 'Local evidence store')}</dd>
        <dt>${L('从本地库导出', 'Export from a local store')}</dt><dd><code>agentprov dashboard export --run RUN_ID --output reading.zip</code></dd>
        <dt>${L('校验来源与签名信任', 'Verification source and signer trust')}</dt><dd>${L('图完整性状态取自实录中的校验结果。浏览器另行核对读取的分片和附件；接收方使用 agentprov-verify 和自己的信任策略验证签名。', 'Graph integrity is the check recorded in this run. The browser checks the shards and attachments it reads. Recipients verify signatures with agentprov-verify and their own trust policy.')}</dd>
      </dl>
      ${window.AgentProvOffline ? `<a class="wb-btn" href="../export-inventory.json" target="_blank" rel="noopener">${L('查看完整导出清单 (export-inventory.json)', 'Open export-inventory.json')}</a>` : ''}
      ${document.querySelector('meta[name="agentprov-display-projection"]') ? `<a class="wb-btn" href="../preview-projection.json" target="_blank" rel="noopener">${L('查看阅读副本的索引变更', 'View display index changes')}</a>` : ''}
    `);
  }

  // --- Data Loading ---
  async function loadGraph() {
    const epoch = ++S.reqEpoch;
    document.querySelectorAll('[data-detail]').forEach(b => b.classList.toggle('on', b.dataset.detail === S.detail));
    const q = new URLSearchParams({ run: S.run, lens: S.lens, detail: S.detail });
    if (S.scope) { q.set('harness', S.scope.harness); q.set('session', S.scope.session_id); }
    if (S.focus) q.set('focus', S.focus);
    S.overlays.forEach(o => q.append('overlay', o));
    const ovQ = new URLSearchParams({ run: S.run, lens: 'default', detail: 'summary' });
    if (S.scope) { ovQ.set('harness', S.scope.harness); ovQ.set('session', S.scope.session_id); }

    const [lens, ovLens] = await Promise.all([api('/api/lens?' + q), api('/api/lens?' + ovQ)]);
    if (epoch !== S.reqEpoch) return;
    S.lensManifest = lens;
    window._lensManifest = lens;
    S.overviewLens = ovLens;
    S.graph = adaptLens(lens);
    if (S.sel && !S.graph.nodes.find(n => n.id === S.sel)) S.sel = null;
    S.gsig = `${S.run}|${S.lens}|${S.detail}|${S.focus}|${JSON.stringify(S.scope)}|${[...S.overlays].sort().join(',')}|${S.graph.nodes.map(n => n.id).join(',')}`;
    S.times = [...new Set([...Object.values(S.graph.nodeT), ...S.graph.edges.map(e => e.t)].filter(Boolean))].sort();
    const sl = $('#wb-slider'); sl.max = S.times.length; sl.value = S.times.length; S.tcur = null;
    updateScrubLabel();
    renderLensStrip();
    renderGraph();
    renderInspector();
    if (S.focus && S.mode === 'graph' && S.sel === S.focus) {
      const host = $('#dag'), node = host.querySelector('[aria-pressed="true"]');
      if (node) {
        const box = host.getBoundingClientRect(), target = node.getBoundingClientRect();
        if (target.left < box.left || target.right > box.right) host.scrollLeft += target.left - box.left - (host.clientWidth - target.width) / 2;
        if (target.top < box.top || target.bottom > box.bottom) host.scrollTop += target.top - box.top - (host.clientHeight - target.height) / 2;
      }
    }
  }

  async function loadRun(runId, keepRoute = false) {
    S.run = runId;
    if (!keepRoute) { S.scope = null; S.sel = null; S.focus = ''; S.insTab = 'summary'; S.fit = true; S.exactFit = false; }
    S.overview = null; showVerifyBadge(null);
    S.wsItems = []; S.wsSelected = 0; S.nativeItems = []; S.nativeSelected = 0; S.handoffs = [];
    S.entries = []; S.entriesCursor = ''; S.sessionSourceFilter = '';
    S.captureManifest = []; S.captureCursor = ''; S.egress = []; S.acCounts = {};
    S.acPage = { events: [], total: 0, offset: 0, limit: 25 }; S.compliance = null;
    $('#wb-runsel').value = runId;
    syncURL();

    const q = new URLSearchParams({ run: runId });
    const [ov, ctxOv, tl, pr, ob, eg, ...acRes] = await Promise.allSettled([
      api('/api/overview?' + q),
      api('/api/context/overview?' + q),
      api('/api/timeline?' + new URLSearchParams({ run: runId, limit: '50', offset: '0' })),
      api('/api/processes?' + q),
      api('/api/outbound?' + q),
      api('/api/egress?' + q),
      ...AC_KINDS.map(([k]) => api('/api/events?' + new URLSearchParams({ run: runId, type: k, limit: '25', offset: '0' })))
    ]);
    if (S.run !== runId) return;

    S.overview = ov.status === 'fulfilled' ? ov.value : {};
    S.contextOverview = ctxOv.status === 'fulfilled' ? ctxOv.value : {};
    S.timeline = tl.status === 'fulfilled' ? { events: tl.value.events || [], total: tl.value.total || 0, offset: 0, limit: 50 } : { events: [], total: 0, offset: 0, limit: 50 };
    S.processes = pr.status === 'fulfilled' ? (pr.value || []) : [];
    S.outbound = ob.status === 'fulfilled' ? (ob.value || []) : [];
    S.egress = eg.status === 'fulfilled' ? (eg.value || []) : [];

    // Populate all 4 access control counts & default to the first non-empty category!
    let bestKind = 'access_control_state', bestPage = { events: [], total: 0, offset: 0, limit: 25 };
    AC_KINDS.forEach(([k], idx) => {
      const r = acRes[idx];
      const val = r?.status === 'fulfilled' ? r.value : { events: [], total: 0 };
      S.acCounts[k] = val.total || 0;
      if ((val.total || 0) > 0 && bestPage.total === 0) {
        bestKind = k;
        bestPage = { events: val.events || [], total: val.total || 0, offset: 0, limit: 25 };
      }
    });
    S.acKind = bestKind;
    S.acPage = bestPage;
    const acTotalAll = Object.values(S.acCounts).reduce((a, b) => a + b, 0);

    // Update verify badge
    showVerifyBadge(S.overview?.verify);

    const sigCount = groupRiskSignals(S.overview?.signals?.signals).length;
    const riskBadge = $('#cnt-risk');
    riskBadge.textContent = String(sigCount + acTotalAll);
    riskBadge.className = 'wb-count' + (sigCount ? ' risk' : '');
    $('#cnt-tl').textContent = String(S.timeline.total || 0);

    // Session scope dropdown
    const sessions = [];
    const seen = new Set();
    for (const c of (S.contextOverview?.coverage || [])) {
      const src = c.source || {};
      if (!src.session_id || !src.harness || src.harness === 'unknown') continue;
      const k = JSON.stringify([src.harness, src.session_id]);
      if (seen.has(k)) continue;
      seen.add(k); sessions.push({ harness: src.harness, session_id: src.session_id });
    }
    const sw = $('#wb-scope-wrap');
    sw.hidden = sessions.length < 2;
    if (sessions.length >= 2) {
      $('#wb-scopesel').innerHTML = `<option value="">${L('全部会话', 'All sessions')} (${sessions.length})</option>`
        + sessions.map(s => `<option value='${esc(JSON.stringify(s))}'>${esc(s.harness)} · ${esc(shortID(s.session_id))}</option>`).join('');
      $('#wb-scopesel').value = S.scope ? JSON.stringify(S.scope) : '';
    }

    // Load graph & compliance in parallel!
    await Promise.all([loadGraph(), loadComplianceForRun(runId)]);

    // Load session entries, capture manifest & execution links in parallel
    const [entRes, capRes, outLinks, inLinks] = await Promise.allSettled([
      api('/api/context/entries?' + new URLSearchParams({ run: runId, limit: '200' })),
      api('/api/capture-manifest?' + new URLSearchParams({ run: runId, limit: '20' })),
      api('/api/execution-links?' + new URLSearchParams({ run: runId, direction: 'outgoing', limit: '50' })),
      api('/api/execution-links?' + new URLSearchParams({ run: runId, direction: 'incoming', limit: '50' }))
    ]);
    if (S.run !== runId) return;

    if (entRes.status === 'fulfilled') {
      S.entries = entRes.value.entries || [];
      S.entriesCursor = entRes.value.has_more ? (entRes.value.next_cursor || '') : '';
    }
    $('#cnt-session').textContent = String(S.entries.length) + (S.entriesCursor ? '+' : '');

    if (capRes.status === 'fulfilled') {
      S.captureManifest = capRes.value.records || [];
      S.captureCursor = capRes.value.has_more ? (capRes.value.next_cursor || '') : '';
    }

    const wsRaw = S.entries.filter(x => x.kind === 'tool_result' && /(^|__)workspace_/.test(x.tool_name || ''));
    $('[data-mode="workspace"]').hidden = wsRaw.length === 0;
    if (wsRaw.length) {
      $('#cnt-ws').textContent = String(wsRaw.length);
      const items = await Promise.all(wsRaw.map(async entry => {
        if (entry.content?.state !== 'stored') return { entry, raw: '', parsed: null, pretty: '' };
        try {
          const p = await api('/api/context/content?' + new URLSearchParams({ run: runId, ref: entry.content.ref, offset: '0', limit: '65536' }));
          let parsed = null, pretty = p.content || '';
          try { parsed = JSON.parse(p.content); pretty = JSON.stringify(parsed, null, 2); } catch {}
          return { entry, raw: p.content, parsed, pretty };
        } catch { return { entry, raw: '', parsed: null, pretty: '' }; }
      }));
      if (S.run !== runId) return;
      S.wsItems = items;
      const rejectedIdx = items.findIndex(w => rejection(w.parsed));
      if (rejectedIdx >= 0) {
        $('#cnt-ws').className = 'wb-count risk';
        $('#cnt-ws').textContent = `${wsRaw.length} · ⚠`;
        S.wsSelected = rejectedIdx;
      }
    }

    S.nativeItems = S.entries.filter(x => x.browser || x.notebook || x.browser_operation || x.notebook_request || x.attachments?.length);
    $('[data-mode="native"]').hidden = S.nativeItems.length === 0;
    if (S.nativeItems.length) {
      $('#cnt-native').textContent = String(S.nativeItems.length);
      const pngIdx = S.nativeItems.findIndex(x => (x.attachments || []).some(a => a.state === 'stored' && a.media_type === 'image/png'));
      S.nativeSelected = pngIdx >= 0 ? pngIdx : 0;
    }

    S.handoffs = [
      ...(outLinks.status === 'fulfilled' ? (outLinks.value.links || []) : []),
      ...(inLinks.status === 'fulfilled' ? (inLinks.value.links || []) : [])
    ];
    $('[data-mode="handoff"]').hidden = S.handoffs.length === 0;
    if (S.handoffs.length) $('#cnt-handoff').textContent = String(S.handoffs.length);

    if (S.mode !== 'graph') setMode(S.mode);
  }

  async function boot() {
    buildShell();
    $('#wb-refresh')?.addEventListener('click', () => { if (S.run) loadRun(S.run, true); });
    S.runs = await api('/api/runs');
    const sel = $('#wb-runsel');
    if (!S.runs.length) {
      sel.innerHTML = `<option value="">${esc(L('暂无执行记录', 'No runs'))}</option>`;
      $('#wb-btn-compare').disabled = true;
      $('#wb-verify').hidden = true;
      $('#dag').innerHTML = `<div class="empty">${esc(L('暂无录制记录。运行 ./agentprov launch -- claude 开始录制。', 'No execution records yet. Record a run or open a signed demo.'))}</div>`;
      return;
    }
    sel.innerHTML = S.runs.map(r => `<option value="${esc(r.run)}" title="${esc(r.run)}">${esc(runTitle(r.run))} (${r.events})</option>`).join('');
    const cmpBtn = $('#wb-btn-compare');
    if (S.runs.length < 2) {
      cmpBtn.disabled = true;
      cmpBtn.title = L('当前回放副本仅包含 1 次执行，需 2 次及以上运行方可对比', 'Single-run copy; open a paired recording to compare');
    }
    const preferred = document.querySelector('meta[name="agentprov-default-run"]')?.content;
    const initialRun = (S.run && S.runs.some(r => r.run === S.run)) ? S.run
      : (preferred && S.runs.some(r => r.run === preferred)) ? preferred
      : S.runs[0]?.run;
    if (!initialRun) return;
    await loadRun(initialRun, initialRun === INIT.get('run') || !INIT.has('run'));
    if (!S.focus && INIT.has('compare_a') && INIT.has('compare_b') && S.runs.length >= 2) {
      openCompare(INIT.get('compare_a'), INIT.get('compare_b'), INIT.get('compare_dim') || 'auto');
    }
    document.body.dataset.tourPage = 'recording';
    document.dispatchEvent(new Event('agentprov:tour-ready'));
  }

  boot().catch(err => {
    document.body.innerHTML = `<div style="padding:32px;font-family:sans-serif"><h2>Workbench failed to load</h2><pre>${esc(err.stack || err.message)}</pre></div>`;
  });
})();
