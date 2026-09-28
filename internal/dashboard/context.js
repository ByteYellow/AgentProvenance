// Saved context is a separate evidence surface. Navigation uses recorded graph
// edges; a command string or a nearby timestamp is never a navigation identity.
window.AgentContextUI = (() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const states = new Map();
  let api, run = '', state, listRequest = 0, previewRequest = 0, summaryRequest = 0, listLoading = false;
  let overview = null, previewChoices = [], previewKey = '', previewOffsets = [0], previewPage = null;
  let formattedContent = null;
  const statusNames = {disabled:'Not enabled',no_input:'No source found',empty:'Valid empty source',ok:'Captured',partial:'Partially captured',failed:'Capture failed',ambiguous:'Ambiguous binding',legacy_not_recorded:'Not recorded in this historical run'};
  const missingNames = {approval_decision:'Approval decision','configuration.model':'Model selection','configuration.provider':'Model provider','configuration.application_version':'Application version','configuration.workdir':'Working directory','configuration.permission_mode':'Permission mode','configuration.approval_policy':'Approval policy','configuration.sandbox_policy':'Sandbox policy','configuration.directory_restrictions':'Directory restrictions','configuration.network_restrictions':'Network restrictions','configuration.mcp_servers':'MCP servers','configuration.tools':'Tool catalog','configuration.skills':'Skills','configuration.plugins':'Plugins'};
  const snapshotNames = {session_metadata:'Session metadata',source_metadata:'Source metadata',initialization:'Initialization',permission_mode:'Permission mode',source_message_event:'Source message event',source_reasoning_event:'Source reasoning event',model_proposal:'Model-proposed tool',completion_only:'Completion recorded; start not recorded',context_replacement:'Replaced context; not a new execution','permission/preset':'Permission preset','sandbox/mode':'Sandbox mode','approval/policy':'Approval policy','plan/mode':'Plan mode','request/header':'Request configuration','request/context':'Request context','model/selection':'Model selection'};
  missingNames.tool_start_time = 'Tool start time';
  missingNames['configuration.change_history_completeness'] = 'Completeness of configuration change history';
  const e = value => api.esc(value == null ? '' : String(value));
  const t = value => api.tr(value);
  const q = values => new URLSearchParams(Object.entries(values).filter(([,v]) => v !== '' && v != null)).toString();
  const unknown = value => value == null ? t('Not recorded') : String(value);
  const status = value => `<span class="context-status" data-status="${e(value)}">${e(t(statusNames[value] || value))}</span>`;
  const errorHTML = error => `<p class="context-error" role="alert">${e(t('Recorded evidence could not be loaded.'))} ${e(error.message)}</p>`;
  const notice = message => `<p class="context-notice">${e(t(message))}</p>`;
  const missingFields = fields => (fields || []).map(field => t(missingNames[field] || field)).join(', ') || t('None reported');

  function freshState() {
    return {tab:'conversation',source:'',cursor:'',history:[],pageNumber:1,page:null,selected:'',node:'',graph:'',scroll:0,open:false,expanded:new Set(),compare:[],returnView:null};
  }
  function init(options) {
    api = options;
    window.addEventListener('pagehide', persist);
    $('context-fold').addEventListener('toggle', () => {
      if (!state) return;
      state.open = $('context-fold').open;
      if (state.open && !state.page && !listLoading) loadList();
    });
    $('context-source').onchange = () => {
      state.source = $('context-source').value;
      resetPage(); loadList();
    };
    $('context-refresh').onclick = () => { resetPage(); refreshSummary(); loadList(); };
    document.querySelectorAll('[data-context-tab]').forEach(button => {
      button.onclick = () => changeTab(button.dataset.contextTab);
      button.onkeydown = event => {
        if (!['ArrowLeft','ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const tabs = [...document.querySelectorAll('[data-context-tab]')];
        const index = (tabs.indexOf(button) + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
        tabs[index].focus(); tabs[index].click();
      };
    });
    $('context-first').onclick = () => { resetPage(); loadList(); };
    $('context-prev').onclick = () => { state.cursor = state.history.pop() || ''; state.pageNumber = Math.max(1,state.pageNumber-1); loadList(); };
    $('context-next').onclick = () => { if (!state.page?.has_more) return; state.history.push(state.cursor); if(state.history.length>200)state.history.shift(); state.pageNumber++; state.cursor = state.page.next_cursor; loadList(); };
    $('context-body').onscroll = () => { if (state && !listLoading) state.scroll = $('context-body').scrollTop; };
    $('context-return').onclick = () => {
      const previous = state.returnView;
      if (previous) Object.assign(state, previous);
      else { state.node = ''; resetPage(); }
      state.returnView = null; syncControls(); loadList(true);
    };
    $('content-choice').onchange = () => { previewOffsets = [0]; loadContent(); };
    $('content-format').onchange = renderContentFormat;
    $('content-prev').onclick = () => { if (previewOffsets.length > 1) { previewOffsets.pop(); loadContent(); } };
    $('content-next').onclick = () => { if (previewPage?.has_more) { previewOffsets.push(previewPage.next_offset); loadContent(); } };
    $('content-expand').onclick = () => {
      const dialog = $('content-dialog');
      $('content-dialog-body').append($('content-pane'));
      dialog.showModal();
    };
    $('content-close').onclick = () => $('content-dialog').close();
    $('content-dialog').addEventListener('close', () => $('content-home').append($('content-pane')));
    $('context-compare-clear').onclick = () => { state.compare = []; renderCompare(); renderList(); };
    $('context-compare-run').onclick = compare;
    document.querySelectorAll('[data-context-open]').forEach(button => button.onclick = () => open(button.dataset.contextOpen));
    $('context-nav-files').onclick = () => scrollRegion('savedcontent');
  }
  function readingState() {
    if (!state) return null;
    const choice = previewChoices[Number($('content-choice').value)];
    return {run,view:{tab:state.tab,source:state.source,cursor:state.cursor,history:state.history.slice(-200),pageNumber:state.pageNumber,selected:state.selected,node:state.node,graph:state.graph,scroll:$('context-body').scrollTop,open:state.open,expanded:[...state.expanded].slice(-200)},
      preview:choice ? {entry:choice.entry?.id || '',raw:choice.node ? choice.mode === 'raw' : choice.mode === 'raw',node:choice.node || '',offsets:previewOffsets.slice(-512),scroll:$('content-body').scrollTop,format:$('content-format').value} : null};
  }
  function persist() {
    const saved = readingState();
    if (!saved) return;
    try { sessionStorage.setItem('agentprov.context.reading/v1',JSON.stringify(saved)); } catch (_) { /* Optional reading state must not block evidence access. */ }
  }
  function previousReading(nextRun) {
    try {
      const text = sessionStorage.getItem('agentprov.context.reading/v1');
      if (!text || text.length > 65536) return null;
      const saved = JSON.parse(text), view = saved.view;
      if (saved.run !== nextRun || !view || !['conversation','configuration','coverage'].includes(view.tab)) return null;
      for (const key of ['source','cursor','selected','node','graph']) if (typeof view[key] !== 'string' || view[key].length > 8192) return null;
      if (!Array.isArray(view.history) || view.history.length > 200 || !view.history.every(v=>typeof v==='string' && v.length<8192)) return null;
      if (!Array.isArray(view.expanded) || view.expanded.length>200 || !view.expanded.every(v=>typeof v==='string' && v.length<512)) return null;
      if (!Number.isFinite(view.scroll) || view.scroll < 0) return null;
      if (!Number.isSafeInteger(view.pageNumber) || view.pageNumber<1) view.pageNumber=1;
      if (saved.preview) {
        const p = saved.preview;
        if (typeof p.entry !== 'string' || p.entry.length>512 || typeof p.node !== 'string' || p.node.length>512 || !Number.isFinite(p.scroll) || p.scroll<0) return null;
        if (!Array.isArray(p.offsets) || !p.offsets.length || p.offsets.length>512 || !p.offsets.every(v=>Number.isSafeInteger(v) && v>=0 && v<=33554432)) return null;
      }
      return saved;
    } catch (_) { return null; }
  }
  async function restoreContent(saved, current) {
    if (!saved) return;
    try {
      if (saved.entry) {
        const page = await api.j('/api/context/entries?' + q({run,entry:saved.entry,revisions:true,limit:1}));
        if (state !== current || previewKey || !page.entries?.length) return;
        const entry = page.entries[0];
        setPreview(entryChoices(entry),'entry:'+entry.id,saved.raw ? 1 : 0,saved);
      } else if (saved.node) {
        if (state === current && !previewKey) {
          const node = saved.node;
          current.graph = '';
          await selectGraph(node,saved);
        }
      }
    } catch (error) { if (state === current) $('content-empty').textContent = t('Recorded evidence could not be loaded.')+' '+error.message; }
  }
  function resetPage() { state.cursor = ''; state.history = []; state.pageNumber = 1; state.page = null; state.scroll = 0; }
  function syncControls() {
    $('context-fold').open = state.open;
    document.querySelectorAll('[data-context-tab]').forEach(button => {
      const selected = button.dataset.contextTab === state.tab;
      button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1;
    });
    $('context-body').setAttribute('aria-labelledby', 'context-tab-' + state.tab);
    $('context-linked').hidden = !state.node;
    $('context-linked-label').textContent = state.node ? t('Only records connected by stored evidence edges') + ': ' + state.node : '';
    $('context-source').value = state.source;
    $('context-source').disabled = state.tab === 'coverage';
  }
  function changeTab(tab) {
    state.tab = tab; state.node = ''; state.returnView = null;
    resetPage(); syncControls(); loadList();
  }
  function scrollRegion(id) {
    const header = document.querySelector('body > header'), region = $(id);
    const inset = header && getComputedStyle(header).position === 'sticky' ? header.getBoundingClientRect().height : 0;
    region.style.scrollMarginTop = Math.ceil(inset + 12) + 'px';
    region.scrollIntoView({block:'start',behavior:'smooth'});
  }
  function open(tab) {
    if (!state) return;
    state.open = true; $('context-fold').open = true;
    if (tab && tab !== state.tab) changeTab(tab);
    else if (!state.page) loadList();
    scrollRegion('agentcontext');
  }
  function setRun(nextRun) {
    if (!nextRun) return;
    if (nextRun !== run) {
      if (state) { state.scroll = $('context-body').scrollTop; state.reading = readingState(); }
      run = nextRun;
      if (!states.has(run)) states.set(run, freshState());
      state = states.get(run);
      const saved = state.reading || previousReading(run);
      if (saved) Object.assign(state,saved.view,{expanded:new Set(saved.view.expanded)});
      else state.graph = '';
      if (states.size > 8) states.delete(states.keys().next().value);
      listRequest++; listLoading = false; previewRequest++; previewKey = ''; previewChoices = [];
      if ($('content-dialog').open) $('content-dialog').close();
      $('content-empty').hidden = false; $('content-pane').hidden = true;
      overview = null;
      $('context-summary').textContent = t('loading…');
      $('context-body').innerHTML = ''; $('context-compare').hidden = true;
      syncControls();
      if (state.open) state.page ? renderList(true) : loadList(Boolean(saved));
      restoreContent(saved?.preview,state);
    }
    refreshSummary();
  }
  async function refreshSummary() {
    const request = ++summaryRequest, currentRun = run;
    try {
      const value = await api.j('/api/context/overview?' + q({run}));
      if (request !== summaryRequest || run !== currentRun) return;
      const coverageChanged = JSON.stringify([overview?.coverage,overview?.runtime_coverage]) !== JSON.stringify([value.coverage,value.runtime_coverage]);
      overview = value;
      const reports = value.coverage || [];
      const sources = [...new Set(reports.map(c => c.source?.harness).filter(Boolean))];
      const hints = [...new Set(reports.map(c => t(statusNames[c.status] || c.status)))];
      $('context-summary').textContent = [sources.join(' / '), api.tx('{messages} message records · {calls} tool calls · {results} results', {messages:unknown(value.messages),calls:unknown(value.tool_calls),results:unknown(value.tool_results)}),reports.some(c=>c.prior_context) ? t('Includes prior context') : '',hints.join(' / ')].filter(Boolean).join(' · ');
      if (coverageChanged) $('context-source').innerHTML = `<option value="">${e(t('All recorded sessions'))}</option>` + reports.filter(c => c.source?.id).map(c => `<option value="${e(c.source.id)}">${e(c.source.harness)} · ${e(c.source.session_id || c.source.id)}</option>`).join('');
      syncControls();
      $('context-nav-count').textContent = unknown(value.messages);
      $('context-nav-tools').textContent = unknown(value.tool_calls);
      $('context-nav-config').textContent = unknown(value.snapshots);
      $('context-nav-coverage').textContent = [hints.join(' / '),value.runtime_coverage ? t('Runtime capture')+': '+t(statusNames[value.runtime_coverage.capture.status] || value.runtime_coverage.capture.status) : ''].filter(Boolean).join(' · ');
      if (state.tab === 'coverage' && state.open && coverageChanged) {
        const scroll = $('context-body').scrollTop;
        renderCoverage(); $('context-body').scrollTop = scroll;
      }
    } catch (error) {
      if (request !== summaryRequest || run !== currentRun) return;
      $('context-summary').textContent = t('Context coverage unavailable');
      if (state.open && state.tab === 'coverage') $('context-body').innerHTML = errorHTML(error);
    }
  }
  async function loadList(restore = false) {
    if (!state) return;
    if (state.tab === 'coverage') { renderCoverage(); return; }
    const request = ++listRequest, current = state;
    const scroll = current.scroll;
    listLoading = true;
    $('context-body').innerHTML = notice('loading…');
    $('context-prev').disabled = true; $('context-next').disabled = true;
    try {
      const page = await api.j('/api/context/entries?' + q({run,source:current.source,group:current.node ? '' : current.tab,node:current.node,cursor:current.cursor,limit:30}));
      if (request !== listRequest || state !== current) return;
      current.page = page;
      if (restore) current.scroll = scroll;
      renderList(restore); listLoading = false;
    } catch (error) {
      if (request !== listRequest || state !== current) return;
      listLoading = false;
      $('context-body').innerHTML = errorHTML(error);
      $('context-prev').disabled = current.history.length === 0;
    }
  }
  function recordLabel(entry) {
    if (entry.kind === 'tool_call') return t('Tool input') + ' · ' + (entry.tool_name || entry.tool_call_id);
    if (entry.kind === 'tool_result') return t('Tool result') + ' · ' + (entry.tool_name || entry.tool_call_id);
    return t(entry.role || entry.kind);
  }
  function recordHTML(entry) {
    const tool = entry.kind === 'tool_call' || entry.kind === 'tool_result';
    const snapshot = ['configuration','approval','task'].includes(entry.kind) || entry.kind === 'message' && entry.role === 'user';
    const body = `<div data-entry-body="${e(entry.id)}">${notice('loading…')}</div>`;
    const expanded = state.expanded.has(entry.id);
    const checked = state.compare.some(x => x.id === entry.id);
    return `<article class="context-record" data-entry="${e(entry.id)}" data-selected="${state.selected === entry.id}">
      <header><strong class="${entry.role === 'user' ? 'context-role' : ''}">${e(recordLabel(entry))}</strong><time>${e(entry.recorded_at || t('Source time not recorded'))}</time>${entry.status ? `<span class="context-status">${e(t(snapshotNames[entry.status] || entry.status))}</span>` : ''}</header>
      <div class="context-meta">${e(entry.source.harness)} · ${e(entry.source.session_id)} · #${e(entry.sequence)}${entry.source_ordinal ? '.' + e(entry.source_ordinal) : ''}${entry.agent_id ? ' · ' + e(entry.agent_id) : ''} · ${e(t(entry.execution_scope === 'prior_context' ? 'Prior context' : entry.execution_scope === 'current_execution' ? 'Current execution range' : 'Execution range not recorded'))}</div>
      ${tool ? `<details data-tool-body${expanded ? ' open' : ''}><summary>${e(t('Arguments / result'))}</summary>${body}</details>` : body}
      <div class="context-actions"><button data-preview="body">${e(t('Open saved content'))}</button><button data-preview="raw">${e(t('Raw source record'))}</button><button data-graph>${e(t('Locate in graph'))}</button>${snapshot ? `<button data-compare aria-pressed="${checked}">${e(t(checked ? 'Selected for comparison' : 'Compare snapshot'))}</button>` : ''}</div>
      <div class="context-link-result" aria-live="polite"></div>
      <details><summary>${e(t('Source and evidence'))}</summary><dl><dt>${e(t('Entry ID'))}</dt><dd>${e(entry.id)}</dd><dt>${e(t('Parser'))}</dt><dd>${e(entry.source.parser_version)}</dd><dt>${e(t('Binding'))}</dt><dd>${e(entry.source.binding)}</dd><dt>${e(t('Source version'))}</dt><dd>${e(entry.source.application_version || entry.source.format_version || t('Not recorded'))}</dd><dt>${e(t('Recorded workdir'))}</dt><dd>${e(entry.source.workdir || t('Not recorded'))}</dd><dt>${e(t('Missing fields'))}</dt><dd>${e(missingFields(entry.missing_fields))}</dd><dt>${e(t('Evidence references'))}</dt><dd>${e((entry.evidence_refs || []).join('\n') || t('Not recorded'))}</dd></dl></details>
    </article>`;
  }
  function renderList(restore = false) {
    if (!state.page) return;
    const entries = state.page.entries || [], current = state;
    const box = $('context-body');
    box.innerHTML = entries.length ? entries.map(recordHTML).join('') : notice(state.node ? 'No session record is linked to this node. No session was guessed.' : 'No records in this selection. See collection status for missing or unsupported sources.');
    $('context-pager').hidden = false;
    $('context-prev').disabled = !state.history.length;
    $('context-first').disabled = state.pageNumber === 1;
    $('context-next').disabled = !state.page.has_more;
    $('context-page-label').textContent = api.tx('Page {page} · {count} records', {page:state.pageNumber,count:entries.length});
    const pending = [];
    box.querySelectorAll('[data-entry]').forEach((row, index) => {
      const entry = entries[index], body = row.querySelector('[data-entry-body]');
      row.querySelectorAll('[data-preview]').forEach(button => button.onclick = () => showEntry(entry, button.dataset.preview));
      row.querySelector('[data-graph]').onclick = () => graphLinks(entry, row.querySelector('.context-link-result'));
      const compareButton = row.querySelector('[data-compare]');
      if (compareButton) compareButton.onclick = () => {
        const found = state.compare.findIndex(x => x.id === entry.id);
        if (found >= 0) state.compare.splice(found,1);
        else { if (state.compare.length === 2) state.compare.shift(); state.compare.push(entry); }
        compareButton.setAttribute('aria-pressed',String(found < 0));
        renderCompare();
      };
      const disclosure = row.querySelector('[data-tool-body]');
      if (disclosure) disclosure.ontoggle = () => {
        if (state !== current) return;
        if (disclosure.open) { current.expanded.add(entry.id); if(current.expanded.size>200)current.expanded.delete(current.expanded.values().next().value); if (!body.dataset.loaded) previewInline(entry, body, current); }
        else current.expanded.delete(entry.id);
      };
      if (!disclosure || disclosure.open) pending.push([entry,body]);
    });
    // Bound concurrent requests and body memory independently from list size.
    const worker = async () => {
      while (pending.length && state === current) { const [entry,body] = pending.shift(); await previewInline(entry,body,current); }
    };
    for (let i=0;i<4;i++) worker();
    box.scrollTop = restore ? state.scroll : 0;
    renderCompare();
  }
  async function previewInline(entry, element, current) {
    if (element.dataset.loaded) return;
    element.dataset.loaded = 'true';
    if (entry.content?.state !== 'stored' || !entry.content.ref) {
      element.innerHTML = notice(entry.content?.reason || 'Content was not recorded'); return;
    }
    try {
      const page = await api.j('/api/context/content?' + q({run:entry.run_id,ref:entry.content.ref,limit:4096}));
      if (state !== current || !element.isConnected) return;
      const readable = page.has_more ? null : readableContent(page.content,entry,t('Other recorded fields'));
      element.innerHTML = `<pre>${e(readable ?? page.content)}</pre>${page.has_more ? notice('Preview only. Open saved content to read every recorded page.') : ''}${page.redacted ? notice('Redacted before storage') : ''}`;
    } catch (error) { if (element.isConnected && state === current) element.innerHTML = errorHTML(error); }
  }
  function renderCoverage() {
    listRequest++; listLoading = false; $('context-pager').hidden = true; $('context-compare').hidden = true;
    if (!overview) { $('context-body').innerHTML = notice('loading…'); return; }
    $('context-body').innerHTML = notice('Context coverage, runtime coverage, and signature verification are separate checks.') + notice('Configuration snapshots show recorded changes only; completeness of the change history is unknown.') + renderRuntimeCoverage() + (overview.coverage || []).map(report => {
      const src = report.source || {};
      const fields = [['Session',src.session_id],['Source path',src.path],['Binding',src.binding],['Parser',src.parser_version],['Source version',src.application_version || src.format_version],['Observed at',report.observed_at],['Last successful capture',report.last_success_at],['Source range',[report.first_line,report.last_line].filter(x=>x!=null && x!==0).join(' – ')],['Missing fields',missingFields(report.missing_fields)],['Binding evidence',(src.binding_evidence || []).join('\n')]];
      const counts = value => `<div class="context-counts">${Object.entries(value || {}).map(([key,n]) => `<span>${e(t(key))}<b>${e(unknown(n))}</b></span>`).join('')}</div>`;
      const prior = report.prior_context;
      const history = prior ? `<details><summary>${e(t('Prior context'))} · ${e(t('Source range'))} ${e(prior.first_line)}–${e(prior.last_line)}</summary>${notice('Retained history is not execution in this run. Historical approvals do not authorize new actions.')}${counts(prior.counts)}<dl><dt>${e(t('Source range'))}</dt><dd>${e([prior.started_at,prior.ended_at].filter(Boolean).join(' → ') || t('Source time not recorded'))}</dd><dt>${e(t('Missing fields'))}</dt><dd>${e(missingFields(prior.missing_fields))}</dd></dl></details>` : '';
      return `<article class="context-coverage"><h3>${e(src.harness || t('Source'))} ${status(report.status)}</h3>${prior ? '<h4>'+e(t('Current execution range'))+'</h4>' : ''}${counts(report.counts)}<p class="context-notice">${e(t('Counts describe this processing range, not the whole run. Unknown counts are not zero.'))}</p><dl>${fields.map(([key,value])=>`<dt>${e(t(key))}</dt><dd>${e(value || t('Not recorded'))}</dd>`).join('')}</dl>${history}${(report.issues || []).map(issue => `<p class="context-notice">${e(t(issue.code))}${issue.line ? ' · '+e(t('line'))+' '+e(issue.line) : ''}${issue.field ? ' · '+e(issue.field) : ''}${issue.scope === 'prior_context' ? ' · '+e(t('Prior context')) : ''}</p>`).join('')}</article>`;
    }).join('') + (overview.has_more_sources ? notice('Source report limit reached. Additional sources are not shown here.') : '');
  }
  function renderRuntimeCoverage() {
    const runtime = overview?.runtime_coverage;
    if (!runtime) return notice('Runtime capture history was not recorded.');
    const capture = runtime.capture || {}, summary = runtime.correlation?.summary || {};
    const states = {disabled:'Not enabled',unavailable:'Kernel sensor unavailable',observed:'Kernel readiness confirmed',unknown:'Not recorded'};
    const counts = [['Stored runtime events',summary.runtime_events],['Scope-field gaps',summary.correlation_gap_count],['Run-specific dropped events',capture.run_dropped_events],['Node pending events at seal',capture.node_pending_events]];
    const fields = [['Kernel capture',t(states[capture.kernel_state] || 'Not recorded')],['Capture interval',[capture.started_at,capture.ended_at].filter(Boolean).join(' → ')],['Run loss assessment',t(capture.run_impact === 'no_node_loss_reported' ? 'No node loss reported; completeness is not established.' : 'Impact on this run is unknown.')],['Probe snapshots',[capture.capabilities_start?.status,capture.capabilities_end?.status].filter(Boolean).join(' → ')],['Saved capture report',capture.ref]];
    const deltas = capture.node_counter_delta;
    const heading = `<h3>${e(t('Runtime capture'))} ${status(capture.status || 'legacy_not_recorded')}</h3>
      <div class="context-counts">${counts.map(([key,value])=>`<span>${e(t(key))}<b>${e(unknown(value))}</b></span>`).join('')}</div>
      ${notice('Event totals cover all stored runtime events in this run. Scope-field coverage does not prove agent attribution or complete capture.')}`;
    if (capture.status === 'legacy_not_recorded') return `<article class="context-coverage" data-runtime-coverage>${heading}${notice('Runtime capture history was not recorded.')}</article>`;
    return `<article class="context-coverage" data-runtime-coverage>${heading}
      ${(capture.issues || []).map(issue=>notice(issue)).join('')}
      <details><summary>${e(t('Capture diagnostics'))}</summary>
      <dl>${fields.map(([key,value])=>`<dt>${e(t(key))}</dt><dd>${e(value || t('Not recorded'))}</dd>`).join('')}</dl>
      <h4>${e(t('Node counters during capture'))}</h4>
      ${notice('Node counters may include other workloads. They are not this run\'s dropped-event count. Snapshots do not prove continuous collector health.')}
      ${deltas ? `<dl>${Object.entries(deltas).sort(([a],[b])=>a.localeCompare(b)).map(([key,value])=>`<dt>${e(t(key))}</dt><dd>${e(value)}</dd>`).join('')}</dl>` : notice('Not recorded')}
      </details></article>`;
  }
  function renderCompare() {
    const entries = state.compare;
    document.querySelectorAll('[data-entry]').forEach(row => {
      const button = row.querySelector('[data-compare]');
      if (!button) return;
      const selected = entries.some(entry => entry.id === row.dataset.entry);
      button.setAttribute('aria-pressed',String(selected));
      button.textContent = t(selected ? 'Selected for comparison' : 'Compare snapshot');
    });
    $('context-compare').hidden = entries.length === 0;
    $('context-compare-label').textContent = entries.map(x => recordLabel(x) + ' · ' + (x.recorded_at || x.id)).join(' → ');
    const kind = x => x.kind === 'message' && x.role === 'user' ? 'task' : x.kind;
    $('context-compare-run').disabled = entries.length !== 2 || kind(entries[0]) !== kind(entries[1]);
    $('context-compare-result').innerHTML = '';
  }
  async function compare() {
    const current = state, ids = state.compare.map(x => x.id).join('|');
    if (state.compare.length !== 2) return;
    $('context-compare-result').innerHTML = notice('loading…');
    try {
      const result = await api.j('/api/context/compare?' + q({run,left:state.compare[0].id,right:state.compare[1].id}));
      if (state !== current || current.compare.map(x=>x.id).join('|') !== ids) return;
      const value = v => v.present ? v.preview + (v.truncated ? '\n'+t('Value preview truncated') : '') : t('Not recorded in this snapshot');
      $('context-compare-result').innerHTML = `<p>${e(t(result.status))}${result.reason ? ' · '+e(t(result.reason)) : ''}</p><div class="context-changes">${(result.changes || []).map(change => `<div class="context-change"><strong>${e(change.path || '/')}</strong><pre class="before">${e(t('Before'))}: ${e(value(change.before))}</pre><pre class="after">${e(t('After'))}: ${e(value(change.after))}</pre></div>`).join('')}</div>${result.has_more ? notice('Additional changes omitted by the comparison limit') : ''}`;
    } catch (error) { if (state === current) $('context-compare-result').innerHTML = errorHTML(error); }
  }
  async function graphLinks(entry, element) {
    const current = state;
    element.innerHTML = notice('loading…');
    try {
      const result = await api.j('/api/context/links?' + q({run,entry:entry.id}));
      if (state !== current || !element.isConnected) return;
      if (!result.links.length) { element.innerHTML = notice(result.reason === 'prior_context_not_current_execution' ? 'This is prior context, not activity in the current execution.' : 'No recorded graph link. The session record is preserved without guessing a runtime match.'); return; }
      element.innerHTML = `<div class="context-actions">${result.links.map((link,index)=>`<button data-link="${index}" title="${e(link.node_id)}">${e(t('Graph node'))} · ${e(link.relation)}</button>`).join('')}</div>${result.has_more ? notice('Additional graph links are not shown') : ''}`;
      const jump = async link => {
        state.selected = entry.id; state.graph = link.node_id;
        element.closest('[data-entry]').dataset.selected = 'true';
        try { await api.navigateGraph(run,link.node_id); }
        catch (error) { if (element.isConnected && state === current) element.innerHTML = errorHTML(error); }
      };
      element.querySelectorAll('[data-link]').forEach(button=>button.onclick=()=>jump(result.links[Number(button.dataset.link)]));
      if (result.links.length === 1) await jump(result.links[0]);
    } catch (error) { if (element.isConnected && state === current) element.innerHTML = errorHTML(error); }
  }
  function linkedSession(node) {
    if (!state) return;
    if (!state.node) state.returnView = {tab:state.tab,source:state.source,cursor:state.cursor,history:[...state.history],pageNumber:state.pageNumber,page:state.page,scroll:state.scroll,node:''};
    state.tab = 'conversation'; state.source = ''; state.node = node; state.open = true;
    resetPage(); syncControls(); loadList();
    scrollRegion('agentcontext');
  }
  function entryChoices(entry) {
    return [{label:t('Saved content')+' · '+recordLabel(entry),ref:entry.content,entry,mode:'body'}, {label:t('Raw source record')+' · '+recordLabel(entry),ref:entry.raw_content,entry,mode:'raw'}];
  }
  function showEntry(entry, kind) {
    state.selected = entry.id;
    document.querySelectorAll('[data-entry]').forEach(row=>row.dataset.selected=String(row.dataset.entry === entry.id));
    setPreview(entryChoices(entry),'entry:'+entry.id,kind === 'raw' ? 1 : 0);
    scrollRegion('savedcontent');
  }
  async function selectGraph(node,reading = null,explicit = false) {
    if (!state || !node || node === state.graph && (!explicit || previewKey === 'node:'+node)) return;
    state.graph = node;
    const current = state, currentRun = run;
    const choices = [{label:t('Recorded graph content'),node,mode:'body'}, {label:t('Raw saved object'),node,mode:'raw'}];
    setPreview(choices,'node:'+node,reading?.raw ? 1 : 0,reading);
    try {
      const page = await api.j('/api/context/entries?' + q({run,node,limit:50}));
      if (state !== current || run !== currentRun || state.graph !== node || previewKey !== 'node:'+node) return;
      const selected = previewChoices[Number($('content-choice').value)];
      previewChoices = previewChoices.filter(choice=>!choice.entry).concat((page.entries || []).flatMap(entryChoices));
      renderChoices(Math.max(0,previewChoices.indexOf(selected)));
      $('content-related').hidden = false;
      $('content-related').textContent = t(page.entries?.length ? 'Locate session records' : 'Check session linkage');
      $('content-related').onclick = () => linkedSession(node);
      $('content-limits').textContent = page.has_more ? t('More linked records are available in the paged session view.') : '';
    } catch (error) { if (state === current && state.graph === node) $('content-limits').textContent = t('Session links could not be loaded.'); }
  }
  function setPreview(choices,key,selected,reading = null) {
    previewRequest++; previewKey = key; previewChoices = choices; previewOffsets = reading?.offsets || [0]; previewPage = null;
    $('content-empty').hidden = true; $('content-pane').hidden = false;
    $('content-related').hidden = true; $('content-limits').textContent = '';
    $('content-format').value = reading?.format === 'bytes' ? 'bytes' : 'readable';
    renderChoices(selected); loadContent(reading?.scroll || 0);
  }
  function renderChoices(selected) {
    $('content-choice').innerHTML = previewChoices.map((choice,index)=>`<option value="${index}">${e(choice.label)}</option>`).join('');
    $('content-choice').value = String(selected);
  }
  // A display projection only: never rewrite the saved body, its digest or byte
  // offsets. Partial pages and deeply nested records stay byte-for-byte views.
  function readableContent(text, entry, metadataLabel = 'Other recorded fields') {
    if (typeof text !== 'string' || text.length > 65536) return null;
    let value;
    try { value = JSON.parse(text); } catch (_) { return null; }
    const pending = [[value,0]];
    while (pending.length) {
      const [node,depth] = pending.pop();
      if (typeof node === 'number' && (!Number.isFinite(node) || Number.isInteger(node) && !Number.isSafeInteger(node))) return null;
      if (!node || typeof node !== 'object') continue;
      if (depth > 12) return null;
      for (const child of Object.values(node)) pending.push([child,depth+1]);
    }
    const blocks = content => typeof content === 'string' ? content : Array.isArray(content)
      ? content.map(block => ['text','input_text','output_text'].includes(block?.type) && typeof block.text === 'string' && Object.keys(block).every(k=>k==='type'||k==='text')
        ? block.text : JSON.stringify(block,null,2)).join('\n\n') : null;
    let result;
    if (entry?.source?.harness === 'deepseek' && entry.kind === 'tool_result' && value?.message?.role === 'tool') {
      const output = blocks(value.message.content);
      if (output != null) {
        const {content,...message} = value.message;
        result = output+'\n\n'+metadataLabel+'\n'+JSON.stringify({...value,message},null,2);
      }
    } else if (['message','tool_result'].includes(entry?.kind)) result = blocks(value);
    result ??= JSON.stringify(value,null,2);
    return result.length <= 262144 ? result : null;
  }
  function renderContentFormat() {
    if (!previewPage || formattedContent == null) return;
    const readable = $('content-format').value === 'readable';
    $('content-body').textContent = readable ? formattedContent : previewPage.content;
    $('content-format-note').hidden = !readable;
  }
  async function loadContent(restoreScroll = 0) {
    const choice = previewChoices[Number($('content-choice').value)];
    if (!choice) return;
    const request = ++previewRequest, current = state, offset = previewOffsets.at(-1);
    $('content-body').textContent = t('loading…'); $('content-body').className = 'content-body';
    $('content-prev').disabled = true; $('content-next').disabled = true;
    $('content-meta').textContent = ''; $('content-page-label').textContent = '';
    formattedContent = null; $('content-format').hidden = true; $('content-format-note').hidden = true;
    try {
      if (choice.node) {
        const value = await api.j('/api/artifact?' + q({run,node:choice.node,mode:choice.mode || 'body',offset,limit:65536,view_lang:api.lang}));
        if (request !== previewRequest || state !== current) return;
        previewPage = value;
        if (value.versions?.length) {
          const selected = Number($('content-choice').value);
          for (const version of value.versions) {
            if (previewChoices.some(c=>c.node === version.ref)) continue;
            previewChoices.push({label:t('Saved version')+' · '+version.ref.slice(7,19),node:version.ref,mode:'body'}, {label:t('Raw saved object')+' · '+version.ref.slice(7,19),node:version.ref,mode:'raw'});
          }
          renderChoices(selected);
          if (value.versions_has_more) $('content-limits').textContent = t('More saved versions exist; use an exact object hash to query them.');
        }
        $('content-meta').textContent = [value.ref,value.sha256 ? t('Body SHA-256')+': '+value.sha256 : '',value.source && t(value.source),value.redacted ? t('Redacted') : ''].filter(Boolean).join(' · ');
        if (value.kind === 'unavailable' || value.kind === 'binary') $('content-body').textContent = t(value.reason || 'Content was not recorded');
        else if (value.kind === 'diff') {
          $('content-body').classList.add('diff');
          $('content-body').innerHTML = (value.content || '').split('\n').map(line => `<span class="${line.startsWith('+')?'add':line.startsWith('-')?'del':line.startsWith('@@')?'hunk':''}">${e(line)}</span>`).join('\n');
        } else $('content-body').textContent = value.content || '';
        $('content-page-label').textContent = value.total_bytes == null ? t('Recorded artifact preview') : api.tx('Bytes {start}–{end} / {total}', {start:value.offset,end:value.next_offset,total:value.total_bytes});
        $('content-prev').disabled = previewOffsets.length < 2;
        $('content-next').disabled = !value.has_more;
      } else if (choice.ref?.state !== 'stored' || !choice.ref.ref) {
        previewPage = null;
        $('content-body').textContent = t(choice.ref?.reason || 'Content was not recorded');
      } else {
        const page = await api.j('/api/context/content?' + q({run,ref:choice.ref.ref,offset,limit:65536}));
        if (request !== previewRequest || state !== current) return;
        previewPage = page;
        $('content-body').textContent = page.content;
        if (choice.mode !== 'raw' && page.offset === 0 && !page.has_more) {
          formattedContent = readableContent(page.content,choice.entry,t('Other recorded fields'));
          $('content-format').hidden = formattedContent == null;
          renderContentFormat();
        }
        $('content-meta').textContent = [page.sha256,page.media_type,page.redacted ? t('Redacted before storage') : '',choice.entry?.source.parser_version].filter(Boolean).join(' · ');
        $('content-page-label').textContent = api.tx('Bytes {start}–{end} / {total}', {start:page.offset,end:page.next_offset,total:page.total_bytes});
        $('content-prev').disabled = previewOffsets.length < 2;
        $('content-next').disabled = !page.has_more;
      }
      $('content-body').scrollTop = restoreScroll;
    } catch (error) {
      if (request !== previewRequest || state !== current) return;
      $('content-body').textContent = t('Recorded evidence could not be loaded.')+' '+error.message;
      $('content-prev').disabled = previewOffsets.length < 2;
    }
  }
  return {init,setRun,selectGraph,linkedSession,open,persist,readableContent};
})();
