window.AgentWorkspaceUI = (() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const panels = {summary:'detail',events:'focusedevidence',content:'savedcontent'};
  let api, run = '', tab = 'summary', dismissed = false, selectedSource = '';
  let available = {summary:false,events:false,content:false};
  let labels = {summary:'',events:'',content:''};
  let model = null, reportsKey = '';
  let sessionScope = null;
  let relationEpoch = 0;
  const t = text => api.tr(text), e = value => api.esc(String(value ?? ''));

  // Session identity comes from source metadata. Processing diagnostics and
  // application agents without a native session ID are not sessions.
  function sessionDirectory(value) {
    const groups = new Map(), unassigned = [], seen = new Set();
    for (const report of value?.coverage || []) {
      const source = report.source || {};
      if (!source.id || seen.has(source.id) || ['runtime_correlation','discovery','processing'].includes(source.channel) || source.harness === 'launch') continue;
      seen.add(source.id);
      if (!source.session_id || !source.harness || source.harness === 'unknown') { unassigned.push(report); continue; }
      const key = JSON.stringify([source.harness,source.session_id]);
      if (!groups.has(key)) groups.set(key,{key,harness:source.harness,id:source.session_id,reports:[],parents:new Set()});
      const group = groups.get(key);
      group.reports.push(report);
      if (source.parent_session_id) group.parents.add(source.parent_session_id);
    }
    const sessions = [...groups.values()];
    for (const group of sessions) {
      if (!group.parents.size) continue;
      const parents = [...group.parents];
      group.parent = parents[0];
      group.relation = parents.length > 1 ? 'conflicting' : group.parent === group.id ? 'self' : 'missing';
      if (group.relation !== 'missing') continue;
      const target = groups.get(JSON.stringify([group.harness,group.parent]));
      if (target) { group.target = sessions.indexOf(target); group.relation = 'linked'; }
    }
    // An asserted parent cycle remains visible as a conflict, never as a chain.
    const cycles = new Set();
    sessions.forEach((group,index) => {
      const path = new Set(); let cursor = index;
      while (sessions[cursor]?.relation === 'linked') {
        if (path.has(cursor)) { path.forEach(i=>cycles.add(i)); break; }
        path.add(cursor); cursor = sessions[cursor].target;
      }
    });
    cycles.forEach(index=>{ sessions[index].relation = 'cycle'; });
    return {sessions,unassigned,limited:Boolean(value?.has_more_sources)};
  }
  function init(options) {
    api = options;
    document.querySelectorAll('[data-inspection-tab]').forEach(button => {
      button.onclick = () => show(button.dataset.inspectionTab);
      button.onkeydown = event => {
        if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
        event.preventDefault();
        const buttons = [...document.querySelectorAll('[data-inspection-tab]')].filter(b=>!b.disabled);
        const index = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length-1 : (buttons.indexOf(button)+(event.key === 'ArrowRight' ? 1 : buttons.length-1))%buttons.length;
        buttons[index]?.click(); buttons[index]?.focus();
      };
    });
    $('inspection-close').onclick = () => { dismissed = true; renderReader(); };
    $('session-directory-open').onclick = () => openDirectory();
    $('session-directory-close').onclick = () => $('session-directory').close();
    $('session-scope-clear').onclick = () => api.selectSession(null);
    $('session-related-back').onclick = () => api.returnSession();
    document.querySelectorAll('[data-investigation]').forEach(button=>button.onclick=()=>{
      api[button.dataset.investigation]();
    });
    window.addEventListener('pagehide', () => {
      try { sessionStorage.setItem('agentprov.workspace.reading/v1',JSON.stringify({run,tab,dismissed})); } catch (_) { /* Optional reading state. */ }
    });
  }
  function setRun(nextRun) {
    if (run === nextRun) return;
    run = nextRun; selectedSource = ''; tab = 'summary'; dismissed = false;
    relationEpoch++;
    available = {summary:false,events:false,content:false}; model = null; reportsKey = '';
    labels = {summary:'',events:'',content:''};
    try {
      const saved = JSON.parse(sessionStorage.getItem('agentprov.workspace.reading/v1'));
      if (saved?.run === run && Object.hasOwn(panels,saved.tab)) { tab = saved.tab; dismissed = saved.dismissed === true; }
    } catch (_) { /* A stale browser preference is not evidence. */ }
    if ($('session-directory').open) $('session-directory').close();
    if ($('export-dialog').open) $('export-dialog').close();
    $('session-count').textContent = '…'; $('session-members').textContent = t('loading…');
    $('session-directory-body').textContent = t('loading…');
    $('inspection-selection').textContent = ''; $('inspection-event-count').textContent = '';
    renderReader();
  }
  function renderReader() {
    $('inspection').hidden = dismissed || !Object.values(available).some(Boolean);
    const active = available[tab] ? tab : Object.keys(panels).find(key=>available[key]);
    $('inspection-selection').textContent = labels[active] || '';
    document.querySelectorAll('[data-inspection-tab]').forEach(button => {
      const key = button.dataset.inspectionTab, selected = key === active;
      button.disabled = !available[key]; button.setAttribute('aria-selected',String(selected)); button.tabIndex = selected ? 0 : -1;
      $(panels[key]).hidden = !selected;
    });
  }
  function show(key) {
    if (!Object.hasOwn(panels,key)) return;
    // The file-evidence shortcut can open an empty reader with its useful hint.
    if (key === 'content') available.content = true;
    tab = key; dismissed = false; renderReader();
  }
  function setNode(value, explicit = false) {
    const id = value?.id || '';
    available.summary = Boolean(id);
    labels.summary = value?.label || id;
    if (explicit) { tab = 'summary'; dismissed = false; }
    renderReader();
  }
  function setEvents(value) {
    available.events = Boolean(value);
    $('inspection-event-count').textContent = value ? (value.count ?? '…') : '';
    labels.events = value?.title || '';
    renderReader();
  }
  function setContent(key,label = '') {
    available.content = Boolean(key); labels.content = label; renderReader();
  }
  function setSource(source) {
    selectedSource = source || '';
    document.querySelectorAll('[data-session-index]').forEach(button => {
      const group = model?.sessions[Number(button.dataset.sessionIndex)];
      button.setAttribute('aria-pressed',String(Boolean(sessionScope ? group?.harness === sessionScope.harness && group?.id === sessionScope.session_id : group?.reports.some(r=>r.source.id === selectedSource))));
    });
    document.querySelectorAll('[data-session-source]').forEach(button=>button.setAttribute('aria-current',String(button.dataset.sessionSource === selectedSource)));
  }
  function setSession(scope, query = null) {
    sessionScope = scope;
    $('session-scope').hidden = !scope;
    $('session-scope-label').textContent = scope ? scope.harness+' · '+scope.session_id : '';
    $('session-scope-count').textContent = query ? api.tx('{tools} linked tools · {events} linked events',{tools:query.tool_count,events:query.event_count}) : '';
    document.querySelectorAll('[data-whole-run]').forEach(el=>{el.hidden=!scope;el.textContent=api.tr('Whole run');});
    $('session-scope-clear').textContent=api.tr('Back to whole run');
    $('session-scope-explanation').textContent=api.tr('Session scope: graph, related events and conversation. Risk, collection status and auxiliary sections cover the whole run.')+' '+api.tr('Risk and auxiliary evidence links return to the whole run.');
    setSource(selectedSource);
  }
  function setOverview(value) {
    const key = JSON.stringify([value?.coverage,value?.has_more_sources]);
    if (key === reportsKey) return;
    reportsKey = key; model = sessionDirectory(value);
    const {sessions,unassigned,limited} = model;
    $('session-count').textContent = sessions.length + (limited ? '+' : '');
    const shortID = id => id.length>26 ? id.slice(0,14)+'…'+id.slice(-8) : id;
    $('session-members').innerHTML = sessions.slice(0,6).map((group,index)=>`<button data-session-index="${index}" title="${e(group.harness+' · '+group.id+(group.parent ? '\n'+t('Recorded parent session')+': '+group.parent : ''))}">${e(group.harness)} · ${e(shortID(group.id))}${group.relation === 'linked' ? `<small>${e(t('Recorded parent session'))}: ${e(shortID(group.parent))}</small>` : ''}</button>`).join('') + (sessions.length>6 ? `<button data-more-sessions>+${sessions.length-6}</button>` : '') + (!sessions.length ? `<span>${e(t('No native session identity recorded'))}</span>` : '') + (unassigned.length ? `<span>${e(api.tx('{count} sources without session identity',{count:unassigned.length}))}</span>` : '') + (limited ? `<span>${e(t('Source list is incomplete'))}</span>` : '');
    $('session-members').querySelectorAll('[data-session-index]').forEach(button=>button.onclick=()=>selectSession(Number(button.dataset.sessionIndex)));
    $('session-members').querySelector('[data-more-sessions]')?.addEventListener('click',()=>openDirectory());
    const relations = {missing:'Parent session is not in this run',conflicting:'Conflicting parent session records',self:'Invalid self-parent record',cycle:'Cyclic parent session records'};
    $('session-directory-body').innerHTML = (limited ? `<p class="context-notice">${e(t('Source report limit reached. Additional sources are not shown here.'))}</p>` : '') + sessions.map((group,index)=>{
      const parent = group.relation === 'linked' ? `<button data-parent-session="${group.target}">${e(group.parent)}</button>` : `<span>${e([...group.parents].join(', '))} · ${e(t(relations[group.relation]))}</span>`;
      return `<section class="session-item" id="session-item-${index}" tabindex="-1"><h3>${e(group.id)} <span>${e(group.harness)}</span><button data-view-session="${index}">${e(t('View session graph'))}</button></h3>${group.relation ? `<div class="session-parent">${e(t('Recorded parent session'))}: ${parent}</div>` : ''}<details class="session-relations" data-relations="${index}"><summary>${e(t('Known session relationships'))} <span data-relation-count></span></summary><div data-relation-body></div></details>${group.reports.map(sourceHTML).join('')}</section>`;
    }).join('') + (unassigned.length ? `<section class="session-item"><h3>${e(t('Sources without session identity'))}</h3>${unassigned.map(sourceHTML).join('')}</section>` : '') + (!sessions.length && !unassigned.length ? `<p class="context-notice">${e(t('No native session identity recorded'))}</p>` : '');
    $('session-directory-body').querySelectorAll('[data-session-source]').forEach(button=>button.onclick=async()=>{
      const source = button.dataset.sessionSource;
      const group = sessions.find(g=>g.reports.some(r=>r.source.id===source));
      $('session-directory').close();
      if (sessionScope && (group?.id!==sessionScope.session_id || group?.harness!==sessionScope.harness)) {
        await api.selectSession(group ? {harness:group.harness,session_id:group.id} : null);
      }
      api.selectSource(source);
    });
    $('session-directory-body').querySelectorAll('[data-parent-session]').forEach(button=>button.onclick=()=>focusSession(Number(button.dataset.parentSession)));
    $('session-directory-body').querySelectorAll('[data-view-session]').forEach(button=>button.onclick=()=>selectSession(Number(button.dataset.viewSession)));
    $('session-directory-body').querySelectorAll('[data-relations]').forEach(details=>{
      details.addEventListener('toggle',()=>{if(details.open&&!details.dataset.loaded)loadRelations(details);});
    });
    setSource(selectedSource);
  }
  function selectSession(index) {
    const group = model?.sessions[index];
    if (!group) return;
    $('session-directory').close();
    return api.selectSession({harness:group.harness,session_id:group.id});
  }
  function sourceHTML(report) {
    const source = report.source;
    const fields = [['Source',source.id],['Source path',source.path],['Parser',source.parser_version],['Binding',source.binding],['Binding evidence',(source.binding_evidence || []).join('\n')],['Evidence references',report.object_hash || report.id]];
    return `<div class="session-source"><div><strong>${e(source.channel || t('Source'))}${source.agent_id ? ' · '+e(source.agent_id) : ''}</strong><p>${e(t(report.status))} · ${e(source.binding || t('Not recorded'))}</p><details><summary>${e(t('Source and evidence'))}</summary><dl>${fields.map(([name,value])=>`<dt>${e(t(name))}</dt><dd>${e(value || t('Not recorded'))}</dd>`).join('')}</dl></details></div><button data-session-source="${e(source.id)}">${e(t('Read source records'))}</button></div>`;
  }
  function overviewError() {
    model = null; reportsKey = ''; $('session-count').textContent = '…';
    $('session-members').textContent = t('Context coverage unavailable');
    $('session-directory-body').textContent = t('Context coverage unavailable');
  }
  function focusSession(index) {
    const item = $('session-item-'+index);
    if (item) { item.focus({preventScroll:true}); item.scrollIntoView({block:'nearest'}); }
  }
  function openDirectory(index) {
    if (!$('session-directory').open) $('session-directory').showModal();
    if (index != null) focusSession(index);
  }
  async function loadRelations(details,cursor='',previous=[]) {
    const group=model?.sessions[Number(details.dataset.relations)], currentRun=run, epoch=relationEpoch;
    if(!group)return;
    const body=details.querySelector('[data-relation-body]');
    body.textContent=t('loading…');details.dataset.loaded='1';
    try {
      const query=new URLSearchParams({run,harness:group.harness,session:group.id,limit:'50'});
      if(cursor)query.set('cursor',cursor);
      const page=await api.j('/api/context/session-relations?'+query);
      if(epoch!==relationEpoch||currentRun!==run||!details.isConnected)return;
      const relations=[...previous,...page.relations];
      details.querySelector('[data-relation-count]').textContent=relations.length+(page.has_more||page.limited?'+':'');
      const kindNames={same_session:'Same native session in another run',parent:'Recorded parent / child',delegation:'Recorded delegation',fork:'Recorded fork',message_request:'Message requested'};
      const target=relation=>relation.kind==='same_session'?relation.to:relation.from.session_id===group.id?relation.to:relation.from;
      body.innerHTML=relations.map((relation,index)=>{
        const dest=target(relation), other=dest.run_ids?.length||dest.run_id&&dest.run_id!==run;
        const identity=ref=>ref.harness+' · '+ref.session_id+(ref.run_id?' · '+ref.run_id:ref.run_ids?.length?' · '+ref.run_ids.join(', '):'');
        const evidence=relation.evidence.map(ev=>`<dl><dt>${e(t('Run'))}</dt><dd>${e(ev.run_id)}</dd><dt>${e(t('Source'))}</dt><dd>${e(ev.source_id)}</dd><dt>${e(t('Binding evidence'))}</dt><dd>${e(t(ev.basis))}</dd><dt>${e(t('Evidence references'))}</dt><dd>${e(ev.object_hash)}${ev.entry_id?'<br>'+e(ev.entry_id):''}</dd>${ev.recorded_at?`<dt>${e(t('Time'))}</dt><dd>${e(ev.recorded_at)}</dd>`:''}</dl>`).join('');
        return `<article class="session-relation"><strong>${e(t(kindNames[relation.kind]||relation.kind))}</strong>`+
          `<p>${e(identity(relation.from))}${relation.kind==='same_session'?' ↔ ':' → '}${e(identity(relation.to))}</p>`+
          (other?`<small>${e(t('Other run'))}</small> `:'')+
          (dest.available?(dest.run_ids?.length?dest.run_ids.map(id=>`<button data-open-relation="${index}" data-relation-run="${e(id)}">${e(api.tx('View in {run}',{run:id}))}</button>`).join(' '):`<button data-open-relation="${index}">${e(t('View session graph'))}</button>`):`<span>${e(t('Target session is not collected or included'))}</span>`)+
          (relation.from.run_ids?.length||relation.to.run_ids?.length?`<p class="context-notice">${e(t('Native session relationship; choose an occurrence to read its run records.'))}</p>`:'')+
          (relation.issues?.length?`<p class="context-notice">${relation.issues.map(issue=>e(t(issue))).join(' · ')}</p>`:'')+
          `<details><summary>${e(t('Source and evidence'))}</summary>${evidence}</details></article>`;
      }).join('')||`<p>${e(t('No explicit session relationships found in saved records'))}</p>`;
      if(page.limited)body.insertAdjacentHTML('beforeend',`<p class="context-notice">${e(t('Relationship discovery is limited; additional sources or records may exist.'))}</p>`);
      if(page.has_more)body.insertAdjacentHTML('beforeend',`<button data-relations-more>${e(t('Load more'))}</button>`);
      body.querySelector('[data-relations-more]')?.addEventListener('click',()=>loadRelations(details,page.next_cursor,relations));
      body.querySelectorAll('[data-open-relation]').forEach(button=>button.onclick=async()=>{
        const dest={...target(relations[Number(button.dataset.openRelation)])};
        if(button.dataset.relationRun)dest.run_id=button.dataset.relationRun;
        button.disabled=true;
        try {
          if(await api.navigateSession(dest)===false)return;
          $('session-directory').close();
        } catch(error) {
          if(epoch!==relationEpoch||currentRun!==run||!details.isConnected)return;
          button.disabled=false;
          let note=body.querySelector('[data-relation-error]');
          if(!note){note=document.createElement('p');note.dataset.relationError='';note.className='context-notice';body.append(note);}
          note.textContent=t('Recorded evidence could not be loaded.')+' '+error.message;
        } finally {
          if(button.isConnected)button.disabled=false;
        }
      });
    } catch(error) {
      if(epoch!==relationEpoch||currentRun!==run||!details.isConnected)return;
      body.textContent=t('Session relationships unavailable')+' '+error.message;
      const retry=document.createElement('button');retry.textContent=t('Retry');retry.onclick=()=>loadRelations(details);body.append(retry);
    }
  }
  function setReturn(label) {
    $('session-related-back').hidden=!label;
    $('session-related-back').textContent=label?api.tx('Return to {run}',{run:label}):'';
  }
  function readingState() {return {tab,dismissed};}
  function restoreReading(value) {
    if(value&&Object.hasOwn(panels,value.tab)){tab=value.tab;dismissed=value.dismissed===true;renderReader();}
  }
  return {init,setRun,setNode,setEvents,setContent,show,setOverview,overviewError,setSource,setSession,sessionDirectory,setReturn,readingState,restoreReading};
})();
