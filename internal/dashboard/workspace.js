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
  const relationCounts = new Map();
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
    $('session-relations-open').onclick = () => openRelationships();
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
    relationCounts.clear(); updateRelationCount();
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
    labels.summary = value ? (api.nodeLabel?.(value) || value.label || id) : '';
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
    updateRelationCount();
  }
  function setOverview(value) {
    const key = JSON.stringify([value?.coverage,value?.has_more_sources]);
    if (key === reportsKey) return;
    reportsKey = key; model = sessionDirectory(value);
    relationEpoch++; relationCounts.clear(); updateRelationCount();
    const {sessions,unassigned,limited} = model;
    $('session-count').textContent = sessions.length + (limited ? '+' : '');
    const shortID = id => id.length>26 ? id.slice(0,14)+'…'+id.slice(-8) : id;
    $('session-members').innerHTML = sessions.slice(0,6).map((group,index)=>`<button data-session-index="${index}" title="${e(group.harness+' · '+group.id+(group.parent ? '\n'+t('Recorded parent session')+': '+group.parent : ''))}">${e(group.harness)} · ${e(shortID(group.id))}${group.relation === 'linked' ? `<small>${e(t('Recorded parent session'))}: ${e(shortID(group.parent))}</small>` : ''}</button>`).join('') + (sessions.length>6 ? `<button data-more-sessions>+${sessions.length-6}</button>` : '') + (!sessions.length ? `<span>${e(t('No native session identity recorded'))}</span>` : '') + (unassigned.length ? `<span>${e(api.tx('{count} sources without session identity',{count:unassigned.length}))}</span>` : '') + (limited ? `<span>${e(t('Source list is incomplete'))}</span>` : '');
    $('session-members').querySelectorAll('[data-session-index]').forEach(button=>button.onclick=()=>selectSession(Number(button.dataset.sessionIndex)));
    $('session-members').querySelector('[data-more-sessions]')?.addEventListener('click',()=>openDirectory());
    const relations = {missing:'Parent session is not in this run',conflicting:'Conflicting parent session records',self:'Invalid self-parent record',cycle:'Cyclic parent session records'};
    $('session-directory-body').innerHTML = (limited ? `<p class="context-notice">${e(t('Source report limit reached. Additional sources are not shown here.'))}</p>` : '') + sessions.map((group,index)=>{
      const parent = group.relation === 'linked' ? `<button data-parent-session="${group.target}">${e(group.parent)}</button>` : `<span>${e([...group.parents].join(', '))} · ${e(t(relations[group.relation]))}</span>`;
      return `<section class="session-item" id="session-item-${index}" tabindex="-1"><h3>${e(group.id)} <span>${e(group.harness)}</span><button data-view-session="${index}">${e(t('View session graph'))}</button></h3>${group.relation ? `<div class="session-parent">${e(t('Recorded parent session'))}: ${parent}</div>` : ''}<div class="session-relations" data-relations="${index}"><button data-relations-toggle aria-expanded="false" aria-controls="session-relations-${index}">${e(t('Related sessions'))} <span data-relation-count></span><span class="session-relations-chevron" aria-hidden="true">⌄</span></button><div data-relation-body id="session-relations-${index}" hidden></div></div>${group.reports.map(sourceHTML).join('')}</section>`;
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
      details.querySelector('[data-relations-toggle]').onclick=()=>toggleRelationships(details);
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
    relationEpoch++; relationCounts.clear(); updateRelationCount();
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
  function updateRelationCount() {
    const count=sessionScope?relationCounts.get(JSON.stringify([sessionScope.harness,sessionScope.session_id])):null;
    $('session-relations-count').hidden=count==null;
    $('session-relations-count').textContent=count??'';
  }
  function toggleRelationships(details,open) {
    const button=details.querySelector('[data-relations-toggle]');
    open=open??button.getAttribute('aria-expanded')!=='true';
    button.setAttribute('aria-expanded',String(open));
    details.querySelector('[data-relation-body]').hidden=!open;
    if(open&&!details.dataset.loaded)loadRelations(details);
    else if(open)revealRelationships(details);
  }
  function revealRelationships(details) {
    const button=details.querySelector('[data-relations-toggle]');
    if(document.activeElement===button&&button.getAttribute('aria-expanded')==='true') {
      details.closest('.session-item').scrollIntoView({block:'start'});
    }
  }
  function openRelationships() {
    openDirectory();
    const sessions=model?.sessions||[];
    let index=sessions.findIndex(group=>group.harness===sessionScope?.harness&&group.id===sessionScope?.session_id);
    if(index<0)index=Math.max(0,sessions.findIndex(group=>group.relation));
    const details=$('session-directory-body').querySelector(`[data-relations="${index}"]`);
    if(!details)return;
    toggleRelationships(details,true);
    const button=details.querySelector('[data-relations-toggle]');
    button.focus({preventScroll:true});button.scrollIntoView({block:'nearest'});
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
      const count=relations.length+(page.has_more||page.limited?'+':'');
      details.querySelector('[data-relation-count]').textContent=count;
      relationCounts.set(group.key,count);updateRelationCount();
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
      if(!cursor)revealRelationships(details);
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
  const associationList=value=>Array.isArray(value)?value.filter(x=>typeof x==='string'&&x):[];
  function associationReference(ref) {
    const label=api.evidenceLabel?.(ref)||ref;
    return `<div class="association-reference"><div>${label!==ref?`<strong>${e(label)}</strong>`:''}<code>${e(ref)}</code></div><span><button data-association-read="${e(ref)}">${e(t('Read saved evidence'))}</button><button data-association-graph="${e(ref)}">${e(t('Locate in graph'))}</button></span></div>`;
  }
  function associationActions(section) {
    section.querySelectorAll('[data-association-read],[data-association-graph]').forEach(button=>button.onclick=async()=>{
      const errorBox=section.querySelector('.association-error');errorBox.hidden=true;button.disabled=true;
      try {
        if(button.dataset.associationRead){await api.readEvidence(button.dataset.associationRead);show('content');}
        else await api.navigateGraph(button.dataset.associationGraph);
      } catch(error) {
        if(section.isConnected){errorBox.textContent=t('Recorded evidence could not be loaded.')+' '+error.message;errorBox.hidden=false;}
      } finally {if(button.isConnected)button.disabled=false;}
    });
  }
  function describeAssociation(node, host) {
    host.querySelector('[data-intent-association]')?.remove();
    if(node?.kind!=='intent_diff')return;
    const data=node.data||{}, association=data.association||{};
    const states={bound:t('Bound to a tool call'),policy_scope:t('Explicit policy scope'),candidate:t('One candidate, binding unresolved'),ambiguous:t('Multiple candidate messages'),missing:t('Intent not captured for this scope')};
    const bases={tool_call_id:t('Tool call identity'),explicit_policy_scope:t('Explicit policy scope'),validity_interval:t('Within policy validity interval'),same_agent:t('Same receiving agent'),missing_operation_binding:t('Operation binding not recorded'),message_not_after_effect:t('Message observed no later than the effect'),time_unknown:t('Capture order unknown')};
    const list=associationList;
    const refs=[...new Set(list(association.evidence_refs))];
    const candidates=Array.isArray(association.candidates)?association.candidates:[];
    const basisHTML=value=>list(value).map(b=>e(bases[b]||b)).join(' · ');
    const referenceHTML=associationReference;
    const section=document.createElement('section');
    section.className='evidence-association';section.dataset.intentAssociation=association.status||'historical';
    section.innerHTML=`<h4>${e(t('Intent association'))} <span>${e(states[association.status]||t('Recorded under an earlier analysis rule'))}</span></h4>`+
      (data.tool_call_id?`<p>${e(t('Tool call'))}: <button data-association-graph="${e(data.tool_call_id)}">${e(data.tool_call_id)}</button></p>`:'')+
      (association.basis?.length?`<p class="association-basis">${basisHTML(association.basis)}</p>`:'')+
      (candidates.length?`<p>${e(api.tx('{count} candidate messages',{count:candidates.length}))}</p><ol class="association-candidates">${candidates.map(candidate=>`<li><div class="association-basis">${basisHTML(candidate.basis)}</div>${[...new Set([candidate.source,...list(candidate.evidence_refs)])].filter(x=>typeof x==='string'&&x).map(referenceHTML).join('')}</li>`).join('')}</ol>`:'')+
      `<details><summary>${e(t('Association evidence'))}${refs.length?' · '+refs.length:''}</summary><p>${e(t('Analysis rule'))}: <code>${e(data.rule_version||t('Not recorded'))}</code></p>${refs.map(referenceHTML).join('')}</details><p class="association-error" role="status" hidden></p>`;
    host.insertBefore(section,host.querySelector('[data-node-fields]'));
    associationActions(section);
  }
  function describeEndpoint(node, host) {
    host.querySelector('[data-endpoint-association]')?.remove();
    const data=node?.data||{}, a=data.endpoint_association;
    if(!a&&!(node?.subtype==='egress_payload'||data.source==='endpoint_capture'))return;
    const section=document.createElement('section');section.className='evidence-association';section.dataset.endpointAssociation=a?.rule_version||'historical';
    if(!a){
      section.innerHTML=`<h4>${e(t('Outbound evidence'))}</h4><p>${e(t('Recorded under an earlier analysis rule'))}</p>`;
      host.insertBefore(section,host.querySelector('[data-node-fields]'));return;
    }
    const content=a.content_match||{}, source=a.source_reads||{}, execution=a.execution||{};
    const candidates=Array.isArray(source.candidates)?source.candidates:[];
    const list=associationList;
    const states={matched:t('Markers found in captured body'),capture_reported:t('Match reported by capture source'),not_matched:t('No marker match recorded'),unknown:t('Attribution unresolved'),path_unavailable:t('Source path not recorded'),candidate:t('One candidate, binding unresolved'),ambiguous:t('Multiple candidate reads'),partial:t('Some reads explicitly linked'),linked:t('Linked by capture reference and content version'),bound:t('Bound by capture operation reference'),conflicting:t('Capture reference conflicts with runtime evidence')};
    const bases={structured_path_match:t('Exact structured path'),read_before_capture:t('Read observed before capture'),read_after_capture:t('Read observed after capture'),time_unknown:t('Capture order unknown'),time_precision_overlap:t('Timestamp precision overlaps'),path_context_unknown:t('Path context not recorded'),content_sha256_match:t('Saved content version matches'),capture_source_reference:t('Explicit source reference from capture'),capture_operation_reference:t('Explicit operation reference from capture'),same_run:t('Same run'),destination_match:t('Destination matches'),execution_reference_unavailable:t('Referenced operation unavailable'),execution_reference_conflict:t('Referenced operation conflicts'),execution_identity_missing:t('Operation identity not recorded')};
    const basis=value=>list(value).map(b=>e(bases[b]||b)).join(' · ');
    const values=value=>list(value).map(s=>`<code>${e(s)}</code>`).join(' · ');
    const state=s=>e(states[s]||s||t('Not recorded'));
    section.innerHTML=`<h4>${e(t('Outbound evidence'))}</h4>`+
      `<div class="endpoint-stage" data-endpoint-stage="content"><h5>${e(t('Body content match'))}<span>${state(content.status)}</span></h5>${content.markers?.length?`<p>${values(content.markers)}</p>`:''}${content.paths?.length?`<p>${values(content.paths)}</p>`:''}</div>`+
      `<div class="endpoint-stage" data-endpoint-stage="sources"><h5>${e(t('Source-read association'))}<span>${state(source.status)}</span></h5>`+
      (candidates.length?`<details ${candidates.length<=3?'open':''}><summary>${e(api.tx('{count} source-read records',{count:candidates.length}))}</summary><ol class="association-candidates">${candidates.map(c=>`<li><p><code>${e(c.path)}</code> · ${c.status==='candidate'?e(t('Candidate source read')):state(c.status)}</p><p class="association-basis">${basis(c.basis)}</p>${list(c.evidence_refs).map(associationReference).join('')}</li>`).join('')}</ol></details>`:'')+
      (source.unresolved_references?.length?`<details><summary>${e(t('Unresolved source references'))}</summary>${list(source.unresolved_references).map(associationReference).join('')}</details>`:'')+`</div>`+
      `<div class="endpoint-stage" data-endpoint-stage="execution"><h5>${e(t('Execution attribution'))}<span>${state(execution.status)}</span></h5>`+
      (execution.basis?.length?`<p class="association-basis">${basis(execution.basis)}</p>`:'')+
      (execution.process_id?`<p>${e(t('Process'))}: <code>${e(execution.process_id)}</code></p>`:'')+
      (execution.tool_call_id?`<p>${e(t('Tool call'))}: <button data-association-graph="${e(execution.tool_call_id)}">${e(execution.tool_call_id)}</button></p>`:'')+
      list(execution.evidence_refs).map(associationReference).join('')+`</div>`+
      `<details><summary>${e(t('Association evidence'))}</summary><dl><dt>${e(t('Analysis rule'))}</dt><dd><code>${e(a.rule_version)}</code></dd><dt>${e(t('Capture time'))}</dt><dd>${e(a.observed_at||t('Not recorded'))}</dd><dt>${e(t('Ingestion time'))}</dt><dd>${e(a.ingested_at||t('Not recorded'))}</dd></dl></details><p class="association-error" role="status" hidden></p>`;
    host.insertBefore(section,host.querySelector('[data-node-fields]'));
    associationActions(section);
  }
  function tlsCaptureHTML(meta) {
    if(!meta)return '';
    const c=meta.capture, position=c?.position;
    const incomplete=meta.truncated===true || Boolean(c&&(c.state!=='complete'||c.reason||(c.data_kind&&c.data_kind!=='http_body')));
    const state=c?.state==='unresolved'?'unresolved':incomplete?'incomplete':c?'complete':'unrecorded';
    const labels={complete:t('HTTP body decoded'),incomplete:t('Capture gap recorded'),unresolved:t('Capture state unresolved'),unrecorded:t('Capture completeness not recorded')};
    const kinds={http_body:t('HTTP body'),tls_fragment:t('Raw TLS fragment'),hpack_fragment:t('Undecoded HPACK fragment'),http2_data_fragment:t('HTTP/2 data fragment')};
    const reasons={capture_limit:t('Per-call capture limit reached'),reassembly_limit:t('Reassembly buffer limit reached'),http2_frame_sequence:t('HTTP/2 frame sequence interrupted'),unsupported_header_frame:t('Unsupported HTTP/2 header frame'),hpack_decode_failed:t('HPACK state could not be decoded'),connection_state_evicted:t('Connection parsing state evicted'),tls_call_sequence:t('TLS call sequence has a gap'),tls_chunk_sequence:t('TLS byte sequence has a gap or reordering'),tls_sequence_reset:t('TLS capture sequence changed'),invalid_tls_chunk_metadata:t('TLS byte position metadata is invalid'),invalid_capture_metadata:t('Capture metadata is invalid')};
    const field=(label,value)=>value==null||value===''?'':`<dt>${e(label)}</dt><dd><code>${e(value)}</code></dd>`;
    const fields=field(t('Analysis rule'),c?.rule)+field(t('Content encoding'),meta.content_encoding)+
      field(t('Capture stream'),position?.stream_id)+field(t('TLS call sequence'),position?.call_sequence)+
      (position?.checkpoint?field(t('Record kind'),t('Sequence checkpoint')):field(t('Byte offset in call'),position?.offset)+field(t('TLS call bytes'),position?.total_bytes));
    return `<section class="evidence-association tls-capture" data-tls-capture="${state}"><h4>${e(t('Message completeness'))}<span>${e(labels[state])}</span></h4>`+
      (c?.data_kind?`<p>${e(kinds[c.data_kind]||c.data_kind)}</p>`:'')+
      (c?.reason?`<p>${e(reasons[c.reason]||c.reason)}</p>`:'')+
      (incomplete?`<p class="association-basis">${e(t('Retained fragments are displayed without model-intent interpretation.'))}</p>`:'')+
      (fields?`<details><summary>${e(t('Capture metadata'))}</summary><dl class="tls-fields">${fields}</dl></details>`:'')+`</section>`;
  }
  function describeTLS(node,host) {
    host.querySelector('[data-tls-capture]')?.remove();
    if(!node || !['tls_write','tls_read','llm_message'].includes(node.subtype))return;
    const holder=document.createElement('div');holder.innerHTML=tlsCaptureHTML(node.data||{});
    host.insertBefore(holder.firstElementChild,host.querySelector('[data-node-fields]'));
  }
  function readingState() {return {tab,dismissed};}
  function restoreReading(value) {
    if(value&&Object.hasOwn(panels,value.tab)){tab=value.tab;dismissed=value.dismissed===true;renderReader();}
  }
  return {init,setRun,setNode,setEvents,setContent,show,setOverview,overviewError,setSource,setSession,sessionDirectory,setReturn,readingState,restoreReading,describeAssociation,describeEndpoint,describeTLS,tlsCaptureHTML};
})();
