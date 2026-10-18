window.AgentSearchUI = (() => {
  'use strict';
  const $=id=>document.getElementById(id),cache=new Map();
  let api,current=null,loan=null,controller=null,epoch=0,selectEpoch=0,returnView=null;
  const t=value=>api.tr(value),esc=value=>api.esc(String(value ?? ''));
  const categoryNames={messages:'Messages',tools:'Tool inputs and outputs',configuration:'Configuration',files:'Saved files',runtime:'Runtime records'};
  const scopeKey=scope=>JSON.stringify([scope.run,scope.harness || '',scope.session_id || '']);
  function init(options) {
    api=options;
    $('search-close').onclick=()=>$('search-dialog').close();
    $('search-dialog').addEventListener('close',close);
    $('search-form').onsubmit=event=>{event.preventDefault();start();};
    $('search-stop').onclick=()=>controller?.abort();
    $('search-more').onclick=()=>next();
    $('search-scope').onchange=()=>{controller?.abort();resetResults();};
    $('search-category').onchange=()=>{controller?.abort();resetResults();};
    $('search-results').onscroll=()=>{if(current)current.scroll=$('search-results').scrollTop;};
    $('search-source').onchange=()=>select(current.selected,Number($('search-source').value));
    $('search-raw').onclick=()=>{
      const hit=current.hits[current.selected],source=hit?.sources[current.source || 0];
      if(source)window.AgentContextUI.searchEvidence(source,{raw:true},'');
    };
    $('search-return').onclick=()=>open(true).catch(showError);
  }
  function fresh(scope) {return {scope,query:'',category:'',whole:false,hits:[],selected:-1,source:0,scroll:0,reading:null,stats:{scanned:0,bytes:0,unavailable:0,states:{}},hasMore:false,engine:null,started:false};}
  function showError(error){$('search-status').textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);}
  async function open(returning=false) {
    if($('search-dialog').open){$('search-query').focus();return;}
    if(returning && returnView){const value=returnView;returnView=null;$('search-return').hidden=true;await api.restoreView(value);}
    const scope=api.scope(),key=scopeKey(scope);
    if(!scope.run)return;
    if(!cache.has(key))cache.set(key,fresh(scope));
    current=cache.get(key);current.scope=scope;
    if(cache.size>8)cache.delete(cache.keys().next().value);
    $('search-query').value=current.draft ?? current.query;$('search-category').value=current.category;
    $('search-scope').innerHTML=(scope.session_id?`<option value="session">${esc(t('Current session'))} · ${esc(scope.session_id)}</option>`:'')+`<option value="run">${esc(t('Whole run'))} · ${esc(scope.run)}</option>`;
    $('search-scope').value=scope.session_id && !current.whole ? 'session' : 'run';
    $('search-body').hidden=false;$('search-detail').hidden=current.selected<0;
    loan=window.AgentContextUI.borrowReader($('search-reader'));
    $('content-pane').hidden=current.selected<0;
    $('search-dialog').showModal();
    render();
    if(current.selected>=0)select(current.selected,current.source,true);
    $('search-results').scrollTop=current.scroll;
    $('search-query').focus();
    coverage();
  }
  function close() {
    controller?.abort();epoch++;selectEpoch++;
    if(current){current.draft=$('search-query').value;current.category=$('search-category').value;current.whole=$('search-scope').value==='run';current.scroll=$('search-results').scrollTop;saveReader();}
    window.AgentContextUI.releaseReader(loan);loan=null;
    $('search-stop').hidden=true;
    $('search-submit').disabled=false;$('search-more').disabled=false;
  }
  function scopeChanged(run,scope) {
    if(current && scopeKey(current.scope)!==scopeKey({run,...scope})){
      if($('search-dialog').open)$('search-dialog').close();
      returnView=null;$('search-return').hidden=true;
    }
  }
  function resetResults(){
    epoch++;selectEpoch++;
    Object.assign(current,{hits:[],selected:-1,source:0,scroll:0,engine:null,started:false,hasMore:false,error:'',stopped:false,reading:null,stats:{scanned:0,bytes:0,unavailable:0,states:{}}});
    $('search-submit').disabled=false;$('search-more').disabled=false;$('search-stop').hidden=true;
    $('search-detail').hidden=true;$('content-pane').hidden=true;render();coverage();
  }
  function selectedScope(){return {...current.scope,...($('search-scope').value==='run'?{harness:'',session_id:''}:{}),lang:api.lang};}
  async function start(){
    controller?.abort();resetResults();
    current.query=$('search-query').value;current.category=$('search-category').value;current.whole=$('search-scope').value==='run';
    current.draft=current.query;
    try{current.engine=window.AgentEvidenceSearch.create({query:current.query,category:current.category,scope:selectedScope(),get:api.j});current.started=true;await next();}
    catch(error){showError(error);}
  }
  async function next(){
    if(!current?.engine)return;
    const request=++epoch,active=current,engine=current.engine,abort=new AbortController();controller=abort;
    $('search-submit').disabled=true;$('search-more').disabled=true;$('search-stop').hidden=false;
    $('search-status').textContent=t('Searching saved content…');
    let last=0;
    try{
      const result=await active.engine.next({signal:abort.signal,onProgress:stats=>{
        if(request!==epoch)return;
        active.stats=stats;
        if(Date.now()-last>120){last=Date.now();$('search-status').textContent=api.tx('Checked {count} records · read {bytes} MiB',{count:stats.scanned,bytes:(stats.bytes/1048576).toFixed(1)});}
      }});
      if(active.engine!==engine)return;
      Object.assign(active,{hits:result.hits,hasMore:result.has_more,stats:result.stats,selected:-1,source:0,error:result.error,stopped:result.cancelled,scroll:0});
      if(request!==epoch)return;
      $('search-detail').hidden=true;render();
      if(active.hits.length)select(0);
    }catch(error){if(request===epoch)showError(error);}
    finally{if(request===epoch){controller=null;$('search-submit').disabled=false;$('search-more').disabled=false;$('search-stop').hidden=true;}}
  }
  function render(){
    if(!current)return;
    $('search-results').innerHTML=current.hits.map((hit,index)=>{
      const s=hit.source,x=hit.excerpt;
      const snippet=esc(x.text.slice(0,x.start))+'<mark>'+esc(x.text.slice(x.start,x.end))+'</mark>'+esc(x.text.slice(x.end));
      const truncated=hit.sources.some(source=>source.entry?.status==='source_truncated');
      const bodyState=hit.reason==='capture_policy'?window.AgentContextUI.contentReason(hit):'Content was not recorded';
      return `<button class="search-result" data-search-hit="${index}" aria-pressed="${index===current.selected}"><strong>${esc(t(categoryNames[s.category]))} · ${esc(s.label)}</strong><span class="search-excerpt">${snippet}</span><small>${esc([s.agent_id || s.harness,s.recorded_at].filter(Boolean).join(' · '))}</small><small>${esc(t(hit.matched_in==='metadata'?'Source field match':'Saved body match'))}${hit.sources.length>1?' · '+esc(api.tx('{count} source references',{count:hit.sources.length})):''}${hit.redacted?' · '+esc(t('Redacted')):''}${s.execution_scope==='prior_context'?' · '+esc(t('Includes prior context')):''}${truncated?' · '+esc(t('truncated')):''}${hit.state && hit.state!=='stored'?' · '+esc(t(bodyState)):''}</small></button>`;
    }).join('');
    $('search-results').querySelectorAll('[data-search-hit]').forEach(button=>button.onclick=()=>select(Number(button.dataset.searchHit)));
    let message=current.started ? (current.hits.length?api.tx('{count} matching records on this page',{count:current.hits.length}):t('No match found in saved content.')) : t('Search messages, tool output, configuration and saved files.');
    if(current.stopped)message=t('Search stopped; some records have not been checked.');
    else if(current.error)message=t('Search interrupted. Retry to continue.')+' '+t(current.error);
    else if(current.hasMore)message+=' '+t('More records remain to be searched.');
    $('search-status').textContent=message;
    $('search-counts').textContent=api.tx('Checked {count} records · {missing} bodies unavailable',{count:current.stats.scanned,missing:current.stats.unavailable});
    if(current.stats.policy_omitted)$('search-counts').textContent+=' · '+api.tx('{count} bodies not saved by retention settings',{count:current.stats.policy_omitted});
    $('search-more').hidden=!current.hasMore;
    $('search-missing').textContent=Object.entries(current.stats.states).map(([state,count])=>state+': '+count).join(' · ');
  }
  function saveReader(){
    if(current?.selected<0)return;
    current.reading=window.AgentContextUI.readerPosition();
  }
  async function select(index,sourceIndex=0,restore=false){
    if(!current || !current.hits[index])return;
    const request=++selectEpoch,active=current,hit=current.hits[index],source=hit.sources[sourceIndex];
    current.selected=index;current.source=sourceIndex;
    if(!restore)current.reading={offset:hit.offset,scroll:0};
    $('search-detail').hidden=false;
    $('search-results').querySelectorAll('[data-search-hit]').forEach(b=>b.setAttribute('aria-pressed',String(Number(b.dataset.searchHit)===index)));
    $('search-detail-title').textContent=source.label;
    $('search-detail-meta').textContent=[source.harness,source.session_id || t('No recorded session identity'),source.agent_id,source.tool_call_id,source.recorded_at].filter(Boolean).join(' · ');
    $('search-source').innerHTML=hit.sources.map((s,i)=>`<option value="${i}">${esc(s.source_id || s.id)}</option>`).join('');
    $('search-source').value=String(sourceIndex);$('search-source').hidden=hit.sources.length<2;
    window.AgentContextUI.searchEvidence(source,current.reading || {},current.reading?.raw ? '' : current.query);
    const links=$('search-links');links.textContent=t('loading…');
    try{
      const result=source.entry ? await api.j('/api/context/links?'+new URLSearchParams({run:current.scope.run,entry:source.entry.id})) : {links:source.graph_node?[{node_id:source.graph_node,relation:'recorded_graph_node'}]:[]};
      if(request!==selectEpoch || current!==active || !$('search-dialog').open)return;
      links.innerHTML=result.links.length?result.links.map((link,i)=>`<button data-search-link="${i}" title="${esc(link.node_id)}">${esc(t('Locate in graph'))}${result.links.length>1?' · '+esc(link.relation):''}</button>`).join(''):esc(t('No recorded graph link.'));
      links.querySelectorAll('[data-search-link]').forEach(button=>button.onclick=async()=>{
        saveReader();const destination=result.links[Number(button.dataset.searchLink)].node_id,scope=selectedScope(),saved=api.captureView();
        $('search-dialog').close();
        try{await api.navigateGraph(destination,scope);returnView=saved;$('search-return').hidden=false;}
        catch(error){await open();showError(error);}
      });
    }catch(error){if(request===selectEpoch)links.textContent=t('Session links could not be loaded.');}
  }
  async function coverage(){
    const active=current,scope=selectedScope();
    $('search-coverage').textContent=t('loading…');
    try{
      const overview=await api.j('/api/context/overview?'+new URLSearchParams({run:scope.run}));
      if(current!==active || scopeKey(selectedScope())!==scopeKey(scope))return;
      const reports=(overview.coverage||[]).filter(c=>!scope.session_id || c.source?.harness===scope.harness && c.source.session_id===scope.session_id);
      $('search-coverage').textContent=reports.map(c=>[c.source?.harness,c.status,...(c.issues||[]).map(i=>i.code)].filter(Boolean).join(' · ')).join('\n') || t('Not recorded');
      $('search-coverage').textContent=window.AgentContextUI.retentionText(overview.capture_policy,true)+'\n'+$('search-coverage').textContent;
      if(overview.has_more_sources)$('search-coverage').textContent+='\n'+t('Additional sources are not shown');
    }catch(error){if(current===active)$('search-coverage').textContent=t('Context coverage unavailable');}
  }
  return {init,open,scopeChanged};
})();
