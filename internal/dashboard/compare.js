window.AgentCompareUI=(()=>{
  'use strict';
  const $=id=>document.getElementById(id),cache=new Map();
  const dimensionNames={configuration:'Configuration',files:'File evidence',network:'Network destinations',outbound:'Outbound data types'};
  const statusNames={only_a:'Only A recorded',only_b:'Only B recorded',different:'Recorded values differ',common:'Common recorded values',unknown:'Comparison incomplete'};
  const operationNames={recorded_configuration:'Recorded configuration',configuration_unavailable:'Configuration unavailable',saved_file_version:'Saved file version',recorded_file_change:'Recorded content change',file_open:'File open attempt',file_write:'File write attempt',secret_path:'Sensitive path access record',file_rename:'File rename record',file_unlink:'File removal record',connection_attempt:'Connection attempt',dns_lookup:'DNS lookup',captured_request:'Captured request',http_request_observed:'HTTP request observed',http_response_observed:'HTTP response observed'};
  let api,current,controller,epoch=0,loan,returnView,originView,reading=null;
  const t=value=>api.tr(value),e=value=>api.esc(String(value??''));
  function init(options){
    api=options;
    $('compare-close').onclick=()=>$('compare-dialog').close();
    $('compare-dialog').addEventListener('close',()=>{cancel();if(current)current.scroll=$('compare-results').scrollTop;});
    $('compare-results').onscroll=()=>{if(current)current.scroll=$('compare-results').scrollTop;};
    $('compare-a').onchange=()=>resetPair();$('compare-b').onchange=()=>resetPair();
    $('compare-swap').onclick=()=>{const a=$('compare-a').value;$('compare-a').value=$('compare-b').value;$('compare-b').value=a;resetPair();};
    $('compare-refresh').onclick=()=>load();$('compare-stop').onclick=()=>controller?.abort();
    $('compare-only').onchange=()=>{current.only=$('compare-only').checked;current.limit=100;render();};
    $('compare-more').onclick=()=>{current.limit+=100;render();};
    $('compare-reader-close').onclick=()=>$('compare-reader-dialog').close();
    $('compare-reader-dialog').addEventListener('close',()=>{if(reading&&current)current.reading.set(reading,window.AgentContextUI.readerPosition());window.AgentContextUI.releaseReader(loan);loan=null;reading=null;});
    $('compare-return').onclick=()=>open(true).catch(showError);
  }
  function cancel(){controller?.abort();controller=null;epoch++;$('compare-stop').hidden=true;$('compare-refresh').disabled=false;}
  function fresh(run){return {origin:run,a:run,b:'',dimension:'configuration',only:true,limit:100,scroll:0,expanded:new Set(),references:new Map(),reading:new Map(),data:null};}
  async function open(returning=false){
    if($('compare-dialog').open)return;
    if(returning&&returnView){await api.restoreView(returnView);returnView=null;$('compare-return').hidden=true;}
    originView=api.captureView();
    const run=originView.run;if(!run)return;
    current=cache.get(run)||fresh(run);cache.delete(run);cache.set(run,current);if(cache.size>3)cache.delete(cache.keys().next().value);
    $('compare-only').checked=current.only;
    $('compare-dialog').showModal();$('compare-status').textContent=t('loading…');
    const request=++epoch;
    try{
      const runs=await api.j('/api/runs');
      if(request!==epoch||!$('compare-dialog').open)return;
      const options=runs.map(r=>`<option value="${e(r.run)}">${e(r.run)} (${e(r.events)})</option>`).join('');
      $('compare-a').innerHTML=options;$('compare-b').innerHTML=`<option value="">${e(t('Choose another run'))}</option>`+options;
      if(!runs.some(r=>r.run===current.a)){current.a=run;current.data=null;}
      if(!runs.some(r=>r.run===current.b)){current.b='';current.data=null;}
      $('compare-a').value=current.a;$('compare-b').value=current.b;
      $('compare-scope-note').textContent=t('Comparing two whole runs. Session filters are retained for your return, not applied to A or B.');
      if(runs.length<2)$('compare-status').textContent=t('No second run is available for comparison.');
      else $('compare-status').textContent=current.data?'':t('Choose another run');
      render();
      $('compare-results').scrollTop=current.scroll;
    }catch(error){if(request===epoch)showError(error);}
  }
  function showError(error){$('compare-status').textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);}
  function resetPair(){
    cancel();
    current.a=$('compare-a').value;current.b=$('compare-b').value;current.data=null;current.expanded.clear();current.reading.clear();current.references.clear();current.limit=100;
    render();if(current.a&&current.b&&current.a!==current.b)load();
    else $('compare-status').textContent=t(current.a===current.b?'Choose two different runs.':'Choose another run');
  }
  async function load(){
    if(!current.a||!current.b||current.a===current.b)return;
    controller?.abort();const abort=new AbortController();controller=abort;const request=++epoch,active=current;
    $('compare-stop').hidden=false;$('compare-refresh').disabled=true;$('compare-status').textContent=t('Loading comparison records…');
    try{
      const progress=side=>count=>{if(request===epoch)$('compare-status').textContent=side+' · '+api.tx('Checked {count} records',{count});};
      const a=await window.AgentRunCompare.load({run:active.a,get:api.j,signal:abort.signal,onProgress:progress('A')});
      const b=await window.AgentRunCompare.load({run:active.b,get:api.j,signal:abort.signal,onProgress:progress('B')});
      if(request!==epoch||current!==active)return;
      active.data={a,b,tasks:{},...window.AgentRunCompare.build(a,b)};
      $('compare-status').textContent=(!a.complete||!b.complete)?t('Comparison limit reached; some saved records are not included.'):t('Saved records loaded');
      render();await renderTasks(active,request);
    }catch(error){if(request===epoch)$('compare-status').textContent=error.name==='AbortError'?t('Comparison loading stopped. Retry to load both runs.'):t('Recorded evidence could not be loaded.')+' '+t(error.message);}
    finally{if(request===epoch){controller=null;$('compare-stop').hidden=true;$('compare-refresh').disabled=false;}}
  }
  function render(){
    if(!current)return;
    const data=current.data;
    if(!controller){$('compare-stop').hidden=true;$('compare-refresh').disabled=false;}
    $('compare-dimensions').innerHTML=Object.entries(dimensionNames).map(([key,label])=>`<button data-dimension="${key}" aria-pressed="${current.dimension===key}">${e(t(label))}<span>${data?data.counts[key].differences:'–'}${data?.counts[key].unknown?` <small title="${e(t('Comparison incomplete'))}">? ${data.counts[key].unknown}</small>`:''}</span></button>`).join('');
    $('compare-dimensions').querySelectorAll('button').forEach(button=>button.onclick=()=>{current.dimension=button.dataset.dimension;current.limit=100;render();});
    const unknowns=data?Object.values(data.counts).reduce((n,c)=>n+c.unknown,0):0;
    $('compare-summary').textContent=data?Object.entries(dimensionNames).map(([key,label])=>t(label)+' '+data.counts[key].differences).concat(unknowns?[t('Comparison incomplete')+' '+unknowns]:[]).join(' · '):'';
    $('compare-pair').hidden=!data;$('compare-coverage').textContent='';
    if(!data){$('compare-results').textContent='';$('compare-task-note').textContent='';$('compare-more').hidden=true;return;}
    for(const side of ['a','b']){
      const saved=data[side],coverage=saved.coverage;
      $("compare-run-"+side).textContent=saved.run;
      $("compare-task-"+side).textContent=data.tasks[side]||t('Task not recorded');
      const capture=coverage.runtime_coverage?.capture;
      const times=saved.records.filter(r=>r.evidence.entry||r.evidence.category==='runtime').map(r=>r.evidence.recorded_at).filter(at=>at&&Number.isFinite(Date.parse(at))).sort((a,b)=>Date.parse(a)-Date.parse(b));
      const interval=capture?.started_at?[capture.started_at,capture.ended_at].filter(Boolean):times.length?[times[0],times.at(-1)]:[];
      const format=at=>Number.isFinite(Date.parse(at))?new Date(at).toISOString().replace(/\.\d+Z$/,'Z'):at;
      $("compare-time-"+side).textContent=interval.length?t(capture?.started_at?'Capture interval':'Recorded event interval')+': '+interval.map(format).join(' → '):t('Time not recorded');
      const sourceLabel=c=>[c.source?.harness,c.source?.channel].filter(v=>v&&v!=='unknown').map(v=>t(v)).join(' · ');
      const sources=[...new Set([...(coverage.coverage||[]).map(sourceLabel).filter(Boolean),...saved.records.filter(r=>r.evidence.category==='runtime').map(r=>r.evidence.source_id).filter(Boolean)])];
      $("compare-source-"+side).textContent=sources.join(' / ')||t('Source not recorded');
      $("compare-capture-"+side).textContent=t('Runtime collection')+': '+t(window.AgentContextUI.coverageSections(coverage).runtime.label);
      $("compare-retention-"+side).textContent=window.AgentContextUI.retentionText(coverage.capture_policy);
      const reports=(coverage.coverage||[]).map(c=>(sourceLabel(c)||t('Source not recorded'))+': '+t(c.status||'Not recorded')+(c.missing_fields?.length?' · '+c.missing_fields.join(', '):''));
      reports.unshift(window.AgentContextUI.retentionText(coverage.capture_policy,true));
      reports.push(...(coverage.coverage||[]).map(c=>window.AgentContextUI.omissionText(c)).filter(Boolean));
      $('compare-coverage').textContent+=side.toUpperCase()+' · '+saved.run+'\n'+[...reports,...(capture?.issues||[]),...(capture?.limitations||[]),...saved.issues.map(i=>i.code+' · '+i.source_id)].join('\n')+'\n\n';
      if(coverage.has_more_sources)$('compare-coverage').textContent+=t('Additional sources are not shown')+'\n';
    }
    const relation={matching_recorded_tasks:'Recorded task texts match; execution conditions may differ.',different_recorded_tasks:'Different recorded tasks; this is a comparison of records.',task_not_recorded:'Task evidence is incomplete; this is a comparison of records.'};
    $('compare-task-note').textContent=t(relation[data.taskRelation]);
    const rows=data.rows.filter(r=>r.dimension===current.dimension&&(!current.only||r.status!=='common'));
    const shown=rows.slice(0,current.limit);
    $('compare-results').innerHTML=shown.map(row=>{
      const index=data.rows.indexOf(row);
      return `<details class="compare-row" data-compare-row="${index}" ${current.expanded.has(row.key)?'open':''}><summary><span><strong>${e(row.label)}</strong><small>${e(t(operationNames[row.operation]||api.channelLabels[row.operation]||row.operation))}</small></span><span class="compare-state compare-${row.status}">${e(t(statusNames[row.status]))}</span></summary><div class="compare-sides">${sideHTML(row,'a',index)}${sideHTML(row,'b',index)}</div></details>`;
    }).join('')||`<p class="compare-empty">${e(t(data.counts[current.dimension].total?'No differing saved values in this view.':'No records for this dimension in either run.'))}</p>`;
    $('compare-results').querySelectorAll('[data-compare-row]').forEach(details=>details.ontoggle=()=>{if(!details.isConnected)return;const key=data.rows[Number(details.dataset.compareRow)].key;if(details.open)current.expanded.add(key);else current.expanded.delete(key);});
    $('compare-results').querySelectorAll('select[data-row]').forEach(select=>select.onchange=()=>current.references.set(referenceKey(select),Number(select.value)));
    $('compare-results').querySelectorAll('[data-record-read]').forEach(button=>button.onclick=()=>readRecord(button));
    $('compare-results').querySelectorAll('[data-record-graph]').forEach(button=>button.onclick=()=>graphRecord(button));
    $('compare-results').querySelectorAll('[data-record-next]').forEach(button=>button.onclick=()=>{
      const select=$(button.dataset.recordNext),records=data.rows[Number(select.dataset.row)][select.dataset.side];
      const offset=Number(select.dataset.offset||0)+50;select.dataset.offset=String(offset>=records.length?0:offset);
      fillSources(select,records);
      current.references.set(referenceKey(select),Number(select.value));
    });
    $('compare-more').hidden=shown.length>=rows.length;
  }
  function sideHTML(row,side,index){
    const records=row[side],id='compare-ref-'+index+'-'+side;
    if(!records.length)return `<section class="compare-side"><h3>${side.toUpperCase()}</h3><p>${e(t('Not recorded on this side'))}</p></section>`;
    const values=[...new Map(records.map(r=>[r.value?.sha256||'unknown/'+(r.evidence.content?.reason||''),{value:r.value,reason:r.evidence.content?.reason}])).values()];
    const selected=Math.min(current.references.get(JSON.stringify([row.key,side]))||0,records.length-1),offset=Math.floor(selected/50)*50;
    const display=values.slice(0,8).map(v=>valueHTML(v.value,row.dimension,v.reason)).join('');
    return `<section class="compare-side"><h3>${side.toUpperCase()} <small>${e(api.tx('{count} source references',{count:records.length}))}</small></h3>${display}${values.length>8?`<p>${e(t('Additional recorded values are available through their source references.'))}</p>`:''}<select id="${id}" data-row="${index}" data-side="${side}" data-offset="${offset}" aria-label="${e(t('Source reference'))} ${side.toUpperCase()}">${sourceOptions(records,offset,selected)}</select><div class="compare-links"><button data-record-read="${id}">${e(t('Read saved evidence'))}</button><button data-record-graph="${id}">${e(t('Locate in graph'))}</button>${records.length>50?`<button data-record-next="${id}">${e(t('Next source references'))}</button>`:''}</div><p id="${id}-status" class="context-notice"></p></section>`;
  }
  function valueHTML(value,dimension,reason){
    if(reason==='capture_policy')return `<p>${e(t(window.AgentContextUI.contentReason({reason})))}</p>`;
    if(!value)return `<p>${e(t('Value unavailable'))}</p>`;
    if(!value.present)return `<p>${e(t('Value unavailable'))}</p>`;
    if(dimension!=='configuration'&&!value.truncated){
      try{
        const fields=JSON.parse(value.preview);
        if(fields&&typeof fields==='object'&&!Array.isArray(fields)&&Object.values(fields).every(v=>v===null||typeof v==='string'||typeof v==='boolean'||typeof v==='number'&&Number.isSafeInteger(v))){
          const labels={data_class:'Recorded data',evidence_level:'Evidence level',decision:'Recorded decision',sha256:'Body SHA-256',redacted:'Redacted',method:'HTTP method',protocol:'Protocol',status:'HTTP status',status_code:'HTTP status',ret:'Return value',errno:'Error number',op:'Operation',mode:'Access mode',flags:'Flags',new_path:'New path',policy_decision:'Recorded decision',blocked:'Blocked'};
          return Object.keys(fields).length?`<dl>${Object.entries(fields).map(([key,v])=>`<dt>${e(t(labels[key]||key))}</dt><dd>${e(key==='data_class'?api.dataLabels[v]||v:key==='evidence_level'?api.evidenceLabels[v]||v:v===null?'null':String(v))}</dd>`).join('')}</dl>`:`<p>${e(t('Target recorded; outcome fields unavailable.'))}</p>`;
        }
      }catch(_){}
    }
    return `<pre>${e(value.preview)}</pre>`+(value.truncated?`<small>${e(t('Value preview truncated; comparison uses its full digest.'))}</small>`:'');
  }
  function referenceKey(select){return JSON.stringify([current.data.rows[Number(select.dataset.row)].key,select.dataset.side]);}
  function sourceOptions(records,offset,selected=offset){return records.slice(offset,offset+50).map((r,i)=>`<option value="${offset+i}" ${offset+i===selected?'selected':''}>${e(r.evidence.session_id||r.evidence.source_id||r.evidence.id)} · ${e(r.evidence.recorded_at||r.evidence.id)}</option>`).join('');}
  function fillSources(select,records){select.innerHTML=sourceOptions(records,Number(select.dataset.offset||0));}
  function chosen(id){const select=$(id),side=select.dataset.side;return {source:current.data.rows[Number(select.dataset.row)][side][Number(select.value)].evidence,run:current.data[side].run};}
  function readRecord(button){
    const {source,run}=chosen(button.dataset.recordRead);
    reading=JSON.stringify([run,source.id]);
    loan=window.AgentContextUI.borrowReader($('compare-reader'));
    $('compare-reader-title').textContent=run+' · '+source.label;
    $('compare-reader-dialog').showModal();
    window.AgentContextUI.searchEvidence(source,current.reading.get(reading)||{},'',run);
  }
  async function graphRecord(button){
    const id=button.dataset.recordGraph,{source,run}=chosen(id),active=current,request=epoch;
    button.disabled=true;
    try{
      const links=source.entry?await api.j('/api/context/links?'+new URLSearchParams({run,entry:source.entry.id})): {links:source.graph_node?[{node_id:source.graph_node}]:[]};
      if(current!==active||request!==epoch||!$('compare-dialog').open)return;
      if(!links.links.length){$(id+'-status').textContent=t('No recorded graph link.');return;}
      // Offer every recorded relation rather than choosing an arbitrary tool.
      const area=$(id+'-status');area.textContent='';
      for(const link of links.links){const b=document.createElement('button');b.textContent=link.relation||t('Locate in graph');b.title=link.node_id;
        b.onclick=async()=>{const saved=originView;$('compare-dialog').close();try{await api.navigateGraph(run,link.node_id);returnView=saved;$('compare-return').hidden=false;}catch(error){await api.restoreView(saved);await open();showError(error);}};area.append(b);}
    }catch(error){if(current===active&&request===epoch)$(id+'-status').textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);}
    finally{if(button.isConnected)button.disabled=false;}
  }
  async function renderTasks(active,request){
    for(const side of ['a','b']){
      const record=active.data[side].records.find(r=>r.dimension==='task'&&r.evidence.entry?.content.state==='stored');
      active.data.tasks[side]=t('Task not recorded');$('compare-task-'+side).textContent=active.data.tasks[side];
      if(!record)continue;
      try{const page=await api.j('/api/context/content?'+new URLSearchParams({run:active.data[side].run,ref:record.evidence.entry.content.ref,offset:'0',limit:'4096'}),{signal:controller?.signal});
        if(current!==active||request!==epoch)return;
        let text=page.content;try{const parsed=JSON.parse(text);if(typeof parsed==='string')text=parsed;}catch(_){}
        active.data.tasks[side]=text.slice(0,200)+(text.length>200||page.has_more?'…':'');$('compare-task-'+side).textContent=active.data.tasks[side];
      }catch(error){if(current===active&&request===epoch)$('compare-task-'+side).textContent=t('Recorded evidence could not be loaded.');}
    }
  }
  return {init,open};
})();
