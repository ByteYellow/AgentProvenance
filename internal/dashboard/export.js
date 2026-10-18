window.AgentExportUI=(()=>{
  'use strict';
  const $=id=>document.getElementById(id);
  const names={messages:'Messages',tools:'Tool inputs and outputs',configuration:'Configuration',files:'Saved files',runtime:'Runtime records'};
  const reasons={outside_scope:'Outside selected session',excluded_record:'Explicit record exclusions',excluded_category:'Excluded categories',linked_record_excluded:'Linked readers and revisions'};
  let api,scope,draft,preview,controller,catalogController,loan,cleanup=Promise.resolve(),epoch=0,catalogEpoch=0,downloadRequested=false,opening=false,page=0,catalog;
  const t=s=>api.tr(s),e=s=>api.esc(String(s??''));
  const bytes=n=>new Intl.NumberFormat(api.lang,{maximumFractionDigits:2}).format(n/1048576)+' MiB';
  const base=id=>'/api/replay/previews/'+encodeURIComponent(id);
  const scopeKey=s=>JSON.stringify([s?.run,s?.harness||'',s?.session_id||'']);
  const selectedScope=()=>({run:scope.run,...(draft.scope==='session'?{harness:scope.harness,session:scope.session_id}:{})});
  function selection(){return {run:scope.run,scope:draft.scope,...(draft.scope==='session'?{harness:scope.harness,session_id:scope.session_id}:{}),exclude_records:[...draft.records].sort(),exclude_categories:[...draft.categories].sort()};}
  async function request(path,options={}){
    const response=await fetch(path,{...options,headers:{'X-AgentProv-Export':'1','Content-Type':'application/json',...options.headers},cache:'no-store'});
    if(!response.ok){let data;try{data=await response.json();}catch(_){}throw new Error(data?.error||'HTTP '+response.status);}
    return response.status===204?null:response.json();
  }
  function init(options){
    api=options;
    $('export-close').onclick=()=>$('export-dialog').close();
    $('export-dialog').addEventListener('close',()=>{
      controller?.abort();controller=null;epoch++;stopCatalog();closeReader();
      if(!downloadRequested)discard();
    });
    $('content-dialog').addEventListener('close',closeReader);
    $('export-ack').onchange=()=>{$('export-prepare').disabled=!$('export-ack').checked;};
    $('export-prepare').onclick=()=>prepare();
    $('export-stop').onclick=()=>controller?.abort();
    $('export-discard').onclick=async()=>{const current=++epoch;await discard();if(current===epoch&&$('export-dialog').open)reset();};
    $('export-files-prev').onclick=()=>{page=Math.max(0,page-1);renderFiles();};
    $('export-files-next').onclick=()=>{page++;renderFiles();};
    $('export-download').onclick=()=>download();
    document.querySelectorAll('input[name="export-scope"]').forEach(input=>input.onchange=()=>{
      draft.scope=input.value;draft.records.clear();resetCatalog();closeReader();syncSelection();
      if($('export-record-picker').open)loadRecords();
    });
    $('export-category-options').innerHTML=Object.entries(names).map(([key,label])=>`<label><input type="checkbox" data-export-category="${key}" checked>${e(t(label))}</label>`).join('');
    $('export-category-options').querySelectorAll('input').forEach(input=>input.onchange=()=>{
      if(input.checked)draft.categories.delete(input.dataset.exportCategory);else draft.categories.add(input.dataset.exportCategory);
      syncSelection();
    });
    $('export-record-picker').addEventListener('toggle',()=>{if($('export-record-picker').open&&!catalog?.loaded&&!preview)loadRecords();});
    $('export-record-clear').onclick=()=>{draft.records.clear();syncSelection();};
    $('export-record-retry').onclick=()=>loadRecords();
    $('export-record-prev').onclick=()=>{if(!catalog.history.length)return;catalog.cursor=catalog.history.pop();catalog.page--;loadRecords();};
    $('export-record-next').onclick=()=>{if(!catalog.next)return;catalog.history.push(catalog.cursor);if(catalog.history.length>200)catalog.history.shift();catalog.cursor=catalog.next;catalog.page++;loadRecords();};
    window.addEventListener('pagehide',()=>{if(preview&&!downloadRequested)fetch(base(preview.id),{method:'DELETE',headers:{'X-AgentProv-Export':'1'},keepalive:true}).catch(()=>{});});
  }
  function stopCatalog(){catalogController?.abort();catalogController=null;catalogEpoch++;}
  function resetCatalog(){stopCatalog();catalog={sources:[],cursor:'',history:[],next:'',page:1,loaded:false};}
  function closeReader(){
    if(!loan)return;
    if($('content-dialog').open)$('content-dialog').close();
    window.AgentContextUI.releaseReader(loan);loan=null;
  }
  function inspect(source){
    if(!loan)loan=window.AgentContextUI.borrowReader($('export-reader'));
    window.AgentContextUI.searchEvidence(source,{},'',scope.run);
    $('content-expand').click();
  }
  async function discard(){
    const old=preview;preview=null;downloadRequested=false;
    if(old)cleanup=cleanup.then(()=>request(base(old.id),{method:'DELETE'})).catch(()=>{});
    await cleanup;
  }
  function reset(){
    $('export-result').hidden=true;$('export-prepare').hidden=false;$('export-stop').hidden=true;
    $('export-settings').hidden=false;$('export-settings').disabled=false;$('export-ack-label').hidden=false;
    $('export-ack').disabled=false;$('export-status').textContent='';syncSelection();
  }
  function syncSelection(render=true){
    $('export-ack').checked=false;$('export-prepare').disabled=true;
    const session=draft.scope==='session';
    document.querySelectorAll('input[name="export-scope"]').forEach(input=>input.checked=input.value===draft.scope);
    $('export-category-options').querySelectorAll('input').forEach(input=>input.checked=!draft.categories.has(input.dataset.exportCategory));
    $('export-scope-note').textContent=t(session?'Only this session’s explicitly linked records. Other sessions and unassigned evidence stay outside the copy.':'All sessions and unassigned evidence, subject to the exclusions below.');
    $('export-ack-text').textContent=t(session?'Confirm this session and the selected categories and records.':'Confirm the whole run and the selected categories and records.');
    $('export-excluded-count').textContent=api.tx('{count} record exclusions',{count:draft.records.size});
    $('export-record-clear').disabled=draft.records.size===0;
    if(render)renderRecords();
  }
  async function open(){
    if(opening||$('export-dialog').open)return;
    opening=true;
    try{await openDialog();}finally{opening=false;}
  }
  async function openDialog(){
    const next=api.scope();if(!next.run)return;
    const changed=scopeKey(scope)!==scopeKey(next);
    if(preview&&(changed||Date.parse(preview.expires_at)<=Date.now()))await discard();
    await cleanup;
    if(changed||!draft){draft={scope:'whole_run',records:new Set(),categories:new Set()};resetCatalog();$('export-record-picker').open=false;}
    scope=next;reset();
    $('export-run').textContent=scope.run;
    $('export-session').hidden=!scope.session_id;
    $('export-session').textContent=scope.session_id?t('Current session filter')+': '+scope.harness+' · '+scope.session_id:'';
    $('export-session-option').hidden=!scope.session_id;
    const replay=Boolean(window.AgentProvReplay);
    $('export-local-only').hidden=!replay;$('export-controls').hidden=replay;
    $('export-dialog').showModal();
    if(preview)render();else if(!replay&&$('export-record-picker').open)loadRecords();
  }
  async function loadRecords(){
    if(!$('export-dialog').open||preview||controller||window.AgentProvReplay)return;
    stopCatalog();const current=catalogEpoch,abort=new AbortController();catalogController=abort;
    $('export-record-status').textContent=t('loading…');$('export-record-retry').hidden=true;
    $('export-record-prev').disabled=true;$('export-record-next').disabled=true;
    try{
      let result,cursor=catalog.cursor;
      const seen=new Set();
      // Legacy runs can have empty source stages before tool and runtime pages.
      for(let i=0;i<20;i++){
        if(seen.has(cursor))throw new Error('Source catalog did not advance.');
        seen.add(cursor);
        result=await api.j('/api/search/sources?'+new URLSearchParams({...selectedScope(),cursor}),{signal:abort.signal});
        if(current!==catalogEpoch)return;
        if(result.schema_version!=='agentprovenance.search_sources/v1'||result.run_id!==scope.run||!Array.isArray(result.sources)||result.sources.length>50||(result.has_more&&(!result.next_cursor||result.next_cursor===cursor)))throw new Error('Invalid search source page');
        if(result.sources.length||!result.has_more)break;
        cursor=result.next_cursor;
      }
      if(!result.sources.length&&result.has_more)throw new Error('Source catalog did not advance.');
      if(current!==catalogEpoch)return;
      catalog.sources=result.sources;catalog.next=result.has_more?result.next_cursor:'';catalog.loaded=true;
      $('export-record-status').textContent=api.tx('{count} saved records on this page',{count:result.sources.length});
    }catch(error){if(current===catalogEpoch){catalog.sources=[];catalog.next='';catalog.loaded=false;$('export-record-status').textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);$('export-record-retry').hidden=false;}}
    finally{if(current===catalogEpoch){catalogController=null;renderRecords();}}
  }
  function renderRecords(){
    if(!catalog)return;
    $('export-records').innerHTML=catalog.sources.map((source,index)=>{
      const category=draft.categories.has(source.category),excluded=category||draft.records.has(source.id);
      const state=source.entry?.status==='source_truncated'?'truncated':source.content?.state||'Not recorded';
      return `<div class="export-record" data-excluded="${excluded}"><label><input type="checkbox" data-export-record="${index}" data-record-id="${e(source.id)}" ${excluded?'':'checked'} ${category?'disabled':''}><span><strong>${e(source.label)}</strong><small>${e(t(names[source.category]||source.category))} · ${e(t(state))}${category?' · '+e(t('Excluded category')):''}</small><small>${e([source.agent_id||source.harness,source.recorded_at].filter(Boolean).join(' · '))}</small><small><code>${e(source.id)}</code></small></span></label><button type="button" data-export-inspect="${index}">${e(t('Read'))}</button></div>`;
    }).join('');
    $('export-records').querySelectorAll('[data-export-record]').forEach(input=>input.onchange=()=>{
      const source=catalog.sources[Number(input.dataset.exportRecord)];
      if(input.checked)draft.records.delete(source.id);
      else if(draft.records.size<4096)draft.records.add(source.id);
      else{input.checked=true;$('export-record-status').textContent=t('Record exclusion limit reached. Use category exclusions for larger selections.');return;}
      input.closest('.export-record').dataset.excluded=String(!input.checked);syncSelection(false);
    });
    $('export-records').querySelectorAll('[data-export-inspect]').forEach(button=>button.onclick=()=>inspect(catalog.sources[Number(button.dataset.exportInspect)]));
    $('export-record-page').textContent=api.tx('Page {page}',{page:catalog.page});
    $('export-record-prev').disabled=!!catalogController||!catalog.history.length;$('export-record-next').disabled=!!catalogController||!catalog.next;
  }
  async function prepare(){
    if(!$('export-ack').checked||controller)return;
    stopCatalog();closeReader();
    const requestID=++epoch,abort=new AbortController();controller=abort;
    $('export-prepare').disabled=true;$('export-ack').disabled=true;$('export-settings').disabled=true;$('export-stop').hidden=false;
    $('export-status').textContent=t('Freezing saved evidence and preparing the archive…');
    try{
      const result=await request('/api/replay/previews',{method:'POST',body:JSON.stringify(selection()),signal:abort.signal});
      if(requestID!==epoch){request(base(result.id),{method:'DELETE'}).catch(()=>{});return;}
      preview=result;page=0;downloadRequested=false;render();
    }catch(error){if(requestID===epoch)$('export-status').textContent=error.name==='AbortError'?t('Replay preparation stopped.'):t(error.message);}
    finally{if(requestID===epoch){controller=null;$('export-stop').hidden=true;if(!preview){$('export-ack').disabled=false;$('export-settings').disabled=false;$('export-prepare').disabled=!$('export-ack').checked;}}}
  }
  function render(){
    const inventory=preview.inventory,contents=inventory.contents,summary=inventory.selection_summary;
    $('export-prepare').hidden=true;$('export-stop').hidden=true;$('export-ack-label').hidden=true;$('export-settings').hidden=true;
    $('export-result').hidden=false;
    $('export-status').textContent=t('Frozen preview ready');
    const chosen=summary?.selection;
    $('export-frozen-scope').textContent=chosen?.scope==='session'?t('Current session')+': '+chosen.harness+' · '+chosen.session_id:t('Whole run');
    if(chosen?.exclude_categories?.length)$('export-frozen-scope').textContent+=' · '+t('Excluded categories')+': '+chosen.exclude_categories.map(c=>t(names[c]||c)).join(', ');
    $('export-selection-counts').textContent=summary?api.tx('{included} records included · {excluded} records outside the copy',{included:summary.included_records,excluded:summary.excluded_records}):'';
    if(summary?.excluded_records)$('export-selection-counts').textContent+=' · '+Object.entries(summary.exclusion_reasons).map(([reason,count])=>t(reasons[reason]||reason)+': '+count).join(' · ');
    const omitted=Object.values(inventory.analysis_omissions||{}).reduce((a,b)=>a+b,0);
    $('export-omissions').hidden=!omitted;$('export-omissions').textContent=api.tx('{count} analysis records omitted from this selection. See the inventory for reasons.',{count:omitted});
    $('export-warnings').hidden=!summary?.warning_count;$('export-warnings').open=!!summary?.warning_count;
    $('export-warning-count').textContent=api.tx('{count} repeated-content warnings',{count:summary?.warning_count||0});
    $('export-warning-limit').textContent=api.tx('Showing up to {count} examples and 10 retained references per example.',{count:100});
    $('export-warning-items').innerHTML=(summary?.warnings||[]).map(w=>`<li><code>${e(w.content_sha256)}</code><br>${e(t('Included records'))}: ${e(w.included_records.join(', '))} (${e(w.included_count)})</li>`).join('');
    const rows=[['Native sessions',contents.sessions],['Runtime records',inventory.events],['Context records, including revisions',contents.context_entries],['Saved context body references',contents.context_body_refs],['Raw context references',contents.context_raw_refs]];
    $('export-counts').innerHTML=rows.map(([label,count])=>`<div><dt>${e(t(label))}</dt><dd>${e(count)}</dd></div>`).join('');
    $('export-categories').innerHTML=Object.entries(names).map(([key,label])=>`<span>${e(t(label))} <strong>${e(contents.indexed_sources[key]||0)}</strong></span>`).join('');
    $('export-size').textContent=bytes(preview.zip_bytes)+' ZIP · '+bytes(inventory.bytes_excluding_inventory)+' '+t('Unpacked files');
    $('export-expires').textContent=t('Preview expires')+': '+new Date(preview.expires_at).toLocaleTimeString(api.lang);
    $('export-digest').textContent=preview.inventory_sha256;
    $('export-view').href=base(preview.id)+'/files/'+(api.lang==='zh-CN'?'zh-CN':'en')+'/index.html?live=0';
    $('export-manifest').href=base(preview.id)+'/files/record-selection.json';
    $('export-download').disabled=false;renderFiles();
  }
  function renderFiles(){
    const files=preview.inventory.files,offset=page*50;
    $('export-files').innerHTML=files.slice(offset,offset+50).map(file=>`<tr><td>${e(file.path)}</td><td>${e(new Intl.NumberFormat(api.lang).format(file.bytes))}</td><td title="${e(file.sha256)}"><code>${e(file.sha256.slice(0,16))}…</code></td></tr>`).join('');
    $('export-files-count').textContent=(offset+1)+'–'+Math.min(offset+50,files.length)+' / '+files.length;
    $('export-files-prev').disabled=page===0;$('export-files-next').disabled=offset+50>=files.length;
  }
  async function download(){
    if(!preview)return;
    const selected=preview,requestID=epoch;
    $('export-download').disabled=true;
    try{
      const latest=await request(base(selected.id));
      if(requestID!==epoch||preview!==selected)return;
      if(latest.inventory_sha256!==selected.inventory_sha256)throw new Error('Replay inventory changed. Prepare it again.');
      const anchor=document.createElement('a');
      anchor.href=base(selected.id)+'/download?inventory='+encodeURIComponent(selected.inventory_sha256);
      anchor.download='agentprovenance-replay.zip';anchor.rel='noopener';
      document.body.append(anchor);anchor.click();anchor.remove();downloadRequested=true;
      $('export-status').textContent=t('Download requested. The frozen archive remains available until expiry.');
    }catch(error){if(requestID===epoch)$('export-status').textContent=t(error.message);}
    finally{if(requestID===epoch)$('export-download').disabled=false;}
  }
  return {init,open};
})();
