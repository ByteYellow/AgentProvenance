window.AgentExportUI=(()=>{
  'use strict';
  const $=id=>document.getElementById(id);
  const names={messages:'Messages',tools:'Tool inputs and outputs',configuration:'Configuration',files:'Saved files',runtime:'Runtime records'};
  let api,scope,preview,controller,epoch=0,downloadRequested=false,page=0;
  const t=s=>api.tr(s),e=s=>api.esc(String(s??''));
  const bytes=n=>new Intl.NumberFormat(api.lang,{maximumFractionDigits:2}).format(n/1048576)+' MiB';
  const base=id=>'/api/replay/previews/'+encodeURIComponent(id);
  async function request(path,options={}){
    const response=await fetch(path,{...options,headers:{'X-AgentProv-Export':'1','Content-Type':'application/json',...options.headers},cache:'no-store'});
    if(!response.ok){let data;try{data=await response.json();}catch(_){}throw new Error(data?.error||'HTTP '+response.status);}
    return response.status===204?null:response.json();
  }
  function init(options){
    api=options;
    $('export-close').onclick=()=>$('export-dialog').close();
    $('export-dialog').addEventListener('close',()=>{
      controller?.abort();controller=null;epoch++;
      if(!downloadRequested)discard();
    });
    $('export-ack').onchange=()=>{$('export-prepare').disabled=!$('export-ack').checked;};
    $('export-prepare').onclick=()=>prepare();
    $('export-stop').onclick=()=>controller?.abort();
    $('export-discard').onclick=async()=>{await discard();reset();};
    $('export-files-prev').onclick=()=>{page=Math.max(0,page-1);renderFiles();};
    $('export-files-next').onclick=()=>{page++;renderFiles();};
    $('export-download').onclick=()=>download();
    window.addEventListener('pagehide',()=>{if(preview&&!downloadRequested)fetch(base(preview.id),{method:'DELETE',headers:{'X-AgentProv-Export':'1'},keepalive:true}).catch(()=>{});});
  }
  async function discard(){
    const old=preview;preview=null;downloadRequested=false;
    if(old)try{await request(base(old.id),{method:'DELETE'});}catch(_){/* Server-side expiry also releases the private snapshot. */}
  }
  function reset(){
    $('export-result').hidden=true;$('export-prepare').hidden=false;$('export-stop').hidden=true;
    $('export-ack').disabled=false;$('export-ack').checked=false;$('export-prepare').disabled=true;
    $('export-status').textContent='';
  }
  async function open(){
    if($('export-dialog').open)return;
    const next=api.scope();if(!next.run)return;
    if(preview&&(preview.inventory.run_id!==next.run||Date.parse(preview.expires_at)<=Date.now()))await discard();
    scope=next;reset();
    $('export-run').textContent=scope.run;
    $('export-session').hidden=!scope.session_id;
    $('export-session').textContent=scope.session_id?t('Current session filter')+': '+scope.harness+' · '+scope.session_id+'. '+t('This export includes the whole run, not just the filtered session.'):'';
    const replay=Boolean(window.AgentProvReplay);
    $('export-local-only').hidden=!replay;$('export-controls').hidden=replay;
    $('export-dialog').showModal();
    if(preview)render();
  }
  async function prepare(){
    if(!$('export-ack').checked||controller)return;
    const requestID=++epoch,abort=new AbortController();controller=abort;
    $('export-prepare').disabled=true;$('export-ack').disabled=true;$('export-stop').hidden=false;
    $('export-status').textContent=t('Freezing saved evidence and preparing the archive…');
    try{
      const result=await request('/api/replay/previews',{method:'POST',body:JSON.stringify({run:scope.run,scope:'whole_run'}),signal:abort.signal});
      if(requestID!==epoch){request(base(result.id),{method:'DELETE'}).catch(()=>{});return;}
      preview=result;page=0;downloadRequested=false;render();
    }catch(error){if(requestID===epoch)$('export-status').textContent=error.name==='AbortError'?t('Replay preparation stopped.'):t(error.message);}
    finally{if(requestID===epoch){controller=null;$('export-stop').hidden=true;if(!preview){$('export-ack').disabled=false;$('export-prepare').disabled=!$('export-ack').checked;}}}
  }
  function render(){
    const inventory=preview.inventory,contents=inventory.contents;
    $('export-prepare').hidden=true;$('export-stop').hidden=true;$('export-ack').checked=true;$('export-ack').disabled=true;
    $('export-result').hidden=false;
    $('export-status').textContent=t('Frozen preview ready');
    const rows=[['Native sessions',contents.sessions],['Runtime records',inventory.events],['Context records, including revisions',contents.context_entries],['Saved context body references',contents.context_body_refs],['Raw context references',contents.context_raw_refs]];
    $('export-counts').innerHTML=rows.map(([label,count])=>`<div><dt>${e(t(label))}</dt><dd>${e(count)}</dd></div>`).join('');
    $('export-categories').innerHTML=Object.entries(names).map(([key,label])=>`<span>${e(t(label))} <strong>${e(contents.indexed_sources[key]||0)}</strong></span>`).join('');
    $('export-size').textContent=bytes(preview.zip_bytes)+' ZIP · '+bytes(inventory.bytes_excluding_inventory)+' '+t('Unpacked files');
    $('export-expires').textContent=t('Preview expires')+': '+new Date(preview.expires_at).toLocaleTimeString(api.lang);
    $('export-digest').textContent=preview.inventory_sha256;
    $('export-view').href=base(preview.id)+'/files/'+(api.lang==='zh-CN'?'zh-CN':'en')+'/index.html?live=0';
    $('export-download').disabled=false;
    renderFiles();
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
