/* Shared reader over the existing read-only evidence APIs. */
(() => {
  'use strict';
  if(window.AgentPortableEvidenceUI) return;
  if(location.protocol==='file:') document.querySelectorAll('[data-site-navigation]').forEach(nav=>nav.remove());
  const $=id=>document.getElementById(id), e=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const t=window.AgentProvI18n.t;
  const q=o=>new URLSearchParams(Object.entries(o).filter(([,v])=>v!==''&&v!=null)).toString();
  const j=(path,opts)=>window.j(path,opts);
  const label=s=>t(({succeeded:'Succeeded',failed:'Failed',running:'Running',incomplete:'Incomplete',complete:'Complete',pending:'Pending',draining:'Draining',persisted:'Receipt saved'})[s]||s||'Not recorded');
  const facts=items=>`<dl class="portable-facts">${items.filter(([,v])=>v!==undefined&&v!=='').map(([k,v])=>`<dt>${e(t(k))}</dt><dd>${e(v===null?t('Unknown'):v)}</dd>`).join('')}</dl>`;
  let current='',pending='',scope=null,revision=0,links=[],records=[],entries=[],entryCursor='',captureCursor='',dialogRequest=0,objectURL='',nativeActive=false,nativeKind='native';
  const card=document.createElement('section');card.className='card full';card.id='portable-executions';card.hidden=true;
  card.innerHTML=`<details><summary class="portable-summary"><span>${e(t('Execution handoffs'))}</span><small id="portable-link-count"></small></summary><div class="portable-body" id="portable-links"></div></details>`;
  $('agentcontext').before(card);
  const tab=document.createElement('button');tab.className='portable-native-tab';tab.id='portable-native-tab';tab.type='button';tab.setAttribute('role','tab');tab.setAttribute('aria-controls','portable-native');tab.setAttribute('aria-selected','false');tab.textContent=t('Browser / Notebook');
  document.querySelector('.context-tabs').append(tab);
  const workspaceTab=tab.cloneNode(true);workspaceTab.id='portable-workspace-tab';workspaceTab.textContent=t('Workspace');tab.before(workspaceTab);
  const native=document.createElement('div');native.id='portable-native';native.className='portable-native';native.hidden=true;native.setAttribute('role','tabpanel');native.setAttribute('aria-labelledby',tab.id);$('context-body').after(native);
  const coverage=document.createElement('div');coverage.id='portable-coverage';coverage.className='portable-coverage';coverage.hidden=true;$('context-pager').after(coverage);
  const dialog=document.createElement('dialog');dialog.className='portable-evidence-dialog';dialog.setAttribute('aria-labelledby','portable-dialog-title');dialog.innerHTML=`<div class="portable-evidence-head"><h2 id="portable-dialog-title"></h2><button type="button" aria-label="${e(t('Close'))}">×</button></div><div class="portable-evidence-content" id="portable-dialog-body"></div>`;document.body.append(dialog);
  dialog.querySelector('button').onclick=()=>dialog.close();dialog.addEventListener('close',()=>{dialogRequest++;if(objectURL)URL.revokeObjectURL(objectURL);objectURL='';});
  const showError=(host,error)=>{host.textContent=t('Recorded evidence could not be loaded.')+' '+error.message;host.setAttribute('role','alert');};
  const showDialog=(title)=>{dialogRequest++;$('portable-dialog-title').textContent=title;$('portable-dialog-body').textContent=t('Loading…');if(!dialog.open)dialog.showModal();return dialogRequest;};
  function setNative(active,kind='native'){nativeActive=active;nativeKind=kind;window.AgentContextUI.setExternalTab(active?kind:'');tab.setAttribute('aria-selected',String(active&&kind==='native'));workspaceTab.setAttribute('aria-selected',String(active&&kind==='workspace'));native.setAttribute('aria-labelledby',kind==='workspace'?workspaceTab.id:tab.id);native.hidden=!active;$('context-body').hidden=active;$('context-pager').hidden=active;if(active){document.querySelectorAll('[data-context-tab]').forEach(b=>b.setAttribute('aria-selected','false'));coverage.hidden=true;renderNative();}}
  let entriesError=null;
  tab.hidden=true;workspaceTab.hidden=true;
  tab.onclick=()=>setNative(true);
  workspaceTab.onclick=()=>setNative(true,'workspace');
  $('context-fold').addEventListener('contexttabchange',event=>{setNative(false);coverage.hidden=event.detail!=='coverage';if(!coverage.hidden)renderCapture();});
  async function paged(path,field,args,maximum=1000){let values=[],cursor='',seen=new Set();for(;;){const page=await j(path+'?'+q({...args,limit:100,cursor}));values.push(...(page[field]||[]));if(values.length>maximum)throw Error('Use a smaller selection to read these records.');if(!page.has_more)return values;if(!page.next_cursor||seen.has(page.next_cursor))throw Error('Invalid evidence continuation');seen.add(page.next_cursor);cursor=page.next_cursor;}}
  async function prefix(path,field,args,count,limit){const values=[],seen=new Set();let cursor='';do{const page=await j(path+'?'+q({...args,limit,cursor}));values.push(...(page[field]||[]));cursor=page.next_cursor||'';if(page.has_more&&(!cursor||seen.has(cursor)))throw Error('Invalid evidence continuation');seen.add(cursor);if(!page.has_more)return {[field]:values,next_cursor:''};}while(values.length<count);return {[field]:values,next_cursor:cursor};}
  let detailsToken=0,detailsPending;
  async function refresh(run,nextScope=null,force=false){if(!run)return;const key=JSON.stringify([run,nextScope]),changed=key!==current;if(pending===key||(!changed&&!force))return;current=key;pending=key;scope=nextScope;const token=++revision;
    if(changed){links=[];records=[];entries=[];entryCursor='';entriesError=null;captureCursor='';setNative(false);tab.hidden=true;workspaceTab.hidden=true;coverage.hidden=document.querySelector('[data-context-tab="coverage"]').getAttribute('aria-selected')!=='true';card.hidden=true;native.textContent=t('Loading…');if(dialog.open)dialog.close();}
    const details=(!window.AgentProvReplay||$('context-fold').open)?loadDetails(run,nextScope,token):null;
    try{
      const both=await Promise.all(['outgoing','incoming'].map(direction=>paged('/api/execution-links','links',{run,direction,...(nextScope?{harness:nextScope.harness,session:nextScope.session_id}:{})}).then(items=>items.map(item=>({...item,direction})))));
      if(token!==revision)return;links=both.flat();card.hidden=!links.length;renderLinks();
    }catch(error){if(token===revision){card.hidden=false;showError($('portable-links'),error);}}
    finally{if(token===revision)pending='';}
    await details;
  }
  function loadDetails(run,nextScope,token){
    if(detailsToken===token)return detailsPending;
    detailsToken=token;
    detailsPending=Promise.allSettled([
      prefix('/api/capture-manifest','records',{run},Math.max(20,records.length),20),
      prefix('/api/context/entries','entries',{run,...(nextScope?{harness:nextScope.harness,session:nextScope.session_id}:{})},Math.max(100,entries.length),100)
    ]).then(([capture,context])=>{
      if(token!==revision)return;
      if(capture.status==='fulfilled'){records=capture.value.records;captureCursor=capture.value.next_cursor;renderCapture();}else showError(coverage,capture.reason);
      if(context.status==='fulfilled'){const next=context.value,updated=entriesError||JSON.stringify([entries,entryCursor])!==JSON.stringify([next.entries,next.next_cursor]);entriesError=null;entries=next.entries;entryCursor=next.next_cursor;if(updated||!nativeActive)renderNative();}
      else {entriesError=context.reason;renderNative();}
    });
    return detailsPending;
  }
  $('context-fold').addEventListener('toggle',()=>{if(current&&$('context-fold').open)loadDetails(runID(),scope,revision).catch(error=>showError(native,error));});
  $('context-refresh').addEventListener('click',()=>{if(current)refresh(runID(),scope,true).catch(error=>showError(native,error));});
  const runID=()=>JSON.parse(current)[0];
  const stateBox=(name,value,description)=>`<div class="portable-state" data-tone="${value==='failed'?'failed':value==='incomplete'?'attention':value==='succeeded'||value==='complete'?'ok':'neutral'}"><span>${e(t(name))}</span><strong>${e(description||label(value))}</strong></div>`;
  const stateGapOnly=link=>{const issues=link.checkpoint?.capture_report?.issues;return issues?.length===1&&issues[0]==='scope_state_sampling_gap';};
  function captureFacts(link){const p=link.checkpoint?.capture_report?.scope_progress;return p?facts([['Saved scope events',p.events],['Ingested',p.ingested],['Dropped',p.dropped],['Failed',p.failed],['Pending events',p.pending],['Missing state snapshots',p.sampling_gaps??0]]):'';}
  function renderLinks(){
    $('portable-link-count').textContent=String(links.length);
    $('portable-links').innerHTML=links.map((link,index)=>{
      const id=link.identity,s=link.manifest?.state||link.checkpoint?.state||{},receipt=link.receipt?.status==='persisted',issues=link.issues||[];
      const hints=[];if(s.execution==='failed')hints.push('The command failed. Read the saved output before deciding whether to create a new attempt.');if(s.capture==='incomplete')hints.push('The saved package has capture gaps. Review the capture observations and use the retained evidence.');hints.push(receipt?'A receipt is saved. If the sender did not receive its ACK, resend the same receipt; keep the original attempt.':'Collect the existing attempt again to retry delivery. An explicit reexecution creates a separate attempt.');
      const captureLabel=s.capture==='incomplete'&&stateGapOnly(link)?t('Security state snapshots incomplete'):null;
      const captureNote=captureLabel?`<p class="portable-note">${e(t('Some process identity, AppArmor or seccomp state snapshots were unavailable. The saved source-call identity, execution result and receipt remain available.'))}</p>`:'';
      return `<article class="portable-row" data-execution-attempt="${e(id.attempt_id)}" data-execution-direction="${e(link.direction)}"><h3>${e(id.source.harness)} <span aria-hidden="true">→</span> ${e(id.target.instance_id)}</h3><div class="portable-states">${stateBox('Execution',s.execution)}${stateBox('Capture',s.capture,captureLabel)}${stateBox('Delivery at packaging',s.delivery)}</div>${captureNote}<p>${link.manifest?`${e(t('Package'))} v${e(link.manifest.package_version)} · ${e(link.manifest.snapshot_at)}`:e(t('Details were excluded from this selection.'))}${receipt?' · '+e(t('Receipt saved')):''}</p>${facts([['Source call',id.source.tool_call_id],['Attempt',id.attempt_id],['Generation',id.target.generation]])}<div class="portable-actions"><button data-portable-action="execution" data-index="${index}" ${issues.includes('execution_run_not_selected')?'disabled':''}>${e(t('Open execution'))}</button><button data-portable-action="source" data-index="${index}" ${issues.some(v=>v==='source_run_not_selected'||v==='source_call_excluded_by_selection')?'disabled':''}>${e(t('Open source call'))}</button>${link.checkpoint?.capture_report?`<button data-portable-action="capture" data-index="${index}">${e(t('Capture details'))}</button>`:''}<button data-portable-action="details" data-index="${index}">${e(t('Saved details'))}</button></div>${issues.length?`<p>${e(t('Included records'))}: ${e(issues.join(' · '))}</p>`:''}<details class="portable-guidance"><summary>${e(t('Next steps'))}</summary>${hints.map(v=>`<p>${e(t(v))}</p>`).join('')}</details></article>`;
    }).join('');
    $('portable-links').querySelectorAll('[data-portable-action]').forEach(button=>button.onclick=async()=>{const link=links[Number(button.dataset.index)];try{
      if(button.dataset.portableAction==='capture'){showDialog(t('Capture details'));const report=link.checkpoint.capture_report;$('portable-dialog-body').innerHTML=`<p class="portable-note">${e(t('These counts describe the sealed execution interval, not the entire node.'))}</p>${captureFacts(link)}<h3>${e(t('Capture issues'))}</h3>${(report.issues||[]).map(issue=>`<p>${e(t(issue))} <code>${e(issue)}</code></p>`).join('')}${stateGapOnly(link)?`<p>${e(t('Some process identity, AppArmor or seccomp state snapshots were unavailable. The saved source-call identity, execution result and receipt remain available.'))}</p>`:''}<p class="portable-ref">${e(link.manifest?.checkpoint_ref||'')}</p>`;return;}
      if(button.dataset.portableAction==='details'){showDialog(t('Saved details'));const pre=document.createElement('pre');pre.textContent=JSON.stringify(link,null,2);$('portable-dialog-body').replaceChildren(pre);return;}
      if(button.dataset.portableAction==='execution'){await window.loadRun(link.identity.local_run_id,{scope:null});card.querySelector('details').open=true;card.scrollIntoView({block:'start',behavior:'smooth'});return;}
      const source=link.identity.source;await window.loadRun(source.run_id,{scope:{harness:source.harness,session_id:source.session_id}});window.AgentContextUI.selectSource(JSON.stringify([source.harness,source.session_id]));
      const request=showDialog(t('Source call'));const page=await j('/api/context/entries?'+q({run:source.run_id,harness:source.harness,session:source.session_id,tool_call:source.tool_call_id,limit:100}));if(request!==dialogRequest)return;renderEntryDialog(page.entries||[],source.run_id);
    }catch(error){showDialog(t('Recorded evidence could not be loaded.'));showError($('portable-dialog-body'),error);}});
  }
  function renderCapture(){coverage.innerHTML=`<h3>${e(t('Saved capture observations'))}</h3><p class="portable-note">${e(t('These are saved observations. Counts and capability changes retain their recorded scope and time.'))}</p>`+records.map(r=>`<article class="portable-row"><h3>${e(r.source)} · ${e(label(r.status))}</h3>${facts([['Target',r.placement],['Time',[r.started_at,r.ended_at].filter(Boolean).join(' → ')||r.observed_at],['Scope',r.identity_domain]])}<details><summary>${e(t('Capabilities'))}</summary>${(r.snapshots||[]).map(s=>`<p>${e(s.observed_at||t('Not recorded'))} · ${e(s.boundary)} · ${e(label(s.status))}</p>${facts((s.features||[]).map(f=>[f.name,[f.state,f.reason].filter(Boolean).join(' · ')]))}`).join('')}</details><details><summary>${e(t('Loss counters'))}</summary>${facts((r.loss||[]).map(c=>[c.name,`${c.value===null?t('Unknown'):c.value} · ${c.scope}${c.scope_id?' / '+c.scope_id:''}`]))}</details>${r.issues?.length?`<p>${e(r.issues.join(' · '))}</p>`:''}<p class="portable-ref">${e(r.evidence_ref)}</p></article>`).join('')+(captureCursor?`<button class="portable-more">${e(t('More records'))}</button>`:'');
    coverage.querySelector('.portable-more')?.addEventListener('click',async()=>{const token=revision;try{const page=await j('/api/capture-manifest?'+q({run:runID(),limit:20,cursor:captureCursor}));if(token!==revision)return;records.push(...page.records);captureCursor=page.next_cursor||'';renderCapture();}catch(err){showError(coverage,err);}});
  }
  const nativeEntries=(kind=nativeKind)=>entries.filter(x=>kind==='workspace'?(x.kind==='tool_result'&&/(^|__)workspace_/.test(x.tool_name||'')):(x.browser||x.notebook||x.browser_operation||x.notebook_request||x.attachments?.length));
  function entryTitle(x){return x.browser?.operation||x.browser?.kind||x.notebook?.message_type||x.tool_name||x.kind;}
  function entryCard(x,index){if(nativeKind==='workspace')return `<article class="portable-row" data-workspace-entry="${e(x.id)}"><h3>${e(x.tool_name)}</h3>${facts([['Source call',x.tool_call_id],['Time',x.recorded_at]])}<button class="portable-more" data-native-body="${index}">${e(t('Versions and receipt'))}</button></article>`;const b=x.browser,n=x.notebook;return `<article class="portable-row" data-native-entry="${e(x.id)}"><h3>${e(entryTitle(x))}</h3><p>${e(x.source.harness)} · ${e(x.recorded_at||t('Not recorded'))}</p>${facts(b?[['Target',b.target_id],['Target type',b.target_type],['Browser operation',b.operation_id],['Request',b.request_key],['Initiator request',b.initiator_request_id],['Frame',b.frame_id],['Download',b.download_id],['Association basis',b.association]]:n?[['Source',n.parent_message_id||n.message_id],['State',n.association]]:[['Source call',x.tool_call_id]])}<div class="portable-actions"><button data-native-body="${index}">${e(t('Read saved content'))}</button>${(x.attachments||[]).map((a,i)=>`<button data-native-attachment="${index}:${i}" ${a.state!=='stored'?'disabled':''}>${e(t(a.media_type==='image/png'?(b?'Screenshot':'Image'):'Network archive'))}${a.state!=='stored'?' · '+e(t('Not retained')):''}</button>`).join('')}</div></article>`;}
  function renderNative(){
    // An unread page or a load failure leaves availability unknown.
    tab.hidden=!entriesError&&!entryCursor&&!nativeEntries('native').length;
    workspaceTab.hidden=!entriesError&&!entryCursor&&!nativeEntries('workspace').length;
    if(nativeActive&&(nativeKind==='workspace'?workspaceTab:tab).hidden)setNative(false);
    if(entriesError){showError(native,entriesError);return;}
    native.setAttribute('role','tabpanel');
    const scroll=native.scrollTop,list=nativeEntries();native.innerHTML=(list.length?list.map(entryCard).join(''):`<p class="portable-note">${e(t(nativeKind==='workspace'?'No Workspace results in this selection.':'No native Browser or Notebook records in this selection.'))}</p>`)+(entryCursor?`<button class="portable-more" data-native-more>${e(t('More records'))}</button>`:'');native.scrollTop=scroll;
    native.querySelectorAll('[data-native-body]').forEach(b=>b.onclick=()=>openContent(list[Number(b.dataset.nativeBody)],runID()));
    native.querySelectorAll('[data-native-attachment]').forEach(b=>b.onclick=()=>{const [a,i]=b.dataset.nativeAttachment.split(':').map(Number);openAttachment(list[a].attachments[i],runID());});
    native.querySelector('[data-native-more]')?.addEventListener('click',async event=>{const button=event.currentTarget,token=revision;button.disabled=true;try{const page=await j('/api/context/entries?'+q({run:runID(),limit:100,cursor:entryCursor,...(scope?{harness:scope.harness,session:scope.session_id}:{})}));if(token!==revision)return;entries.push(...page.entries);entryCursor=page.next_cursor||'';renderNative();}catch(err){if(token===revision)showError(native,err);}finally{button.disabled=false;}});
  }
  function renderEntryDialog(list,run){$('portable-dialog-body').innerHTML=list.length?list.map((x,i)=>`<article class="portable-row"><h3>${e(x.tool_name||x.kind)}</h3><p class="portable-ref">${e(x.tool_call_id)}</p><button class="portable-more" data-dialog-entry="${i}">${e(t('Read saved content'))}</button></article>`).join(''):`<p>${e(t('Details were excluded from this selection.'))}</p>`;$('portable-dialog-body').querySelectorAll('[data-dialog-entry]').forEach(b=>b.onclick=()=>openContent(list[Number(b.dataset.dialogEntry)],run));}
  async function openContent(entry,run,offset=0){const request=showDialog(t('Recorded inputs and outputs'));try{if(entry.content?.state!=='stored'){$('portable-dialog-body').textContent=t('Not retained')+' · '+(entry.content?.reason||t('Not recorded'));return;}const page=await j('/api/context/content?'+q({run,ref:entry.content.ref,offset,limit:65536}));if(request!==dialogRequest)return;const host=$('portable-dialog-body');host.replaceChildren();const meta=document.createElement('p');meta.className='portable-ref';meta.textContent=entry.content.ref+' · '+page.offset+'–'+page.next_offset+' / '+page.total_bytes;host.append(meta);if(offset===0&&!page.has_more)workspaceSummary(host,entry,page.content,run);const pre=document.createElement('pre');pre.textContent=page.content;host.append(pre);if(page.has_more){const next=document.createElement('button');next.className='portable-more';next.textContent=t('More content');next.onclick=()=>openContent(entry,run,page.next_offset);host.append(next);}const raw=document.createElement('details');raw.innerHTML=`<summary>${e(t('Recorded fields'))}</summary>`;const fields=document.createElement('pre');fields.textContent=JSON.stringify(entry,null,2);raw.append(fields);host.append(raw);}catch(error){if(request===dialogRequest)showError($('portable-dialog-body'),error);}}
  function workspaceSummary(host,entry,raw,run){
    let value;try{value=JSON.parse(raw);}catch(_){return;}
    if(value?.schema!=='agentprovenance.workspace_tool_result/v1'||value.run_id!==run||value.tool_call_id!==entry.tool_call_id||!value.view?.binding)return;
    const binding=value.view.binding,receipt=value.view.last_receipt;
    const ownReceipt=receipt&&receipt.ref===value.operation_ref&&receipt.tool_call_id===entry.tool_call_id;
    const section=document.createElement('section');section.className='portable-workspace-result';
    section.innerHTML=`<h3>${e(t('Saved workspace revision'))}</h3>${facts([['Workspace',binding.workspace_id],['Target',binding.target?.instance_id],['Generation',binding.target?.generation],['Output revision',binding.revision],['Source call',entry.tool_call_id]])}`;
    if(ownReceipt){
      section.dataset.workspaceReceipt=receipt.ref;
      section.innerHTML+=`<h3>${e(t('Receipt'))}</h3>${facts([['Outcome',receipt.outcome],['Path',receipt.path],['Input revision',receipt.input_revision],['Output revision',receipt.output_revision],['Input manifest',receipt.input_manifest_ref],['Output manifest',receipt.output_manifest_ref],['Record attempt',receipt.record?.attempt_id]])}`;
      const changes=Array.isArray(receipt.changes)?receipt.changes:[];
      if(changes.length){
        const version=v=>v?[(v.Hash||v.hash||'').slice(0,12),v.SizeBytes??v.size_bytes].filter(x=>x!==undefined).join(' · '):'—';
        section.innerHTML+=`<h3>${e(t('Changes'))}</h3><table class="portable-change-table"><thead><tr><th>${e(t('Path'))}</th><th>${e(t('Before'))}</th><th>${e(t('After'))}</th></tr></thead><tbody>${changes.slice(0,500).map(c=>`<tr><td>${e(c.path)}<small>${e(c.kind)}</small></td><td>${e(version(c.before))}</td><td>${e(version(c.after))}</td></tr>`).join('')}</tbody></table>`;
      }
    }else section.innerHTML+=`<p class="portable-note">${e(t('This observation carries the current workspace version.'))}</p>`;
    section.innerHTML+=`<p class="portable-note">${e(t('Inspect the saved Workspace result below.'))}</p>`;
    host.append(section);
  }
  const deliveryBar=document.querySelector('.offline-replay-bar');
  if(deliveryBar){
    const button=document.createElement('button');button.type='button';button.className='portable-more';button.id='portable-delivery-details';button.textContent=t('Delivery details');deliveryBar.append(button);
    button.onclick=()=>{
      showDialog(t('Delivery details'));
      const names={reading:'Unsigned reading copy',derived:'Exporter-signed reading copy',originals:'Signed reader with original bundles'};
      $('portable-dialog-body').innerHTML=facts([['Current copy',t(names[deliveryBar.dataset.deliveryMode]||'Not recorded')],['Recipient verification',t('Not run')]])+`<table class="portable-change-table"><thead><tr><th>${e(t('Delivery mode'))}</th><th>${e(t('Contents'))}</th></tr></thead><tbody>${Object.entries(names).map(([key,label])=>`<tr><td><code>${e(key)}</code></td><td>${e(t(label))}</td></tr>`).join('')}</tbody></table><p class="portable-note">${e(t('Signature trust is evaluated using the recipient’s own trust policy.'))}</p>`;
    };
  }
  async function openAttachment(a,run){const request=showDialog(t(a.media_type==='image/png'?'Image':'Network archive'));try{
    if(a.state!=='stored'||!a.ref)throw Error(t('Attachment omitted by the capture or export selection.'));
    if(!['image/png','application/har+json'].includes(a.media_type)||!Number.isSafeInteger(a.bytes)||a.bytes<1||a.bytes>8388608)throw Error('Unsupported attachment');
    const chunks=[];let offset=0;while(offset<a.bytes){const page=await j('/api/context/attachment?'+q({run,ref:a.ref,offset,limit:262144}));if(request!==dialogRequest)return;const bytes=Uint8Array.from(atob(page.data),c=>c.charCodeAt(0));if(page.run_id!==run||page.ref!==a.ref||page.offset!==offset||page.total_bytes!==a.bytes||page.media_type!==a.media_type||page.sha256!==a.sha256||!bytes.length||page.next_offset!==offset+bytes.length||page.next_offset>a.bytes||Boolean(page.has_more)!==(page.next_offset<a.bytes))throw Error('Invalid attachment continuation');chunks.push(bytes);offset=page.next_offset;}
    const bytes=new Uint8Array(a.bytes);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.length;}
    const hash=await window.agentProvSHA256(bytes);if(hash!==a.sha256)throw Error('Attachment hash mismatch');if(request!==dialogRequest)return;
    const host=$('portable-dialog-body');host.replaceChildren();const meta=document.createElement('p');meta.className='portable-ref';meta.textContent=a.ref+' · '+a.bytes+' bytes';host.append(meta);
    if(a.media_type==='image/png'){const source=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(Error('Image could not be read'));reader.readAsDataURL(new Blob([bytes],{type:'image/png'}));});if(request!==dialogRequest)return;const img=document.createElement('img');img.alt=t('Image');img.src=source;host.append(img);}else{const pre=document.createElement('pre');pre.textContent=JSON.stringify(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),null,2);host.append(pre);}
  }catch(error){if(request===dialogRequest)showError($('portable-dialog-body'),error);}}
  window.AgentPortableEvidenceUI={refresh,openAttachment,prepareSessionTabs:()=>current?loadDetails(runID(),scope,revision):null};
  window.AgentContextUI.onRunChange((run,nextScope)=>refresh(run,nextScope,!window.AgentProvReplay).catch(error=>showError($('portable-links'),error)));
})();
