/* Candidate reader; all inputs come from the existing read-only evidence APIs. */
(() => {
  'use strict';
  const $=id=>document.getElementById(id), e=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const zh=window.AgentProvI18n?.locale==='zh-CN';
  const words={
    'Execution handoffs':'跨环境执行','Saved capture observations':'采集记录','Browser / Notebook':'Browser / Notebook',
    'Execution':'执行','Capture':'采集','Delivery at packaging':'封包时的交付状态','Succeeded':'成功','Failed':'失败','Running':'运行中','Incomplete':'有采集缺口','Complete':'完成','Pending':'待交付','Not recorded':'未记录','Draining':'正在收尾',
    'Security state snapshots incomplete':'安全状态补采不完整','Capture details':'查看采集详情','Saved scope events':'作用域事件','Ingested':'已入库','Dropped':'已报告丢失','Pending events':'待处理事件','Missing state snapshots':'状态补采缺失','Capture issues':'采集问题',
    'Some process identity, AppArmor or seccomp state snapshots were unavailable. The saved source-call identity, execution result and receipt remain available.':'部分进程身份、AppArmor 或 seccomp 状态快照未能取得。来源调用标识、执行结果和回执仍可查看。',
    'These counts describe the sealed execution interval, not the entire node.':'这些计数对应封包时的本次执行范围。',
    'scope_state_sampling_gap':'进程安全状态补采缺失','scope_prefix_pending':'本次执行仍有事件待入库','scope_prefix_loss':'本次执行存在事件丢失或入库失败','shared_collector_loss':'共享采集器报告丢失','shared_spool_loss':'共享缓冲报告丢失','shared_tls_pending':'共享采集器仍有 TLS 数据待处理','shared_tls_loss':'共享采集器报告 TLS 数据丢失',
    'Receipt saved':'回执已保存','Package':'证据包','Open execution':'查看执行','Open source call':'查看来源调用','Saved details':'查看记录详情','Source call':'来源调用','Target':'执行环境','Attempt':'执行尝试','Generation':'代次','Next steps':'接下来怎么处理',
    'Read saved content':'阅读正文','Screenshot':'截图','Image':'图片','Network archive':'网络记录','More records':'继续加载','Close':'关闭','Loading…':'正在读取…','Recorded evidence could not be loaded.':'记录读取失败。',
    'No native Browser or Notebook records in this selection.':'当前选择中没有 Browser 或 Notebook 原生记录。',
    'Scope':'范围','State':'状态','Time':'时间','Source':'来源','Saved bytes':'保存的字节','Not retained':'未保留','Unknown':'未知','Included records':'已包含的记录','Capabilities':'采集能力','Loss counters':'丢失统计',
    'Excluded from this copy':'未包含在此副本中','Recorded inputs and outputs':'保存的输入与输出','More content':'继续读取正文','Recorded fields':'原始字段','Evidence references':'证据引用',
    'The saved package has capture gaps. Review the capture observations and use the retained evidence.':'这份证据包有采集缺口，可以查看采集记录和已经保留的证据。',
    'The command failed. Read the saved output before deciding whether to create a new attempt.':'命令执行失败。先查看保存的输出，再决定是否创建新的执行尝试。',
    'A receipt is saved. If the sender did not receive its ACK, resend the same receipt; keep the original attempt.':'回执已经保存。如果发送端未收到 ACK，应重发同一份回执，继续使用原执行尝试。',
    'Collect the existing attempt again to retry delivery. An explicit reexecution creates a separate attempt.':'再次收取现有执行尝试可以重试交付。显式重新执行会创建另一次尝试。',
    'These are saved observations. Counts and capability changes retain their recorded scope and time.':'这里展示保存的采集记录。计数和能力变化保留各自的范围及时间。',
    'Only the selected evidence is available in this copy.':'此副本只包含选定的证据。',
    'Details were excluded from this selection.':'详情未包含在当前选择中。',
    'Attachment omitted by the capture or export selection.':'附件根据采集设置或导出选择被省略。',
    'Nothing was executed by this reader.':'阅读器仅展示保存的内容。',
    'Workspace':'工作区','Versions and receipt':'版本与回执','Saved workspace revision':'保存的工作区版本','Input revision':'输入版本','Output revision':'输出版本','Input manifest':'输入清单','Output manifest':'输出清单','Receipt':'操作回执','Changes':'文件变更','Before':'变更前','After':'变更后','Path':'路径','Outcome':'执行结果','Record attempt':'记录尝试',
    'No Workspace results in this selection.':'当前选择中没有工作区操作结果。','Inspect the saved Workspace result below.':'下方保留了工作区返回的原始结果。','This observation carries the current workspace version.':'这条观察记录保存了当时的工作区版本。',
    'Browser operation':'浏览器操作','Request':'网络请求','Initiator request':'发起请求','Frame':'页面框架','Target type':'页面或 Worker 类型','Association basis':'关联依据','Download':'下载',
    'Delivery details':'交付说明','Current copy':'当前副本','Recipient verification':'接收方验证','Not run':'尚未执行','Delivery mode':'交付模式','Contents':'包含的内容',
    'Unsigned reading copy':'未签名的阅读副本','Exporter-signed reading copy':'导出者签名的阅读副本','Signed reader with original bundles':'附带原始证据包的签名阅读副本',
    'Signature trust is evaluated using the recipient’s own trust policy.':'签名者是否可信，由接收方自己的信任策略判断。',
  };
  const t=s=>zh?(words[s]||s):s;
  const q=o=>new URLSearchParams(Object.entries(o).filter(([,v])=>v!==''&&v!=null)).toString();
  const j=(path,opts)=>window.j(path,opts);
  const label=s=>t(({succeeded:'Succeeded',failed:'Failed',running:'Running',incomplete:'Incomplete',complete:'Complete',pending:'Pending',draining:'Draining',persisted:'Receipt saved'})[s]||s||'Not recorded');
  const facts=items=>`<dl class="portable-facts">${items.filter(([,v])=>v!==undefined&&v!=='').map(([k,v])=>`<dt>${e(t(k))}</dt><dd>${e(v===null?t('Unknown'):v)}</dd>`).join('')}</dl>`;
  let current='',scope=null,revision=0,links=[],records=[],entries=[],entryCursor='',captureCursor='',dialogRequest=0,objectURL='',nativeActive=false,nativeKind='native';
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
  function setNative(active,kind='native'){nativeActive=active;nativeKind=kind;tab.setAttribute('aria-selected',String(active&&kind==='native'));workspaceTab.setAttribute('aria-selected',String(active&&kind==='workspace'));native.setAttribute('aria-labelledby',kind==='workspace'?workspaceTab.id:tab.id);native.hidden=!active;$('context-body').hidden=active;$('context-pager').hidden=active;if(active){document.querySelectorAll('[data-context-tab]').forEach(b=>b.setAttribute('aria-selected','false'));coverage.hidden=true;renderNative();}}
  tab.onclick=()=>setNative(true);
  workspaceTab.onclick=()=>setNative(true,'workspace');
  document.querySelectorAll('[data-context-tab]').forEach(b=>b.addEventListener('click',()=>{setNative(false);coverage.hidden=b.dataset.contextTab!=='coverage';if(!coverage.hidden)renderCapture();}));
  async function paged(path,field,args,maximum=1000){let values=[],cursor='',seen=new Set();for(;;){const page=await j(path+'?'+q({...args,limit:100,cursor}));values.push(...(page[field]||[]));if(values.length>maximum)throw Error('Use a smaller selection to read these records.');if(!page.has_more)return values;if(!page.next_cursor||seen.has(page.next_cursor))throw Error('Invalid evidence continuation');seen.add(page.next_cursor);cursor=page.next_cursor;}}
  async function refresh(run,nextScope){if(!run)return;const key=JSON.stringify([run,nextScope]);if(key===current)return;current=key;scope=nextScope;const token=++revision;links=[];records=[];entries=[];entryCursor='';captureCursor='';setNative(false);coverage.hidden=true;card.hidden=true;native.textContent=t('Loading…');
    const results=await Promise.allSettled([
      Promise.all(['outgoing','incoming'].map(direction=>paged('/api/execution-links','links',{run,direction,...(nextScope?{harness:nextScope.harness,session:nextScope.session_id}:{})}).then(items=>items.map(item=>({...item,direction}))))),
      j('/api/capture-manifest?'+q({run,limit:20})),
      j('/api/context/entries?'+q({run,limit:100,...(nextScope?{harness:nextScope.harness,session:nextScope.session_id}:{})}))
    ]);if(token!==revision)return;
    if(results[0].status==='fulfilled'){links=results[0].value.flat();card.hidden=!links.length;renderLinks();}else{card.hidden=false;showError($('portable-links'),results[0].reason);}
    if(results[1].status==='fulfilled'){records=results[1].value.records||[];captureCursor=results[1].value.next_cursor||'';renderCapture();}else showError(coverage,results[1].reason);
    if(results[2].status==='fulfilled'){entries=results[2].value.entries||[];entryCursor=results[2].value.next_cursor||'';renderNative();}else showError(native,results[2].reason);
  }
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
  const nativeEntries=()=>entries.filter(x=>nativeKind==='workspace'?(x.kind==='tool_result'&&/(^|__)workspace_/.test(x.tool_name||'')):(x.browser||x.notebook||x.browser_operation||x.notebook_request||x.attachments?.length));
  function entryTitle(x){return x.browser?.operation||x.browser?.kind||x.notebook?.message_type||x.tool_name||x.kind;}
  function entryCard(x,index){if(nativeKind==='workspace')return `<article class="portable-row" data-workspace-entry="${e(x.id)}"><h3>${e(x.tool_name)}</h3>${facts([['Source call',x.tool_call_id],['Time',x.recorded_at]])}<button class="portable-more" data-native-body="${index}">${e(t('Versions and receipt'))}</button></article>`;const b=x.browser,n=x.notebook;return `<article class="portable-row" data-native-entry="${e(x.id)}"><h3>${e(entryTitle(x))}</h3><p>${e(x.source.harness)} · ${e(x.recorded_at||t('Not recorded'))}</p>${facts(b?[['Target',b.target_id],['Target type',b.target_type],['Browser operation',b.operation_id],['Request',b.request_key],['Initiator request',b.initiator_request_id],['Frame',b.frame_id],['Download',b.download_id],['Association basis',b.association]]:n?[['Source',n.parent_message_id||n.message_id],['State',n.association]]:[['Source call',x.tool_call_id]])}<div class="portable-actions"><button data-native-body="${index}">${e(t('Read saved content'))}</button>${(x.attachments||[]).map((a,i)=>`<button data-native-attachment="${index}:${i}" ${a.state!=='stored'?'disabled':''}>${e(t(a.media_type==='image/png'?(b?'Screenshot':'Image'):'Network archive'))}${a.state!=='stored'?' · '+e(t('Not retained')):''}</button>`).join('')}</div></article>`;}
  function renderNative(){const list=nativeEntries();native.innerHTML=(list.length?list.map(entryCard).join(''):`<p class="portable-note">${e(t(nativeKind==='workspace'?'No Workspace results in this selection.':'No native Browser or Notebook records in this selection.'))}</p>`)+(entryCursor?`<button class="portable-more">${e(t('More records'))}</button>`:'');
    native.querySelectorAll('[data-native-body]').forEach(b=>b.onclick=()=>openContent(list[Number(b.dataset.nativeBody)],runID()));
    native.querySelectorAll('[data-native-attachment]').forEach(b=>b.onclick=()=>{const [a,i]=b.dataset.nativeAttachment.split(':').map(Number);openAttachment(list[a].attachments[i],runID());});
    native.querySelector('.portable-more')?.addEventListener('click',async()=>{const token=revision;try{const page=await j('/api/context/entries?'+q({run:runID(),limit:100,cursor:entryCursor,...(scope?{harness:scope.harness,session:scope.session_id}:{})}));if(token!==revision)return;entries.push(...page.entries);entryCursor=page.next_cursor||'';renderNative();}catch(err){showError(native,err);}});
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
    const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');if(hash!==a.sha256)throw Error('Attachment hash mismatch');if(request!==dialogRequest)return;
    const host=$('portable-dialog-body');host.replaceChildren();const meta=document.createElement('p');meta.className='portable-ref';meta.textContent=a.ref+' · '+a.bytes+' bytes';host.append(meta);
    if(a.media_type==='image/png'){const source=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(Error('Image could not be read'));reader.readAsDataURL(new Blob([bytes],{type:'image/png'}));});if(request!==dialogRequest)return;const img=document.createElement('img');img.alt=t('Image');img.src=source;host.append(img);}else{const pre=document.createElement('pre');pre.textContent=JSON.stringify(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),null,2);host.append(pre);}
  }catch(error){if(request===dialogRequest)showError($('portable-dialog-body'),error);}}
  const original=window.AgentContextUI.setRun;window.AgentContextUI.setRun=function(run,nextScope){const result=original.apply(this,arguments);refresh(run,nextScope).catch(error=>showError($('portable-links'),error));return result;};
  window.AgentPortableEvidenceUI={refresh,openAttachment};
  const initial=new URL(location.href).searchParams;refresh(initial.get('run'),initial.get('session')?{harness:initial.get('harness'),session_id:initial.get('session')}:null);
})();
