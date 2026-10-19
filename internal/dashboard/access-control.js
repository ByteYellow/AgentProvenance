window.AgentAccessControlUI=(()=>{
  'use strict';
  const $=id=>document.getElementById(id);
  const kinds={access_control:'Audit records',access_control_state:'Observed task state',access_control_config:'Configuration declarations',access_control_collection:'Audit collection'};
  const fieldNames={mechanism:'Mechanism',decision:'Recorded decision',profile:'Profile',profile_namespace:'Profile namespace',label:'Label',class:'Class',operation:'Operation',target:'Target',requested_mask:'Requested access',denied_mask:'Denied access',arch:'Architecture',abi:'ABI',syscall_name:'System call',syscall_number:'System call number',action_code:'Logged action code',action_data:'Logged action data',signal:'Logged signal',status:'Status',reason:'Reason',source:'Source',mode:'Mode',mode_number:'Mode number',filter_count:'Filter count',no_new_privs:'No new privileges',profile_type:'Profile type',localhost_profile:'Local profile',annotation_value:'Annotation',observed_at:'State observed at',source_path:'Source path',coverage_scope:'Coverage scope',upstream_loss:'Upstream loss',raw_records_retained:'Raw records retained',pending_bytes:'Pending bytes',read:'Records read',ingested:'Saved',duplicates:'Duplicates',skipped:'Skipped',failed:'Failed',identity_incomplete:'Incomplete identity',syscall_result:'Return value',syscall_outcome:'Observed outcome',id:'Operation ID',kind:'Operation',attempt_state:'Attempt observation',result_state:'Result observation',attempt_record_count:'Attempt records',result_record_count:'Result records'};
  const decisions={
    apparmor:{DENIED:'AppArmor rejected this operation.',ALLOWED:'AppArmor logged this operation without blocking it.',AUDIT:'AppArmor audit record.',KILLED:'AppArmor recorded a termination decision.'},
    seccomp:{ERRNO:'seccomp rejected the syscall; the actual return is recorded separately.',LOG:'seccomp logged this call without blocking it.',KILL_PROCESS:'seccomp selected process termination; exit observations are separate.',KILL_THREAD:'seccomp selected thread termination; exit observations are separate.',TRAP:'seccomp selected a SIGSYS trap.',TRACE:'seccomp selected tracing.',USER_NOTIF:'seccomp selected a userspace notification.',ALLOW:'seccomp selected ALLOW.'}
  };
  let api,run='',kind='access_control',offset=0,epoch=0,pageRequest=0,detailController,summaryController,listController,loan;
  let refreshed=0;
  const t=value=>api.tr(value),e=value=>api.esc(String(value??''));
  const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
  function payload(event){
    let value=typeof event.payload==='string'?JSON.parse(event.payload):event.payload;
    for(let depth=0;depth<12&&object(value);depth++){
      if(object(value.payload)){value=value.payload;continue;}
      if(object(value.raw)){value=value.raw;continue;}
      return value;
    }
    throw new Error('Invalid access-control record');
  }
  function fields(value,keys=Object.keys(value||{})){
    return '<dl>'+keys.filter(key=>Object.hasOwn(value||{},key)).map(key=>{
      const v=value[key],text=object(v)||Array.isArray(v)?JSON.stringify(v):v===null?'null':String(v);
      return `<dt>${e(t(fieldNames[key]||key))}</dt><dd>${e(text)}</dd>`;
    }).join('')+'</dl>';
  }
  function query(type,start=0,limit=25){return '/api/events?'+new URLSearchParams({run,type,offset:String(start),limit:String(limit)});}
  function init(options){
    api=options;
    $('access-summary').innerHTML=Object.entries(kinds).map(([key,label])=>`<button data-access-kind="${key}" aria-haspopup="dialog">${e(t(label))} <span>…</span></button>`).join('');
    $('access-summary').querySelectorAll('button').forEach(button=>button.onclick=()=>open(button.dataset.accessKind));
    $('access-close').onclick=()=>$('access-dialog').close();
    $('access-dialog').addEventListener('close',()=>{pageRequest++;listController?.abort();});
    $('access-kind').innerHTML=Object.entries(kinds).map(([key,label])=>`<option value="${key}">${e(t(label))}</option>`).join('');
    $('access-kind').onchange=()=>{kind=$('access-kind').value;offset=0;loadPage();};
    $('access-prev').onclick=()=>{offset=Math.max(0,offset-25);loadPage();};
    $('access-next').onclick=()=>{offset+=25;loadPage();};
    $('access-refresh').onclick=()=>loadPage();
    $('access-reader-close').onclick=()=>$('access-reader-dialog').close();
    $('access-reader-dialog').addEventListener('close',()=>{window.AgentContextUI.releaseReader(loan);loan=null;});
  }
  async function setRun(next){
    if(run===next&&Date.now()-refreshed<10000)return;
    const changed=run!==next;run=next;refreshed=Date.now();const token=++epoch;
    summaryController?.abort();const abort=new AbortController();summaryController=abort;
    if(changed){
      detailController?.abort();listController?.abort();pageRequest++;
      $('access-summary').querySelectorAll('button').forEach(button=>{
        button.querySelector('span').textContent='…';button.title=t('loading…');
      });
      if($('access-reader-dialog').open)$('access-reader-dialog').close();
      if($('access-dialog').open)$('access-dialog').close();
    }
    const results=await Promise.all(Object.keys(kinds).map(async type=>{
      try{const page=await api.j(query(type,0,1),{signal:abort.signal});return {type,total:page.total};}
      catch(error){return {type,error};}
    }));
    if(token!==epoch)return;
    for(const result of results){
      const button=$('access-summary').querySelector(`[data-access-kind="${result.type}"]`);
      button.querySelector('span').textContent=result.error?'?':result.total;
      button.title=result.error?t('Recorded evidence could not be loaded.'):t('Browse saved access-control evidence');
    }
  }
  function open(type){
    kind=Object.hasOwn(kinds,type)?type:'access_control';offset=0;
    $('access-kind').value=kind;
    if(!$('access-dialog').open)$('access-dialog').showModal();
    loadPage();
  }
  async function loadPage(){
    listController?.abort();const abort=new AbortController();listController=abort;
    const token=++pageRequest,currentRun=run;
    $('access-list').textContent=t('loading…');$('access-page').textContent='';
    $('access-prev').disabled=true;$('access-next').disabled=true;
    const notes={access_control:'Audit decisions, task state and configuration are separate evidence. Select a record to inspect its runtime association.',access_control_state:'Timestamped task observations. Each mechanism keeps its own state and source.',access_control_config:'Saved configuration declarations. Read observed task state separately.',access_control_collection:'Reader checkpoints describe the saved source. Upstream audit loss may be unknown.'};
    $('access-note').textContent=t(notes[kind]);
    try{
      const page=await api.j(query(kind,offset),{signal:abort.signal});
      if(token!==pageRequest||currentRun!==run)return;
      $('access-page').textContent=api.tx('{from}–{to} of {total}',{from:page.total?offset+1:0,to:Math.min(offset+25,page.total),total:page.total});
      $('access-prev').disabled=offset===0;$('access-next').disabled=offset+25>=page.total;
      $('access-list').innerHTML=page.events.map((event,index)=>{
        let body;
        try{body=recordHTML(event,payload(event));}catch(_){body=`<p class="context-notice">${e(t('Recorded evidence could not be loaded.'))}</p>`;}
        return `<article class="access-record"><header><strong>${e(t(kinds[event.event_type]||event.event_type))}</strong><span>${e(event.created_at)}</span></header>${body}<div class="access-links"><button data-access-inspect="${index}">${e(t(event.event_type==='access_control'?'Inspect operation evidence':'Locate in graph'))}</button><button data-access-read="${index}">${e(t('Read saved evidence'))}</button></div><details><summary>${e(t('Source and evidence'))}</summary><dl><dt>${e(t('Source'))}</dt><dd>${e(event.source)}</dd><dt>${e(t('Evidence references'))}</dt><dd>${e('runtime_event/'+event.id)}</dd></dl></details></article>`;
      }).join('')||`<p class="context-notice">${e(t('No records of this kind in saved evidence.'))}</p>`;
      $('access-list').querySelectorAll('[data-access-read]').forEach(button=>button.onclick=()=>read('runtime_event/'+page.events[Number(button.dataset.accessRead)].id));
      $('access-list').querySelectorAll('[data-access-inspect]').forEach(button=>button.onclick=async()=>{
        const event=page.events[Number(button.dataset.accessInspect)];button.disabled=true;
        try{
          $('access-dialog').close();await api.navigateGraph(currentRun,'runtime_event/'+event.id);
          $('inspection').scrollIntoView({block:'start',behavior:'smooth'});
        }catch(error){if(run===currentRun){$('access-dialog').showModal();$('access-note').textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);}}
        finally{button.disabled=false;}
      });
    }catch(error){
      if(token!==pageRequest||currentRun!==run||error.name==='AbortError')return;
      $('access-list').textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);
    }
  }
  function recordHTML(event,p){
    if(event.event_type==='access_control'){
      const mechanism=p.mechanism==='apparmor'?'AppArmor':p.mechanism==='seccomp'?'seccomp':p.mechanism;
      const interpretation=p.evidence_kind==='audit_decision'?decisions[p.mechanism]?.[p.decision]:'';
      return `<div class="access-decision"><strong>${e(mechanism)}</strong> <code>${e(p.decision)}</code></div>`+
        (interpretation?`<p>${e(t(interpretation))}</p>`:'')+
        fields(p,['profile','label','operation','target','requested_mask','denied_mask','arch','abi','syscall_name','syscall_number','action_code','action_data','signal'])+
        (p.warnings?.length?`<p class="context-notice">${e(t('Record diagnostics'))}: ${e(p.warnings.join(', '))}</p>`:'');
    }
    if(event.event_type==='access_control_state')return `<p>${e(p.observed_at)} · PID ${e(p.identity?.pid)} / TID ${e(p.identity?.tid)}</p><div class="access-mechanisms">`+['apparmor','seccomp'].map(mechanism=>`<section><h4>${e(mechanism==='apparmor'?'AppArmor':'seccomp')}</h4>${fields(p[mechanism],['status','reason','source','label','mode','mode_number','filter_count','no_new_privs'])}</section>`).join('')+'</div>';
    if(event.event_type==='access_control_config')return (p.declarations||[]).slice(0,64).map(d=>`<section><h4>${e(d.mechanism)}</h4>${fields(d,['status','source','observed_at','profile_type','localhost_profile','annotation_value'])}</section>`).join('')+((p.declarations||[]).length>64?`<p>${e(t('Additional recorded values are available through their source references.'))}</p>`:'');
    return fields(p,['mechanism','source_path','status','reason','coverage_scope','upstream_loss','raw_records_retained','pending_bytes','read','ingested','duplicates','skipped','failed','identity_incomplete']);
  }
  function read(ref){
    if(!/^runtime_event\/.+/.test(ref))return;
    loan=window.AgentContextUI.borrowReader($('access-reader'));
    $('access-reader-title').textContent=t('Saved content')+' · '+ref;
    $('access-reader-dialog').showModal();
    window.AgentContextUI.searchEvidence({id:ref,node:ref},{},'',run);
  }
  function refsHTML(refs){return (refs||[]).map(ref=>`<button class="access-ref" data-access-ref="${e(ref)}" title="${e(ref)}">${e(ref)}</button>`).join('');}
  function operationRefs(op,refs){
    return `<details><summary>${e(t('Evidence references'))} · ${(refs||[]).length}${op.refs_truncated?'+':''}</summary><p>${e(t('Operation ID'))}: ${e(op.id)}</p>${refsHTML(refs)}</details>`;
  }
  async function selectNode(node,host){
    detailController?.abort();
    if(!node?.id.startsWith('runtime_event/')||!Object.hasOwn(kinds,node.subtype))return;
    const abort=new AbortController();detailController=abort;const currentRun=run;
    const container=document.createElement('section');container.className='access-detail';container.textContent=t('loading…');
    host.querySelector('details')?.before(container);
    const valid=()=>!abort.signal.aborted&&run===currentRun&&container.isConnected;
    try{
      const page=await api.j('/api/events?'+new URLSearchParams({run,focus:node.id,limit:'1'}),{signal:abort.signal});
      if(!valid())return;
      const event=page.events.find(event=>'runtime_event/'+event.id===node.id);
      if(!event)throw new Error('Recorded evidence unavailable');
      const p=payload(event);
      if(event.event_type!=='access_control'){container.innerHTML=recordHTML(event,p);return;}
      container.innerHTML=`<div class="access-three"><section data-access-stage="attempt"><h4>${e(t('Operation attempt'))}</h4><div data-access-attempt>${e(t('loading…'))}</div></section><section data-access-stage="decision"><h4>${e(t('Mechanism decision'))}</h4>${recordHTML(event,p)}</section><section data-access-stage="result"><h4>${e(t('Observed result'))}</h4><div data-access-result>${e(t('loading…'))}</div></section></div><p class="context-notice" data-access-association></p><details><summary>${e(t('Association basis'))}</summary><pre data-access-diagnostics></pre></details>`;
      const report=await api.j('/api/audit/associations?'+new URLSearchParams({run,event:event.id,limit:'1'}),{signal:abort.signal});
      if(!valid())return;
      const item=report.items.find(item=>item.event_id===event.id);
      if(!item)throw new Error('Audit association unavailable');
      const operations=item.operations||[];
      const labels={inferred:'Inferred operation association',ambiguous:'Multiple or conflicting operation candidates',unassociated:'Operation not associated'};
      container.querySelector('[data-access-association]').textContent=t(labels[item.operation.status]||item.operation.status)+(report.status==='incomplete'?' · '+t('Association analysis incomplete'):'');
      if(item.operation.reason==='replay_evidence_excluded')container.querySelector('[data-access-association]').textContent+=' · '+t('Supporting records were excluded from this replay.');
      const candidate=index=>operations.length>1?`<h5>${e(api.tx('Candidate {number}',{number:index+1}))}</h5>`:'';
      container.querySelector('[data-access-attempt]').innerHTML=operations.map((op,index)=>`<article>${candidate(index)}${fields(op,['kind','attempt_state','attempt_record_count'])}${operationRefs(op,op.attempt_refs)}</article>`).join('')||`<p>${e(t('No associated operation attempt recorded.'))}</p>`;
      container.querySelector('[data-access-result]').innerHTML=operations.map((op,index)=>`<article>${candidate(index)}${fields(op,['result_state','syscall_result','syscall_outcome','result_record_count'])}${operationRefs(op,op.result_refs)}</article>`).join('')||`<p>${e(t('No associated syscall return recorded.'))}</p>`;
      if(item.process_exit_refs?.length)container.querySelector('[data-access-result]').insertAdjacentHTML('beforeend',`<details><summary>${e(t('Same-process exit records'))} · ${item.process_exit_refs.length}</summary>${refsHTML(item.process_exit_refs)}</details>`);
      container.querySelector('[data-access-diagnostics]').textContent=JSON.stringify({rule:report.rule,status:report.status,issues:report.issues,process:item.process,operation:item.operation,time_window:item.time_window,evidence_scope:item.evidence_scope},null,2);
      container.querySelectorAll('[data-access-ref]').forEach(button=>button.onclick=()=>read(button.dataset.accessRef));
    }catch(error){
      if(!valid())return;
      const note=document.createElement('p');note.className='context-notice';note.textContent=t('Recorded evidence could not be loaded.')+' '+t(error.message);
      if(container.querySelector('.access-three')){
        for(const key of ['attempt','result'])container.querySelector('[data-access-'+key+']').textContent=t('Association unavailable');
        container.append(note);
      }else container.replaceChildren(note);
    }
  }
  return {init,setRun,selectNode,open};
})();
