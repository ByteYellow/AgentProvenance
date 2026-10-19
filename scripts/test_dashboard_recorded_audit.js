// Read the saved live-audit-mixed fixture from an online or offline Dashboard.
// The test never executes its recorded commands or changes host policy.
async (page) => {
  const url=new URL(await page.url());url.searchParams.set('run','live-audit-mixed');url.searchParams.set('lang','en');url.searchParams.set('live','0');
  const checks=[],errors=[],external=[];
  page=await page.context().newPage();
  const check=(value,label)=>{if(!value)throw new Error(label);checks.push(label);};
  const waitForAssociation=item=>page.waitForFunction(({rule,item})=>{
    const diagnostics=document.querySelector('[data-access-diagnostics]');
    if(!diagnostics?.textContent)return false;
    const shown=JSON.parse(diagnostics.textContent);
    return shown.rule===rule&&JSON.stringify(shown.process)===JSON.stringify(item.process)&&JSON.stringify(shown.operation)===JSON.stringify(item.operation)&&document.querySelector('[data-access-stage="decision"] code')?.textContent===item.decision;
  },{rule:audits.rule,item});
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(/^https?:/.test(request.url())&&new URL(request.url()).origin!==url.origin)external.push(request.url());});
  await page.setViewportSize({width:1440,height:1050});
  await page.goto(url.href);
  const tag=await page.evaluate(()=>window.AgentProvReplay?'offline':'online');
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='6');
  const audits=await page.evaluate(async()=>{
    const events=await j('/api/events?run=live-audit-mixed&type=access_control&limit=25');
    const report=await j('/api/audit/associations?run=live-audit-mixed&limit=25');
    return {events:events.events,items:report.items,rule:report.rule};
  });
  const v1='agentprov.audit_lifecycle_operation/v1',v2='agentprov.audit_lifecycle_operation/v2';
  check(tag==='online'?audits.rule===v2:[v1,v2].includes(audits.rule),tag==='online'?'live analysis uses rule v2':'replay retains a supported frozen rule');
  check(audits.events.length===6&&audits.items.length===6,'six original mixed-mechanism decisions');
  let inferred=0,missing=0;
  for(const event of audits.events){
    const item=audits.items.find(item=>item.event_id===event.id);
    await page.locator('[data-access-kind="access_control"]').click();
    const row=page.locator('.access-record').filter({hasText:'runtime_event/'+event.id});
    await row.getByRole('button',{name:'Inspect operation evidence',exact:true}).click();
    await waitForAssociation(item);
    check(await page.locator('[data-access-stage="decision"] code').innerText()===item.decision,event.id+': original mechanism decision');
    if(item.operation.status==='inferred'){
      inferred++;
      check(item.operations.length===1,event.id+': one candidate operation');
      const value=page.locator('[data-access-result] dt').filter({hasText:'Return value'}).locator('+ dd');
      check(await value.innerText()===String(item.operations[0].syscall_result),event.id+': actual syscall result unchanged');
      const reason='Time and recorded fields identify a candidate; a shared audit/runtime call identity is unavailable.';
      if(audits.rule===v2){
        check(item.operation.basis==='lifetime_syscall_time_candidate'&&item.operation.reason==='shared_call_identity_unavailable',event.id+': v2 time-window candidate discloses missing shared call identity');
      }
      check(await page.locator('[data-access-association]').innerText()==='Inferred operation association'+(audits.rule===v2?' · '+reason:''),event.id+': derived association and version-appropriate reason are visible');
      if(audits.rule===v2)check(await page.locator('[data-access-candidate-note]').innerText()==='Attempts and returns shown here are the candidates’ saved runtime evidence. The mechanism decision is a separate audit record.',event.id+': candidate evidence is explained explicitly');
    }else{
      missing++;
      if(audits.rule===v2){
        check(item.operation.reason==='seccomp_original_syscall_not_executed'&&item.operation.candidate_count===0&&(item.operations||[]).length===0,event.id+': v2 action gate retains no executed-call candidate');
        check(await page.locator('[data-access-association]').innerText()==='Operation not associated · seccomp prevented the original syscall from executing. Nearby syscall results remain separate.',event.id+': action-gating reason is readable');
      }
      check(await page.locator('[data-access-result]').innerText().then(text=>text.includes('No associated syscall return recorded.')),event.id+': missing return not manufactured');
      check(await page.locator('[data-access-result] dt').filter({hasText:'Return value'}).count()===0,event.id+': logged ERRNO data is not an actual result');
      check(await page.locator('[data-access-result] summary').innerText().then(text=>text.includes('Same-process exit records')),event.id+': process exit evidence retained separately');
    }
    if(item.decision==='DENIED'){
      await page.locator('#inspection').scrollIntoViewIfNeeded();
      await page.screenshot({path:'output/playwright/access-control-'+tag+'-detail.png'});
      await page.locator('[data-access-attempt] summary').click();
      await page.locator('[data-access-attempt] [data-access-ref]').first().click();
      await page.waitForFunction(()=>document.querySelector('#access-reader #content-body').textContent.includes('file_open'));
      check(await page.locator('#access-reader-dialog').isVisible(),'attempt source uses original reader');
      await page.locator('#access-reader-close').click();
    }
  }
  check(inferred===4&&missing===2,'four LOG/AppArmor candidate associations and two unassociated ERRNO records');
  const paired=audits.items.filter(item=>item.operation.status==='inferred');
  check(new Set(paired.map(item=>item.operations[0].id)).size===2,'two mechanisms share two operation identities, not four attempts');
  await page.locator('[data-access-kind="access_control_state"]').click();
  await page.waitForFunction(()=>document.querySelectorAll('.access-record').length===6);
  check(await page.locator('.access-mechanisms').count()===6,'all six task-state snapshots remain readable');
  await page.locator('#access-close').click();
  url.searchParams.set('lang','zh-CN');
  if(tag==='offline')url.pathname=url.pathname.replace('/en/','/zh-CN/');
  await page.goto(url.href);
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='6');
  await page.screenshot({path:'output/playwright/access-control-'+tag+'-overview.png'});
  await page.setViewportSize({width:390,height:844});
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile overview has no horizontal overflow');
  await page.locator('[data-access-kind="access_control"]').click();
  const denied=page.locator('.access-record').filter({has:page.locator('code',{hasText:'DENIED'})});
  await denied.locator('[data-access-inspect]').click();
  await waitForAssociation(audits.items.find(item=>item.decision==='DENIED'));
  if(audits.rule===v2){
    check(await page.locator('[data-access-association]').innerText()==='推断的操作关联 · 根据时间和已记录字段找到候选；审计与运行时记录缺少共同的调用标识。','Chinese candidate reason is readable');
    check(await page.locator('[data-access-candidate-note]').innerText()==='此处的尝试和返回值来自候选操作已保存的运行时证据；机制决定来自独立的审计记录。','Chinese candidate evidence explanation is visible');
  }
  check(await page.locator('.access-three').evaluate(el=>getComputedStyle(el).gridTemplateColumns.split(' ').length===1),'mobile stages use one column');
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile detail has no horizontal overflow');
  await page.locator('.access-three').screenshot({path:'output/playwright/access-control-'+tag+'-mobile.png'});
  check(errors.length===0,'no page errors: '+errors.join('; '));
  check(external.length===0,'no external requests');
  await page.close();
  return {input:'saved ARM64 mixed audit capture; no new execution',mode:tag,rule:audits.rule,checks:checks.length,passed:checks};
}
