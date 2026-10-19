// Run against TestContextDashboardFixture. Synthetic records test presentation.
async (page) => {
  const base=new URL(await page.url()).origin,passed=[],errors=[];
  page=await page.context().newPage();
  page.on('pageerror',error=>errors.push(error.message));
  const check=(value,label)=>{if(!value)throw new Error(label);passed.push(label);};
  await page.setViewportSize({width:1440,height:1050});
  await page.goto(base+'/?run=ui-access-a&lang=en&live=0');
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='61');
  check(await page.locator('[data-investigation]').count()===3,'search, compare and export remain visible');
  check(await page.locator('#session-relations-open').isVisible(),'session relationship entry remains visible');
  check(await page.locator('[data-access-kind="access_control_state"] span').innerText()==='1','state record count is separate');
  await page.locator('[data-access-kind="access_control"]').click();
  await page.locator('.access-record').first().waitFor();
  check(await page.locator('.access-record').count()===25,'audit records use bounded pages');
  check(await page.locator('#access-page').innerText()==='1–25 of 61','audit pagination reports saved records, not attempts');
  await page.locator('#access-next').click();
  await page.waitForFunction(()=>document.getElementById('access-page').textContent==='26–50 of 61');
  await page.locator('#access-next').click();
  await page.waitForFunction(()=>document.getElementById('access-page').textContent==='51–61 of 61');
  check(await page.locator('.access-record').count()===11,'final audit page retains all records');
  check(await page.locator('#access-next').isDisabled(),'last-page boundary is disabled');
  const log=page.locator('.access-record').filter({has:page.locator('code', {hasText:'LOG'})}).first();
  check(await log.innerText().then(text=>text.includes('seccomp logged this call without blocking it.')),'LOG has its own neutral interpretation');
  const denied=page.locator('.access-record').filter({has:page.locator('code',{hasText:'DENIED'})});
  while(await denied.count()===0&&!await page.locator('#access-prev').isDisabled()){
    const oldPage=await page.locator('#access-page').innerText();
    await page.locator('#access-prev').click();
    await page.waitForFunction(old=>document.getElementById('access-page').textContent!==''&&document.getElementById('access-page').textContent!==old,oldPage);
  }
  await denied.getByRole('button',{name:'Read saved evidence',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#access-reader #content-body').textContent.includes('DENIED'));
  await page.locator('#content-choice').selectOption('1');
  await page.waitForFunction(()=>document.querySelector('#access-reader #content-body').textContent.includes('DENIED'));
  check(await page.locator('#access-reader #content-body').innerText().then(text=>text.includes('fixture')),'original source uses the shared bounded reader');
  await page.locator('#access-reader-close').click();
  check(await page.locator('#access-dialog').isVisible(),'closing source reader returns to audit page');
  await denied.getByRole('button',{name:'Inspect operation evidence',exact:true}).click();
  await page.waitForSelector('[data-access-stage="decision"]');
  await page.waitForFunction(()=>document.querySelector('[data-access-association]')?.textContent==='Operation not associated');
  check(await page.locator('[data-access-stage]').count()===3,'graph detail has three evidence stages');
  check(await page.locator('[data-access-stage="decision"]').innerText().then(text=>text.includes('DENIED')),'actual mechanism decision remains visible without a match');
  check(await page.locator('[data-access-result]').innerText()==='No associated syscall return recorded.','unmatched audit does not fabricate a runtime result');
  await page.locator('[data-access-kind="access_control_state"]').click();
  await page.waitForSelector('.access-mechanisms');
  const state=await page.locator('.access-mechanisms').innerText();
  check(state.includes('AppArmor')&&state.includes('seccomp')&&state.includes('complain')&&state.includes('disabled'),'mechanism states stay separate including observed disabled');
  await page.locator('#access-kind').selectOption('access_control_config');
  await page.waitForFunction(()=>document.getElementById('access-list').textContent.includes('RuntimeDefault'));
  check(await page.locator('#access-list').innerText().then(text=>text.includes('not_declared')),'missing declaration does not become enabled');
  await page.locator('#access-kind').selectOption('access_control_collection');
  await page.waitForFunction(()=>document.getElementById('access-list').textContent.includes('selected_source_file'));
  check(await page.locator('#access-list').innerText().then(text=>text.includes('unknown')),'audit upstream coverage remains unknown');
  await page.locator('#access-close').click();
  await page.locator('[data-investigation="compare"]').click();
  await page.locator('#compare-b').selectOption('ui-access-b');
  await page.waitForFunction(()=>document.getElementById('compare-status').textContent==='Saved records loaded');
  await page.locator('[data-dimension="access_control"]').click();
  check(await page.locator('.compare-row').count()===1,'comparison isolates the changed declaration');
  await page.locator('.compare-row summary').click();
  const comparison=await page.locator('.compare-sides').innerText();
  check(comparison.includes('RuntimeDefault')&&comparison.includes('Unconfined')&&comparison.includes('Profile type'),'access-control comparison uses readable fields');
  await page.locator('[data-record-read]').first().click();
  await page.waitForFunction(()=>document.querySelector('#compare-reader #content-body').textContent.includes('RuntimeDefault'));
  check(await page.locator('#compare-reader-dialog').isVisible(),'comparison retains original evidence reading');
  await page.locator('#compare-reader-close').click();
  await page.locator('#compare-close').click();
  let failList=true,releaseSummary,summaryArrived,summaryCompleted;
  const gate=new Promise(resolve=>{releaseSummary=resolve;});
  const arrived=new Promise(resolve=>{summaryArrived=resolve;});
  const completed=new Promise(resolve=>{summaryCompleted=resolve;});
  const auditRoute=async route=>{
    const query=new URL(route.request().url()).searchParams;
    if(query.get('run')==='ui-access-b'&&query.get('limit')==='1'){
      if(query.get('type')==='access_control'){
        summaryArrived();await gate;
        try{await route.fulfill({json:{events:[],total:999}});}finally{summaryCompleted();}
        return;
      }
      if(query.get('type')==='access_control_config'){
        await route.fulfill({status:503,body:'fixture unavailable'});return;
      }
    }
    if(failList&&query.get('type')==='access_control'&&query.get('limit')==='25'){
      await route.fulfill({status:503,body:'fixture unavailable'});return;
    }
    await route.continue();
  };
  await page.route('**/api/events?*',auditRoute);
  await page.locator('[data-access-kind="access_control"]').click();
  await page.getByText(/Recorded evidence could not be loaded/).waitFor();
  check(await page.locator('#access-page').innerText()==='','failed query does not show a successful empty page');
  failList=false;
  await page.locator('#access-refresh').click();
  await page.waitForFunction(()=>document.getElementById('access-page').textContent==='1–25 of 61');
  check(await page.locator('.access-record').count()===25,'refresh retries a failed query');
  await page.locator('#access-close').click();
  await page.locator('#runsel').selectOption('ui-access-b');
  await arrived;
  check(await page.locator('[data-access-kind="access_control"] span').innerText()==='…','changing run clears the previous count while loading');
  await page.locator('#runsel').selectOption('ui-access-a');
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='61');
  releaseSummary();await completed;
  check(await page.locator('[data-access-kind="access_control"] span').innerText()==='61','late responses cannot overwrite the selected run');
  await page.locator('#runsel').selectOption('ui-access-b');
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control_config"] span').textContent==='?');
  check(await page.locator('[data-access-kind="access_control_config"]').getAttribute('title')==='Recorded evidence could not be loaded.','failed count is marked unavailable, not zero');
  await page.unroute('**/api/events?*',auditRoute);
  await page.goto(base+'/?run=ui-fixture&lang=en&live=0');
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='0');
  await page.locator('[data-access-kind="access_control"]').click();
  await page.getByText('No records of this kind in saved evidence.',{exact:true}).waitFor();
  check(await page.locator('#access-list').innerText().then(text=>!text.includes('allowed')),'empty saved set does not claim allowed operations');
  await page.locator('#access-close').click();
  await page.goto(base+'/?run=ui-access-a&lang=zh-CN&live=0');
  await page.setViewportSize({width:390,height:844});
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='61');
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile overview has no horizontal overflow');
  await page.locator('[data-access-kind="access_control_state"]').click();
  await page.waitForSelector('.access-mechanisms');
  check(await page.locator('#access-dialog').evaluate(el=>el.scrollWidth<=el.clientWidth+1),'mobile state reader has no horizontal overflow');
  await page.keyboard.press('Escape');
  check(await page.locator('#access-dialog').isHidden(),'Escape closes access evidence without graph reset');
  check(errors.length===0,'no browser errors: '+errors.join('; '));
  await page.close();
  return {fixture:'synthetic access-control records',checks:passed.length,passed};
}
