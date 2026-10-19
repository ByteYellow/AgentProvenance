// Use the saved live-audit-mixed replay with its DENIED attempt excluded.
async (page) => {
  const checks=[],errors=[];
  const check=(ok,label)=>{if(!ok)throw new Error(label);checks.push(label);};
  page=await page.context().newPage();
  page.on('pageerror',error=>errors.push(error.message));
  const base=page.context().pages().find(p=>p!==page&&p.url().includes('excluded-attempt'));
  if(!base)throw new Error('Open the excluded-attempt replay first');
  await page.goto(base.url());
  await page.waitForFunction(()=>document.querySelector('[data-access-kind="access_control"] span').textContent==='6');
  await page.locator('[data-access-kind="access_control"]').click();
  const row=page.locator('.access-record').filter({has:page.locator('code',{hasText:'DENIED'})});
  await row.getByRole('button',{name:'Inspect operation evidence',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('[data-access-diagnostics]')?.textContent.includes('replay_evidence_excluded'));
  check(await page.locator('[data-access-stage="decision"] code').innerText()==='DENIED','selected audit decision remains readable');
  check(await page.locator('[data-access-association]').innerText().then(text=>text.includes('Supporting records were excluded')),'sharing exclusion has a visible explanation');
  check(await page.locator('[data-access-attempt]').innerText()==='No associated operation attempt recorded.','excluded support does not produce an inferred attempt');
  check(await page.locator('[data-access-result]').innerText()==='No associated syscall return recorded.','partial evidence does not reconstruct the old result');
  check(await page.locator('[data-access-ref]').count()===0,'withheld association references remain absent');
  const hidden=await page.evaluate(()=>j('/api/events?run=live-audit-mixed&focus=runtime_event/evt-6792b8daa31f&limit=25'));
  check(hidden.events.length===0,'excluded event is not available through offline queries');
  check(errors.length===0,'no page errors: '+errors.join('; '));
  await page.close();
  return {input:'saved ARM64 capture with one attempt excluded',checks:checks.length,passed:checks};
}
