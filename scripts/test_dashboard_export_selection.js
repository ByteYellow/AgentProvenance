// Run through playwright-cli against the historical DeepSeek and multiagent
// store. Downloads are real archives. Fault, race and warning-presentation cases
// are explicitly synthetic; they never change the source store or downloaded ZIPs.
async (page) => {
  const checks=[],errors=[],archives=[];
  let warningFixture;
  const check=(ok,name)=>{if(!ok)throw new Error(name);checks.push(name);};
  const base=await page.evaluate(()=>location.origin);
  page=await page.context().newPage();page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:1440,height:1050});
  const scope=value=>page.locator('input[name="export-scope"][value="'+value+'"]');
  const prepare=async(synthetic=false)=>{
    await page.locator('#export-ack').check();
    const ready=page.waitForResponse(r=>r.url().endsWith('/api/replay/previews')&&r.request().method()==='POST');
    await page.locator('#export-prepare').click();
    const response=await ready;check(response.status()===201,synthetic?'synthetic warning preview rendered':'real selected archive prepared');
    const p=await response.json();await page.locator('#export-result').waitFor();return p;
  };
  for(const run of ['run-dbc2adf273d4','run-double-attempt']){
    await page.goto(base+'/?run='+run+'&lang=en&live=0');
    await page.waitForFunction(run=>window._lensManifest?.run_id===run,run);
    const native=run==='run-dbc2adf273d4';
    if(native){await page.locator('#session-members [data-session-index]').first().click();await page.waitForFunction(()=>SESSION_SCOPE?.session_id&&window._lensManifest?.query.session_scope);}
    const before=await page.evaluate(()=>({run:cur,lens:LENS,zoom:ZOOM,scope:SESSION_SCOPE,selected:SEL}));
    await page.locator('[data-investigation="export"]').click();
    check(await scope('whole_run').isChecked(),'whole run remains default: '+run);
    let excluded;
    if(native){
      await scope('session').check();
      await page.locator('#export-record-picker summary').click();
      await page.waitForFunction(()=>document.querySelectorAll('[data-export-record]').length===50);
      const record=page.locator('[data-export-record]').first();excluded=await record.getAttribute('data-record-id');
      await page.locator('[data-export-inspect]').first().click();
      await page.locator('#content-dialog').waitFor();
      await page.waitForFunction(()=>document.querySelector('#content-body').textContent.length>50);
      check(await page.locator('#content-dialog #content-pane').count()===1,'record uses the existing body reader');
      await page.locator('#content-close').click();
      await page.waitForFunction(()=>document.querySelector('#content-home #content-pane'));
      check(await page.locator('#export-dialog').isVisible(),'body reader returns to selection');
      await record.uncheck();
      await page.locator('#export-record-next').click();await page.waitForFunction(()=>document.querySelector('#export-record-page').textContent==='Page 2'&&!document.querySelector('#export-record-prev').disabled);
      await page.locator('#export-record-prev').click();await page.waitForFunction(()=>document.querySelector('#export-record-page').textContent==='Page 1'&&!document.querySelector('#export-record-next').disabled);
      check(!(await page.locator('[data-export-record]').first().isChecked()),'record exclusion survives paging');
      await page.locator('#export-ack').check();await page.locator('[data-export-category="tools"]').uncheck();
      check(await page.locator('#export-prepare').isDisabled(),'selection change requires confirmation again');
      await page.locator('#export-record-picker summary').click();
    }else{
      check(await page.locator('#export-session-option').isHidden(),'legacy run has no invented session');
      await page.locator('[data-export-category="messages"]').uncheck();
    }
    await page.screenshot({path:'output/playwright/selection-'+run+'-desktop.png'});
    await page.setViewportSize({width:390,height:844});
    check(await page.locator('#export-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+1),'selection fits mobile: '+run);
    await page.screenshot({path:'output/playwright/selection-'+run+'-mobile.png'});await page.setViewportSize({width:1440,height:1050});
    const p=await prepare(),summary=p.inventory.selection_summary;
    if(native)warningFixture=structuredClone(p);
    check(summary&&summary.excluded_records>0&&summary.included_records>0,'frozen summary counts actual membership: '+run);
    check(summary.selection.scope===(native?'session':'whole_run'),'frozen scope matches choice: '+run);
    if(native){
      check(summary.selection.exclude_records.includes(excluded)&&summary.selection.exclude_categories.includes('tools'),'record and category choices reach server');
      check(summary.exclusion_reasons.outside_scope>0&&p.inventory.events<=2,'unassigned events stay outside session');
    }else check(!p.inventory.contents.indexed_sources.messages,'messages category is removed from search');
    check(await page.locator('#export-settings').isHidden(),'frozen result cannot be silently edited');
    const manifestResponse=await page.request.get(base+'/api/replay/previews/'+p.id+'/files/record-selection.json');
    const manifest=await manifestResponse.json();
    check(manifest.records.filter(r=>r.included).length===summary.included_records&&manifest.records.filter(r=>!r.included).length===summary.excluded_records,'manifest and summary agree: '+run);
    if(native)check(manifest.records.find(r=>r.id===excluded)?.included===false,'chosen record excluded in frozen manifest');
    check(manifest.warning_count===summary.warning_count,'warning summary matches manifest');
    if(summary.warning_count)check(await page.locator('#export-warnings').isVisible(),'retained duplicate content is called out');
    const popupReady=page.waitForEvent('popup');await page.locator('#export-view').click();const popup=await popupReady;
    await popup.waitForFunction(()=>window._lensManifest&&document.querySelector('#dag svg'));
    check((await popup.locator('#verify').innerText()).includes('Selected evidence'),'partial preview is labeled');
    const ids=await popup.evaluate(async run=>{let cursor='',ids=[];do{const p=await AgentProvReplay.query('/api/search/sources?'+new URLSearchParams({run,cursor}));ids.push(...p.sources.map(s=>s.id));cursor=p.has_more?p.next_cursor:'';}while(cursor);return ids;},run);
    const expected=manifest.records.filter(r=>r.included&&r.indexed).map(r=>r.id).sort();
    check(JSON.stringify(ids.sort())===JSON.stringify(expected),'frozen search contains exactly selected records: '+run);await popup.close();
    const downloaded=page.waitForEvent('download');await page.locator('#export-download').click();const download=await downloaded;
    await download.saveAs('output/playwright/selected-'+run+'.zip');check((await download.failure())===null,'selected ZIP actually downloaded: '+run);
    archives.push({run,scope:p.inventory.scope,events:p.inventory.events,included:summary.included_records,excluded:summary.excluded_records,warnings:summary.warning_count,bytes:p.zip_bytes,sha256:p.zip_sha256});
    await page.screenshot({path:'output/playwright/selection-ready-'+run+'-desktop.png'});
    await page.setViewportSize({width:390,height:844});check(await page.locator('#export-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+1),'result fits mobile: '+run);
    await page.screenshot({path:'output/playwright/selection-ready-'+run+'-mobile.png'});await page.setViewportSize({width:1440,height:1050});
    await page.locator('#export-discard').click();await page.waitForFunction(()=>document.querySelector('#export-result').hidden);
    check((await page.request.get(base+'/api/replay/previews/'+p.id)).status()===410,'changing selection retires the old archive');
    if(native){
      check(await scope('session').isChecked(),'change selection retains chosen scope');
      await scope('whole_run').check();check((await page.locator('#export-excluded-count').innerText()).includes('0'),'switching scope clears scope-specific record exclusions');
    }
    await page.locator('#export-close').click();
    const after=await page.evaluate(()=>({run:cur,lens:LENS,zoom:ZOOM,scope:SESSION_SCOPE,selected:SEL}));
    check(JSON.stringify(before)===JSON.stringify(after),'export leaves graph and session unchanged: '+run);
  }
  // A failed catalog page can be retried; a stopped preparation can be edited.
  await page.locator('[data-investigation="export"]').click();
  await page.route('**/api/search/sources?**',route=>route.fulfill({status:503,body:'catalog temporarily unavailable'}),{times:1});
  await page.locator('#export-record-picker summary').click();await page.locator('#export-record-retry').waitFor();
  check((await page.locator('#export-record-status').innerText()).includes('503'),'catalog errors remain visible');
  await page.locator('#export-record-retry').click();await page.waitForFunction(()=>document.querySelectorAll('[data-export-record]').length>0);
  check(await page.locator('#export-record-retry').isHidden(),'catalog retry restores usable records');
  await page.route('**/api/replay/previews',async route=>{await new Promise(resolve=>setTimeout(resolve,1500));await route.fulfill({status:408,contentType:'application/json',body:'{"error":"timeout"}'}).catch(()=>{});},{times:1});
  await page.locator('#export-ack').check();await page.locator('#export-prepare').click();await page.locator('#export-stop').click();
  await page.waitForFunction(()=>!document.querySelector('#export-settings').disabled);
  check((await page.locator('#export-status').innerText()).includes('stopped'),'cancellation restores editable selection');
  await page.locator('#export-close').click();
  await page.goto(base+'/?run=run-dbc2adf273d4&lang=en&live=0');
  await page.waitForFunction(()=>window._lensManifest?.run_id==='run-dbc2adf273d4');
  await page.locator('#session-members [data-session-index]').first().click();
  await page.waitForFunction(()=>SESSION_SCOPE?.session_id&&window._lensManifest?.query.session_scope);
  await page.evaluate(()=>Promise.all([AgentExportUI.open(),AgentExportUI.open()]));
  check(await page.locator('#export-dialog').isVisible(),'duplicate open requests keep one dialog');
  let held,release,finished;
  const ready=new Promise(resolve=>held=resolve),gate=new Promise(resolve=>release=resolve),done=new Promise(resolve=>finished=resolve);
  await page.route('**/api/search/sources?**',async route=>{
    const response=await route.fetch(),data=await response.json();
    if(data.sources.length)data.sources[0].label='STALE CATALOG RESPONSE';
    held();await gate;
    await route.fulfill({response,json:data}).catch(()=>{});finished();
  },{times:1});
  await page.locator('#export-record-picker summary').click();await ready;
  await scope('session').check();await page.waitForFunction(()=>document.querySelectorAll('[data-export-record]').length===50);
  const sessionRecords=await page.locator('[data-export-record]').evaluateAll(inputs=>inputs.map(input=>input.dataset.recordId));
  release();await done;
  check(!(await page.locator('#export-records').innerText()).includes('STALE CATALOG RESPONSE'),'obsolete catalog response cannot overwrite new scope');
  check(JSON.stringify(await page.locator('[data-export-record]').evaluateAll(inputs=>inputs.map(input=>input.dataset.recordId)))===JSON.stringify(sessionRecords),'scope change preserves the new catalog');
  await page.route('**/api/search/sources?**',route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({schema_version:'agentprovenance.search_sources/v1',run_id:'run-dbc2adf273d4',sources:[],has_more:true,next_cursor:'repeated'})}),{times:2});
  await scope('whole_run').check();await page.locator('#export-record-retry').waitFor();
  check((await page.locator('#export-record-status').innerText()).includes('Invalid search source page'),'nonadvancing catalog fails visibly');
  await page.locator('#export-record-retry').click();await page.waitForFunction(()=>document.querySelectorAll('[data-export-record]').length>0);
  check(await page.locator('#export-record-retry').isHidden(),'catalog is usable after malformed page retry');
  await page.locator('#export-close').click();
  await page.getByRole('link',{name:'中文',exact:true}).click();await page.waitForFunction(()=>window._lensManifest);
  await page.locator('[data-investigation="export"]').click();
  check(await page.locator('#export-settings legend').innerText()==='分享范围','selection labels are localized');
  await scope('session').check();await page.locator('#export-record-picker summary').click();
  await page.waitForFunction(()=>document.querySelectorAll('[data-export-record]').length===50);
  await page.screenshot({path:'output/playwright/selection-zh-CN-desktop.png'});
  await page.setViewportSize({width:390,height:844});
  check(await page.locator('#export-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+1),'Chinese record picker fits mobile');
  await page.screenshot({path:'output/playwright/selection-zh-CN-mobile.png'});
  // UI-only warning fixture: bounded examples, escaped source IDs, no download.
  warningFixture.id='synthetic-warning-preview';warningFixture.inventory.selection_summary.warning_count=101;
  warningFixture.inventory.selection_summary.warnings=Array.from({length:100},(_,i)=>({code:'same_content_in_retained_record',content_sha256:'a'.repeat(64),included_records:['<img src=x onerror=alert(1)>',String(i)],excluded_records:['synthetic-excluded'],included_count:11,excluded_count:1}));
  await page.route('**/api/replay/previews',route=>route.fulfill({status:201,contentType:'application/json',body:JSON.stringify(warningFixture)}),{times:1});
  await prepare(true);check(await page.locator('#export-warnings').isVisible(),'repeated-content warning is visible');
  check((await page.locator('#export-warning-count').innerText()).includes('101'),'warning total includes unsampled warnings');
  check((await page.locator('#export-warning-limit').innerText()).includes('100'),'warning sampling limit is disclosed');
  check(await page.locator('#export-warning-items li').count()===100,'bounded warning examples remain inspectable');
  check(await page.locator('#export-warning-items img').count()===0,'source IDs render as text, not markup');
  check(await page.locator('#export-warning-items').evaluate(e=>e.clientHeight<=240&&e.scrollHeight>e.clientHeight),'long warning list scrolls independently');
  await page.locator('#export-download').scrollIntoViewIfNeeded();
  check(await page.locator('#export-download').isVisible(),'download stays reachable after many warnings');
  await page.route('**/api/replay/previews/synthetic-warning-preview',route=>route.fulfill({status:204}),{times:1});
  await page.locator('#export-close').click();
  check(errors.length===0,'no browser errors: '+errors.join('; '));await page.close();
  return {checks:checks.length,passed:checks,archives};
}
