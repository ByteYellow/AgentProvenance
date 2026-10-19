// Run with playwright-cli against dashboard serve containing the two public
// historical bundles. This exercises actual preparation and browser downloads.
async (page) => {
  const checks=[],errors=[],previews=[];
  const check=(ok,name)=>{if(!ok)throw new Error(name);checks.push(name);};
  const base=await page.evaluate(()=>location.origin);
  page=await page.context().newPage();
  page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:1440,height:1050});
  for(const run of ['run-dbc2adf273d4','run-double-attempt']){
    await page.goto(base+'/?run='+run+'&lang=en&live=0');
    await page.waitForFunction(run=>window._lensManifest?.run_id===run,run);
    if(run==='run-dbc2adf273d4'){
      await page.locator('#session-members [data-session-index]').first().click();
      await page.waitForFunction(()=>SESSION_SCOPE?.session_id&&window._lensManifest?.query.session_scope);
    }
    await page.locator('#lenssel').selectOption('orchestration');
    await page.waitForFunction(()=>window._lensManifest?.lens==='orchestration');
    await page.locator('#zoomin').click();
    const before=await page.evaluate(()=>({run:cur,lens:LENS,detail:DETAIL,zoom:ZOOM,scope:SESSION_SCOPE,selected:SEL,focus:GRAPH_FOCUS}));
    await page.locator('[data-investigation="export"]').click();
    check(await page.locator('#export-prepare').isDisabled(),'explicit whole-run confirmation: '+run);
    if(run==='run-dbc2adf273d4')check(await page.locator('input[name="export-scope"][value="whole_run"]').isChecked()&&await page.locator('#export-session-option').isVisible(),'session filter offers an explicit choice without silently changing scope');
    await page.locator('#export-ack').check();
    const prepared=page.waitForResponse(r=>r.url().endsWith('/api/replay/previews')&&r.request().method()==='POST');
    await page.locator('#export-prepare').click();
    const response=await prepared;check(response.status()===201,'prepare actual frozen archive: '+run);
    const preview=await response.json();previews.push(preview);
    await page.locator('#export-result').waitFor();
    check(preview.inventory.run_id===run&&preview.inventory.scope==='whole_run'&&!preview.inventory.signed,'preview identity and unsigned scope: '+run);
    check(preview.zip_bytes>0&&preview.inventory.files.length>50,'exact archive size and paged file inventory: '+run);
    await page.locator('.export-files summary').click();
    check(await page.locator('#export-files tr').count()===50,'inventory first page bounded: '+run);
    const first=await page.locator('#export-files tr').first().innerText();
    await page.locator('#export-files-next').click();
    check(await page.locator('#export-files tr').first().innerText()!==first,'inventory next page: '+run);
    await page.locator('#export-files-prev').click();
    await page.locator('.export-files summary').click();
    const popupReady=page.waitForEvent('popup');await page.locator('#export-view').click();const popup=await popupReady;
    popup.on('pageerror',error=>errors.push(error.message));
    await popup.waitForFunction(()=>window._lensManifest&&document.querySelector('#dag svg'));
    check(await popup.locator('#runsel option').count()===1,'frozen inspection contains one run: '+run);
    check(await popup.locator('#live').isHidden(),'frozen inspection never advertises live capture: '+run);
    const events=await popup.evaluate(run=>AgentProvReplay.query('/api/events?run='+run),run);
    check(events.total===preview.inventory.events,'frozen reader count matches preview: '+run);
    await popup.locator('[data-investigation="export"]').click();
    check(await popup.locator('#export-local-only').isVisible()&&await popup.locator('#export-controls').isHidden(),'frozen replay explains local-only export: '+run);
    await popup.close();
    if(run==='run-double-attempt'){
      for(let i=0;i<6;i++){
        const opened=page.waitForEvent('popup');await page.locator('#export-view').click();const reader=await opened;
        reader.on('pageerror',error=>errors.push(error.message));
        await reader.waitForFunction(()=>window._lensManifest&&document.querySelector('#dag svg'));
        check(await reader.locator('#runsel').inputValue()===run,'large frozen index repeated load '+(i+1));
        await reader.close();
      }
    }
    const downloaded=page.waitForEvent('download');await page.locator('#export-download').click();const download=await downloaded;
    await download.saveAs('output/playwright/preview-'+run+'.zip');
    check((await download.failure())===null,'actual ZIP downloaded: '+run);
    await page.screenshot({path:'output/playwright/export-'+run+'-desktop.png'});
    await page.setViewportSize({width:390,height:844});
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'no mobile page overflow: '+run);
    check(await page.locator('#export-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+1),'mobile preview fits: '+run);
    await page.screenshot({path:'output/playwright/export-'+run+'-mobile.png'});
    await page.locator('#export-close').click();
    const after=await page.evaluate(()=>({run:cur,lens:LENS,detail:DETAIL,zoom:ZOOM,scope:SESSION_SCOPE,selected:SEL,focus:GRAPH_FOCUS}));
    check(JSON.stringify(before)===JSON.stringify(after),'closing export restores graph and session selection: '+run);
    await page.locator('[data-investigation="export"]').click();
    check(await page.locator('#export-digest').textContent()===preview.inventory_sha256,'reopen reuses the same prepared archive: '+run);
    await page.locator('#export-discard').click();
    await page.waitForFunction(()=>document.querySelector('#export-result').hidden);
    const gone=await page.request.get(base+'/api/replay/previews/'+preview.id);
    check(gone.status()===410,'discard releases preview: '+run);
    await page.locator('#export-close').click();
    await page.setViewportSize({width:1440,height:1050});
  }
  await page.getByRole('link',{name:'中文',exact:true}).click();
  await page.waitForFunction(()=>window._lensManifest);
  await page.locator('[data-investigation="export"]').click();
  check(await page.locator('#export-title').innerText()==='导出回放','export is localized');
  check(await page.locator('#export-prepare').innerText()==='准备预览','localized preparation controls');
  await page.locator('#export-close').click();
  check(errors.length===0,'no browser errors: '+errors.join('; '));
  await page.close();
  return {source:'historical DeepSeek and multiagent bundles',checks:checks.length,passed:checks,archives:previews.map(p=>({run:p.inventory.run_id,events:p.inventory.events,files:p.inventory.files.length,zip_bytes:p.zip_bytes,zip_sha256:p.zip_sha256,inventory_sha256:p.inventory_sha256}))};
}
