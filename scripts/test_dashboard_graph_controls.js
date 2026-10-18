// Run with playwright-cli on a local demo or an exported static replay page.
// Uses the original multi-agent and DeepSeek captures without response fixtures.
async (page) => {
  const entry = await page.evaluate(()=>location.origin+location.pathname);
  page = await page.context().newPage();
  const checks = [], errors = [];
  const check = (ok,name) => { if (!ok) throw new Error(name); checks.push(name); };
  page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:1440,height:1050});
  for (const run of ['run-double-attempt','run-dbc2adf273d4']) {
    await page.goto(entry+'?run='+run+'&live=0&lang=en&lens=process&detail=raw');
    await page.waitForFunction(value=>window._lensManifest?.run_id===value && TIMES.length>1,run);
    const width = await page.locator('#dag svg').getAttribute('width');
    await page.locator('#zoomin').click();
    check(Number(await page.locator('#dag svg').getAttribute('width'))>Number(width),run+': zoom enlarges graph');
    await page.locator('#zoomfit').click();
    check(await page.locator('#dag svg').getAttribute('width')===width,run+': fit restores graph width');
    await page.locator('#playbtn').click();
    await page.waitForFunction(()=>Number(document.querySelector('#slider').value)>0 && Boolean(PLAYING));
    await page.locator('#playbtn').click();
    check(await page.evaluate(()=>!PLAYING && TCUR!==null),run+': playback advances and pauses');
    await page.locator('#slider').focus();
    await page.keyboard.press('End');
    check(await page.evaluate(()=>TCUR===null),run+': scrubber restores all events');
    const lens = run==='run-double-attempt' ? 'orchestration' : 'file-artifact';
    await page.locator('#lenssel').selectOption(lens);
    await page.locator('#detailsel').selectOption(run==='run-double-attempt' ? 'summary' : 'raw');
    await page.waitForFunction(value=>window._lensManifest?.lens===value && window._lensManifest?.query.detail===document.querySelector('#detailsel').value,lens);
    const node = await page.evaluate(value=>window._lg.nodes.find(n=>value==='run-double-attempt' ? n.kind==='message' && n.data.from_name==='alice' && n.data.to_name==='bob' : n.id==='workspace_file/report.py'),run);
    check(Boolean(node),run+': expected recorded message or file exists');
    await page.locator('#dag [data-id="'+node.id+'"]').click();
    await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent && !document.querySelector('#content-pane').hidden && !document.querySelector('#content-body').textContent.includes('Loading'));
    await page.locator('#inspection-tab-content').click();
    const body = await page.locator('#content-body').textContent();
    check(body.length>20,run+': selected evidence body is readable');
    const expected = await page.evaluate(async id=>(await j('/api/artifact?run='+encodeURIComponent(cur)+'&node='+encodeURIComponent(id)+'&mode=body&view_lang=en')).content,node.id);
    check(body===expected,run+': reader preserves recorded body');
    await page.locator('#content-expand').click();
    await page.keyboard.press('Escape');
    check(await page.locator('#content-body').textContent()===body,run+': enlarged reader returns without changing content');
    await page.locator('#inspection-tab-events').click();
    await page.waitForFunction(()=>document.querySelector('#inspection-event-count')?.textContent!=='…');
    const total = await page.evaluate(async ()=>(await j('/api/events?run='+encodeURIComponent(cur)+'&lens='+EV_FILTER.lens+'&focus='+encodeURIComponent(EV_FILTER.focus)+'&group='+encodeURIComponent(EV_FILTER.group)+'&refs='+encodeURIComponent(EV_FILTER.refs.join(',')))).total);
    check(await page.locator('#inspection-event-count').textContent()===String(total),run+': related-event count matches saved query');
    await page.locator('#inspection-tab-content').click();
    await page.locator('#inspection').scrollIntoViewIfNeeded();
    await page.screenshot({path:'output/playwright/workspace-reader-'+run+'.png'});
    await page.evaluate(()=>window.scrollTo(0,0));
    await page.screenshot({path:'output/playwright/workspace-overview-'+run+'.png'});
    await page.setViewportSize({width:390,height:844});
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),run+': graph and reader fit mobile page');
    await page.setViewportSize({width:1440,height:1050});
  }
  check(errors.length===0,'no unhandled browser errors: '+errors.join('; '));
  await page.close();
  return {source:'two original captures',checks:checks.length,passed:checks};
}
