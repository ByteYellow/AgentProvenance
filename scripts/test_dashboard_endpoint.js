// Run against TestContextDashboardFixture. No external service is called.
async (page) => {
  const base=new URL(await page.url()).origin,passed=[],errors=[];
  page=await page.context().newPage();
  page.on('pageerror',error=>errors.push(error.message));
  const check=(value,label)=>{if(!value)throw new Error(label);passed.push(label);};
  const open=async(mode,lang='en')=>{
    await page.goto(base+'/?run=ui-endpoint-'+mode+'&lens=data-flow-taint&detail=raw&lang='+lang+'&live=0');
    await page.waitForFunction(()=>window._lg?.nodes?.some(n=>n.data?.source==='endpoint_capture'));
    const id=await page.evaluate(()=>window._lg.nodes.find(n=>n.data?.source==='endpoint_capture').id);
    await page.locator('g[data-id="'+id+'"]').click();
    await page.locator('[data-endpoint-association]').waitFor();
    return id;
  };
  try {
    await page.setViewportSize({width:1440,height:1080});
    const selected=await open('candidates');
    check(await page.locator('[data-endpoint-stage]').count()===3,'three distinct evidence stages in existing detail');
    check(await page.locator('[data-investigation]').count()===3,'search, compare and export remain available');
    check(await page.locator('[data-endpoint-stage="content"]').innerText().then(s=>s.includes('Markers found in captured body')&&s.includes('PUBLIC-ENDPOINT-FIXTURE-CANARY')),'content fact and matched marker are visible');
    check(await page.locator('[data-endpoint-stage="sources"]').innerText().then(s=>s.includes('Multiple candidate reads')),'source ambiguity remains explicit');
    check(await page.locator('.association-candidates li').count()===2,'both read candidates are retained');
    check(await page.locator('[data-endpoint-stage="execution"]').innerText().then(s=>s.includes('Attribution unresolved')),'content match does not fill execution identity');
    await page.locator('.association-candidates [data-association-read]').first().click();
    await page.waitForFunction(()=>document.getElementById('content-body').textContent.includes('/fixture/secret.txt'));
    check(await page.locator('#detail').getAttribute('data-node')===selected,'reading source evidence keeps the selected endpoint');
    await page.locator('[data-inspection-tab="summary"]').click();
    check(await page.locator('.association-candidates li').count()===2,'reader return preserves candidate set');
    await page.locator('[data-investigation="search"]').click();
    await page.locator('#search-close').click();
    check(await page.locator('#detail').getAttribute('data-node')===selected,'search return preserves selected endpoint');
    await page.locator('[data-endpoint-association] > details > summary').click();
    check(await page.locator('[data-endpoint-association]').innerText().then(s=>s.includes('agentprov.endpoint_attribution/v2')&&s.includes('2026-11-06T00:00:03.000000Z')),'rule and capture time stay inspectable');
    await page.locator('.association-candidates [data-association-graph]').last().click();
    await page.waitForFunction(()=>document.getElementById('detail').dataset.node==='runtime_event/ui-endpoint-candidates-read-b');
    check(await page.locator('#runsel').inputValue()==='ui-endpoint-candidates','source link stays in the same run');
    await open('bound');
    check(await page.locator('[data-endpoint-stage="sources"]').innerText().then(s=>s.includes('Linked by capture reference and content version')),'explicit source link remains available');
    check(await page.locator('[data-endpoint-stage="execution"]').innerText().then(s=>s.includes('Bound by capture operation reference')&&s.includes('ui-endpoint-bound-sender')),'sender identity stays separate from reader identity');
    await open('missing');
    check(await page.locator('.association-candidates li').count()===0,'missing read evidence has no invented candidate');
    check(await page.locator('[data-endpoint-stage="content"]').innerText().then(s=>s.includes('PUBLIC-ENDPOINT-FIXTURE-CANARY')),'missing source does not erase body match');
    await page.setViewportSize({width:390,height:844});
    await open('candidates','zh-CN');
    check(await page.locator('[data-endpoint-association]').innerText().then(s=>s.includes('正文命中')&&s.includes('源读取关联')&&s.includes('执行归属')&&s.includes('存在多条候选读取')),'Chinese stage labels and states');
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile details have no horizontal overflow');
    for(let i=0;i<2;i++){
      await page.locator('[data-expand="upstream"]').click();
      await page.locator('[data-expand="lineage"]').click();
    }
    check(await page.locator('[data-endpoint-association]').count()===1,'redraw does not duplicate detail sections');
    await page.locator('.association-candidates [data-association-read]').last().click();
    await page.waitForFunction(()=>document.getElementById('content-body').textContent.includes('/fixture/secret.txt'));
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile evidence reader has no horizontal overflow');
    check(errors.length===0,'no browser errors: '+errors.join('; '));
    await page.close();
    return {fixture:'synthetic endpoint associations',checks:passed.length,passed};
  } catch(error) {throw new Error('After '+passed.length+' checks: '+passed.at(-1)+'; '+error.message);}
}
