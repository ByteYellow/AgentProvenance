// Run against TestContextDashboardFixture. All records are synthetic.
async (page) => {
  const base=new URL(await page.url()).origin,passed=[],errors=[];
  page=await page.context().newPage();
  page.on('pageerror',error=>errors.push(error.message));
  const check=(value,label)=>{if(!value)throw new Error(label);passed.push(label);};
  try {
  const open=async lang=>{
    await page.goto(base+'/?run=ui-intent&lens=intent&detail=raw&lang='+lang+'&live=0');
    await page.waitForFunction(()=>window._lg?.nodes?.some(n=>n.kind==='intent_diff'));
  };
  const select=async subtype=>{
    const id=await page.evaluate(type=>window._lg.nodes.find(n=>n.subtype===type).id,subtype);
    await page.locator('g[data-id="'+id+'"]').click();
    await page.locator('[data-intent-association]').waitFor();
    return id;
  };
  await page.setViewportSize({width:1440,height:1050});
  await open('en');
  const selected=await select('intent_association_gap');
  check(await page.locator('[data-investigation]').count()===3,'search, compare and export stay in place');
  check(await page.locator('.association-candidates li').count()===2,'both unbound messages remain candidates');
  check(await page.locator('[data-intent-association] h4').innerText().then(s=>s.includes('Multiple candidate messages')),'ambiguity is visible in the selected detail');
  const refs=await page.locator('.association-candidates [data-association-read]').evaluateAll(els=>els.map(el=>el.dataset.associationRead));
  check(new Set(refs).size===2,'candidate message hashes stay distinct');
  await page.locator('.association-candidates [data-association-read]').first().click();
  await page.waitForFunction(()=>document.querySelector('#content-body').textContent.includes('Synthetic delegation'));
  check(await page.locator('#detail').getAttribute('data-node')===selected,'reading a message keeps the selected analysis node');
  await page.locator('[data-inspection-tab="summary"]').click();
  check(await page.locator('.association-candidates li').count()===2,'returning from the reader preserves all candidates');
  await page.locator('[data-intent-association] summary').click();
  check(await page.locator('[data-intent-association]').innerText().then(s=>s.includes('agentprov.intent_scope/v4')&&s.includes('runtime_event/ui-intent-secret')),'analysis rule and runtime evidence remain inspectable');
  await page.locator('[data-node-fields] summary').click();
  check(await page.locator('[data-node-fields]').innerText().then(s=>s.includes('"candidates"')&&!s.includes('[object Object]')),'structured original fields are readable JSON');
  await page.locator('[data-investigation="search"]').click();
  await page.locator('#search-close').click();
  check(await page.locator('#detail').getAttribute('data-node')===selected,'search close restores the selected graph node');
  await select('intent_coverage_gap');
  check(await page.locator('[data-intent-association]').getAttribute('data-intent-association')==='missing','missing intent remains separate from ambiguous delegation');
  check(await page.locator('[data-intent-association]').innerText().then(s=>s.includes('ui-intent-uncovered')),'coverage gap identifies the specific tool call');
  await select('decided_and_executed');
  check(await page.locator('[data-intent-association]').getAttribute('data-intent-association')==='bound','explicit positive binding remains visible');
  await select('intent_association_gap');
  await page.locator('.association-candidates [data-association-graph]').first().click();
  await page.waitForFunction(ids=>ids.includes(document.getElementById('detail').dataset.node),refs);
  check(await page.locator('#runsel').inputValue()==='ui-intent','candidate reference navigates within the same run');
  await open('zh-CN');
  await page.setViewportSize({width:390,height:844});
  await select('intent_association_gap');
  check(await page.locator('[data-intent-association] h4').innerText().then(s=>s.includes('存在多条候选消息')),'Chinese association copy is rendered');
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile detail has no page overflow');
  for(let i=0;i<3;i++){
    await page.locator('[data-expand="upstream"]').click();
    await page.locator('[data-expand="lineage"]').click();
  }
  check(await page.locator('[data-intent-association]').count()===1,'redrawing does not duplicate the detail section');
  check(await page.locator('.association-candidates li').count()===2,'redrawing preserves candidate references');
  await page.locator('.association-candidates [data-association-read]').last().click();
  await page.waitForFunction(()=>document.querySelector('#content-body').textContent.includes('Synthetic delegation'));
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile source reader has no page overflow');
  check(errors.length===0,'no browser errors: '+errors.join('; '));
  await page.close();
  return {fixture:'synthetic intent associations',checks:passed.length,passed};
  } catch(error) {throw new Error('After '+passed.length+' checks: '+passed.at(-1)+'; '+error.message);}
}
