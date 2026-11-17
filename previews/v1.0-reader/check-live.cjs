// Exercise the shared reader's live refresh using controlled in-browser API responses.
const {chromium}=require('playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const base=process.argv[2],output=path.resolve(process.argv[3]);
const repo=path.resolve(__dirname,'../..');
(async()=>{
  fs.mkdirSync(output,{recursive:true});
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  try {
    const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    for(const asset of ['context.js','evidence.js']) await page.route('**/assets/'+asset,route=>route.fulfill({contentType:'application/javascript',body:fs.readFileSync(asset==='evidence.js'&&process.env.AGENTPROV_EVIDENCE_SOURCE?process.env.AGENTPROV_EVIDENCE_SOURCE:path.join(repo,'internal/dashboard',asset),'utf8')}));
    await page.goto(new URL('workspace/en/index.html?live=0',base).href);
    await page.waitForFunction(()=>window.AgentPortableEvidenceUI&&document.querySelector('#dag')?.childElementCount>0);
    await page.locator('#context-fold>summary').click();
    await page.locator('#portable-workspace-tab').click();
    await page.locator('[data-workspace-entry]').first().waitFor();
    const before=await page.locator('[data-workspace-entry]').count();
    await page.evaluate(()=>{
      const original=window.j;window.entryQueries=0;
      window.j=(query,...args)=>{if(query.startsWith('/api/context/entries?'))window.entryQueries++;return original(query,...args);};
    });
    await page.locator('[data-native-body]').first().click();
    await page.locator('#portable-dialog-body pre').first().waitFor();
    assert.equal(await page.evaluate(()=>entryQueries),0,'opening a body must not also paginate');
    assert.equal(await page.locator('[data-workspace-entry]').count(),before);
    await page.locator('.portable-evidence-head button').click();
    await page.evaluate(async()=>{
      const replay=window.AgentProvReplay,originalFetch=window.fetch,run=new URL(location.href).searchParams.get('run');
      const first=await replay.query('/api/context/entries?run='+run+'&limit=100');
      const entry=first.entries.find(e=>e.kind==='tool_result'&&e.tool_name.includes('workspace_'));
      window.liveRows=Array.from({length:201},(_,i)=>({...entry,id:'live-'+i,tool_call_id:'call-'+i}));
      window.fetch=async(input,options)=>{
        const query=new URL(typeof input==='string'?input:input.url,location.href);
        if(!query.pathname.startsWith('/api/'))return originalFetch(input,options);
        let value;
        if(query.pathname==='/api/context/entries'){
          const offset=Number(query.searchParams.get('cursor')||0),limit=Number(query.searchParams.get('limit')||100),next=offset+limit;
          value={entries:liveRows.slice(offset,next),has_more:next<liveRows.length,next_cursor:next<liveRows.length?String(next):''};
        } else value=await replay.query(query.pathname+query.search);
        return new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
      };
      delete window.AgentProvReplay;
      window.AgentContextUI.setRun(run,null);
    });
    await page.locator('[data-workspace-entry="live-99"]').waitFor();
    assert.equal(await page.locator('[data-workspace-entry]').count(),100);
    assert.equal(await page.locator('#portable-workspace-tab').getAttribute('aria-selected'),'true');
    assert.equal(await page.locator('[data-context-tab][aria-selected="true"]').count(),0);
    assert(await page.locator('#context-source').isDisabled());
    await page.locator('[data-native-more]').click();
    await page.locator('[data-workspace-entry="live-199"]').waitFor();
    await page.evaluate(()=>{document.querySelector('#portable-native').scrollTop=100;liveRows[0].tool_name='workspace_write_updated';});
    await page.evaluate(()=>window.AgentPortableEvidenceUI.refresh(new URL(location.href).searchParams.get('run'),null,true));
    assert.equal(await page.locator('[data-workspace-entry]').count(),200,'refresh preserves loaded pages');
    assert.equal(await page.locator('#portable-native').evaluate(e=>e.scrollTop),100);
    assert.equal(await page.locator('[data-workspace-entry="live-0"] h3').innerText(),'workspace_write_updated');
    await page.locator('[data-native-more]').click();
    await page.locator('[data-workspace-entry="live-200"]').waitFor();
    assert.equal(await page.locator('[data-workspace-entry]').count(),201);
    assert.equal(await page.locator('[data-native-more]').count(),0);
    await page.evaluate(()=>window.AgentContextUI.selectSource(''));
    assert(await page.locator('#portable-native').isHidden(),'session navigation reveals the conversation');
    await page.locator('#portable-workspace-tab').click();
    await page.evaluate(()=>window.AgentContextUI.open('configuration'));
    assert(await page.locator('#portable-native').isHidden(),'configuration navigation reveals its tab');
    await page.locator('#portable-workspace-tab').click();
    await page.locator('[data-context-tab="conversation"]').click();
    assert(await page.locator('#portable-native').isHidden());
    assert(await page.locator('#context-source').isEnabled());
    assert.deepEqual(errors,[]);
    const report={passed:true,bodyDoesNotPaginate:true,liveRefresh:true,loadedPagesPreserved:true,scrollPreserved:true,tabPreserved:true,errors};
    fs.writeFileSync(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify(report));
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
