// Check an actual selected Workspace export after build.py --workspace-archive.
const {chromium}=require('playwright'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),{pathToFileURL}=require('node:url');
const root=path.resolve(process.argv[2]),excluded=process.argv[3],output=path.resolve(process.argv[4]);
(async()=>{
  assert.ok(excluded?.startsWith('context-'),'supply the excluded context entry ID');
  fs.mkdirSync(output,{recursive:true});const browser=await chromium.launch({headless:true}),reports=[];
  try{
    for(const locale of ['en-US','zh-CN']){
      const context=await browser.newContext({offline:true,locale,viewport:{width:1440,height:1050}}),page=await context.newPage(),errors=[],requests=[];
      page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/^https?:/.test(r.url()))requests.push(r.url());});
      try{
        await page.goto(pathToFileURL(path.join(root,'workspace/index.html')).href);
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI&&document.querySelector('#dag')?.childElementCount>0);
        assert.equal(await page.locator('#context-fold').getAttribute('open'),null);
        const entries=await page.evaluate(async()=>{
          const run=new URL(location.href).searchParams.get('run');
          return (await window.j('/api/context/entries?run='+encodeURIComponent(run)+'&limit=200')).entries;
        });
        assert.ok(entries.length>0);assert.ok(entries.every(e=>e.id!==excluded));
        await page.locator('#context-fold>summary').click();await page.locator('#portable-workspace-tab').click();
        await page.waitForFunction(()=>document.querySelectorAll('[data-workspace-entry]').length>0);
        const ids=await page.locator('[data-workspace-entry]').evaluateAll(es=>es.map(e=>e.dataset.workspaceEntry));
        assert.ok(!ids.includes(excluded));
        const retained=page.locator('[data-workspace-entry]').filter({has:page.locator('h3',{hasText:'workspace_read'})}).first();
        await retained.locator('[data-native-body]').click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        assert.deepEqual(errors,[]);assert.deepEqual(requests,[]);
        await page.screenshot({path:path.join(output,locale+'.png')});
        reports.push({locale,excludedEntry:excluded,retainedWorkspaceRecords:ids.length,retainedContentReadable:true,networkRequests:0,errors});
      }finally{await context.close();}
    }
    const report={selectivePreviewPassed:true,reports};fs.writeFileSync(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
