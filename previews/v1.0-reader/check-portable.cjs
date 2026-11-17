// Browser language, mobile layout and file:// reading of every retained preview.
const {chromium}=require('playwright'),assert=require('node:assert/strict'),fs=require('node:fs');
const path=require('node:path'),{pathToFileURL}=require('node:url');
const root=path.resolve(process.argv[2]),output=path.resolve(process.argv[3]);
(async()=>{
  fs.mkdirSync(output,{recursive:true});const browser=await chromium.launch({headless:true}),reports=[];
  try{
    for(const name of ['execution','workspace','browser','notebook','investigation'])for(const locale of ['fr-FR','zh-CN']){
      const zh=locale==='zh-CN',context=await browser.newContext({offline:true,locale,viewport:{width:390,height:844}}),page=await context.newPage();
      const errors=[],network=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/^https?:/.test(r.url()))network.push(r.url());});
      try{
        await page.goto(pathToFileURL(path.join(root,name,'index.html')).href);
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI&&document.querySelector('#dag')?.childElementCount>0);
        assert.equal(await page.locator('html').getAttribute('lang'),zh?'zh-CN':'en');
        assert.equal(await page.locator('#context-fold').getAttribute('open'),null);
        const graph=await page.locator('#dag').boundingBox(),session=await page.locator('#context-fold').boundingBox();assert.ok(graph.y<session.y);
        for(const selector of ['#compare-dialog','#search-dialog','#content-body'])assert.equal(await page.locator(selector).count(),1);
        await page.locator('#portable-delivery-details').click();
        const delivery=await page.locator('#portable-dialog-body').innerText();
        assert.match(await page.locator('#portable-dialog-body dd').first().innerText(),zh?/阅读副本/:/Unsigned reading copy/);
        assert.match(delivery,zh?/等待|未执行|尚未/:/Not run/);
        for(const mode of ['reading','derived','originals'])assert.ok(delivery.includes(mode));
        assert.ok(await page.locator('#portable-dialog-body').evaluate(e=>e.scrollWidth<=e.clientWidth+1));
        await page.locator('.portable-evidence-head button').click();
        if(['workspace','browser','notebook'].includes(name)){
          await page.locator('#context-fold>summary').click();
          await page.locator(name==='workspace'?'#portable-workspace-tab':'#portable-native-tab').click();
          const row=name==='workspace'?page.locator('[data-workspace-entry]').filter({has:page.locator('h3',{hasText:'workspace_bash'})}):page.locator('[data-native-entry]').first();
          await row.locator('[data-native-body]').click();
          await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
          if(name==='workspace'){
            assert.equal(await page.locator('[data-workspace-receipt]').count(),1);
            assert.match(await page.locator('#portable-dialog-body').innerText(),zh?/输入版本/:/Input revision/);
          }
          assert.ok(await page.locator('#portable-dialog-body').evaluate(e=>e.scrollWidth<=e.clientWidth+1));
        }
        assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
        await page.screenshot({path:path.join(output,name+'-'+(zh?'zh-CN':'en')+'-mobile.png')});
        assert.deepEqual(errors,[]);assert.deepEqual(network,[]);
        reports.push({name,language:zh?'zh-CN':'en',browserLocale:locale,offline:true,mobile:true,networkRequests:0,errors});
      }finally{await context.close();}
    }
    console.log(JSON.stringify({portablePreviewPassed:true,reports}));
    fs.writeFileSync(path.join(output,'report.json'),JSON.stringify({portablePreviewPassed:true,reports},null,2)+'\n');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
