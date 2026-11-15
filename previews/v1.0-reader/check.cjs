const {chromium}=require('playwright');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const root=require('node:path').resolve(process.argv[2]||'.preview-check');
const previewURL=(process.env.AGENTPROV_PREVIEW_URL||'http://127.0.0.1:47920').replace(/\/$/,'');
(async()=>{
  const browser=await chromium.launch({headless:true});
  const reports=[];fs.mkdirSync(root+'/ui-screenshots',{recursive:true});
  try {
    for(const name of ['execution','browser','notebook','investigation']){
      const context=await browser.newContext({viewport:{width:1440,height:1050},locale:'en-US'});
      const page=await context.newPage();const errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      const outside=[];page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(previewURL+'/'))outside.push(r.url());});
      await page.goto(previewURL+'/'+name+'/index.html');
      await page.waitForFunction(()=>window.AgentPortableEvidenceUI&&document.querySelector('#context-summary').textContent!=='loading…');
      await page.waitForFunction(()=>document.querySelector('#dag').childElementCount>0);
      assert.equal(await page.locator('#context-fold').getAttribute('open'),null);
      assert.equal(await page.locator('#compare-dialog').count(),1);
      const result={name,errors,outside};
      if(name==='execution'){
        await page.waitForSelector('[data-execution-attempt]',{state:'attached'});
        await page.locator('#portable-executions>details>summary').click();
        result.attempts=await page.locator('[data-execution-attempt]').count();assert.ok(result.attempts>=2);
        await page.locator('#portable-executions').screenshot({path:root+'/ui-screenshots/execution.png'});
        await page.locator('[data-portable-action="source"]').first().click();
        await page.waitForSelector('[data-dialog-entry]');
        await page.locator('[data-dialog-entry]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        result.sourceBody=await page.locator('#portable-dialog-body pre').first().innerText();
        assert.match(result.sourceBody,/python3 analyze\.py/);
        await page.locator('.portable-evidence-head button').click();
        const originRun=new URL(page.url()).searchParams.get('run');
        await page.locator('[data-portable-action="execution"]').first().click();
        await page.waitForFunction(run=>new URL(location.href).searchParams.get('run')!==run,originRun);
        await page.waitForSelector('[data-execution-direction="incoming"]');
        await page.locator('[data-execution-direction="incoming"] [data-portable-action="source"]').first().click();
        await page.waitForFunction(run=>new URL(location.href).searchParams.get('run')===run,originRun);
        await page.waitForSelector('[data-dialog-entry]');
        await page.locator('[data-dialog-entry]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        assert.match(await page.locator('#portable-dialog-body pre').first().innerText(),/python3 analyze\.py/);
        result.bidirectional=true;
      }else if(name==='browser'||name==='notebook'){
        await page.locator('#context-fold>summary').click();await page.locator('#portable-native-tab').click();
        await page.waitForSelector('[data-native-entry]');result.records=await page.locator('[data-native-entry]').count();
        let attachments=page.locator('[data-native-attachment]:enabled');
        if(await attachments.count()===0&&await page.locator('#portable-native .portable-more').count()){
          await page.locator('#portable-native .portable-more').click();await page.waitForSelector('[data-native-attachment]:enabled');
        }
        await attachments.first().click();await page.waitForSelector('#portable-dialog-body img');
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body img')?.naturalWidth>0);
        result.image=true;await page.screenshot({path:root+'/ui-screenshots/'+name+'.png'});
        await page.locator('.portable-evidence-head button').click();
        await page.locator('[data-native-body]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        result.content=true;
      }else{
        await page.screenshot({path:root+'/ui-screenshots/investigation.png'});
      }
      assert.deepEqual(errors,[]);assert.deepEqual(outside,[]);delete result.sourceBody;reports.push(result);console.log(JSON.stringify(result));await context.close();
    }
  }finally{await browser.close();fs.writeFileSync(root+'/ui-screenshots/report.json',JSON.stringify(reports,null,2));}
})().catch(error=>{console.error(error);process.exitCode=1;});
