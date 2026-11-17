const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {pathToFileURL}=require('node:url');

const root=path.resolve(process.argv[2]);
const output=path.resolve(process.argv[3]);
const base=(process.env.AGENTPROV_PREVIEW_URL||'').replace(/\/$/,'');
const run='run-w01-445a3a164ae14723b82f90634cff96f5';
const expected='value=2\ncontrolled-write\n';

(async()=>{
  fs.mkdirSync(output,{recursive:true});
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const reports=[];
  try{
    for(const lang of ['en','zh-CN'])for(const mobile of [false,true]){
      const context=await browser.newContext({locale:lang,offline:!base,viewport:mobile?{width:390,height:844}:{width:1440,height:1050}});
      const page=await context.newPage(),errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      try{
        const url=new URL(base?`${base}/workspace/${lang}/index.html`:pathToFileURL(path.join(root,'workspace',lang,'index.html')).href);
        url.search=new URLSearchParams({run,lang,lens:'file-artifact',detail:'raw',live:'0'}).toString();
        await page.goto(url.href);
        await page.locator('#dag [data-id="workspace_file/result.txt"]').click();
        await page.locator('[data-inspection-tab="content"]').click();
        await page.waitForFunction(value=>document.querySelector('#content-body')?.textContent===value,expected);
        const choose=async index=>{
          const label=await page.locator('#content-choice option').nth(index).textContent();
          assert.equal(await page.locator('#content-choice').isVisible(),true,'reading modes remain a dropdown');
          await page.locator('#content-choice').selectOption(String(index));
          return label;
        };
        const rawLabel=await choose(1);
        await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent.includes('agentprov.provenance.object.v1'));
        assert.equal(await page.locator('#inspection-selection').textContent(),rawLabel,'reader title follows the selected raw record');
        const bodyLabel=await choose(0);
        await page.waitForFunction(value=>document.querySelector('#content-body')?.textContent===value,expected);
        assert.equal(await page.locator('#inspection-selection').textContent(),bodyLabel,'reader title follows the selected file content');
        assert.match(await page.locator('#content-page-label').innerText(),/0–25 \/ 25/);
        await page.locator('#content-expand').click();
        await choose(1);
        await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent.includes('content_ref'));
        await choose(0);
        await page.waitForFunction(value=>document.querySelector('#content-body')?.textContent===value,expected);
        assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
        await page.screenshot({path:path.join(output,`file-preview-${lang}-${mobile?'mobile':'desktop'}.png`)});
        await page.locator('#content-close').click();
        assert.equal(await page.locator('#content-body').textContent(),expected,'closing the reader preserves file content');
        assert.deepEqual(errors,[]);
        reports.push({language:lang,mobile,offline:!base,status:'PASS',file:'result.txt',bodyBytes:25});
      }finally{await context.close();}
    }
  }finally{
    await browser.close();
    fs.writeFileSync(path.join(output,'report.json'),JSON.stringify({reports},null,2)+'\n');
  }
  console.log(JSON.stringify({readerPassed:true,reports}));
})().catch(error=>{console.error(error);process.exitCode=1;});
