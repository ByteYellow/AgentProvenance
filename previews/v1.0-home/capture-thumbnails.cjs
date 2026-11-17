const {chromium} = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const base = process.argv[2] || 'http://127.0.0.1:58729/';
const output = path.resolve(process.argv[3] || path.join(__dirname,'media'));
fs.mkdirSync(output,{recursive:true});

(async()=>{
  const browser = await chromium.launch({channel:'chrome',headless:true});
  try {
    for(const language of ['zh-CN','en']) for(const name of ['investigation','remote','native','team']) {
      if(process.env.CAPTURE_ONLY && process.env.CAPTURE_ONLY !== `${name}-${language}`) continue;
      const page = await browser.newPage({viewport:{width:name==='remote'||name==='native'?760:1080,height:900},deviceScaleFactor:1.5,locale:language});
      const routes = {
        investigation:`current/investigation/${language}/index.html?run=run-3bfc6838a9c6&lens=file-artifact&live=0&detail=summary`,
        remote:`current/workspace/${language}/index.html?run=run-w01-445a3a164ae14723b82f90634cff96f5&live=0`,
        native:`current/browser/${language}/index.html?run=run-da25e015ca1f&live=0`,
        team:`archive/${language}/replay.html?run=run-double-attempt&lens=orchestration&live=0&detail=summary`
      };
      await page.goto(base+routes[name]);
      if(name==='investigation'||name==='team') {
        await page.waitForFunction(()=>document.querySelector('#dag')?.childElementCount>0).catch(async error=>{
          console.error(await page.locator('body').innerText());
          throw error;
        });
      }
      let selector = '#dag';
      if(name==='remote') {
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI);
        await page.locator('#context-fold>summary').click();
        await page.locator('#portable-workspace-tab').click();
        const row = page.locator('[data-workspace-entry]').filter({has:page.locator('h3',{hasText:'workspace_bash'})});
        await row.locator('[data-native-body]').click();
        await page.locator('[data-workspace-receipt]').waitFor();
        selector='.portable-workspace-result';
      }
      if(name==='native') {
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI);
        await page.locator('#context-fold>summary').click();
        const record = page.locator('.context-record').filter({hasText:'browser.navigate'}).first();
        await record.waitFor();
        await record.locator('[data-tool-body]>summary').click();
        await record.locator('[data-entry-body] pre').waitFor();
        selector = '.context-record[data-entry="' + await record.getAttribute('data-entry') + '"]';
      }
      const element = page.locator(selector);
      if(name==='native') await element.scrollIntoViewIfNeeded();
      await page.evaluate(()=>window.scrollTo(0,0));
      const box = await element.boundingBox();
      const scroll = await page.evaluate(()=>({x:scrollX,y:scrollY}));
      await page.screenshot({path:path.join(output,`${name}-${language}.png`),fullPage:true,clip:{x:box.x+scroll.x,y:box.y+scroll.y,width:box.width,height:Math.min(box.height,380)}});
      console.log(JSON.stringify({name,language,selector,width:box.width,height:Math.min(box.height,380)}));
      await page.close();
    }
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
