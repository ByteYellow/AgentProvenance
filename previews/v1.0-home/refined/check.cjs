const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const base=process.argv[2]||'http://127.0.0.1:58729/';
const production=process.env.AGENTPROV_SITE_PRODUCTION==='1';
const output=path.resolve(process.argv[3]||'output/playwright/refined-home');
fs.mkdirSync(output,{recursive:true});

(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const reports=[],links=new Set();
  try {
    for(const lang of ['zh-CN','en']) for(const width of [1440,760,390,320]) {
      const page=await browser.newPage({viewport:{width,height:960},locale:lang,reducedMotion:'reduce'});
      const errors=[];page.on('pageerror',e=>errors.push(e.message));
      const route=new URL(`${production?'index.html':'refined.html'}?lang=${lang}`,base).href;
      await page.goto(route);
      await page.locator('.story').last().waitFor();
      assert.equal(await page.locator('.story').count(),4);
      const pair=page.locator('.story[data-case="investigation"]');
      assert.equal(await pair.locator('.preview-link').getAttribute('href'),await pair.locator('.compare-action').getAttribute('href'),'comparison image must open the same pair as the button');
      assert.equal(await page.locator('.story .x86-recordings a').count(),4,'featured cards must expose the real x86 recordings');
      assert.equal(await page.locator('.topic-card').count(),3);
      assert.equal(await page.locator('.topic-guides a svg').count(),4);
      assert((await page.locator('h1,h2,h3').allTextContents()).every(t=>!/[.。]$/.test(t.trim())));
      for(const img of await page.locator('.story-preview img').all()) {
        await img.scrollIntoViewIfNeeded();await img.evaluate(x=>x.decode());
        assert(await img.evaluate(x=>x.naturalWidth>0));
      }
      await page.evaluate(()=>scrollTo(0,0));
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${lang} at ${width}: overflow`);
      await page.screenshot({path:path.join(output,`home-${lang}-${width}.png`),fullPage:true});
      if(width===1440){
        await page.screenshot({path:path.join(output,`first-screen-${lang}.png`)});
        await page.locator('#topics').scrollIntoViewIfNeeded();
        await page.screenshot({path:path.join(output,`topics-${lang}.png`)});
      }
      for(const a of await page.locator('a[href]').evaluateAll(xs=>xs.map(x=>x.href)))links.add(a);
      for(const id of ['investigation','remote','native','team','archive']) {
        await page.locator(`[data-story="${id}"]`).click();
        assert(await page.locator('#case-dialog').evaluate(x=>x.open));
        assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
        if(id==='archive') {
          assert.equal(await page.locator('.archive-chapter').count(),4);
          if(width===1440)await page.screenshot({path:path.join(output,`archive-${lang}.png`)});
          for(const child of ['grok','earlier','development','presets']) {
            await page.locator(`#case-dialog [data-story="${child}"]`).click();
            assert(await page.locator('.recording').count()>0);
            for(const a of await page.locator('#case-dialog a').evaluateAll(xs=>xs.map(x=>x.href)))links.add(a);
            await page.locator('.back-to-archive').click();
          }
        } else {
          assert(await page.locator('.recording').count()>0);
          for(const a of await page.locator('#case-dialog a').evaluateAll(xs=>xs.map(x=>x.href)))links.add(a);
        }
        await page.keyboard.press('Escape');
        assert.equal(await page.evaluate(()=>document.activeElement.dataset.story),id);
      }
      const other=lang==='en'?'zh-CN':'en';
      await page.locator(`[data-lang="${other}"]`).click();
      assert.equal(new URL(page.url()).pathname,new URL(route).pathname);
      assert.equal(await page.locator('html').getAttribute('lang'),other);
      assert.equal(await page.locator('.previous-preview').count(),production?0:1);
      assert((await page.locator('.story-preview img').first().getAttribute('src')).endsWith(`-${other}.png`));
      await page.goto(route+'&case=investigation');
      await page.locator('#case-dialog[open]').waitFor();
      const compare=await page.locator('#case-dialog .compare-action').getAttribute('href');
      assert.equal(new URL(compare).searchParams.get('compare_a'),'run-860466af8a9a');
      assert.equal(new URL(compare).searchParams.get('compare_b'),'run-3bfc6838a9c6');
      if(width===1440){
        await page.goto(compare);
        await page.waitForFunction(()=>document.querySelector('#compare-dialog')?.open&&document.querySelector('#compare-refresh')?.disabled===false);
        assert.equal(await page.locator('#compare-a').inputValue(),'run-860466af8a9a');
        assert.equal(await page.locator('#compare-b').inputValue(),'run-3bfc6838a9c6');
      }
      assert.deepEqual(errors,[]);
      reports.push({lang,width,cases:4,topics:3,dialogs:9,overflow:false,errors});
      console.log(JSON.stringify(reports.at(-1)));
      await page.close();
    }
    const context=await browser.newContext();let checked=0;
    const x86=(await (await context.request.get(new URL('sources.json',base).href)).json()).filter(x=>x.name.startsWith('x86-'));
    assert.equal(x86.length,7);
    for(const lang of ['zh-CN','en']) {
      const page=await context.newPage();
      for(const item of x86) {
        const href=`recordings/${item.name}/${lang}/index.html?live=0`;
        const reader=new URL(href,base).href;
        assert(links.has(reader),'missing case link: '+reader);
        await page.goto(new URL(`${production?'index.html':'refined.html'}?lang=${lang}`,base).href);
        const shortcut=page.locator(`.x86-recordings a[href="${href}"]`);
        if(await shortcut.count()) await shortcut.click();
        else {
          await page.locator('[data-story="remote"]').click();
          await page.locator(`#case-dialog a[href="${href}"]`).click();
        }
        await page.waitForFunction(run=>document.querySelector('#runsel')?.value===run,item.run_id);
        await page.locator('#dag svg g[data-id]').first().waitFor();
      }
      await page.close();
    }
    if(production) for(const lang of ['en','zh-CN']) {
      const page=await context.newPage();
      await page.goto(new URL(`${lang}/index.html`,base).href);
      await page.locator('.story').last().waitFor();
      assert.equal(await page.locator('html').getAttribute('lang'),lang);
      assert.equal(await page.locator('[data-preview]').count(),0);
      assert(!/Local review|本地审核|上一版设计/.test(await page.locator('body').innerText()));
      for(const img of await page.locator('.story img').all()) await img.evaluate(x=>x.decode());
      for(const href of await page.locator('a[href]').evaluateAll(xs=>xs.map(a=>a.href)))links.add(href);
      await page.locator('.section-nav a').nth(2).click();
      assert.equal(new URL(page.url()).pathname,new URL(`${lang}/index.html`,base).pathname);
      assert.equal(new URL(page.url()).hash,'#history');
      await page.goto(new URL(`${lang}/`,base).href);
      await page.locator('.story').last().waitFor();
      assert.equal(await page.locator('html').getAttribute('lang'),lang);
      await page.close();
    }
    for(const href of links){if(!href.startsWith(base))continue;const response=await context.request.head(href);assert(response.ok(),href);checked++;}
    await context.close();
    fs.writeFileSync(path.join(output,'report.json'),JSON.stringify({reports,links:checked},null,2)+'\n');
    console.log(`Checked ${checked} local links`);
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
