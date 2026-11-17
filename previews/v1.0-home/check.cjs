const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {pathToFileURL} = require('node:url');

const base = process.argv[2] || 'http://127.0.0.1:58729/';
const production = process.env.AGENTPROV_SITE_PRODUCTION === '1';
const archive = production ? '' : 'archive/';
const output = path.resolve(process.argv[3] || 'output/playwright/home-review');
fs.mkdirSync(output, {recursive:true});
const reports = [];
const links = new Set();

(async()=>{
  const browser = await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  try {
    for(const lang of ['zh-CN','en']) for(const [size,width,height] of [['desktop',1440,1050],['mobile',390,844]]) {
      const context = await browser.newContext({viewport:{width,height},locale:lang,reducedMotion:'reduce'});
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror',e=>errors.push(e.message));
      await page.goto(base+'?lang='+lang+'#topics');
      await page.locator('.story').last().waitFor();
      assert.equal(await page.locator('.story').count(),4);
      assert.equal(await page.locator('.topic-card').count(),3);
      assert.equal(await page.locator('.section-nav a[aria-current="location"]').evaluate(a=>a.hash),'#topics');
      assert.equal(await page.locator('.topic-guides a').count(),4);
      assert.equal(await page.locator('.topic-guides a svg').count(),4,'each guide has its own icon');
      assert((await page.locator('h1,h2,h3').allTextContents()).every(text=>!/[.。]$/.test(text.trim())),'headings have no final period');
      assert.equal(await page.locator('.topic-action a').count(),2);
      const topicGuides = await page.locator('.topic-guides a').evaluateAll(xs=>xs.map(x=>x.href));
      assert(topicGuides.some(href=>href.endsWith('/endpoint-attribution.html')));
      assert(topicGuides.every(href=>href.includes('/'+lang+'/demos/')));
      assert.equal(await page.locator('.brand b').evaluate(x=>getComputedStyle(x).color),'rgb(0, 113, 227)');
      assert.equal(await page.locator('.brand').evaluate(x=>getComputedStyle(x).fontSize),production?(width===1440?'18px':'17px'):'17px');
      assert.equal(await page.locator('.story').first().evaluate(x=>getComputedStyle(x).borderRadius),'18px');
      for(const img of await page.locator('.story-preview img').all()) {
        await img.scrollIntoViewIfNeeded();
        await img.evaluate(img=>img.decode());
        assert(await img.evaluate(x=>x.naturalWidth>0));
      }
      await page.evaluate(()=>scrollTo(0,0));
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      await page.screenshot({path:path.join(output,`home-${lang}-${size}.png`),fullPage:true});
      if(size==='desktop') {
        const top = await page.locator('#topics').boundingBox();
        const bottom = await page.locator('#capture').boundingBox();
        await page.screenshot({path:path.join(output,`lower-${lang}.png`),fullPage:true,clip:{x:top.x-16,y:top.y-18,width:top.width+32,height:bottom.y+bottom.height-top.y+18}});
      }
      await page.locator('#topics').scrollIntoViewIfNeeded();
      await page.screenshot({path:path.join(output,`topics-${lang}-${size}.png`)});
      for(const href of await page.locator('a[href]').evaluateAll(xs=>xs.map(x=>x.href))) links.add(href);
      if(size==='desktop') {
        for(const href of topicGuides) {
          const response = await page.goto(href);
          assert(response.ok(),href);
          assert((await page.locator('.document h1').innerText()).length>0,href);
          assert((await page.locator('.document').innerText()).length>200,href);
        }
        await page.goto(base+'?lang='+lang+'#topics');
        await page.locator('.topic-guides a').first().waitFor();
      }
      for(const id of ['investigation','remote','native','team']) {
        await page.locator(`[data-story="${id}"]`).click();
        assert(await page.locator('#case-dialog').evaluate(x=>x.open));
        assert(await page.locator('.recording').count()>0);
        assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
        for(const href of await page.locator('#case-dialog a[href]').evaluateAll(xs=>xs.map(x=>x.href))) links.add(href);
        if(id==='remote') await page.screenshot({path:path.join(output,`case-${lang}-${size}.png`)});
        await page.keyboard.press('Escape');
        assert(!(await page.locator('#case-dialog').evaluate(x=>x.open)));
        assert.equal(await page.evaluate(()=>document.activeElement.dataset.story),id);
      }
      await page.locator('.section-nav a').nth(2).click();
      await page.locator('[data-story="archive"]').click();
      assert.equal(await page.locator('.archive-chapter').count(),4);
      await page.screenshot({path:path.join(output,`archive-${lang}-${size}.png`)});
      for(const id of ['grok','earlier','development','presets']) {
        await page.locator(`#case-dialog [data-story="${id}"]`).click();
        if(id==='earlier') {
          assert.equal(await page.locator('.recording').count(),2,'each historical reproduction has its own pair');
          assert.equal(await page.locator('.recording a[href*="compare_a="]').count(),2);
          await page.screenshot({path:path.join(output,`repair-pairs-${lang}-${size}.png`)});
        }
        for(const href of await page.locator('#case-dialog a[href]').evaluateAll(xs=>xs.map(x=>x.href))) links.add(href);
        await page.locator('.back-to-archive').click();
      }
      await page.locator('#close-dialog').click();
      assert.equal(await page.evaluate(()=>document.activeElement.dataset.story),'archive');
      const other = lang==='en'?'zh-CN':'en';
      await page.locator(`[data-lang="${other}"]`).click();
      assert.equal(await page.locator('html').getAttribute('lang'),other);
      assert.equal(new URL(page.url()).searchParams.get('lang'),other);
      await page.goto(base+'?lang='+lang+'&case=remote');
      assert(await page.locator('#case-dialog').evaluate(x=>x.open));
      assert.deepEqual(errors,[]);
      reports.push({lang,size,stories:4,topics:3,topicGuides:4,dialogs:9,overflow:false,errors});
      await context.close();
      console.log(JSON.stringify(reports.at(-1)));
    }
    const request = await browser.newContext();
    let checked = 0;
    for(const href of links) {
      if(!href.startsWith(base)) continue;
      const response = await request.request.head(href);
      assert(response.ok(),href+': '+response.status());
      checked++;
    }
    const download = await request.request.get(base+'downloads/workspace-contract.zip');
    const bytes = await download.body();
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(digest,'4dc4230ee69e8e0f28d86e1671e584201fdb5799a82ee5cf0c34ae7526a2136a');
    fs.writeFileSync(path.join(output,'workspace-contract.zip'),bytes);
    if(production) {
      const source = (await request.request.get(base+'sources.json').then(r=>r.json())).find(s=>s.name==='workspace-contract');
      const updated = await request.request.get(new URL(source.reading_copy,base).href);
      assert(updated.ok());
      const reading = await updated.body();
      assert.equal(crypto.createHash('sha256').update(reading).digest('hex'),source.reading_copy_sha256);
      fs.writeFileSync(path.join(output,'workspace-current.zip'),reading);
    }
    await request.close();
    const diagrams=[];
    for(const lang of ['zh-CN','en']) for(const width of [1440,390]) {
      const page=await browser.newPage({viewport:{width,height:950},reducedMotion:'reduce'});
      const errors=[],external=[];
      page.on('pageerror',error=>errors.push(error.message));
      page.on('request',request=>{if(!request.url().startsWith(base))external.push(request.url());});
      await page.goto(base+`${archive}${lang}/guides/capabilities.html`);
      const figure=page.locator('.rendered-diagram');
      assert.equal(await figure.count(),1);
      await figure.locator('img').evaluate(img=>img.decode());
      assert(await figure.locator('img').evaluate(img=>img.naturalWidth>0&&img.naturalHeight>0));
      assert(!(await figure.locator('pre').isVisible()));
      await figure.screenshot({path:path.join(output,`architecture-${lang}-${width}.png`)});
      await figure.locator('[data-diagram-open]').click();
      await page.locator('.diagram-dialog[open]').waitFor();
      const initial=parseInt(await page.locator('.diagram-dialog output').innerText());
      await page.locator('[data-diagram-action="plus"]').click();
      assert(parseInt(await page.locator('.diagram-dialog output').innerText())>initial);
      await page.locator('[data-diagram-action="fit"]').click();
      assert(parseInt(await page.locator('.diagram-dialog output').innerText())<=initial);
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      await page.keyboard.press('Escape');
      await page.waitForFunction(()=>!document.querySelector('.diagram-dialog').open);
      assert(await page.locator('[data-diagram-open]').evaluate(el=>el===document.activeElement));
      await figure.locator('.diagram-source summary').click();
      const source=await figure.locator('code.language-mermaid').textContent();
      const build=await page.request.get(base+'diagram-build.json').then(response=>response.json());
      assert.equal(crypto.createHash('sha256').update(source).digest('hex'),build.evidence.find(item=>item.language===lang).sourceSHA256);
      assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
      diagrams.push({lang,width,rendered:true,zoom:true,sourcePreserved:true});
      await page.close();
    }
    const cases = [
      ['investigation','current/investigation/zh-CN/index.html?run=run-3bfc6838a9c6&live=0'],
      ['workspace','current/workspace/zh-CN/index.html?run=run-w01-445a3a164ae14723b82f90634cff96f5&live=0'],
      ['browser','current/browser/zh-CN/index.html?run=run-da25e015ca1f&live=0'],
      ['notebook','recordings/notebook-detailed/zh-CN/index.html?live=0'],
      ['team',archive+'zh-CN/replay.html?run=run-double-attempt&lens=orchestration&live=0']
    ];
    const readers = [];
    for(const [id,route] of cases) {
      const page = await browser.newPage({viewport:{width:1440,height:1000}});
      const errors=[],failedRequests=[];
      page.on('pageerror',e=>errors.push(e.message));
      page.on('requestfailed',request=>failedRequests.push({url:request.url(),error:request.failure()}));
      await page.goto(base+route);
      try {
        await page.waitForFunction(()=>document.querySelector('#dag')?.childElementCount>0);
      } catch(error) {
        await page.screenshot({path:path.join(output,`reader-${id}-failure.png`),fullPage:true});
        fs.writeFileSync(path.join(output,`reader-${id}-failure.json`),JSON.stringify({url:page.url(),errors,failedRequests,body:await page.locator('body').innerText()},null,2)+'\n');
        throw error;
      }
      const graphElements = await page.locator('#dag').evaluate(x=>x.childElementCount);
      if(id==='notebook') {
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI);
        await page.locator('#context-fold>summary').click();
        await page.locator('#portable-native-tab').click();
        await page.locator('[data-native-entry]').first().waitFor();
        await page.locator('[data-native-body]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
      }
      await page.screenshot({path:path.join(output,`reader-${id}.png`)});
      assert.deepEqual(errors,[]);
      readers.push({id,graphElements,errors});
      console.log(JSON.stringify(readers.at(-1)));
      await page.close();
    }
    const comparisons=[];
    const pairs=[
      ['current/investigation/{lang}/index.html','run-860466af8a9a','run-3bfc6838a9c6'],
      [archive+'{lang}/replay.html','run-2fd63df0ab9b','run-48baa3821074'],
      [archive+'{lang}/replay.html','run-e9c3f452461a','run-2267309eda57']
    ];
    for(const lang of ['zh-CN','en']) for(const [index,[route,a,b]] of pairs.entries()) {
      const page=await browser.newPage({viewport:{width:1440,height:1050}});
      const errors=[];page.on('pageerror',error=>errors.push(error.message));
      const query=new URLSearchParams({run:a,compare_a:a,compare_b:b,live:'0'});
      await page.goto(base+route.replace('{lang}',lang)+'?'+query);
      try {
        await page.waitForFunction(()=>document.querySelector('#compare-dialog')?.open&&!document.querySelector('#compare-refresh').disabled&&document.querySelector('#compare-summary').textContent.length>0);
      } catch(error) {
        await page.screenshot({path:path.join(output,`compare-${index}-${lang}-failure.png`)});
        fs.writeFileSync(path.join(output,`compare-${index}-${lang}-failure.json`),JSON.stringify({url:page.url(),errors,status:await page.locator('#compare-status').textContent(),loadError:await page.locator('#loaderror-detail').textContent()},null,2)+'\n');
        throw error;
      }
      assert.equal(await page.locator('#compare-a').inputValue(),a);
      assert.equal(await page.locator('#compare-b').inputValue(),b);
      assert.equal(await page.evaluate(()=>cur),a);
      await page.screenshot({path:path.join(output,`compare-${index}-${lang}.png`)});
      await page.locator('#compare-swap').click();
      await page.waitForFunction(()=>!document.querySelector('#compare-refresh').disabled);
      assert.equal(new URL(page.url()).searchParams.get('compare_a'),b);
      await page.setViewportSize({width:390,height:844});
      assert(await page.locator('#compare-dialog').evaluate(el=>el.scrollWidth<=el.clientWidth+1));
      await page.locator('#compare-close').click();
      await page.waitForURL(url=>!url.searchParams.has('compare_a')&&!url.searchParams.has('compare_b'));
      assert.equal(await page.evaluate(()=>cur),a,'closing keeps the original recording');
      assert(!new URL(page.url()).searchParams.has('compare_a'));
      await page.reload();
      await page.waitForFunction(()=>document.querySelector('#dag')?.childElementCount>0);
      assert(!(await page.locator('#compare-dialog').evaluate(el=>el.open)));
      assert.deepEqual(errors,[]);
      comparisons.push({lang,a,b,paired:true,restored:true});
      await page.close();
    }
    if(process.argv[4]) {
      const page=await browser.newPage();
      await page.context().setOffline(true);
      const [route,a,b]=pairs[0];
      const url=pathToFileURL(path.join(path.resolve(process.argv[4]),route.replace('{lang}','en')));
      url.search=new URLSearchParams({run:a,compare_a:a,compare_b:b,live:'0'}).toString();
      await page.goto(url.href);
      await page.waitForFunction(()=>document.querySelector('#compare-dialog')?.open&&document.querySelector('#compare-summary').textContent.length>0&&!document.querySelector('#compare-refresh').disabled);
      assert.equal(await page.locator('#compare-b').inputValue(),b);
      await page.locator('#compare-close').click();
      comparisons.push({offline:true,protocol:'file:',a,b});
      await page.goto(pathToFileURL(path.join(path.resolve(process.argv[4]),archive+'zh-CN/guides/capabilities.html')).href);
      await page.locator('.rendered-diagram img').evaluate(img=>img.decode());
      await page.locator('[data-diagram-open]').click();
      await page.locator('.diagram-dialog[open]').waitFor();
      await page.locator('[data-diagram-action="plus"]').click();
      diagrams.push({offline:true,protocol:'file:',rendered:true,zoom:true});
      await page.close();
    }
    fs.writeFileSync(path.join(output,'report.json'),JSON.stringify({home:reports,localLinksChecked:checked,download:{file:'workspace-contract.zip',sha256:digest},readers,comparisons,diagrams},null,2)+'\n');
    console.log(JSON.stringify({localLinksChecked:checked,readers:readers.length,result:'PASS'}));
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
