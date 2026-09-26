// Browser acceptance for a running `agentprov demo --no-browser` instance.
// Install Playwright for development, then run:
//   node scripts/accept_dashboard_i18n.cjs http://127.0.0.1:PORT
// PLAYWRIGHT_CHANNEL=msedge selects an installed Edge browser.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const base=process.argv[2];
if(!base)throw new Error('Pass the demo URL, including its port');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const errors=[],report={pages:0,lenses:0,languageRules:[],interactions:[],failureStates:[]};
  try{
    for(const [locale,expected] of [['zh-CN','zh-CN'],['en-US','en'],['fr-FR','en']]){
      const context=await browser.newContext({locale,viewport:{width:1440,height:1080}});
      const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
      const root=new URL('/',base).href;
      await page.goto(root+'?live=0');
      await page.waitForFunction(()=>window._lg);
      assert.equal(await page.locator('html').getAttribute('lang'),expected);
      report.languageRules.push({locale,expected});
      if(locale==='fr-FR'){await context.close();continue;}
      const runs=await (await context.request.get(new URL('/api/runs',base).href)).json();
      for(const {run} of runs){
        await page.goto(root+'?live=0&run='+encodeURIComponent(run));
        await page.waitForFunction(r=>window._lensManifest?.run_id===r,run);
        const lenses=await page.locator('#lenssel option').evaluateAll(xs=>xs.map(x=>x.value));
        assert.equal(lenses.length,12);
        for(const lens of lenses){
          await page.locator('#lenssel').selectOption(lens);
          await page.waitForFunction(l=>window._lensManifest?.lens===l,lens);
          assert.equal(await page.locator('#loaderror').isVisible(),false);
          assert.equal(await page.locator('#detailsel').inputValue(),'summary');
          if(expected==='zh-CN'){
            const hints=await page.locator('#lensmeta').innerText();
            assert.ok(!hints.includes('layout')&&!hints.includes('run_overview')&&!hints.includes('raw detail for'),'Untranslated graph hints');
          }
          report.lenses++;
        }
        report.pages++;
      }
      // Check display-only transformations with words that are also catalog keys.
      assert.equal(await page.evaluate(()=>{
        const nodes=[
          {id:'run-risk',kind:'run',label:'no runs'},
          {id:'agent-original',kind:'agent',label:'Copy'},
          {id:'file-original',kind:'file',label:'/tmp/secret'},
          {id:'cmd-original',kind:'runtime_event',subtype:'execve',label:'echo risk'},
          {id:'tool-original',kind:'tool_call',label:'risk'},
        ];
        const before=JSON.stringify(nodes);
        return nodes.every(n=>nodeLabel(n)===n.label)&&before===JSON.stringify(nodes);
      }),true);
      report.interactions.push(expected+': original labels unchanged');
      // A policy decision is not an execution receipt. Exercise mixed decisions
      // in the rendered card, without writing synthetic evidence to the store.
      const complianceFixture={disclaimer:'Framework assessment note',summary:{total:1,enforced:1,detected:0,not_triggered:0,no_rule:0},items:[{
        control_id:'test-control',title:'test control',status:'enforced',rules:[{
          id:'test-rule',mode:'enforce',fired:2,enforced:true,intended_decision:'kill',hits:[
            {ref:'policy_decision/test-kill',decision:'kill',reason:'Copy',enforced:true},
            {ref:'policy_decision/test-audit',decision:'audit',reason:'original reason',enforced:false},
          ],
        }],
      }]};
      await page.evaluate(rep=>{COMP_OPEN.add('test-control');renderCompliance(rep);},complianceFixture);
      const complianceText=await page.locator('#complist').innerText();
      assert.match(complianceText,expected==='zh-CN'?/阻断/:/Enforcement/);
      assert.match(complianceText,expected==='zh-CN'?/命中 ×2/:/hits ×2/);
      assert.match(complianceText,expected==='zh-CN'?/预期决策：终止/:/intended: kill/);
      assert.doesNotMatch(complianceText,/已阻断|已执行阻断|blocked ×|not blocked/);
      assert.equal(await page.locator('#complist .chit').count(),2);
      assert.equal(await page.locator('#complist .chit-r').first().innerText(),'Copy','Original reason was translated');
      assert.equal(await page.locator('#compdisclaimer').innerText(),complianceFixture.disclaimer);
      assert.deepEqual(await page.evaluate(()=>window._comp),complianceFixture,'Compliance presentation changed evidence');
      report.interactions.push(expected+': compact compliance labels; mixed hits and raw reasons preserved');
      await page.goto(root+'?live=0&run=run-snake-supervised&lens=security&detail=raw');
      await page.waitForFunction(()=>window._lensManifest?.query.detail==='raw');
      const id=await page.locator('#dag g[data-id]').first().getAttribute('data-id');
      await page.evaluate(id=>selectNode(id),id);
      await page.waitForSelector('#preview');
      await page.waitForFunction(()=>document.querySelector('#preview pre')||document.querySelector('#preview .none')?.innerText.match(/preview|预览/));
      await page.locator('#ov-risk').click();
      await page.waitForFunction(()=>window._lensManifest?.query.overlays?.includes('risk'));
      const before=await page.evaluate(()=>({run:cur,lens:LENS,detail:DETAIL,selected:SEL,overlay:[...OV].sort(),live:LIVE}));
      const other=expected==='en'?'zh-CN':'en';
      await page.locator(`.language-switch a[lang="${other}"]`).click();
      await page.waitForFunction(()=>window._lg);
      assert.equal(await page.locator('html').getAttribute('lang'),other);
      assert.deepEqual(await page.evaluate(()=>({run:cur,lens:LENS,detail:DETAIL,selected:SEL,overlay:[...OV].sort(),live:LIVE})),before);
      await page.goto(root+'?live=0');
      await page.waitForFunction(()=>window._lg);
      assert.equal(await page.locator('html').getAttribute('lang'),other,'Saved choice lost');
      report.interactions.push(expected+': language switch retains run, lens, detail, selection and overlays');
      // Table payloads keep the exact original values on expand/collapse.
      const payload=page.locator('#tl .pl').first();
      const original=await payload.textContent();await payload.click();
      assert.equal(await payload.textContent(),original);
      await page.locator('#tlnext').click();
      await page.waitForFunction(()=>tlOffset>0);
      report.interactions.push(expected+': pagination and original payload');
      await page.setViewportSize({width:390,height:844});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Mobile horizontal overflow');
      await context.close();
    }
    const context=await browser.newContext({locale:'zh-CN'});
    const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
    const root=new URL('/',base).href;
    await page.route('**/api/runs',route=>route.fulfill({status:200,contentType:'application/json',body:'[]'}));
    await page.goto(root+'?live=0');await page.getByText('还没有执行记录。请先记录一次执行，或打开带签名的示例。').waitFor();
    report.failureStates.push('empty run list');await page.unroute('**/api/runs');
    await page.route('**/api/runs',route=>route.fulfill({status:503,body:'database unavailable'}));
    await page.goto(root+'?live=0');await page.locator('#loaderror').waitFor();
    assert.match(await page.locator('#loaderror-text').textContent(),/部分数据加载失败/);
    assert.match(await page.locator('#loaderror-detail').textContent(),/503/);
    report.failureStates.push('HTTP failure');await page.unroute('**/api/runs');
    await page.route('**/api/runs',route=>route.fulfill({status:200,body:'not json'}));
    await page.goto(root+'?live=0');await page.locator('#loaderror').waitFor();
    assert.match(await page.locator('#loaderror-detail').textContent(),/无法解析/);
    report.failureStates.push('malformed response');await page.unroute('**/api/runs');
    await page.route('**/api/frameworks',route=>route.fulfill({status:500,body:'unavailable'}));
    await page.goto(root+'?live=0');await page.getByText('合规映射加载失败').waitFor();
    report.failureStates.push('compliance unavailable');await page.unroute('**/api/frameworks');
    for(const path of ['/api/runs','/api/lens?run=run-snake-supervised&lens=security','/api/timeline?run=run-snake-supervised','/api/compliance?run=run-snake-supervised&framework=owasp-asi','/api/artifact?run=run-snake-supervised&node=runtime_event/missing']){
      const separator=path.includes('?')?'&':'?';
      const en=await(await context.request.get(new URL(path+separator+'lang=en',base).href)).text();
      const zh=await(await context.request.get(new URL(path+separator+'lang=zh-CN',base).href)).text();
      assert.equal(en,zh,'API changed with interface language: '+path);
    }
    report.apiUnchanged=true;assert.deepEqual(errors,[]);report.passed=true;
    console.log(JSON.stringify(report,null,2));
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
