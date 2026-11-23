// Exercise the hosted readers on a genuinely non-secure HTTP origin.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const base=new URL(process.argv[2]);
assert.equal(base.hostname,'127.0.0.1');
base.hostname='agentprov-lan.test';

(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{}),
    args:['--no-proxy-server','--host-resolver-rules=MAP agentprov-lan.test 127.0.0.1']});
  try{
    const page=await browser.newPage({viewport:{width:1440,height:900}});
    const errors=[],requests=[];
    page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
    await page.goto(new URL('current/browser/en/index.html',base).href);
    await page.locator('#dag svg [data-id]').first().waitFor();await page.waitForLoadState('networkidle');
    const firstLoad=requests.length;
    assert.deepEqual(await page.evaluate(()=>[isSecureContext,!!crypto.subtle]),[false,false]);
    assert.equal(await page.evaluate(()=>window.agentProvSHA256(new TextEncoder().encode('abc'))),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    const closedHeight=await page.locator('#detailsel').evaluate(el=>el.getBoundingClientRect().height);
    assert(closedHeight<35);
    assert(await page.locator('#slider').isHidden());assert(await page.locator('#playbtn').isDisabled());
    assert.match(await page.locator('#scrublabel').innerText(),/timestamps/);
    assert.equal(await page.locator('body>nav').count(),1);
    assert.equal(await page.locator('body>nav a',{hasText:'Download CLI'}).count(),1);
    await page.locator('#lenssel').selectOption('intent');
    await page.waitForFunction(()=>document.querySelector('#lensmeta b')?.textContent.startsWith('Conformance'));
    assert((await page.locator('#lenssel').boundingBox()).height<35);

    await page.goto(new URL('current/workspace/en/index.html?lens=file-artifact&detail=raw&live=0',base).href);
    const node=page.locator('#dag [data-id="workspace_file/result.txt"]');await node.waitFor();
    await page.evaluate(()=>{window.testRoot=document.querySelector('#dag svg');window.testFile=document.querySelector('#dag [data-id="workspace_file/result.txt"]');});
    await page.locator('#graph-find').fill('result.txt');await page.locator('#graph-find').press('Enter');
    assert(await page.evaluate(()=>document.activeElement.matches('#dag .graph-match')));
    assert.equal(await page.locator('#dag [tabindex="0"]').count(),1);
    await node.focus();await node.press('Enter');assert.equal(await node.getAttribute('aria-pressed'),'true');
    await page.locator('#zoomin').click();
    const before=await page.locator('#dag svg').getAttribute('width');
    await page.locator('#dag').dispatchEvent('wheel',{deltaY:-100,ctrlKey:true,bubbles:true,cancelable:true});
    assert(Number(await page.locator('#dag svg').getAttribute('width'))>Number(before));
    assert(await page.locator('#slider').isVisible());
    await page.locator('#playbtn').click();
    await page.waitForFunction(()=>document.querySelector('#slider').value==='1');
    await page.locator('#playbtn').click();
    assert(await page.evaluate(()=>window.testRoot===document.querySelector('#dag svg')&&window.testFile===document.querySelector('#dag [data-id="workspace_file/result.txt"]')));
    const graph=page.locator('#dag');
    await graph.scrollIntoViewIfNeeded();
    const drag=await graph.evaluate(el=>{
      el.scrollTop=el.scrollLeft=0;
      const r=el.getBoundingClientRect(),vertical=el.scrollHeight>el.clientHeight+12;
      if(!vertical&&el.scrollWidth<=el.clientWidth+12)throw Error('graph must overflow at this zoom');
      return {x:r.left+(vertical?4:64),y:r.top+(vertical?64:4),vertical};
    });
    await page.mouse.move(drag.x,drag.y);await page.mouse.down();
    await page.mouse.move(drag.x-(drag.vertical?0:40),drag.y-(drag.vertical?40:0));await page.mouse.up();
    assert(await graph.evaluate((el,v)=>(v?el.scrollTop:el.scrollLeft)>0,drag.vertical),'drag scrolls the graph');

    await page.goto(new URL('zh-CN/replay.html?run=run-snake-supervised&live=0',base).href);
    await page.waitForFunction(()=>document.querySelector('#context-summary')?.textContent.includes('未记录'));
    assert.doesNotMatch(await page.locator('#context-summary').innerText(),/unknown|未记录\s*[条次]/);
    await page.locator('#context-fold>summary').click();await page.evaluate(()=>window.AgentPortableEvidenceUI.prepareSessionTabs());
    assert(await page.locator('#portable-native-tab').isHidden());assert(await page.locator('#portable-workspace-tab').isHidden());
    assert.doesNotMatch(await page.locator('#siglist').innerText(),/detect-only; would/);
    assert.equal(await page.locator('body>nav').count(),1);
    await page.goto(new URL('current/notebook/en/index.html',base).href);
    await page.locator('#context-fold>summary').click();await page.locator('#portable-native-tab').click();
    await page.locator('[data-native-attachment]:not([disabled])').first().click();
    await page.waitForFunction(()=>document.querySelector('#portable-dialog-body img')?.naturalWidth>0);
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({lanHTTP:true,firstLoadRequests:firstLoad,svgIdentity:true,keyboard:true,attachmentVerified:true}));
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
