// End-to-end static replay parity against a current, isolated `agentprov demo`.
// Usage: node scripts/accept_static_demo.cjs SITE_URL LOCAL_DEMO_URL
// Run SITE_URL under a project subpath to catch GitHub Pages routing mistakes.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const { gunzipSync } = require('node:zlib');

async function main() {
  const site = new URL(process.argv[2]), native = new URL(process.argv[3]);
  const browser = await chromium.launch({headless:true, ...(process.env.PLAYWRIGHT_CHANNEL ? {channel:process.env.PLAYWRIGHT_CHANNEL} : {})});
  const report = {parity:0, pages:0, runs:0, focusedGraphs:0, contentPages:0};
  const errors = [];
  const responseJSON = async (request,url) => {const r=await request.get(url);assert.equal(r.status(),200,url);return r.json();};
  try {
    const context=await browser.newContext({viewport:{width:1440,height:1060},locale:'en-US'});
    await context.route('**/*',route=>{
      const url=new URL(route.request().url());
      if(url.origin===site.origin && url.pathname.startsWith(site.pathname) && !url.pathname.includes('/api/'))return route.continue();
      errors.push('Unexpected browser request: '+url);return route.abort();
    });
    const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
    const manifest=await responseJSON(context.request,new URL('replay-manifest.json',site).href);
    assert.equal(Object.keys(manifest.runs).length,7);
    assert.ok(manifest.verifications.every(v=>v.signature_verified&&v.graph.status==='ok'));
    const data=async ref=>{const r=await context.request.get(new URL(ref.path,site).href);assert.ok(r.ok());return JSON.parse(gunzipSync(await r.body()).toString());};
    await page.goto(new URL('en/replay.html?run=run-dbc2adf273d4',site).href);
    await page.waitForFunction(()=>window._lensManifest && document.querySelector('#dag svg'));
    const compare=async query=>{
      const [expected,actual]=await Promise.all([responseJSON(context.request,new URL(query,native).href),page.evaluate(q=>AgentProvReplay.query(q),query)]);
      // Import locations differ; compare the same content-addressed object path.
      const normalize=v=>JSON.parse(JSON.stringify(v).replace(/\/tmp\/agentprov-(?:public-demo|demo)-[0-9]+\/state\/provenance\/objects\//g,'/demo/objects/'));
      try {assert.deepEqual(normalize(actual),normalize(expected));}catch(e){console.error('Query mismatch: '+query);throw e;}report.parity++;return actual;
    };
    await compare('/api/runs');
    for(const [run,snapshot] of (process.env.STATIC_UI_ONLY?[]:Object.entries(manifest.runs))){
      const q='?run='+encodeURIComponent(run),index=await data(snapshot.lenses),nodes=await data(index.nodes);
      for(const key of Object.keys(snapshot.api)){
        const route=key.startsWith('compliance/')?'compliance'+q+'&framework='+key.slice(11):key+q;
        await compare('/api/'+route);
      }
      for(const key of Object.keys(index.views)){
        const [lens,detail]=key.split('/'),query='/api/lens'+q+'&lens='+lens+'&detail='+detail;
        await compare(query);await compare(query+'&overlay=risk&overlay=trust');
        // Cover each displayed kind across summary, expanded and raw filters.
        const view=await data(index.views[key]);
        const byKind=new Map();for(const node of view.manifest.nodes)if(!byKind.has(node.kind))byKind.set(node.kind,node.id);
        for(const id of byKind.values()){
          await compare(query+'&focus='+encodeURIComponent(id));report.focusedGraphs++;
        }
      }
      for(const endpoint of ['events','timeline'])for(const offset of [0,7,100000])await compare('/api/'+endpoint+q+'&limit=7&offset='+offset);
      for(const key of Object.keys(snapshot.filters)){
        const [lens,group]=key.split('/');
        if(group && !['tls','dns','loopback','workspace_source_files','secret_or_config','execve','risky_egress'].includes(group))continue;
        await compare('/api/events'+q+'&lens='+lens+'&group='+group+'&limit=7');
      }
      for(const id of Object.keys(snapshot.event_refs).filter(id=>!id.startsWith('runtime_event/')).slice(0,12)){
        await compare('/api/events'+q+'&ref='+encodeURIComponent(id)+'&ref=runtime_event/missing');
      }
      const session=await data(snapshot.context);
      // Cursor representations are intentionally opaque; compare the traversed records.
      for(const group of ['','conversation','configuration'])for(const revisions of [false,true]){
        const path='/api/context/entries'+q+'&group='+group+'&revisions='+revisions+'&limit=7';
        const collect=async fetchPage=>{let cursor='',entries=[];do{const result=await fetchPage(path+(cursor?'&cursor='+encodeURIComponent(cursor):''));entries.push(...result.entries);cursor=result.next_cursor||'';}while(cursor);return entries;};
        assert.deepEqual(await collect(q=>page.evaluate(q=>AgentProvReplay.query(q),q)),await collect(q=>responseJSON(context.request,new URL(q,native).href)));report.parity++;
      }
      for(const id of Object.keys(session.nodes)){
        const query='/api/context/entries'+q+'&node='+encodeURIComponent(id)+'&limit=200';
        await compare(query);
      }
      for(const [entry] of Object.entries(session.links))await compare('/api/context/links'+q+'&entry='+encodeURIComponent(entry));
      for(const ref of Object.keys(session.content)){
        const query='/api/context/content'+q+'&ref='+encodeURIComponent(ref);
        const content=await compare(query);report.contentPages++;
        if(content.total_bytes>20)await compare(query+'&offset=0&limit=17');
      }
      for(const pair of Object.keys(session.comparisons)){
        const [left,right]=pair.split('/');await compare('/api/context/compare'+q+'&left='+left+'&right='+right);
      }
      const artifacts=await data(snapshot.artifacts);
      // Every saved or unavailable file/body, with both presentations and languages.
      for(const key of Object.keys(artifacts)){
        const [lang,mode,...parts]=key.split('/'),node=parts.join('/');
        if(!['file','artifact','tool_call','llm_prompt','llm_completion'].includes(nodes[node]?.kind)&&!node.startsWith('workspace_file/')&&!node.startsWith('object/'))continue;
        await compare('/api/artifact'+q+'&node='+encodeURIComponent(node)+'&mode='+mode+'&view_lang='+lang);report.contentPages++;
      }
      report.runs++;console.log(JSON.stringify({run,...report}));
    }
    // Use actual UI controls for the recorded DeepSeek task, with no API backend.
    await page.goto(new URL('en/replay.html?run=run-dbc2adf273d4',site).href);
    await page.waitForFunction(()=>document.querySelector('#context-summary')?.textContent.includes('13 message records'));
    assert.equal(await page.locator('#context-fold').evaluate(e=>e.open),false);
    for(const id of ['graphcard','siglist','focusedevidence','outboundcard','tl','ptree','egtbl','compliancecard'])assert.equal(await page.locator('#'+id).count(),1);
    for(const lens of await page.locator('#lenssel option').evaluateAll(options=>options.map(o=>o.value))){
      await page.locator('#lenssel').selectOption(lens);
      await page.waitForFunction(lens=>window._lensManifest?.lens===lens,lens);
      assert.ok(await page.locator('#loaderror').isHidden());
    }
    await page.locator('#lenssel').selectOption('file-artifact');
    await page.locator('#detailsel').selectOption('raw');
    await page.waitForFunction(()=>window._lensManifest?.lens==='file-artifact'&&window._lensManifest?.query.detail==='raw');
    await page.locator('#dag [data-id="workspace_file/report.py"]').click();
    await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent.includes('def daily_revenue'));
    assert.equal(await page.locator('#context-fold').evaluate(e=>e.open),false);
    await page.locator('#content-choice').selectOption({label:'Raw saved object'});
    await page.waitForFunction(()=>document.querySelector('#content-body')?.textContent.includes('content_ref'));
    await page.getByRole('button',{name:'Task & conversation 13',exact:true}).click();
    await page.waitForSelector('#context-body [data-entry]');
    const before=await page.locator('#context-body [data-entry]').first().getAttribute('data-entry');
    await page.locator('#context-next').click();
    await page.waitForFunction(id=>document.querySelector('#context-body [data-entry]')?.getAttribute('data-entry')!==id,before);
    const tool=page.locator('#context-body [data-entry]').filter({has:page.getByRole('button',{name:'Locate in graph',exact:true})}).first();
    await tool.getByRole('button',{name:'Locate in graph',exact:true}).click();
    await page.locator('#detail-session').waitFor();await page.locator('#detail-session').click();
    await page.waitForFunction(()=>!document.querySelector('#context-linked')?.hidden);
    await page.locator('#context-return').click();
    await page.getByRole('tab',{name:'Permissions & configuration',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('#context-body')?.textContent.includes('workspace-write'));
    await page.locator('.language-switch a[lang="zh-CN"]').click();
    await page.waitForFunction(()=>window._lensManifest);
    assert.equal(await page.locator('html').getAttribute('lang'),'zh-CN');
    assert.equal(new URL(page.url()).searchParams.get('run'),'run-dbc2adf273d4');
    await page.goto(site.href);await page.waitForURL('**/zh-CN/index.html');
    for(const [locale,lang] of [['zh-CN','zh-CN'],['en-US','en'],['fr-FR','en']]){
      const fresh=await browser.newContext({locale});const first=await fresh.newPage();
      await first.goto(site.href);await first.waitForURL('**/'+lang+'/index.html');await fresh.close();
    }
    report.ui='graph, files, session paging, graph navigation and language passed';

    // All published guides, images and table-of-contents links, at both sizes.
    for(const lang of ['en','zh-CN']){
      await page.goto(new URL(lang+'/index.html',site).href);
      const links=await page.locator('a[href]').evaluateAll(a=>[...new Set(a.map(x=>x.href).filter(s=>/\/(demos|guides)\/[^/]+\.html/.test(s)))]);
      assert.equal(links.length,manifest.guides.length-6+9);
      assert.equal(await page.locator('a[href*="benchmarks"]').count(),0);
      const allGuides=[...new Set([...links,...manifest.guides.map(g=>new URL(lang+'/guides/'+g.ID+'.html',site).href)])];
      for(const href of allGuides){
        assert.equal((await page.goto(href)).status(),200);
        assert.equal(await page.locator('article.document h1').count(),1);
        await page.locator('.document img').evaluateAll(imgs=>Promise.all(imgs.map(img=>img.decode())));
        assert.ok(await page.locator('.page-nav a').evaluateAll(a=>a.every(x=>document.getElementById(decodeURIComponent(x.hash.slice(1))))));
        const local=await page.locator('a[href]').evaluateAll(a=>[...new Set(a.filter(x=>x.origin===location.origin).map(x=>x.href.split('#')[0]))]);
        for(const url of local)assert.equal((await context.request.get(url)).status(),200,url);
        for(const width of [1440,390]){await page.setViewportSize({width,height:1060});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,href);}
        report.pages++;
      }
    }
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({...report,passed:true},null,2));
  } finally {await browser.close();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
