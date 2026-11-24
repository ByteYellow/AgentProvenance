// End-to-end static replay parity against a current, isolated `agentprov demo`.
// Usage: node scripts/accept_static_demo.cjs SITE_URL LOCAL_DEMO_URL
// Run SITE_URL under a project subpath to catch GitHub Pages routing mistakes.
const assert = require('node:assert/strict');
const { gunzipSync } = require('node:zlib');
const { tmpdir } = require('node:os');
const { createHash } = require('node:crypto');

function assertNavigationParity(nativeHrefs, staticHrefs, {native, site, lang}) {
  const nativeBase=new URL(native), siteBase=new URL(site);
  assert.ok(siteBase.pathname.endsWith('/'),'Static site base must end with a slash');
  const canonical=url=>{url.searchParams.sort();return url.href;};
  const expected=[];
  for(const href of nativeHrefs){
    const url=new URL(href,nativeBase),parts=url.pathname.split('/');
    if(url.origin!==nativeBase.origin || parts.length!==4 || parts[1]!=='demos' || !['docs','guide'].includes(parts[2]) || !parts[3])continue;
    assert.equal(url.searchParams.get('lang')||lang,lang,'Native navigation must use the selected language');
    const translated=new URL(lang+'/'+(parts[2]==='docs'?'demos':'guides')+'/'+parts[3]+'.html',siteBase);
    url.searchParams.delete('lang');
    translated.search=url.search;
    translated.hash=url.hash;
    expected.push(canonical(translated));
  }
  const actual=[];
  for(const href of staticHrefs){
    const url=new URL(href,siteBase);
    if(url.origin!==siteBase.origin || !url.pathname.startsWith(siteBase.pathname))continue;
    const parts=url.pathname.slice(siteBase.pathname.length).split('/');
    if(parts.length===3 && ['demos','guides'].includes(parts[1]) && parts[2].endsWith('.html'))actual.push(canonical(url));
  }
  const links=[...new Set(actual)].sort();
  assert.ok(expected.length>0,'Native documentation navigation must not be empty');
  assert.deepEqual(links,[...new Set(expected)].sort(),'Static documentation navigation must exactly match native navigation');
  return links;
}

async function viewNodes(index, view, readGraph) {
  if (!view.schema_version) {
    assert.ok(Array.isArray(view.manifest.nodes), 'Legacy graph nodes are missing');
    return view.manifest.nodes;
  }
  assert.equal(view.schema_version, 'agentprovenance.replay_lens_view/v2');
  assert.ok(index.graph, 'Shared graph reference is missing');
  const graph = await readGraph(index.graph);
  assert.equal(graph.schema_version, 'agentprovenance.replay_graph/v1');
  assert.ok(Array.isArray(graph.nodes) && Array.isArray(view.node_indexes));
  return view.node_indexes.map(i => {
    assert.ok(Number.isInteger(i) && i >= 0 && i < graph.nodes.length, 'Invalid shared node reference');
    return graph.nodes[i];
  });
}

async function main() {
  const { chromium } = require('playwright');
  const site = new URL(process.argv[2]), native = new URL(process.argv[3]);
  const browser = await chromium.launch({headless:true, ...(process.env.PLAYWRIGHT_CHANNEL ? {channel:process.env.PLAYWRIGHT_CHANNEL} : {})});
  const report = {parity:0, pages:0, runs:0, sessions:0, focusedGraphs:0, contentPages:0, runIndexes:0};
  const errors = [];
  const failedRequests = [];
  let page;
  const responseJSON = async (request,url) => {const r=await request.get(url);assert.equal(r.status(),200,url);return r.json();};
  try {
    const context=await browser.newContext({viewport:{width:1440,height:1060},locale:'en-US'});
    await context.route('**/*',route=>{
      const url=new URL(route.request().url());
      if(url.origin===site.origin && url.pathname.startsWith(site.pathname) && !url.pathname.includes('/api/'))return route.continue();
      errors.push('Unexpected browser request: '+url);return route.abort();
    });
    const browserPaths=[];
    page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
    page.on('request',request=>browserPaths.push(new URL(request.url()).pathname));
    page.on('requestfailed',request=>failedRequests.push({url:request.url(),error:request.failure()?.errorText}));
    const manifest=await responseJSON(context.request,new URL('replay-manifest.json',site).href);
    assert.equal(Object.keys(manifest.runs).length,12);
    assert.ok(manifest.verifications.every(v=>v.signature_verified&&v.graph.status==='ok'));
    const catalog=await responseJSON(context.request,new URL('replay-catalog.json',site).href);
    assert.equal(catalog.schema_version,'agentprovenance.static_catalog/v1');
    assert.equal(catalog.commit,manifest.commit);assert.deepEqual(catalog.summaries,manifest.summaries);
    assert.deepEqual(Object.keys(catalog.run_indexes).sort(),Object.keys(manifest.runs).sort());
    for(const [run,ref] of Object.entries(catalog.run_indexes)){
      const response=await context.request.get(new URL(ref.path,site).href);assert.equal(response.status(),200);
      const bytes=gunzipSync(await response.body());assert.equal(bytes.length,ref.bytes);
      assert.equal(createHash('sha256').update(bytes).digest('hex'),ref.sha256);
      const index=JSON.parse(bytes);assert.equal(index.schema_version,'agentprovenance.replay_run/v1');
      assert.equal(index.run_id,run);assert.deepEqual(index.run,manifest.runs[run]);report.runIndexes++;
    }
    const data=async ref=>{const r=await context.request.get(new URL(ref.path,site).href);assert.ok(r.ok());return JSON.parse(gunzipSync(await r.body()).toString());};
    const graphs=new Map();
    const graphData=ref=>{if(!graphs.has(ref.path))graphs.set(ref.path,data(ref));return graphs.get(ref.path);};
    await page.goto(new URL('en/replay.html?run=run-dbc2adf273d4',site).href);
    await page.waitForFunction(()=>window._lensManifest && document.querySelector('#dag svg'));
    const indexPaths=Object.values(catalog.run_indexes).map(ref=>new URL(ref.path,site).pathname);
    assert.deepEqual([...new Set(browserPaths.filter(path=>indexPaths.includes(path)))],[new URL(catalog.run_indexes['run-dbc2adf273d4'].path,site).pathname]);
    assert.ok(!browserPaths.includes(new URL('replay-manifest.json',site).pathname),'the browser must not load the full legacy manifest');
    const compare=async query=>{
      const [expected,actual]=await Promise.all([responseJSON(context.request,new URL(query,native).href),page.evaluate(q=>AgentProvReplay.query(q),query)]).catch(error=>{console.error('Query failed: '+query);throw error;});
      // Import locations differ; compare the same content-addressed object path.
      const root=tmpdir().replace(/\/$/,'').replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const importedPath=new RegExp(root+'/agentprov-(?:public-demo|demo)-[0-9]+/state/provenance/objects/','g');
      const normalize=v=>JSON.parse(JSON.stringify(v).replace(importedPath,'/demo/objects/'));
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
        const byKind=new Map();for(const node of await viewNodes(index,view,graphData))if(!byKind.has(node.kind))byKind.set(node.kind,node.id);
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
      for(const [identity,scope] of Object.entries(snapshot.sessions || {})){
        const [harness,sessionID]=JSON.parse(identity),params=q+'&harness='+encodeURIComponent(harness)+'&session='+encodeURIComponent(sessionID);
        for(const cursor of Object.keys(scope.relations||{})){
          const query='/api/context/session-relations'+params+'&limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):'');
          const [expected,actual]=await Promise.all([data(scope.relations[cursor]),page.evaluate(q=>AgentProvReplay.query(q),query)]);
          assert.deepEqual(actual,expected);report.parity++;
        }
        const scopedIndex=await data(scope.lenses);
        for(const key of Object.keys(scopedIndex.views)){
          const [lens,detail]=key.split('/'),query='/api/lens'+params+'&lens='+lens+'&detail='+detail;
          await compare(query);await compare(query+'&overlay=risk&overlay=trust');
          const view=await data(scopedIndex.views[key]);
          const byKind=new Map();for(const node of await viewNodes(scopedIndex,view,graphData))if(!byKind.has(node.kind))byKind.set(node.kind,node.id);
          for(const id of byKind.values())await compare(query+'&focus='+encodeURIComponent(id));
        }
        for(const offset of [0,7,100000])await compare('/api/events'+params+'&limit=7&offset='+offset);
        for(const id of Object.keys(snapshot.event_refs).filter(id=>!id.startsWith('runtime_event/')).slice(0,12))await compare('/api/events'+params+'&ref='+encodeURIComponent(id));
        for(const group of ['conversation','configuration']){
          const path='/api/context/entries'+params+'&group='+group+'&limit=7';
          const collect=async fetchPage=>{let cursor='',entries=[];do{const result=await fetchPage(path+(cursor?'&cursor='+encodeURIComponent(cursor):''));entries.push(...result.entries);cursor=result.next_cursor||'';}while(cursor);return entries;};
          assert.deepEqual(await collect(q=>page.evaluate(q=>AgentProvReplay.query(q),q)),await collect(q=>responseJSON(context.request,new URL(q,native).href)));report.parity++;
        }
        report.sessions++;
      }
      const session=await data(snapshot.context);
      for(const cursor of Object.keys(snapshot.compare || {}))await compare('/api/compare/records'+q+'&cursor='+encodeURIComponent(cursor));
      for(const [identity,pages] of Object.entries(snapshot.search || {})){
        const [harness,sessionID]=JSON.parse(identity);
        for(const cursor of Object.keys(pages))await compare('/api/search/sources'+q+'&harness='+encodeURIComponent(harness)+'&session='+encodeURIComponent(sessionID)+'&cursor='+encodeURIComponent(cursor));
      }
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
    // Use actual UI controls on the unified Apple Workbench for the recorded DeepSeek task, with no API backend.
    await page.goto(new URL('en/replay.html?run=run-dbc2adf273d4',site).href);
    await page.waitForFunction(()=>window._lensManifest && document.querySelector('#dag svg') && document.querySelector('#wb-runsel')?.options.length);
    for(const lens of await page.locator('#wb-lens-select option').evaluateAll(options=>options.map(o=>o.value))){
      await page.locator('#wb-lens-select').selectOption(lens);
      await page.waitForFunction(lens=>window._lensManifest?.lens===lens,lens);
    }
    await page.locator('#wb-lens-select').selectOption('file-artifact');
    await page.locator('[data-detail="raw"]').click();
    await page.waitForFunction(()=>window._lensManifest?.lens==='file-artifact'&&window._lensManifest?.query.detail==='raw');
    await page.locator('#dag [data-id="workspace_file/report.py"]').click();
    await page.locator('[data-instab="content"]').click();
    await page.waitForFunction(()=>document.querySelector('#wb-inspector')?.textContent.includes('def daily_revenue'));
    await page.locator('.wb-tab[data-mode="session"]').click();
    await page.waitForSelector('#session-body .wb-card');
    await page.locator('.wb-tab[data-mode="graph"]').click();
    await page.locator('.wb-lang a[lang="zh-CN"]').click();
    await page.waitForURL(url=>url.pathname===new URL('zh-CN/replay.html',site).pathname);
    await page.waitForFunction(()=>window._lensManifest);
    assert.equal(await page.locator('html').getAttribute('lang'),'zh-CN');
    assert.equal(new URL(page.url()).searchParams.get('run'),'run-dbc2adf273d4');
    await page.goto(site.href);await page.waitForURL('**/zh-CN/index.html');
    for(const [locale,lang] of [['zh-CN','zh-CN'],['en-US','en'],['fr-FR','en']]){
      const fresh=await browser.newContext({locale});const first=await fresh.newPage();
      await first.goto(site.href);await first.waitForURL('**/'+lang+'/index.html');await fresh.close();
    }
    report.ui='graph, files, session view and language passed';

    for(const [lang,before,after] of [['en','Oct reproduction · Before','Oct reproduction · After'],['zh-CN','10 月复现 · 修复前','10 月复现 · 修复后']]){
      await page.goto(new URL(lang+'/replay.html?run=run-e9c3f452461a',site).href);
      await page.waitForFunction(()=>window._lensManifest && document.querySelector('#wb-runsel')?.options.length);
      assert.ok((await page.locator('#wb-runsel option:checked').innerText()).startsWith(before));
      assert.equal(await page.locator('#wb-runsel').inputValue(),'run-e9c3f452461a');
      await page.locator('#wb-btn-compare').click();
      await page.waitForFunction(()=>document.querySelector('#cmp-a')?.options.length>1);
      assert.ok((await page.locator('#cmp-a option[value="run-e9c3f452461a"]').innerText()).startsWith(before));
      assert.ok((await page.locator('#cmp-b option[value="run-2267309eda57"]').innerText()).startsWith(after));
      await page.locator('[data-close="wb-compare-dlg"]').click();
    }
    report.runLabels='English and Chinese run and comparison selectors preserve evidence IDs';

    // The same scanner must find the same saved records through both readers.
    const live=await browser.newPage();await live.goto(new URL('/?run=run-dbc2adf273d4&live=0',native).href);
    await live.waitForFunction(()=>window.AgentEvidenceSearch && window._lensManifest);
    await page.goto(new URL('en/replay.html?run=run-dbc2adf273d4',site).href);
    await page.waitForFunction(()=>window.AgentEvidenceSearch && window._lensManifest);
    for(const [run,query,category] of [['run-dbc2adf273d4','Ran 7 tests','tools'],['run-dbc2adf273d4','report.py','files'],['run-double-attempt','169.254.169.254',''],['run-double-attempt','install','messages']]){
      const search=async page=>page.evaluate(async({run,query,category})=>{
        const scanner=AgentEvidenceSearch.create({query,category,scope:{run,lang:'en'},get:j});let ids=[],last;
        do{last=await scanner.next();if(last.error)throw new Error(last.error);ids.push(...last.hits.flatMap(h=>h.sources.map(s=>s.id)));}while(last.has_more);
        return {ids:ids.sort(),scanned:last.stats.scanned,unavailable:last.stats.unavailable};
      },{run,query,category});
      const expected=await search(live),actual=await search(page);assert.ok(expected.ids.length,'historical search '+query);assert.deepEqual(actual,expected);report.parity++;
    }
    // Compare the same historical records through native and static readers.
    for(const [a,b] of [['run-grok-exfil','run-grok-3routes'],['run-dbc2adf273d4','run-double-attempt']]){
      const build=page=>page.evaluate(async({a,b})=>{
        const left=await AgentRunCompare.load({run:a,get:j}),right=await AgentRunCompare.load({run:b,get:j});
        const result=AgentRunCompare.build(left,right);
        return {complete:[left.complete,right.complete],...result};
      },{a,b});
      const expected=await build(live),actual=await build(page);
      assert.deepEqual(actual,expected);assert.deepEqual(actual.complete,[true,true]);
      assert.ok(actual.rows.length);assert.notEqual(actual.taskRelation,'matching_recorded_tasks');report.parity++;
    }
    await live.close();
    await page.locator('#wb-btn-search').click();
    await page.locator('#wb-srch-q').fill('Ran 7 tests');await page.locator('#wb-srch-cat').selectOption('tools');
    await page.locator('#wb-srch-form button[type="submit"]').click();
    await page.waitForSelector('#wb-srch-res .wb-card');
    assert.ok((await page.locator('#wb-srch-res').innerText()).includes('Ran 7 tests'));
    await page.locator('[data-close="wb-search-dlg"]').click();

    await page.goto(new URL('en/replay.html?run=run-grok-exfil',site).href);
    await page.waitForFunction(()=>window._lensManifest && window.AgentRunCompare);
    await page.locator('#wb-btn-compare').click();
    await page.waitForSelector('#cmp-b');
    await page.locator('#cmp-b').selectOption('run-grok-3routes');
    await page.waitForSelector('[data-cdim="outbound"]');
    assert.ok(!(await page.locator('.cmp-pair').innerText()).includes('undefined'));
    await page.locator('[data-cdim="outbound"]').click();
    await page.locator('#cmp-only').uncheck();
    const mixpanel=page.locator('.cmp-row').filter({hasText:'api.mixpanel.com'});
    if(!(await mixpanel.evaluate(el=>el.open))) await mixpanel.locator('summary').click();
    assert.ok((await mixpanel.innerText()).includes('Product analytics'));
    assert.equal(await mixpanel.locator('.cmp-box').count(),2);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    await page.locator('[data-close="wb-compare-dlg"]').click();
    await page.setViewportSize({width:1440,height:1060});
    report.comparison='historical Grok and DeepSeek/multiagent parity; Grok compare and mobile passed';

    // Attribution examples render in desktop and mobile without overflow.
    for(const lang of ['en','zh-CN']){
      for(const [run,lens,id] of [
        ['run-2fd63df0ab9b','intent','diff/v2/4958f6486e058efd80454be9ea8e6b8306c9cfc69337419c20db7db94f45b96c'],
        ['run-2fd63df0ab9b','agent-intent','sha256:072f5b3948ca4c5693b882722815b3958815c72ba807706b926dc67001bbbb49'],
        ['ui-endpoint-candidates','data-flow-taint','sha256:44fe36c9defe9293755c49b45c2223d11f6ba5ef32aba86b7f6f4b50fcef2768'],
      ]){
        const query=new URLSearchParams({run,lens,detail:'raw',live:'0',selected:id});
        await page.goto(new URL(lang+'/replay.html?'+query,site).href);
        await page.waitForFunction(()=>window._lensManifest && document.querySelector('#wb-inspector'));
        for(const width of [1440,390]){
          await page.setViewportSize({width,height:1060});
          assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
        }
      }
    }
    report.attribution='real intent and TLS detail, synthetic endpoint candidates; bilingual desktop/mobile passed';

    // All published guides, images and table-of-contents links, at both sizes.
    for(const lang of ['en','zh-CN']){
      await page.goto(new URL(lang+'/index.html',site).href);
      const nativeGallery=await context.request.get(new URL('/demos/?lang='+lang,native).href);
      assert.equal(nativeGallery.status(),200);
      const nativeLinks=await page.evaluate(html=>[...new DOMParser().parseFromString(html,'text/html').querySelectorAll('a[href]')].map(a=>a.getAttribute('href')),await nativeGallery.text());
      const links=assertNavigationParity(nativeLinks,await page.locator('a[href]').evaluateAll(a=>a.map(x=>x.href)),{native,site,lang});
      assert.equal(await page.locator('a[href*="benchmarks"]').count(),0);
      // Linked reference pages are exported and checked even when absent from navigation.
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
  } catch(error) {
    if(errors.length)console.error(JSON.stringify({browserErrors:errors}));
    console.error(JSON.stringify({failedRequests:failedRequests.slice(-20),page:page && await page.evaluate(()=>({url:location.href,reader:!!window.AgentProvReplay,error:document.querySelector('#loaderror-text')?.textContent})).catch(()=>({url:page.url()}))}));
    throw error;
  } finally {await browser.close();}
}
module.exports={assertNavigationParity,viewNodes};
if(require.main===module)main().catch(error=>{console.error(error);process.exitCode=1;});
