// Verify downloaded replay ZIPs in an offline browser, using no source store.
// Usage: node scripts/accept_offline_replay.cjs replay.zip [another.zip ...]
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {pathToFileURL}=require('node:url');
const {execFileSync}=require('node:child_process');
const {gunzipSync}=require('node:zlib');
const {createHash}=require('node:crypto');

async function main(){
  assert.ok(process.argv.length>2,'supply at least one generated replay ZIP');
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const reports=[];
  try{
    for(const archive of process.argv.slice(2)){
      const names=execFileSync('unzip',['-Z1',archive],{encoding:'utf8'}).trim().split('\n');
      assert.ok(names.every(n=>!path.isAbsolute(n)&&!n.split(/[\\/]/).includes('..')&&!n.includes('\\')),'portable archive members');
      const root=fs.mkdtempSync(path.join(os.tmpdir(),'agentprov-offline-check-'));
      const context=await browser.newContext({offline:true,viewport:{width:1440,height:1050},locale:'en-US'});
      const report={run:'',files:0,shards:0,queries:0,views:0,sessions:0,contextBodies:0,networkRequests:0};
      try{
        execFileSync('unzip',['-q',archive,'-d',root]);
        const inventory=JSON.parse(fs.readFileSync(path.join(root,'export-inventory.json'),'utf8'));
        report.run=inventory.run_id;
        assert.equal(inventory.signed,false);assert.ok(['whole_run','session'].includes(inventory.scope));
        report.scope=inventory.scope;
        assert.deepEqual(names.sort(),[...inventory.files.map(f=>f.path),'export-inventory.json'].sort());
        const hash=b=>createHash('sha256').update(b).digest('hex');
        let total=0;
        for(const file of inventory.files){
          const bytes=fs.readFileSync(path.join(root,file.path));
          assert.equal(bytes.length,file.bytes);assert.equal(hash(bytes),file.sha256);total+=bytes.length;report.files++;
          assert.ok(!/\.(db|sqlite|json\.gz|dsse\.json)$/.test(file.path),'no hidden database or evidence bundle');
          if(file.path.startsWith('data/')){
            const match=bytes.toString().match(/^window\.AgentProvOffline\.accept\("(data\/[a-f0-9]{64}\.json\.gz)","([A-Za-z0-9+/]*={0,2})"\);$/);
            assert.ok(match,'shards contain a fixed wrapper and base64 only');
            assert.equal(match[1].replace('.json.gz','.js'),file.path);
            const decoded=gunzipSync(Buffer.from(match[2],'base64'));JSON.parse(decoded);assert.equal(hash(decoded),match[1].slice(5,69));report.shards++;
          }
        }
        assert.equal(total,inventory.bytes_excluding_inventory);
        const encoded=fs.readFileSync(path.join(root,'assets/catalog.js'),'utf8').match(/^window\.AgentProvOfflineCatalog="([A-Za-z0-9+/]*={0,2})";$/);
        assert.ok(encoded);
        const catalog=JSON.parse(Buffer.from(encoded[1],'base64'));
        assert.deepEqual(Object.keys(catalog.runs),[report.run]);assert.deepEqual(catalog.summaries.map(r=>r.run),[report.run]);
        const saved=ref=>{
          const file=fs.readFileSync(path.join(root,ref.path.replace('.json.gz','.js')),'utf8');
          const encoded=file.match(/,"([A-Za-z0-9+/]*={0,2})"\);$/)[1];
          const bytes=gunzipSync(Buffer.from(encoded,'base64'));assert.equal(bytes.length,ref.bytes);assert.equal(hash(bytes),ref.sha256);return JSON.parse(bytes);
        };
        const errors=[];
        const page=await context.newPage();
        page.on('pageerror',e=>errors.push(e.message));
        page.on('request',r=>{if(/^https?:/.test(r.url()))report.networkRequests++;});
        page.on('dialog',async d=>{errors.push('Evidence opened a dialog');await d.dismiss();});
        await page.goto(pathToFileURL(path.join(root,'index.html')).href+'?lang=en');
        await page.waitForFunction(()=>window._lensManifest && document.querySelector('#dag svg'));
        assert.equal(await page.locator('#runsel option').count(),1);
        assert.equal(await page.locator('#runsel').inputValue(),report.run);
        assert.ok(await page.locator('#live').isHidden());
        assert.match(await page.locator('.offline-replay-bar').innerText(),/unsigned sharing copy/);
        const query=async q=>{report.queries++;return page.evaluate(q=>AgentProvReplay.query(q),q);};
        const q='?run='+encodeURIComponent(report.run),run=catalog.runs[report.run];let partial=false;
        if(inventory.record_selection){
          const file=inventory.record_selection,raw=fs.readFileSync(path.join(root,file.path));
          assert.equal(raw.length,file.bytes);assert.equal(hash(raw),file.sha256);
          const selection=JSON.parse(raw);
          assert.equal(selection.schema_version,'agentprovenance.replay_selection/v1');
          assert.equal(selection.selection.run_id,report.run);assert.equal(selection.selection.scope,inventory.scope);
          partial=inventory.scope==='session'||(selection.selection.exclude_records||[]).length>0||(selection.selection.exclude_categories||[]).length>0;
          if(!partial)assert.ok(selection.records.every(r=>r.included),'whole-run selection retains every record');
          else assert.match(await page.locator('#verify').innerText(),/Selected evidence/);
          const actual=selection.records.filter(r=>r.included&&r.indexed).map(r=>r.id).sort();
          const expected=Object.values(run.search['["",""]']).flatMap(ref=>saved(ref).sources.map(s=>s.id)).sort();
          assert.deepEqual(actual,expected,'record manifest matches every source in the exported search catalog');
          assert.deepEqual(selection.records.filter(r=>r.included&&r.id.startsWith('entry/')).map(r=>r.id.slice(6)).sort(),saved(run.context).entries.map(e=>e.id).sort(),'record manifest includes only selected context revisions');
        }
        const index=saved(run.lenses);
        for(const [key,ref] of Object.entries(index.views)){
          const [lens,detail]=key.split('/'),expected=saved(ref).manifest;
          assert.deepEqual(await query('/api/lens'+q+'&lens='+lens+'&detail='+detail+'&overlay=risk&overlay=trust'),expected);report.views++;
        }
        for(const [key,scope] of Object.entries(run.sessions||{})){
          const [harness,session]=JSON.parse(key),extra='&harness='+encodeURIComponent(harness)+'&session='+encodeURIComponent(session);
          const scoped=saved(scope.lenses);
          assert.deepEqual(await query('/api/lens'+q+extra+'&overlay=risk&overlay=trust'),saved(scoped.views['default/summary']).manifest);
          const events=await query('/api/events'+q+extra+'&limit=500');assert.ok(events.events.every(e=>scope.event_ids.includes(e.id)));report.sessions++;
        }
        let events=[];
        for(let offset=0;;offset+=500){const value=await query('/api/events'+q+'&limit=500&offset='+offset);events.push(...value.events);if(events.length>=value.total)break;}
        assert.deepEqual(events,saved(run.events));assert.equal(events.length,inventory.events);
        if(run.audit){
          const expected=run.audit.pages.flatMap(shard=>saved(shard.data).items);
          for(const limit of [1,17,100,500]){
            let items=[],cursor='';
            do{const value=await query('/api/audit/associations'+q+'&limit='+limit+'&cursor='+encodeURIComponent(cursor));assert.equal(value.analysis_scope,'export_pages');items.push(...value.items);cursor=value.next_cursor||'';}while(cursor);
            assert.deepEqual(items,expected,'audit pagination preserves candidates and references');
          }
          if(expected.length){
            const one=await query('/api/audit/associations'+q+'&event='+encodeURIComponent(expected[0].event_id));assert.deepEqual(one.items,[expected[0]]);
            if(report.run==='audit-interface-fixture')for(const item of expected){
              if(partial){assert.equal(item.operation.reason,'replay_evidence_excluded');assert.equal(item.operation.status,'unassociated');assert.ok(!item.operations);}
              else {assert.equal(item.operation.status,'ambiguous');assert.equal(item.operation.candidate_count,2);assert.ok(item.operations.some(op=>op.syscall_result===0));}
            }
          }
          for(const extra of ['&session=x','&harness=claude','&limit=0','&limit=501','&limit=1.5','&limit=','&run=duplicate','&cursor=bad'])await assert.rejects(query('/api/audit/associations'+q+extra));
          report.auditDecisions=expected.length;
        }
        const session=saved(run.context);
        let contextText='';
        let entries=[],cursor='';
        do{const value=await query('/api/context/entries'+q+'&revisions=true&limit=200&cursor='+encodeURIComponent(cursor));entries.push(...value.entries);cursor=value.next_cursor||'';}while(cursor);
        assert.deepEqual(entries,session.entries);
        for(const [ref,pages] of Object.entries(session.content)){
          for(const offset of [...new Set([0,pages.offsets.at(-1)])]){
            const value=await query('/api/context/content'+q+'&ref='+ref+'&offset='+offset);
            const expected=saved(pages.pages[pages.offsets.indexOf(offset)]);assert.deepEqual(value,expected);report.contextBodies++;
            contextText+=value.content||'';
          }
        }
        if(report.run==='run-dbc2adf273d4')assert.match(contextText,/Ran 7 tests/,'the seven-test result remains historical saved evidence');
        for(const lens of ['orchestration','file-artifact','default']){
          await page.locator('#lenssel').selectOption(lens);
          await page.waitForFunction(lens=>window._lensManifest?.lens===lens,lens);
        }
        await page.locator('#zoomin').click();
        const zoom=await page.evaluate(()=>ZOOM);
        await page.locator('#zoomout').click();assert.ok(await page.evaluate(()=>ZOOM)<zoom);
        await page.locator('[data-investigation="compare"]').click();
        await page.waitForFunction(()=>document.querySelector('#compare-status').textContent.includes('No second run'));
        assert.deepEqual(await page.locator('#compare-b option').evaluateAll(options=>options.map(o=>o.value)),['',report.run],'no unselected run is offered');
        await page.locator('#compare-close').click();
        await page.locator('[data-investigation="search"]').click();
        if(partial)assert.match(await page.locator('#search-scope').innerText(),/Included records/,'partial replay does not claim whole-run search');
        await page.locator('#search-query').fill(report.run==='run-double-attempt'?'169.254.169.254':report.run==='ui-fixture'?'SAVED-OUTPUT-TAIL':report.run==='audit-interface-fixture'?'SECCOMP':'report.py');
        await page.locator('#search-submit').click();
        await page.waitForFunction(()=>!document.querySelector('#search-submit').disabled);
        assert.ok(await page.locator('.search-result').count()>0,'saved evidence remains searchable offline');
        await page.waitForFunction(()=>!document.querySelector('#content-body').textContent.includes('loading…'));
        assert.equal(await page.locator('#content-body img, #content-body script').count(),0);
        if(report.run==='ui-fixture'){
          assert.ok(await page.evaluate(()=>AgentContextUI.readerPosition().offset>65536),'long-body search opens beyond the first saved page');
          await page.locator('#search-query').fill('onerror');await page.locator('#search-submit').click();
          await page.waitForFunction(()=>!document.querySelector('#search-submit').disabled&&document.querySelector('#content-body').textContent.includes('onerror'));
          assert.equal(await page.locator('#content-body img, #content-body script').count(),0,'saved HTML is text even inside search results');
        }
        await page.screenshot({path:'output/playwright/offline-'+report.run+'-desktop.png'});
        await page.setViewportSize({width:390,height:844});
        assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
        assert.ok(await page.locator('#search-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+1));
        assert.equal(await page.locator('#content-body').evaluate(e=>getComputedStyle(e).overflowY),'auto');
        await page.screenshot({path:'output/playwright/offline-'+report.run+'-mobile.png'});
        await page.locator('#search-close').click();
        const englishAudit=run.audit?await query('/api/audit/associations'+q+'&limit=1'):null;
        await page.getByRole('link',{name:'中文',exact:true}).click();
        await page.waitForFunction(()=>window._lensManifest);
        assert.match(await page.locator('.offline-replay-bar').innerText(),/未签名的分享副本/);
        if(englishAudit)assert.deepEqual(await query('/api/audit/associations'+q+'&limit=1'),englishAudit,'Chinese UI does not localize API output');
        assert.equal(report.networkRequests,0);assert.deepEqual(errors,[]);
        reports.push(report);console.log(JSON.stringify(report));
      }finally{await context.close();fs.rmSync(root,{recursive:true,force:true});}
    }
  }finally{await browser.close();}
  console.log(JSON.stringify({offlineReplayPassed:true,reports}));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
