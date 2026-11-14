// Verify downloaded replay ZIPs in an offline browser, using no source store.
// Usage: node scripts/accept_offline_replay.cjs replay.zip [another.zip ...]
// AGENTPROV_REPLAY_SEARCH_QUERY selects a known saved phrase for a custom capture.
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
        assert.equal(inventory.signed,false);assert.ok(['whole_run','session','run_set'].includes(inventory.scope));
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
        const items=inventory.scope==='run_set'?inventory.runs:[inventory];
        const runIDs=items.map(item=>item.run_id);report.runs=runIDs;
        assert.deepEqual(Object.keys(catalog.runs).sort(),[...runIDs].sort());assert.deepEqual(catalog.summaries.map(r=>r.run),runIDs);
        assert.equal(new Set(runIDs).size,runIDs.length);
        if(inventory.scope==='run_set'){
          const master=JSON.parse(fs.readFileSync(path.join(root,inventory.record_selection.path)));
          assert.equal(master.schema_version,'agentprovenance.replay_selection_set/v1');assert.deepEqual(master.runs,items);
          assert.equal(items.reduce((n,item)=>n+item.events,0),inventory.events);
          for(const key of ['sessions','context_entries','latest_context_entries','context_body_refs','context_raw_refs'])
            assert.equal(items.reduce((n,item)=>n+item.contents[key],0),inventory.contents[key]);
        }
        const saved=ref=>{
          const file=fs.readFileSync(path.join(root,ref.path.replace('.json.gz','.js')),'utf8');
          const encoded=file.match(/,"([A-Za-z0-9+/]*={0,2})"\);$/)[1];
          const bytes=gunzipSync(Buffer.from(encoded,'base64'));assert.equal(bytes.length,ref.bytes);assert.equal(hash(bytes),ref.sha256);return JSON.parse(bytes);
        };
        const errors=[];
        for(const item of items){
        const runID=item.run_id;
        const page=await context.newPage();
        page.on('pageerror',e=>errors.push(e.message));
        page.on('request',r=>{if(/^https?:/.test(r.url()))report.networkRequests++;});
        page.on('dialog',async d=>{errors.push('Evidence opened a dialog');await d.dismiss();});
        await page.goto(pathToFileURL(path.join(root,'index.html')).href+'?lang=en&run='+encodeURIComponent(runID));
        await page.waitForFunction(()=>window._lensManifest && document.querySelector('#dag svg'));
        assert.equal(await page.locator('#runsel option').count(),runIDs.length);
        assert.equal(await page.locator('#runsel').inputValue(),runID);
        assert.ok(await page.locator('#live').isHidden());
        assert.match(await page.locator('.offline-replay-bar').innerText(),/unsigned sharing copy/);
        const query=async q=>{report.queries++;return page.evaluate(q=>AgentProvReplay.query(q),q);};
        const q='?run='+encodeURIComponent(runID),run=catalog.runs[runID];let partial=false;
        if(item.record_selection){
          const file=item.record_selection,raw=fs.readFileSync(path.join(root,file.path));
          assert.equal(raw.length,file.bytes);assert.equal(hash(raw),file.sha256);
          const selection=JSON.parse(raw);
          assert.equal(selection.schema_version,'agentprovenance.replay_selection/v1');
          assert.equal(selection.selection.run_id,runID);assert.equal(selection.selection.scope,item.scope);
          partial=item.scope==='session'||(selection.selection.exclude_records||[]).length>0||(selection.selection.exclude_categories||[]).length>0;
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
        assert.deepEqual(events,saved(run.events));assert.equal(events.length,item.events);
        if(run.audit){
          const expected=run.audit.pages.flatMap(shard=>saved(shard.data).items);
          for(const limit of [1,17,100,500]){
            let items=[],cursor='';
            do{const value=await query('/api/audit/associations'+q+'&limit='+limit+'&cursor='+encodeURIComponent(cursor));assert.equal(value.analysis_scope,'export_pages');items.push(...value.items);cursor=value.next_cursor||'';}while(cursor);
            assert.deepEqual(items,expected,'audit pagination preserves candidates and references');
          }
          if(expected.length){
            const one=await query('/api/audit/associations'+q+'&event='+encodeURIComponent(expected[0].event_id));assert.deepEqual(one.items,[expected[0]]);
            if(runID==='audit-interface-fixture')for(const item of expected){
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
        if(runID==='run-dbc2adf273d4')assert.match(contextText,/Ran 7 tests/,'the seven-test result remains historical saved evidence');
        for(const lens of ['orchestration','file-artifact','default']){
          await page.locator('#lenssel').selectOption(lens);
          await page.waitForFunction(lens=>window._lensManifest?.lens===lens,lens);
        }
        await page.locator('#zoomin').click();
        const zoom=await page.evaluate(()=>ZOOM);
        await page.locator('#zoomout').click();assert.ok(await page.evaluate(()=>ZOOM)<zoom);
        if(runIDs.length>1){
          await page.locator('#runsel').selectOption(runIDs.find(id=>id!==runID));
          await page.waitForFunction(id=>window._lensManifest?.run_id===id,runIDs.find(id=>id!==runID));
          await page.locator('#runsel').selectOption(runID);
          await page.waitForFunction(id=>window._lensManifest?.run_id===id,runID);
        }
        if(await page.evaluate(()=>TIMES.length>1)){
          await page.locator('#playbtn').click();
          await page.waitForFunction(()=>Number(document.querySelector('#slider').value)>0);
          if(await page.evaluate(()=>Boolean(PLAYING)))await page.locator('#playbtn').click();
          await page.locator('#slider').focus();await page.keyboard.press('End');
          assert.ok(await page.evaluate(()=>TCUR===null),'scrubber restores all saved events');
          report.playbacks=(report.playbacks||0)+1;
        }
        await page.locator('[data-investigation="compare"]').click();
        await page.waitForFunction(()=>document.querySelector('#compare-b option'));
        assert.deepEqual(await page.locator('#compare-b option').evaluateAll(options=>options.map(o=>o.value)),['',...runIDs],'no unselected run is offered');
        if(runIDs.length===1){
          await page.waitForFunction(()=>document.querySelector('#compare-status').textContent.includes('No second run'));
        }else{
          const other=runIDs.find(id=>id!==runID);
          await page.locator('#compare-b').selectOption(other);
          await page.waitForFunction(()=>document.querySelector('#compare-status').textContent==='Saved records loaded');
          assert.equal(await page.locator('#compare-a').inputValue(),runID);
          assert.ok(!(await page.locator('#compare-results').innerText()).includes('Recorded evidence could not be loaded.'));
          if(partial)assert.match(await page.locator('#compare-scope-note').innerText(),/included records/);
          await page.locator('#compare-swap').click();
          await page.waitForFunction(()=>document.querySelector('#compare-status').textContent==='Saved records loaded');
          assert.equal(await page.locator('#compare-a').inputValue(),other);assert.equal(await page.locator('#compare-b').inputValue(),runID);
        }
        await page.locator('#compare-close').click();
        assert.equal(await page.locator('#runsel').inputValue(),runID,'closing Compare preserves the current run');
        await page.locator('[data-investigation="search"]').click();
        if(partial)assert.match(await page.locator('#search-scope').innerText(),/Included records/,'partial replay does not claim whole-run search');
        await page.locator('#search-query').fill(process.env.AGENTPROV_REPLAY_SEARCH_QUERY||(runID==='run-double-attempt'?'169.254.169.254':runID==='ui-fixture'?'SAVED-OUTPUT-TAIL':runID==='audit-interface-fixture'?'SECCOMP':'report.py'));
        await page.locator('#search-submit').click();
        await page.waitForFunction(()=>!document.querySelector('#search-submit').disabled);
        assert.ok(await page.locator('.search-result').count()>0,'saved evidence remains searchable offline');
        await page.waitForFunction(()=>!document.querySelector('#content-body').textContent.includes('loading…'));
        assert.equal(await page.locator('#content-body img, #content-body script').count(),0);
        if(runID==='ui-fixture'){
          assert.ok(await page.evaluate(()=>AgentContextUI.readerPosition().offset>65536),'long-body search opens beyond the first saved page');
          await page.locator('#search-query').fill('onerror');await page.locator('#search-submit').click();
          await page.waitForFunction(()=>!document.querySelector('#search-submit').disabled&&document.querySelector('#content-body').textContent.includes('onerror'));
          assert.equal(await page.locator('#content-body img, #content-body script').count(),0,'saved HTML is text even inside search results');
        }
        const screenshot=path.join('output/playwright','offline-'+path.basename(archive,'.zip')+'-'+runID.replace(/[^a-zA-Z0-9_-]/g,'_'));
        await page.screenshot({path:screenshot+'-desktop.png'});
        await page.setViewportSize({width:390,height:844});
        assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
        assert.ok(await page.locator('#search-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+1));
        assert.equal(await page.locator('#content-body').evaluate(e=>getComputedStyle(e).overflowY),'auto');
        await page.screenshot({path:screenshot+'-mobile.png'});
        await page.locator('#search-close').click();
        const englishAudit=run.audit?await query('/api/audit/associations'+q+'&limit=1'):null;
        await page.getByRole('link',{name:'中文',exact:true}).click();
        await page.waitForFunction(()=>window._lensManifest);
        assert.equal(await page.locator('#runsel').inputValue(),runID,'language switch preserves the current run');
        assert.match(await page.locator('.offline-replay-bar').innerText(),/未签名的分享副本/);
        if(englishAudit)assert.deepEqual(await query('/api/audit/associations'+q+'&limit=1'),englishAudit,'Chinese UI does not localize API output');
        assert.equal(await page.evaluate(()=>globalThis.evidenceExecuted),undefined,'evidence remains inert text');
        await page.close();
        }
        assert.equal(report.networkRequests,0);assert.deepEqual(errors,[]);
        reports.push(report);console.log(JSON.stringify(report));
      }finally{await context.close();fs.rmSync(root,{recursive:true,force:true});}
    }
  }finally{await browser.close();}
  console.log(JSON.stringify({offlineReplayPassed:true,reports}));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
