const {chromium}=require('playwright');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const root=require('node:path').resolve(process.argv[2]||'.preview-check');
const previewURL=(process.env.AGENTPROV_PREVIEW_URL||'http://127.0.0.1:47920').replace(/\/$/,'');
(async()=>{
  const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const reports=[];fs.mkdirSync(root+'/ui-screenshots',{recursive:true});
  try {
    for(const name of ['execution','workspace','browser','notebook','investigation']){
      const context=await browser.newContext({viewport:{width:1440,height:1050},locale:'en-US'});
      const page=await context.newPage();const errors=[];
      page.on('pageerror',error=>errors.push(error.message));
      page.on('requestfailed',request=>errors.push(request.url()+': '+request.failure()?.errorText));
      const outside=[];page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(previewURL+'/'))outside.push(r.url());});
      await page.goto(previewURL+'/'+name+'/index.html');
      await page.waitForFunction(()=>window.AgentPortableEvidenceUI&&document.querySelector('#context-summary').textContent!=='loading…');
      await page.waitForFunction(()=>document.querySelector('#dag').childElementCount>0);
      assert.equal(await page.locator('#context-fold').getAttribute('open'),null);
      assert.equal(await page.locator('#compare-dialog').count(),1);
      const result={name,errors,outside};
      result.drilldowns=await page.evaluate(async()=>{
        let checked=0;const catalog=await window.AgentProvOffline.manifest();
        for(const item of await j('/api/runs')){
          const scopes=['',...Object.keys(catalog.runs[item.run].sessions||{}).map(key=>{const [harness,session]=JSON.parse(key);return '&harness='+encodeURIComponent(harness)+'&session='+encodeURIComponent(session);})];
          for(const scope of scopes){
          const query='run='+encodeURIComponent(item.run)+scope;
          for(const lens of ['default','file-artifact','process','network-egress','security','agent-intent']){
            const graph=await j('/api/lens?'+query+'&lens='+lens+'&detail=summary');
            for(const node of graph.nodes||[]){
              const d=node.data||{},count=d.count??d.total??d.runtime_processes??((d.agents||0)+(d.messages||0));
              if(!d.drilldown_lens||!count)continue;
              const next=await j('/api/lens?'+query+'&lens='+d.drilldown_lens+'&detail='+d.drilldown_detail+(d.drilldown_focus?'&focus='+encodeURIComponent(d.drilldown_focus):''));
              if(!next.nodes?.length)throw Error(item.run+': '+node.label+' opens an empty graph');
              if(next.query.node_count!==next.nodes.length)throw Error('Graph node count mismatch');
              checked++;
            }
          }
          }
        }
        return checked;
      });
      if(name==='execution'){
        await page.waitForSelector('[data-execution-attempt]',{state:'attached'});
        await page.locator('#portable-executions>details>summary').click();
        result.attempts=await page.locator('[data-execution-attempt]').count();assert.ok(result.attempts>=2);
        await page.locator('[data-portable-action="capture"]').first().click();
        assert.match(await page.locator('#portable-dialog-body').innerText(),/scope_state_sampling_gap/);
        assert.match(await page.locator('#portable-dialog-body').innerText(),/36/);
        await page.locator('.portable-evidence-head button').click();
        await page.locator('#portable-executions').screenshot({path:root+'/ui-screenshots/execution.png'});
        await page.locator('[data-portable-action="source"]').first().click();
        await page.waitForSelector('[data-dialog-entry]');
        await page.locator('[data-dialog-entry]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        result.sourceBody=await page.locator('#portable-dialog-body pre').first().innerText();
        assert.match(result.sourceBody,/python3 analyze\.py/);
        await page.locator('.portable-evidence-head button').click();
        const originRun=new URL(page.url()).searchParams.get('run');
        await page.locator('[data-portable-action="execution"]').first().click();
        await page.waitForFunction(run=>new URL(location.href).searchParams.get('run')!==run,originRun);
        await page.waitForSelector('[data-execution-direction="incoming"]');
        await page.locator('#dag [data-id="overview/tool_calls"]').click();
        await page.waitForFunction(()=>window._lensManifest?.lens==='intent');
        assert.ok(await page.locator('#dag [data-id]').count()>0,'recorded remote call remains inspectable');
        await page.locator('[data-execution-direction="incoming"] [data-portable-action="source"]').first().click();
        await page.waitForFunction(run=>new URL(location.href).searchParams.get('run')===run,originRun);
        await page.waitForSelector('[data-dialog-entry]');
        await page.locator('[data-dialog-entry]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        assert.match(await page.locator('#portable-dialog-body pre').first().innerText(),/python3 analyze\.py/);
        assert.ok(await page.evaluate(async()=>{
          const p=new URL(location.href).searchParams;
          const m=await j('/api/lens?run='+p.get('run')+'&harness='+p.get('harness')+'&session='+p.get('session')+'&lens=default&detail=summary');
          const n=m.nodes.find(n=>n.id==='overview/tool_calls');
          return document.querySelector('.qbtn[data-node="overview/tool_calls"] .m').textContent===nodeLabel(n);
        }),'investigation counts follow the selected session');
        result.bidirectional=true;
      }else if(name==='workspace'){
        await page.locator('#context-fold>summary').click();await page.locator('#portable-workspace-tab').click();
        const row=page.locator('[data-workspace-entry]').filter({has:page.locator('h3',{hasText:'workspace_bash'})});
        await row.locator('[data-native-body]').click();
        await page.waitForSelector('[data-workspace-receipt]');
        const body=await page.locator('#portable-dialog-body').innerText();
        assert.match(body,/Input revision/);assert.match(body,/Output manifest/);assert.match(body,/Record attempt/);assert.match(body,/"exit_code":0/);
        result.receipt=await page.locator('[data-workspace-receipt]').getAttribute('data-workspace-receipt');
        assert.match(result.receipt,/^sha256:[a-f0-9]{64}$/);
        await page.screenshot({path:root+'/ui-screenshots/workspace.png'});
        await page.locator('.portable-evidence-head button').click();
        await page.locator('#portable-delivery-details').click();
        const modes=await page.locator('#portable-dialog-body').innerText();
        for(const mode of ['reading','derived','originals'])assert.ok(modes.includes(mode));
        result.versions=true;result.deliveryModes=true;
      }else if(name==='browser'||name==='notebook'){
        await page.locator('#context-fold>summary').click();await page.locator('#portable-native-tab').click();
        await page.waitForSelector('[data-native-entry]');result.records=await page.locator('[data-native-entry]').count();
        let attachments=page.locator('[data-native-attachment]:enabled');
        if(await attachments.count()===0&&await page.locator('#portable-native .portable-more').count()){
          await page.locator('#portable-native .portable-more').click();await page.waitForSelector('[data-native-attachment]:enabled');
        }
        await attachments.first().click();await page.waitForSelector('#portable-dialog-body img');
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body img')?.naturalWidth>0);
        result.image=true;await page.screenshot({path:root+'/ui-screenshots/'+name+'.png'});
        await page.locator('.portable-evidence-head button').click();
        await page.locator('[data-native-body]').first().click();
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body pre')?.textContent.length>0);
        result.content=true;
      }else{
        await page.screenshot({path:root+'/ui-screenshots/investigation.png'});
      }
      assert.deepEqual(errors,[]);assert.deepEqual(outside,[]);delete result.sourceBody;reports.push(result);console.log(JSON.stringify(result));await context.close();
    }
  }finally{await browser.close();fs.writeFileSync(root+'/ui-screenshots/report.json',JSON.stringify(reports,null,2));}
})().catch(error=>{console.error(error);process.exitCode=1;});
