// Compare two exported sites on the same loopback host and browser.
// Usage: PLAYWRIGHT_CHANNEL=chrome node scripts/bench_static_replay.cjs BEFORE AFTER
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const os=require('node:os');
const {chromium}=require('playwright');

async function main(){
  assert.equal(process.argv.length,4,'provide the previous and candidate exported site directories');
  const roots={before:fs.realpathSync(process.argv[2]),after:fs.realpathSync(process.argv[3])};
  const manifests=Object.fromEntries(Object.entries(roots).map(([key,root])=>[key,JSON.parse(fs.readFileSync(path.join(root,'replay-manifest.json')))]));
  const runs=['run-dbc2adf273d4','run-double-attempt','run-grok-3routes'];
  const samples=Number(process.env.STATIC_BENCH_SAMPLES||3);
  assert.ok(Number.isInteger(samples)&&samples>=1&&samples<=10);
  for(const manifest of Object.values(manifests))for(const run of runs)assert.ok(manifest.runs[run],'missing benchmark recording '+run);
  const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json','.gz':'application/gzip'};
  const server=http.createServer((req,res)=>{
    try{
      const parts=decodeURIComponent(new URL(req.url,'http://localhost').pathname).split('/'),root=roots[parts[1]];
      if(!root){res.writeHead(404).end();return;}
      const file=fs.realpathSync(path.resolve(root,parts.slice(2).join('/'))),relative=path.relative(root,file);
      if(relative.startsWith('..')||path.isAbsolute(relative)){res.writeHead(403).end();return;}
      const stat=fs.statSync(file);if(!stat.isFile()){res.writeHead(404).end();return;}
      res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Content-Length':stat.size,'Cache-Control':'public, max-age=60'});
      fs.createReadStream(file).pipe(res);
    }catch{res.writeHead(404).end();}
  });
  let browser;
  try{
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
    const origin='http://127.0.0.1:'+server.address().port;
    const report={schema_version:'agentprovenance.static_load_benchmark/v1',measured_at:new Date().toISOString(),environment:{platform:os.platform(),arch:os.arch(),cpu:os.cpus()[0]?.model,system_memory_bytes:os.totalmem(),browser:browser.version(),viewport:{width:1440,height:1060},transport:'loopback HTTP, no HTTP compression; stored gzip assets unchanged',cache:'cold=new browser context; warm=reload in the same context, max-age=60',memory:'retained JS heap after forced GC, not peak process memory'},commits:{before:manifests.before.commit,after:manifests.after.commit},measurements:[]};
    for(const run of runs)for(let sample=0;sample<samples;sample++)for(const side of ['before','after']){
      const context=await browser.newContext({viewport:report.environment.viewport,locale:'en-US'});
      try{
        const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
        page.on('request',request=>{if(new URL(request.url()).origin!==origin)errors.push('unexpected external request');});
        const session=await context.newCDPSession(page);await session.send('Performance.enable');
        for(const cache of ['cold','warm']){
          if(cache==='cold')await page.goto(`${origin}/${side}/en/replay.html?live=0&run=${encodeURIComponent(run)}`,{waitUntil:'domcontentloaded'});
          else await page.reload({waitUntil:'domcontentloaded'});
          await page.waitForFunction(()=>window._lensManifest&&document.querySelector('#dag svg'));
          await page.evaluate(id=>AgentProvReplay.query('/api/context/overview?run='+encodeURIComponent(id)),run);
          assert.equal(await page.locator('#loaderror').isHidden(),true);assert.deepEqual(errors,[]);
          const result=await page.evaluate(()=>{
            const entries=[...performance.getEntriesByType('navigation'),...performance.getEntriesByType('resource')];
            return {ready_ms:performance.now(),transferred_bytes:entries.reduce((n,r)=>n+r.transferSize,0),resource_body_bytes:entries.reduce((n,r)=>n+r.decodedBodySize,0),requests:entries.length,resources:entries.map(r=>({path:new URL(r.name).pathname,transfer:r.transferSize,body:r.decodedBodySize})),nodes:window._lensManifest.nodes.length};
          });
          await session.send('HeapProfiler.collectGarbage');
          const metrics=await session.send('Performance.getMetrics');
          result.retained_js_heap_bytes=metrics.metrics.find(m=>m.name==='JSHeapUsedSize').value;
          report.measurements.push({run,side,sample,cache,...result});
        }
      }finally{await context.close();}
      process.stderr.write(`${side} ${run} sample ${sample+1}/${samples}\n`);
    }
    const median=values=>{const sorted=[...values].sort((a,b)=>a-b),mid=Math.floor(sorted.length/2);return sorted.length%2?sorted[mid]:(sorted[mid-1]+sorted[mid])/2;};
    report.summary=[];
    for(const run of runs)for(const side of ['before','after'])for(const cache of ['cold','warm']){
      const rows=report.measurements.filter(r=>r.run===run&&r.side===side&&r.cache===cache),entry={run,side,cache,samples:rows.length};
      for(const key of ['ready_ms','transferred_bytes','resource_body_bytes','retained_js_heap_bytes'])entry[key]=median(rows.map(row=>row[key]));
      report.summary.push(entry);
    }
    process.stdout.write(JSON.stringify(report,null,2)+'\n');
  }finally{
    if(browser)await browser.close();
    await new Promise(resolve=>server.close(resolve));
  }
}
main().catch(error=>{console.error(error);process.exitCode=1;});
