// Byte paging, integrity failures and run isolation for the static reader.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {gzipSync,gunzipSync}=require('node:zlib');
const {createHash,webcrypto}=require('node:crypto');
const source=fs.readFileSync('internal/dashboard/replay.js','utf8');
async function main(){
 const files=new Map(), hash=b=>createHash('sha256').update(b).digest('hex');
 const save=value=>{const b=Buffer.from(JSON.stringify(value)),sha=hash(b),path='data/'+sha+'.json.gz';files.set('/site/'+path,gzipSync(b));return {path,sha256:sha,bytes:b.length};};
 const original='x'.repeat(65533)+'中文😃'+'z'.repeat(80000),bytes=Buffer.from(original);
 const parts={offsets:[],pages:[]};
 for(let offset=0;offset<bytes.length;){let end=Math.min(offset+65536,bytes.length);while(end<bytes.length&&(bytes[end]&0xc0)===0x80)end--;parts.offsets.push(offset);parts.pages.push(save({content:bytes.subarray(offset,end).toString(),offset,next_offset:end,total_bytes:bytes.length,has_more:end<bytes.length,integrity:'verified'}));offset=end;}
 const unavailable={offsets:[0],pages:[save({content_state:'legacy_not_recorded',total_bytes:null,has_more:false,offset:0,next_offset:0})]};
 const raster=Buffer.alloc(180000);for(let i=0;i<raster.length;i++)raster[i]=i%251;
 const rasterRef='sha256:'+hash(Buffer.from('attachment manifest'));
 const attachment={offsets:[],pages:[]};
 for(let offset=0;offset<raster.length;offset+=65536){
  const end=Math.min(offset+65536,raster.length);attachment.offsets.push(offset);
  attachment.pages.push(save({schema_version:'agentprovenance.raster_attachment/v1',run_id:'run',ref:rasterRef,media_type:'image/png',encoding:'base64',data:raster.subarray(offset,end).toString('base64'),offset,next_offset:end,total_bytes:raster.length,has_more:end<raster.length,sha256:hash(raster)}));
 }
 const harRef='sha256:'+hash(Buffer.from('har manifest')),har=Buffer.from(JSON.stringify({log:{version:'1.2',entries:[],comment:'x'.repeat(150000)}})),harPages={offsets:[],pages:[]};
 for(let offset=0;offset<har.length;offset+=65536){const end=Math.min(offset+65536,har.length);harPages.offsets.push(offset);harPages.pages.push(save({schema_version:'agentprovenance.har_attachment/v1',run_id:'run',ref:harRef,media_type:'application/har+json',encoding:'base64',data:har.subarray(offset,end).toString('base64'),offset,next_offset:end,total_bytes:har.length,has_more:end<har.length,sha256:hash(har)}));}
 const contextValue={entries:[],latest:[],nodes:{},links:{},content:{saved:parts},attachments:{[rasterRef]:attachment,[harRef]:harPages},comparisons:{}};
 const context=save(contextValue);
 const artifacts=save({'en/body/file':parts,'en/body/unavailable':unavailable});
 const oldNode='runtime_process/pid/42',firstNode='runtime_process/instance/boot:42:100',secondNode='runtime_process/instance/boot:42:200';
 const events=save([{id:'first',pid:42},{id:'second',pid:42},{id:'last',pid:42},{id:'old',pid:42},{id:'new-parent-number',pid:99}]);
 const catalog={schema_version:'agentprovenance.static_replay/v1',runs:{run:{context,artifacts,events,filters:{},event_refs:{[firstNode]:['first','last'],[secondNode]:['second'],[oldNode]:['old'],'runtime_process/pid/99':[]}},legacy:{events,filters:{},event_refs:{}}},summaries:[]};
 const relation=save({relations:[{kind:'message_request',from:{run_id:'run',harness:'codex',session_id:'root',available:true},to:{run_ids:['legacy','not-exported'],harness:'codex',session_id:'worker',available:true}},{kind:'parent',from:{run_id:'not-exported',harness:'codex',session_id:'parent',available:true},to:{run_id:'run',harness:'codex',session_id:'root',available:true}}]});
 catalog.runs.run.sessions={'["codex","root"]':{relations:{'':relation}}};
 catalog.runs.legacy.sessions={'["codex","worker"]':{}};
 const emptyNode={id:'overview/agent_network',kind:'overview'};
 const emptyNodes=save({[emptyNode.id]:emptyNode});
 const emptyView=save({manifest:{nodes:[emptyNode],edges:[],query:{layout_hint:'overview',raw_event_count:0}},focus_edges:[],priorities:[],total_nodes:1,total_edges:0});
 catalog.runs.run.sessions['["codex","empty"]']={lenses:save({views:{'default/summary':emptyView},nodes:emptyNodes,focus_nodes:emptyNodes,present:null}),event_ids:null};
 const search=save({schema_version:'agentprovenance.search_sources/v1',run_id:'run',sources:[{id:'entry/saved',category:'messages',content:{ref:'saved',state:'stored'}}],has_more:false});
 catalog.runs.run.search={'["",""]':{'':search},'["codex","root"]':{'':search}};
 const comparison=save({schema_version:'agentprovenance.comparison_records/v1',run_id:'run',records:[],issues:[],sources_read:1,has_more:false});
 catalog.runs.run.compare={'':comparison};
 const executionA={identity:{source:{run_id:'run',harness:'claude',session_id:'root',tool_call_id:'call-a'},local_run_id:'worker'},basis:'authenticated_admission',issues:['execution_run_not_selected']};
 const executionB={identity:{source:{run_id:'run',harness:'codex',session_id:'root',tool_call_id:'call-b'},local_run_id:'worker-b'},basis:'authenticated_delivery',issues:[]};
 catalog.runs.run.execution_links={schema_version:'agentprovenance.replay_execution_links/v1',directions:{outgoing:[{count:1,data:save([executionA])},{count:1,data:save([executionB])}],incoming:[]}};
 const captureRecords=[...Array.from({length:258},(_,i)=>'event/'+String(i).padStart(3,'0')),'event/\uffff','event/\u{10000}'].sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map(id=>({id,evidence_kind:'event',evidence_ref:'runtime_event/'+id.slice(6),loss:[{name:'drops',scope:'collector',value:'9007199254740993',basis:'saved'}]}));
 const capturePages=[];
 for(let offset=0;offset<captureRecords.length;offset+=50){const values=captureRecords.slice(offset,offset+50);capturePages.push({count:values.length,first:values[0].id,last:values.at(-1).id,data:save(values)});}
 catalog.runs.run.capture_manifest={schema_version:'agentprovenance.replay_capture_manifest/v1',scope:'selected_evidence',pages:capturePages};
 files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
 const setup=()=>{const box={window:{},document:{querySelector:()=>({content:'/site/'})},location:new URL('https://example.test/site/en/replay.html'),URL,URLSearchParams,Map,Set,TextEncoder,TextDecoder,structuredClone,Response,DecompressionStream,crypto:webcrypto,btoa,atob,fetch:async url=>{const body=files.get(new URL(url).pathname);return new Response(body||'missing',{status:body?200:404});}};vm.runInNewContext(source,box);return box.window.AgentProvReplay;};
 const reader=setup();
 for(const limit of [1,17,50,200]){
  let records=[],cursor='';
  do{const page=await reader.query('/api/capture-manifest?run=run&limit='+limit+'&cursor='+encodeURIComponent(cursor));assert.equal(page.selection_scope,'selected_evidence');records.push(...page.records);cursor=page.next_cursor||'';assert.equal(page.has_more,records.length<captureRecords.length);}while(cursor);
  assert.deepEqual(records,captureRecords);
 }
 const captureFirst=await reader.query('/api/capture-manifest?run=run&limit=1');
 const captureSecond=await reader.query('/api/capture-manifest?run=run&limit=200&cursor='+captureFirst.next_cursor);
 assert.deepEqual(Array.from(captureSecond.records),captureRecords.slice(1,201));
 for(const query of ['run=legacy','run=run&limit=0','run=run&limit=201','run=run&limit=','run=run&cursor=wrong','run=run&session=x','run=run&run=run'])await assert.rejects(()=>reader.query('/api/capture-manifest?'+query));
 const foreignCursor=Buffer.from(JSON.stringify({version:'agentprovenance.capture_manifest/v1',run_id:'legacy',kind:'event',id:'001'})).toString('base64url');
 await assert.rejects(()=>reader.query('/api/capture-manifest?run=run&cursor='+foreignCursor));
 for(const offset of [0,65535,131070,har.length])for(const limit of [1,7193,262144]){
  const value=await reader.query('/api/context/attachment?run=run&ref='+harRef+'&offset='+offset+'&limit='+limit);
  assert.equal(value.media_type,'application/har+json');assert.equal(value.schema_version,'agentprovenance.har_attachment/v1');
  assert.deepEqual(Buffer.from(value.data,'base64'),har.subarray(offset,Math.min(offset+limit,har.length)));
 }
 for(const offset of [0,17,65535,65536,131070,raster.length])for(const limit of [1,7193,65536,262144]){
  const value=await reader.query('/api/context/attachment?run=run&ref='+rasterRef+'&offset='+offset+'&limit='+limit);
  const end=Math.min(offset+limit,raster.length);assert.deepEqual(Buffer.from(value.data,'base64'),raster.subarray(offset,end));
  assert.equal(value.next_offset,end);assert.equal(value.has_more,end<raster.length);assert.equal(value.sha256,hash(raster));
 }
 await assert.rejects(()=>reader.query('/api/context/attachment?run=run&ref=absent'));
 for(const query of ['run=legacy','run=other','run=run&offset=-1','run=run&offset=180001','run=run&limit=0','run=run&limit=262145'])
  await assert.rejects(()=>reader.query('/api/context/attachment?ref='+rasterRef+'&'+query));
 const attachmentOriginal=attachment.pages[1];
 for(const mutation of [{run_id:'other'},{media_type:'image/svg+xml'},{media_type:'application/har+json',schema_version:'agentprovenance.har_attachment/v1'},{offset:65537},{next_offset:65539},{total_bytes:8388609},{encoding:'url'},{data:'%%invalid%%'}]){
  const originalPage=JSON.parse(gunzipSync(files.get('/site/'+attachmentOriginal.path)));
  attachment.pages[1]=save({...originalPage,...mutation});catalog.runs.run.context=save(contextValue);
  files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
  await assert.rejects(()=>setup().query('/api/context/attachment?run=run&ref='+rasterRef+'&offset=65530&limit=20'));
 }
 attachment.pages[1]=attachmentOriginal;catalog.runs.run.context=context;
 files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
 const executionFirst=await reader.query('/api/execution-links?run=run&harness=codex&limit=1');
 assert.equal(executionFirst.links.length,0);assert.equal(executionFirst.scanned,1);assert.equal(executionFirst.has_more,true);
 const executionNext=await reader.query('/api/execution-links?run=run&harness=codex&limit=1&cursor='+executionFirst.next_cursor);
 assert.equal(executionNext.links[0].identity.source.tool_call_id,'call-b');assert.equal(executionNext.has_more,false);
 const executionAll=await reader.query('/api/execution-links?run=run');
 assert.equal(executionAll.links.length,2);assert.equal(executionAll.links[0].issues[0],'execution_run_not_selected');
 assert.equal((await reader.query('/api/execution-links?run=run&direction=incoming')).links.length,0);
 for(const query of ['run=legacy','run=run&direction=sideways','run=run&limit=0','run=run&limit=101','run=run&cursor=wrong','run=run&harness=%00','run=run&session=%20root','run=run&run=run','run=run&harness=claude&cursor='+executionFirst.next_cursor,'run=run&direction=incoming&cursor='+executionFirst.next_cursor])await assert.rejects(()=>reader.query('/api/execution-links?'+query));
 const emptyFocus=await reader.query('/api/lens?run=run&harness=codex&session=empty&focus=overview%2Fagent_network');
 assert.equal(emptyFocus.nodes[0].id,emptyNode.id);
 assert.equal((await reader.query('/api/events?run=run&harness=codex&session=empty')).total,0);
 await assert.rejects(()=>reader.query('/api/lens?run=run&harness=codex&session=empty&focus=outside'),/outside the recorded session/);
 assert.equal((await reader.query('/api/search/sources?run=run')).sources[0].content.ref,'saved');
 assert.equal((await reader.query('/api/compare/records?run=run')).sources_read,1);
 for(const query of ['run=legacy','run=run&cursor=wrong','run=not-exported'])await assert.rejects(()=>reader.query('/api/compare/records?'+query),/not included|not found/);
 for(const scope of ['&harness=','&session=root','&harness=codex&session=root'])await assert.rejects(()=>reader.query('/api/compare/records?run=run'+scope),/session filter/);
 assert.equal((await reader.query('/api/search/sources?run=run&harness=codex&session=root')).sources.length,1);
 for(const query of ['run=legacy','run=run&cursor=wrong','run=run&harness=claude&session=root'])await assert.rejects(()=>reader.query('/api/search/sources?'+query),/not included/);
 const stopped=new AbortController();stopped.abort();
 await assert.rejects(()=>reader.query('/api/search/sources?run=run',{signal:stopped.signal}),{name:'AbortError'});
 await assert.rejects(()=>reader.query('/api/compare/records?run=run',{signal:stopped.signal}),{name:'AbortError'});
 await assert.rejects(()=>reader.query('/api/execution-links?run=run',{signal:stopped.signal}),{name:'AbortError'});
 const stopExecution=new AbortController(),pendingExecution=setup().query('/api/execution-links?run=run',{signal:stopExecution.signal});
 stopExecution.abort();await assert.rejects(()=>pendingExecution,{name:'AbortError'});
 assert.equal((await reader.query('/api/execution-links?run=run')).links.length,2);
 const interrupted=new AbortController(),pending=setup().query('/api/search/sources?run=run',{signal:interrupted.signal});
 interrupted.abort();await assert.rejects(()=>pending,{name:'AbortError'});
 assert.equal((await reader.query('/api/search/sources?run=run')).sources.length,1);
 const relationships=await reader.query('/api/context/session-relations?run=run&harness=codex&session=root&limit=50');
 assert.deepEqual(Array.from(relationships.relations[0].to.run_ids),['legacy']);
 assert.equal(relationships.relations[0].to.available,true);
 assert.equal(relationships.relations[1].from.available,false);
 await assert.rejects(()=>reader.query('/api/context/session-relations?run=run&harness=claude&session=root'),/not included/);
 await assert.rejects(()=>reader.query('/api/context/session-relations?run=run&harness=codex&session=root&cursor=wrong'),/not included/);
 await assert.rejects(()=>reader.query('/api/context/session-relations?run=run&harness=codex&session=root&limit=1'),/limit of 50/);
 for(const [node,ids] of [[firstNode,['first','last']],[secondNode,['second']],[oldNode,['old']],['runtime_process/pid/99',[]],['runtime_process/instance/unknown',[]]]){
  const result=await reader.query('/api/events?run=run&focus='+encodeURIComponent(node));
  assert.deepEqual(Array.from(result.events,e=>e.id),ids);assert.equal(result.total,ids.length);
 }
 assert.equal((await reader.query('/api/events?run=run&focus='+encodeURIComponent(firstNode)+'&offset=1&limit=1')).events[0].id,'last');
 const firstRefs=await reader.query('/api/events?run=run&ref='+encodeURIComponent(firstNode));
 assert.deepEqual(Array.from(firstRefs.events,e=>e.id),['first','last']);
 assert.equal((await reader.query('/api/events?run=legacy&focus='+encodeURIComponent(oldNode))).total,4);
 for(const offset of [0,17,65529,65533,65536,65539,65543,120000,bytes.length])for(const limit of [4,17,65536,262144]){
  const result=await reader.query('/api/context/content?run=run&ref=saved&offset='+offset+'&limit='+limit);
  let end=Math.min(offset+limit,bytes.length);while(end<bytes.length&&(bytes[end]&0xc0)===0x80)end--;
  assert.equal(result.content,bytes.subarray(offset,end).toString());assert.equal(result.next_offset,end);assert.equal(result.has_more,end<bytes.length);
 }
 for(const query of ['offset=-1','offset=65534','offset=999999','limit=3','limit=262145','limit=no'])await assert.rejects(()=>reader.query('/api/context/content?run=run&ref=saved&'+query));
 assert.equal((await reader.query('/api/artifact?run=run&node=unavailable')).total_bytes,null);
 await assert.rejects(()=>reader.query('/api/context/content?run=another&ref=saved'),/run was not found/);
 await assert.rejects(()=>reader.query('/api/context/content?run=run&ref=absent'),/not found/);
 const first=parts.pages[0],path='/site/'+first.path,good=files.get(path);
 files.set(path,gzipSync(Buffer.from('0'.repeat(first.bytes))));
 await assert.rejects(()=>setup().query('/api/context/content?run=run&ref=saved'),/integrity check failed/);
 files.set(path,gzipSync(Buffer.from('0'.repeat(first.bytes+1))));
 await assert.rejects(()=>setup().query('/api/context/content?run=run&ref=saved'),/size check failed/);
 files.delete(path);await assert.rejects(()=>setup().query('/api/context/content?run=run&ref=saved'),/HTTP 404/);
 files.set(path,gunzipSync(good));
 assert.equal((await setup().query('/api/context/content?run=run&ref=saved&limit=4')).content,'xxxx');
 files.set(path,good);
 const originalExecution=catalog.runs.run.execution_links.directions.outgoing[0];
 for(const shard of [{...originalExecution,count:2},{...originalExecution,count:0},{count:1,data:save([{...executionA,identity:{...executionA.identity,source:{...executionA.identity.source,run_id:'other'}}}])}]){
  catalog.runs.run.execution_links.directions.outgoing[0]=shard;
  files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
  await assert.rejects(()=>setup().query('/api/execution-links?run=run'),/shard|does not match/);
 }
 catalog.runs.run.execution_links.directions.outgoing[0]=originalExecution;
 files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
 const executionPath='/site/'+originalExecution.data.path,executionBytes=files.get(executionPath);
 files.set(executionPath,gzipSync(Buffer.from('x'.repeat(originalExecution.data.bytes))));
 await assert.rejects(()=>setup().query('/api/execution-links?run=run'),/integrity check failed/);
 files.set(executionPath,executionBytes);
 // Old exports without an index rule retain v1. New exports freeze v3, and
 // mismatched or unknown versions fail instead of silently reinterpreting data.
 for(const version of [1,2,3]){
  const rule='agentprov.audit_lifecycle_operation/v'+version;
  const item={event_id:'audit-1',decision:'ERRNO',operation:{status:version===1?'inferred':'unassociated'}};
  const data=save({schema_version:'agentprovenance.audit_associations/v1',run_id:'run',rule,status:'complete',issues:[],items:[item]});
  catalog.runs.run.audit={schema_version:'agentprovenance.replay_audit/v1',pages:[{first:'audit-1',last:'audit-1',data}]};
  if(version>=2)catalog.runs.run.audit.rule=rule;
  files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
  const report=await setup().query('/api/audit/associations?run=run');
  assert.equal(report.rule,rule);assert.equal(report.items[0].operation.status,item.operation.status);
  catalog.runs.run.audit.rule='agentprov.audit_lifecycle_operation/v'+(version===1?2:1);
  files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
  await assert.rejects(()=>setup().query('/api/audit/associations?run=run'),/does not match/);
 }
 catalog.runs.run.audit.rule='agentprov.audit_lifecycle_operation/v999';
 files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
 await assert.rejects(()=>setup().query('/api/audit/associations?run=run'),/Unsupported|unsupported/);
 await catalogChecks();
 console.log('Static reader: UTF-8 paging, process lifetime focus, legacy replay, search/compare scopes and cancellation, lazy run catalogs, run scope and integrity checks passed.');
}

async function catalogChecks(){
 const files=new Map(),requests=[];
 const save=value=>{const bytes=Buffer.from(JSON.stringify(value)),sha=createHash('sha256').update(bytes).digest('hex'),path='data/'+sha+'.json.gz';files.set('/site/'+path,gzipSync(bytes));return {path,sha256:sha,bytes:bytes.length};};
 const relations=save({relations:[
  {from:{run_id:'a',harness:'codex',session_id:'root',available:true},to:{run_ids:['b','excluded'],harness:'codex',session_id:'child',available:true}},
  {from:{run_id:'missing',harness:'codex',session_id:'root',available:true},to:{run_id:'a',harness:'codex',session_id:'missing',available:true}}
 ]});
 const runs={
  a:{api:{summary:save({run_id:'a',value:'A'})},sessions:{'["codex","root"]':{relations:{'':relations}}}},
  b:{api:{summary:save({run_id:'b',value:'B'})},sessions:{'["codex","child"]':{}}},
  archived:{api:{summary:save({run_id:'archived',value:'historical'})},sessions:{}}
 };
 const catalog={schema_version:'agentprovenance.static_catalog/v1',summaries:Object.keys(runs).map(run=>({run})),frameworks:save([{id:'built-in',control_count:1}]),run_indexes:{}};
 for(const [run_id,run] of Object.entries(runs))catalog.run_indexes[run_id]=save({schema_version:'agentprovenance.replay_run/v1',run_id,run});
 const compact='/site/replay-catalog.json',legacy='/site/replay-manifest.json';
 const publish=()=>files.set(compact,Buffer.from(JSON.stringify(catalog)));
 publish();
 const setup=(options={})=>{
  const window={};
  if(options.offline)window.AgentProvOffline={manifest:()=>({schema_version:'agentprovenance.static_replay/v1',runs,summaries:catalog.summaries}),read:ref=>files.get('/site/'+ref.path)};
  const box={window,document:{querySelector:()=>({content:'/site/'})},location:new URL('https://example.test/site/en/replay.html'),URL,URLSearchParams,Map,Set,TextEncoder,TextDecoder,structuredClone,Response,DecompressionStream,crypto:webcrypto,btoa,atob,fetch:async url=>{const path=new URL(url).pathname;requests.push(path);if(options.fetch)return options.fetch(path);const bytes=files.get(path);return new Response(bytes||'missing',{status:bytes?200:404});}};
  vm.runInNewContext(source,box);return window.AgentProvReplay;
 };
 const reader=setup();
 assert.equal((await reader.query('/api/runs')).length,3);
 assert.deepEqual(requests,[compact],'listing runs must not load per-run indexes or the legacy manifest');
 assert.equal((await reader.query('/api/frameworks'))[0].id,'built-in');
 assert.deepEqual(requests,[compact,'/site/'+catalog.frameworks.path],'global frameworks must not load an unrelated run index');
 const result=await Promise.all([reader.query('/api/summary?run=a'),reader.query('/api/summary?run=a')]);
 assert.equal(result[0].value,'A');assert.equal(result[1].value,'A');
 assert.equal(requests.filter(path=>path==='/site/'+catalog.run_indexes.a.path).length,1);
 assert.ok(!requests.includes('/site/'+catalog.run_indexes.b.path));
 assert.ok(!requests.includes('/site/'+catalog.run_indexes.archived.path));
 const linked=await reader.query('/api/context/session-relations?run=a&harness=codex&session=root');
 assert.deepEqual(Array.from(linked.relations[0].to.run_ids),['b']);
 assert.equal(linked.relations[1].from.available,false);assert.equal(linked.relations[1].to.available,false);
 assert.equal((await reader.query('/api/summary?run=b')).value,'B');
 assert.equal((await reader.query('/api/summary?run=a')).value,'A');
 assert.equal(requests.filter(path=>path==='/site/'+catalog.run_indexes.b.path).length,1);
 assert.ok(!requests.includes('/site/'+catalog.run_indexes.archived.path),'unrelated archives must stay unloaded');
 assert.ok(!requests.includes(legacy));
 for(const id of ['absent','__proto__','constructor'])await assert.rejects(()=>reader.query('/api/summary?run='+id),/not found/);
 const good=catalog.run_indexes.a;
 for(const value of [{schema_version:'unknown',run_id:'a',run:runs.a},{schema_version:'agentprovenance.replay_run/v1',run_id:'b',run:runs.b},{schema_version:'agentprovenance.replay_run/v1',run_id:'a',run:null}]){
  catalog.run_indexes.a=save(value);publish();
  await assert.rejects(()=>setup().query('/api/summary?run=a'),/run index/);
 }
 catalog.run_indexes.a=good;publish();
 const goodBytes=files.get('/site/'+good.path);
 files.set('/site/'+good.path,gzipSync(Buffer.from('x'.repeat(good.bytes))));
 await assert.rejects(()=>setup().query('/api/summary?run=a'),/integrity check/);
 files.delete('/site/'+good.path);
 const recovering=setup();await assert.rejects(()=>recovering.query('/api/summary?run=a'),/HTTP 404/);
 files.set('/site/'+good.path,goodBytes);assert.equal((await recovering.query('/api/summary?run=a')).value,'A');
 files.set(legacy,Buffer.from(JSON.stringify({schema_version:'agentprovenance.static_replay/v1',runs,summaries:catalog.summaries})));
 for(const [status,body] of [[403,'forbidden'],[500,'unavailable'],[200,'{broken'],[200,'{"schema_version":"unknown"}']]){
  requests.length=0;
  await assert.rejects(()=>setup({fetch:path=>new Response(path===compact?body:files.get(path),{status:path===compact?status:200})}).query('/api/runs'));
  assert.deepEqual(requests,[compact],'an invalid current catalog must not silently use an older manifest');
 }
 files.delete(compact);requests.length=0;
 assert.equal((await setup().query('/api/summary?run=a')).value,'A');
 assert.deepEqual(requests.slice(0,2),[compact,legacy]);
 requests.length=0;assert.equal((await setup({offline:true}).query('/api/summary?run=a')).value,'A');
 assert.deepEqual(requests,[],'file:// exports must stay entirely offline');
 publish();requests.length=0;
 const stopped=new AbortController();stopped.abort();
 await assert.rejects(()=>setup().query('/api/summary?run=a',{signal:stopped.signal}),{name:'AbortError'});
 assert.deepEqual(requests,[]);
}
main().catch(error=>{console.error(error);process.exitCode=1;});
