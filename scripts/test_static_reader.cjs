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
 const context=save({entries:[],latest:[],nodes:{},links:{},content:{saved:parts},comparisons:{}});
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
 files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
 const setup=()=>{const box={window:{},document:{querySelector:()=>({content:'/site/'})},location:new URL('https://example.test/site/en/replay.html'),URL,URLSearchParams,Map,Set,TextEncoder,TextDecoder,structuredClone,Response,DecompressionStream,crypto:webcrypto,btoa,atob,fetch:async url=>{const body=files.get(new URL(url).pathname);return new Response(body||'missing',{status:body?200:404});}};vm.runInNewContext(source,box);return box.window.AgentProvReplay;};
 const reader=setup();
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
 // Old exports without an index rule retain v1. New exports freeze v2, and
 // mismatched or unknown versions fail instead of silently reinterpreting data.
 for(const version of [1,2]){
  const rule='agentprov.audit_lifecycle_operation/v'+version;
  const item={event_id:'audit-1',decision:'ERRNO',operation:{status:version===1?'inferred':'unassociated'}};
  const data=save({schema_version:'agentprovenance.audit_associations/v1',run_id:'run',rule,status:'complete',issues:[],items:[item]});
  catalog.runs.run.audit={schema_version:'agentprovenance.replay_audit/v1',pages:[{first:'audit-1',last:'audit-1',data}]};
  if(version===2)catalog.runs.run.audit.rule=rule;
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
 console.log('Static reader: UTF-8 paging, process lifetime focus, legacy replay, search/compare scopes and cancellation, run scope and integrity checks passed.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
