// Shared graph encoding must produce exactly the legacy reader's query results.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {gzipSync}=require('node:zlib'),{createHash,webcrypto}=require('node:crypto');
const source=['digest.js','replay.js'].map(name=>fs.readFileSync('internal/dashboard/'+name,'utf8')).join('\n');
(async()=>{
  const files=new Map();
  const save=value=>{const b=Buffer.from(JSON.stringify(value)),sha=createHash('sha256').update(b).digest('hex'),path='data/'+sha+'.json.gz';files.set(path,gzipSync(b));return {path,sha256:sha,bytes:b.length};};
  const a={id:'a',kind:'browser',label:'Summary',risk:'high',trust_origin:'application_observed'},b={id:'b',kind:'request',label:'Request'},variant={...a,label:'Expanded'};
  const edge={from_id:'a',to_id:'b',edge_type:'request',evidence_refs:['object/observed']},derived={...edge,derived:true,derivation_rule:'saved-rule/v1'};
  const views={};
  for(const detail of ['summary','expanded','raw'])views['default/'+detail]={manifest:{run_id:'run',nodes:[detail==='expanded'?variant:a,b],edges:[edge],derived_edges:[derived],query:{layout_hint:'graph',raw_event_count:2,node_count:2,edge_count:2,derived_edge_count:1},overlays:[{target_id:'a',kind:'risk',label:'high',severity:'high'}]},focus_edges:[derived,edge],priorities:[7,2],total_nodes:2,total_edges:2};
  const nodes=save({a,b}),graph=save({schema_version:'agentprovenance.replay_graph/v1',nodes:[a,b,variant],edges:[edge,derived]});
  const make=(shared,alter=x=>x)=>{
    const index={nodes,focus_nodes:nodes,present:['a','b'],views:{}};
    if(shared)index.graph=graph;
    for(const [key,view] of Object.entries(views)){
      const encoded=shared?{schema_version:'agentprovenance.replay_lens_view/v2',manifest:{...view.manifest,nodes:null,edges:null,derived_edges:undefined},node_indexes:[key.endsWith('expanded')?2:0,1],edge_indexes:[0],derived_indexes:[1],focus_indexes:[1,0],priorities:view.priorities,total_nodes:2,total_edges:2}:view;
      index.views[key]=save(alter(encoded));
    }
    const lenses=save(index),catalog={schema_version:'agentprovenance.static_replay/v1',runs:{run:{lenses,sessions:{'["browser","one"]':{lenses}}}},summaries:[]};
    const box={window:{AgentProvOffline:{manifest:async()=>catalog,read:async ref=>files.get(ref.path)}},document:{querySelector:()=>({content:'file:///replay/'})},location:new URL('file:///replay/index.html'),URL,URLSearchParams,Map,Set,TextEncoder,TextDecoder,structuredClone,Response,DecompressionStream,crypto:webcrypto,btoa,atob};
    vm.runInNewContext(source,box);return box.window.AgentProvReplay;
  };
  const legacy=make(false),compact=make(true),plain=x=>JSON.parse(JSON.stringify(x));let queries=0;
  for(const detail of ['summary','expanded','raw'])for(const focus of ['','a','b'])for(const scope of ['','&harness=browser&session=one'])for(const overlay of ['','&overlay=risk&overlay=trust']){
    const q='/api/lens?run=run&detail='+detail+'&focus='+focus+scope+overlay;
    const want=plain(await legacy.query(q)),got=plain(await compact.query(q));assert.deepEqual(got,want);queries++;
    got.nodes[0].label='mutated client';assert.deepEqual(plain(await compact.query(q)),want,'cached objects remain immutable');
  }
  for(const invalid of [v=>({...v,node_indexes:[-1]}),v=>({...v,edge_indexes:[2]}),v=>({...v,node_indexes:[0.5]}),v=>({...v,focus_indexes:[0],priorities:[]}),v=>({...v,schema_version:'unknown'})]){
    await assert.rejects(()=>make(true,invalid).query('/api/lens?run=run'),/Graph|graph/);
  }
  await assert.rejects(()=>compact.query('/api/lens?run=run&harness=browser&session=one&focus=outside'),/outside/);
  console.log(JSON.stringify({sharedGraphPassed:true,equivalentQueries:queries,legacy:true,offline:true,invalidReferencesRejected:5}));
})().catch(e=>{console.error(e);process.exitCode=1;});
