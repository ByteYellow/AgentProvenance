import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';

const env={window:{},TextEncoder,URLSearchParams,structuredClone,document:{}};
vm.runInNewContext(fs.readFileSync(new URL('../internal/dashboard/search-engine.js',import.meta.url),'utf8'),env);
const {create}=env.window.AgentEvidenceSearch;
const source=(id,body,category='tools')=>({id,node:id,category,label:id,content:{state:'reader'},body});
function reader(sources,hook=()=>{}) {
  const calls=[];
  const get=async(url,{signal}={})=>{
    signal?.throwIfAborted();calls.push(url);await hook(url,signal);
    signal?.throwIfAborted();
    const u=new URL(url,'http://fixture'),p=u.searchParams;
    if(u.pathname==='/api/search/sources'){
      const at=Number(p.get('cursor')||0),has_more=at+50<sources.length;
      return {schema_version:'agentprovenance.search_sources/v1',run_id:'run',sources:sources.slice(at,at+50).map(({body,...s})=>s),has_more,next_cursor:has_more?String(at+50):''};
    }
    const s=sources.find(s=>s.id===p.get('node')),offset=Number(p.get('offset')),limit=Number(p.get('limit'));
    assert.equal(limit,65536,'body reads stay bounded');
    if(s.body==null)return {kind:'unavailable',content_state:'omitted',total_bytes:null};
    const buf=Buffer.from(s.body);let end=Math.min(buf.length,offset+limit);
    while(end<buf.length && (buf[end]&0xc0)===0x80)end--;
    return {content:buf.subarray(offset,end).toString(),offset,next_offset:end,total_bytes:buf.length,has_more:end<buf.length,sha256:crypto.createHash('sha256').update(buf).digest('hex'),content_state:'stored'};
  };
  return {get,calls};
}
const scope={run:'run'};
let data=[source('long','header\n'+'字'.repeat(900000)+'\nPermission Denied: report.txt\nend')];
let r=reader(data),result=await create({query:'permission denied',scope,get:r.get}).next();
assert.equal(result.hits.length,1);assert.ok(result.hits[0].offset>2600000);
assert.ok(result.hits[0].excerpt.text.includes('Permission Denied'));
assert.ok(r.calls.length>40,'the scanner reaches the saved tail beyond the preview');
assert.equal(result.has_more,false);

data=[source('boundary','x'.repeat(65532)+'needle-at-boundary\nnext')];
r=reader(data);result=await create({query:'needle-at-boundary',scope,get:r.get}).next();
assert.equal(result.hits.length,1);assert.ok(result.hits[0].offset<=65532);
assert.equal(result.hits[0].excerpt.text.slice(result.hits[0].excerpt.start,result.hits[0].excerpt.end),'needle-at-boundary');

r=reader([source('literal','actual .* literal'),source('not-a-regexp','actual any literal')]);
result=await create({query:'.*',scope,get:r.get}).next();assert.equal(result.hits.length,1);
r=reader([source('unicode','İstanbul and 𠮷野家')]);
result=await create({query:'𠮷野家',scope,get:r.get}).next();assert.equal(result.hits.length,1);

data=Array.from({length:123},(_,n)=>source('s'+n,'needle unique '+n));
r=reader(data);const paged=create({query:'needle',scope,get:r.get});
const ids=[];for(let n=0;n<3;n++){result=await paged.next();assert.ok(result.hits.length<=50);ids.push(...result.hits.map(h=>h.source.id));}
assert.equal(ids.length,123);assert.equal(new Set(ids).size,123);assert.equal(result.has_more,false);

r=reader([source('one','same saved needle'),source('two','same saved needle'),source('three','different needle')]);
result=await create({query:'needle',scope,get:r.get}).next();
assert.equal(result.hits.length,2);assert.equal(result.hits[0].sources.length,2,'duplicate bodies retain both sources');

r=reader([source('report.txt',null,'files'),source('other',null),source('empty','')]);
result=await create({query:'report.txt',scope,get:r.get}).next();
assert.equal(result.hits.length,1);assert.equal(result.hits[0].matched_in,'metadata');assert.equal(result.stats.unavailable,2);assert.equal(result.error,undefined);
r=reader([{id:'policy-result',category:'tools',label:'Tool result',content:{state:'omitted',reason:'capture_policy'}},source('missing',null)]);
result=await create({query:'Tool result',scope,get:r.get}).next();
assert.equal(result.stats.policy_omitted,1);assert.equal(result.stats.unavailable,1);
assert.equal(result.hits[0].reason,'capture_policy');assert.equal(result.hits[0].matched_in,'metadata');
assert.ok(!r.calls.some(path=>path.includes('policy-result')),'omitted body has no fabricated reader request');
r=reader([source('a','needle','messages'),source('b','needle','tools')]);
result=await create({query:'needle',category:'tools',scope,get:r.get}).next();
assert.equal(result.hits.length,1);assert.equal(result.hits[0].source.id,'b');assert.equal(result.stats.excluded,1);

const abort=new AbortController();let blocked=false;
r=reader([source('first','needle'),source('second','x'.repeat(100000)+'needle')],url=>{if(url.includes('node=second')&&!blocked){blocked=true;abort.abort();}});
const cancelled=create({query:'needle',scope,get:r.get});
result=await cancelled.next({signal:abort.signal});assert.equal(result.cancelled,true);assert.equal(result.hits[0].source.id,'first');assert.equal(result.has_more,true);
const stoppedAt=r.calls.length;await new Promise(r=>setTimeout(r,5));assert.equal(r.calls.length,stoppedAt,'cancel stops fetching');
result=await cancelled.next();assert.equal(result.hits[0].source.id,'second','resume retries the interrupted source');

let fail=true;r=reader([source('a','needle')],url=>{if(url.includes('/artifact')&&fail){fail=false;throw new Error('reader offline');}});
const retry=create({query:'needle',scope,get:r.get});result=await retry.next();assert.equal(result.error,'reader offline');assert.equal(result.has_more,true);
result=await retry.next();assert.equal(result.hits.length,1);
for(const query of ['', ' ', 'x'.repeat(257)])assert.throws(()=>create({query,scope,get:r.get}));
r=reader([source('changing','x'.repeat(70000)+'needle')]);
const stableGet=r.get;
result=await create({query:'needle',scope,get:async(url,options)=>{
  const page=await stableGet(url,options);
  if(page.offset>0)page.sha256='changed';
  return page;
}}).next();
assert.equal(result.hits.length,0);assert.match(result.error,/changed during search/);
console.log('search engine: long UTF-8 tail, chunk boundary, literal matching, paging, duplicate references, omitted/empty bodies, filters, cancellation and retry passed');
