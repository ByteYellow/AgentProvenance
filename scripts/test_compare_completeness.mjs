import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const env={URLSearchParams,DOMException};
vm.runInNewContext(fs.readFileSync(new URL('../internal/dashboard/compare-engine.js',import.meta.url),'utf8'),env);
const {load,build}=env.AgentRunCompare;
const record=(key,extra={})=>({key,dimension:'configuration',label:key,operation:'recorded_configuration',value:{present:true,sha256:key,preview:JSON.stringify(key)},evidence:{id:key},...extra});
const full=records=>({records,complete:true,issues:[]});
const page=(records,more=false,extra={})=>({schema_version:'agentprovenance.comparison_records/v1',run_id:'a',records,issues:[],sources_read:50,has_more:more,next_cursor:more?'next':'',...extra});
const fixture=pages=>{
  let calls=0;
  return {get:async url=>url.includes('/overview')?{}:pages[calls++],calls:()=>calls};
};

test('record cap: common evidence beyond A limit is unknown in both orientations',async()=>{
  const common=record('shared-beyond-limit');
  const source=fixture([page(Array.from({length:50000},(_,i)=>record('a'+i)),true),page([common])]);
  const a=await load({run:'a',get:source.get}),b=full([common]);
  assert.equal(source.calls(),1);
  assert.equal(a.records.length,50000);
  assert.equal(a.complete,false);
  for(const [left,right,missing] of [[a,b,'a'],[b,a,'b']]){
    const result=build(left,right),row=result.rows.find(r=>r.key===common.key);
    assert.equal(row.status,'unknown','an unscanned key must not become a definite one-sided difference');
    assert.equal(row.sides[missing].enumerationComplete,false);
    assert.equal(row.sides[missing].readable,false);
    assert.ok(row.sides[missing].reasons.includes('comparison_record_limit'));
    assert.equal(result.counts.configuration.differences,0,'conservative incomplete scan contributes no definite differences');
  }
});

test('source cap: empty pages still leave unseen common keys unknown',async()=>{
  const common=record('shared-beyond-sources');
  const source=fixture([page([],true,{sources_read:100000}),page([common])]);
  const a=await load({run:'a',get:source.get});
  assert.equal(source.calls(),1);
  assert.equal(a.sources,100000);
  assert.equal(a.complete,false);
  for(const [left,right] of [[a,full([common])],[full([common]),a]]){
    const result=build(left,right);
    assert.equal(result.rows[0].status,'unknown');
    assert.equal(result.counts.configuration.differences,0);
  }
  assert.equal(a.issues.at(-1).code,'comparison_source_limit');
});

test('last-page overflow is incomplete but an exact terminal boundary is complete',async()=>{
  const records=Array.from({length:50001},(_,i)=>record('r'+i));
  const a=await load({run:'a',get:fixture([page(records)]).get});
  assert.equal(a.complete,false);
  assert.equal(build(a,full([records.at(-1)])).rows.find(r=>r.key===records.at(-1).key).status,'unknown');
  const exact=await load({run:'a',get:fixture([page(records.slice(0,50000),false,{sources_read:100000})]).get});
  assert.equal(exact.complete,true);
  assert.equal(exact.issues.length,0);
  assert.equal(build(exact,full([])).counts.configuration.differences,50000);
});

test('full scan retains genuine one-sided evidence and distinct unavailable reasons',()=>{
  const withheld=record('omitted',{value:null,partial:true,evidence:{id:'omitted',content:{reason:'capture_policy'}}});
  const missing=record('missing',{value:null,evidence:{id:'missing',content:{reason:'missing_body'}}});
  const a={...full([withheld,missing]),issues:[{dimension:'configuration',source_id:'omitted',code:'capture_policy'}]};
  const b=full([record('retained')]);
  for(const [left,right,status] of [[a,b,'only_b'],[b,a,'only_a']]){
    const result=build(left,right);
    assert.equal(result.rows.find(r=>r.key==='retained').status,status);
    assert.equal(result.counts.configuration.differences,1);
    assert.equal(result.counts.configuration.unknown,2);
  }
  const result=build(a,b);
  assert.ok(result.rows.find(r=>r.key==='omitted').sides.a.reasons.includes('capture_policy'));
  assert.ok(result.rows.find(r=>r.key==='missing').sides.a.reasons.includes('missing_body'));
  assert.equal(result.rows.find(r=>r.key==='omitted').sides.a.reasons.includes('comparison_record_limit'),false);
  assert.equal(result.rows.find(r=>r.key==='missing').sides.a.reasons.includes('capture_policy'),false);
  assert.equal(result.rows.find(r=>r.key==='retained').sides.a.enumerationComplete,true);
  const partial=build(full([record('partial',{partial:true})]),full([])).rows[0];
  assert.equal(partial.status,'unknown','a partial value is not a definite one-sided difference');
  assert.equal(partial.sides.a.readable,true,'readable evidence and completeness are separate');
  const bodyGap=build({...full([record('file',{dimension:'files',value:null})]),issues:[{dimension:'files',source_id:'file',code:'file_body_not_available'}]},full([]));
  assert.equal(bodyGap.rows[0].status,'unknown');
  assert.ok(bodyGap.rows[0].sides.a.reasons.includes('file_body_not_available'),'server missing-body issue is preserved');
  assert.equal(bodyGap.counts.files.differences,0);
});

test('pagination preserves counts and cancellation never returns a completed partial scan',async()=>{
  const progress=[],source=fixture([page([record('first')],true),page([record('last')])]);
  const a=await load({run:'a',get:source.get,onProgress:n=>progress.push(n)});
  assert.equal(source.calls(),2);
  assert.equal(a.records.length,2);
  assert.equal(a.sources,100);
  assert.equal(a.complete,true);
  assert.deepEqual(progress,[50,100]);
  assert.equal(build(a,full([record('last')])).counts.configuration.differences,1);
  const abort=new AbortController();
  await assert.rejects(load({run:'a',signal:abort.signal,get:async url=>{
    if(url.includes('/overview'))return {};
    abort.abort();
    return page([record('late')]);
  }}),{name:'AbortError'},'a response completing after cancellation must not publish results');
});
