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
 const catalog={schema_version:'agentprovenance.static_replay/v1',runs:{run:{context,artifacts}},summaries:[]};
 files.set('/site/replay-manifest.json',Buffer.from(JSON.stringify(catalog)));
 const setup=()=>{const box={window:{},document:{querySelector:()=>({content:'/site/'})},location:new URL('https://example.test/site/en/replay.html'),URL,URLSearchParams,Map,Set,TextEncoder,TextDecoder,structuredClone,Response,DecompressionStream,crypto:webcrypto,btoa,atob,fetch:async url=>{const body=files.get(new URL(url).pathname);return new Response(body||'missing',{status:body?200:404});}};vm.runInNewContext(source,box);return box.window.AgentProvReplay;};
 const reader=setup();
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
 files.delete(path);await assert.rejects(()=>setup().query('/api/context/content?run=run&ref=saved'),/HTTP 404/);
 files.set(path,gunzipSync(good));
 assert.equal((await setup().query('/api/context/content?run=run&ref=saved&limit=4')).content,'xxxx');
 files.set(path,good);
 console.log('Static reader: UTF-8 paging, unavailable content, invalid ranges, run scope and integrity checks passed.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
