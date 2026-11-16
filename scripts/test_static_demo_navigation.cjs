const assert=require('node:assert/strict');
const {assertNavigationParity}=require('./accept_static_demo.cjs');
const native='http://127.0.0.1:8123',site='http://127.0.0.1:8456/AgentProvenance/';
let checks=0;
for(const lang of ['en','zh-CN']){
  const options={native,site,lang};
  const sources=['/demos/guide/start?lang='+lang,'/demos/docs/deepseek-context?lang='+lang,
    '/demos/guide/runtime-adapters?section=guest&lang='+lang+'#binding','/demos/guide/start?lang='+lang,
    'https://example.com/demos/guide/external','/demos/?lang='+lang];
  const links=[site+lang+'/guides/runtime-adapters.html?section=guest#binding',site+lang+'/demos/deepseek-context.html',site+lang+'/guides/start.html'];
  assert.equal(assertNavigationParity(sources,links,options).length,3);checks++;
  for(const [name,changed] of [
    ['missing link',links.slice(1)],
    ['extra link',[...links,site+lang+'/guides/unexpected.html']],
    ['same-count substitution',[...links.slice(1),site+lang+'/guides/unexpected.html']],
    ['extra wrong-language link',[...links,site+(lang==='en'?'zh-CN':'en')+'/guides/start.html']],
  ]){
    assert.throws(()=>assertNavigationParity(sources,changed,options),{code:'ERR_ASSERTION'},lang+': '+name);checks++;
  }
  const linkedPage='/demos/guide/kata-qemu-acceptance?lang='+lang;
  assert.throws(()=>assertNavigationParity([...sources,linkedPage],links,options),{code:'ERR_ASSERTION'});checks++;
  assert.equal(assertNavigationParity([...sources,linkedPage],[...links,site+lang+'/guides/kata-qemu-acceptance.html'],options).length,4);checks++;
}
console.log(JSON.stringify({checks,passed:true,coverage:'bilingual URL mapping, missing/extra links, same-count replacement, cross-language extras, and no Kata-specific exception'}));
