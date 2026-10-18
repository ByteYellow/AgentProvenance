// Pure display-model checks; no source records or graph edges are rewritten.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const scope = {window:{}};
for(const name of ['workspace.js','context.js','search.js','search-engine.js','compare.js','compare-engine.js','replay.js']){
  new vm.Script(fs.readFileSync(new URL('../internal/dashboard/'+name,import.meta.url),'utf8'),{filename:name});
}
vm.runInNewContext(fs.readFileSync(new URL('../internal/dashboard/workspace.js',import.meta.url),'utf8'),scope);
const directory = scope.window.AgentWorkspaceUI.sessionDirectory;
const report = (id,session,parent = '',harness = 'codex',channel = 'transcript') => ({source:{id,harness,channel,session_id:session,parent_session_id:parent},status:'ok'});
const data = {coverage:[report('a','parent'),report('b','child','parent'),report('c','child','parent','codex','hooks'),report('d','parent','','claude'),report('e','orphan','elsewhere'),report('f',''),report('g','fake','','launch','processing'),report('h','fake','','codex','discovery'),report('i','fake','','launch','runtime_correlation')],has_more_sources:true};
const before = JSON.stringify(data), result = directory(data);
assert.equal(result.sessions.length,4,'harness namespace separates same-named sessions');
assert.equal(result.sessions[1].reports.length,2,'multiple sources remain individually readable');
assert.equal(result.sessions[1].relation,'linked');
assert.equal(result.sessions[result.sessions[1].target].harness,'codex','parent stays in its harness namespace');
assert.equal(result.sessions[3].relation,'missing','no invented cross-run link');
assert.equal(result.unassigned.length,1);
assert.equal(result.limited,true);
assert.equal(JSON.stringify(data),before,'evidence remains unchanged');
assert.equal(directory({coverage:[report('a','child','missing'),report('b','missing','','claude')]}).sessions[0].relation,'missing');
assert.equal(directory({coverage:[report('a','same','same')]}).sessions[0].relation,'self');
assert.equal(directory({coverage:[report('a','child','p1'),report('b','child','p2')]}).sessions[0].relation,'conflicting');
const cyclic = directory({coverage:[report('a','a','b'),report('b','b','a')]});
assert.ok(cyclic.sessions.every(s=>s.relation==='cycle'));
assert.equal(directory({coverage:[report('a','id','','unknown')]}).unassigned.length,1);
assert.equal(directory({coverage:[report('same','id'),report('same','id')]}).sessions[0].reports.length,1);
assert.equal(directory({coverage:[{source:{harness:'unknown'},status:'legacy_not_recorded'}]}).sessions.length,0);
assert.equal(directory({}).sessions.length,0);
console.log('session directory identity and parent-relation checks passed');
