// A display-only projection must neither rewrite evidence nor infer run loss
// from node counters. Browser checks cover the disclosure controls and labels.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const scope = {window:{}};
vm.runInNewContext(fs.readFileSync(new URL('../internal/dashboard/context.js', import.meta.url), 'utf8'), scope);
const sections = scope.window.AgentContextUI.coverageSections;
const value = {
  coverage:[
    {source:{harness:'launch',channel:'runtime_correlation'},status:'partial',counts:{stored:0}},
    {source:{harness:'deepseek',channel:'transcript'},status:'ok',counts:{stored:73}},
    {source:{harness:'deepseek',channel:'discovery'},status:'ok'},
  ],
  runtime_coverage:{capture:{status:'partial',run_dropped_events:null,node_pending_events:235,node_counter_delta:{invalid:3},run_impact:'unknown'}},
};
const original = JSON.stringify(value), result = sections(value);
assert.equal(result.sessions.length,1);
assert.equal(result.discoveries.length,1);
assert.equal(result.associations.length,1);
assert.ok(result.sessions.every(r => r.source.harness === 'deepseek'));
assert.equal(result.runtime.label,'Capture completeness unconfirmed');
assert.equal(result.runtime.state,'partial');
assert.equal(JSON.stringify(value),original,'display leaves all evidence and counters unchanged');

const presentation = capture => sections({runtime_coverage:{capture}}).runtime;
assert.equal(presentation({status:'ok',run_dropped_events:2}).label,'Run event loss confirmed');
assert.equal(presentation({status:'ok',run_dropped_events:2}).state,'failed','confirmed loss cannot be hidden by a stale OK state');
assert.equal(presentation({status:'partial',run_dropped_events:0}).state,'partial','zero attributed losses do not clear other coverage gaps');
assert.equal(presentation({status:'ok',run_impact:'no_node_loss_reported'}).label,'No reported capture issues');
assert.ok(presentation({status:'ok'}).message.includes('completeness is not established'));
assert.equal(presentation({status:'failed'}).state,'failed');
assert.equal(presentation({status:'partial',issues:[],limitations:['tls_discovery_partial']}).state,'limited');
assert.equal(presentation({status:'partial',issues:['node_backlog_at_seal'],limitations:['tls_discovery_partial']}).state,'partial');
assert.ok(presentation({status:'partial',issues:['node_backlog_at_seal']}).message.includes('not an ongoing confirmation task'));
assert.equal(presentation({status:'disabled'}).label,'Not enabled');
assert.equal(presentation({status:'no_input'}).message,'Kernel sensor unavailable');
assert.equal(sections({}).runtime.state,'legacy_not_recorded');
assert.equal(sections({}).sessions.length,0);
assert.equal(sections({coverage:[{source:{harness:'unknown'},status:'legacy_not_recorded'}]}).sessions.length,1);
console.log('context coverage presentation checks passed');
