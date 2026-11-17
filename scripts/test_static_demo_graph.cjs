const assert = require('node:assert/strict');
const {viewNodes} = require('./accept_static_demo.cjs');

(async () => {
  const nodes = [{id:'call',kind:'tool_call'}, {id:'file',kind:'artifact'}, {id:'other',kind:'process'}];
  const index = {graph:{path:'data/graph.json.gz'}};
  const shared = {schema_version:'agentprovenance.replay_lens_view/v2',manifest:{nodes:null},node_indexes:[1,0]};
  const read = async ref => {
    assert.deepEqual(ref,index.graph);
    return {schema_version:'agentprovenance.replay_graph/v1',nodes};
  };
  const expected = [nodes[1],nodes[0]];
  assert.deepEqual(await viewNodes(index,shared,read),expected);
  assert.deepEqual(await viewNodes({}, {manifest:{nodes:expected}},read),expected);
  for(const bad of [[-1],[nodes.length],[0.5],null]) {
    await assert.rejects(()=>viewNodes(index,{...shared,node_indexes:bad},read),{code:'ERR_ASSERTION'});
  }
  await assert.rejects(()=>viewNodes({},shared,read),{code:'ERR_ASSERTION'});
  await assert.rejects(()=>viewNodes(index,{...shared,schema_version:'future'},read),{code:'ERR_ASSERTION'});
  console.log('Static acceptance: legacy and shared views enumerate the same focus nodes; invalid references fail.');
})().catch(error=>{console.error(error);process.exitCode=1;});
