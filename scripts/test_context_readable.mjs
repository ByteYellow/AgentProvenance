// Pure display tests; the browser gate checks the actual controls and escaping.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const scope = {window:{}};
vm.runInNewContext(fs.readFileSync(new URL('../internal/dashboard/context.js', import.meta.url), 'utf8'), scope);
const format = scope.window.AgentContextUI.readableContent;
const entry = {kind:'tool_result',source:{harness:'deepseek'}};
const result = {
  message:{role:'tool',toolCallId:'call-1',content:[{type:'text',text:'line 1\nline 2\nRan 7 tests\nOK'}],isError:true},
  errorReason:'recorded diagnostic',fileDiffs:[{path:'report.py',patch:'+change'}],step:7,
};
const raw = JSON.stringify(result), projected = format(raw,entry);
assert.ok(projected.startsWith('line 1\nline 2\nRan 7 tests\nOK\n'));
for (const text of ['call-1','"isError": true','recorded diagnostic','report.py','+change','"step": 7']) assert.ok(projected.includes(text), text);
assert.equal(JSON.stringify(result),raw, 'display must not mutate the source');
assert.equal(format('[{"type":"text","text":"hello\\nworld"}]',{kind:'message'}),'hello\nworld');
for (const type of ['input_text','output_text']) {
  assert.equal(format(JSON.stringify([{type,text:'source message\nsecond line'}]),{kind:'message'}),'source message\nsecond line');
  assert.ok(format(JSON.stringify([{type,text:'source message',annotations:['retained']}]),{kind:'message'}).includes('retained'));
}
assert.equal(format('"escaped\\ntext"',{kind:'tool_result'}),'escaped\ntext');
assert.ok(format('{"cmd":"echo ok"}',{kind:'tool_call'}).includes('\n  "cmd": "echo ok"\n'));
assert.equal(format('plain output',entry),null);
assert.equal(format(raw.slice(0,-1),entry),null);
assert.equal(format('"'+ 'x'.repeat(65536) +'"',entry),null);
assert.equal(format('['.repeat(30)+'0'+']'.repeat(30),entry),null);
assert.equal(format('{"id":9007199254740993}',entry),null);
assert.equal(format('{"value":1e400}',entry),null);
const nonText = [{type:'image',data:'retained'}, {type:'text',text:'text with extra field',annotation:'keep'}];
const mixed = format(JSON.stringify(nonText),{kind:'message'});
for (const value of ['image','retained','annotation','keep']) assert.ok(mixed.includes(value));
assert.ok(format(JSON.stringify([{type:'text',text:'<img src=x onerror=alert(1)>'}]),{kind:'message'}).includes('<img'));
assert.ok(format(raw,{kind:'tool_result',source:{harness:'unknown'}}).includes('"content"'), 'unknown envelopes remain complete JSON');
console.log('context readable display checks passed');
