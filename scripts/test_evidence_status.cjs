// Exercise the shipped Workbench verification helpers without a server or browser dependency.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const src = fs.readFileSync('internal/dashboard/workbench.js', 'utf8');
const section = (start, end) => {
  const first = src.indexOf(start), last = src.indexOf(end, first);
  assert(first >= 0 && last > first, `missing Workbench helper: ${start}`);
  return src.slice(first, last);
};

const badge = {className: '', textContent: ''};
const box = {
  $: () => badge,
  L: (_zh, en) => en,
  IS_REPLAY: true,
};
vm.createContext(box);
vm.runInContext(section('function graphVerification(v)', 'function openDeliveryModal()'), box);

for (const [status, label, tone] of [
  ['ok', 'Graph integrity passed', 'ok'],
  ['subset', 'Selected evidence only', 'warn'],
  ['failed', 'Graph integrity check failed', 'bad'],
  ['deferred', 'Graph check deferred', 'neutral'],
  ['unavailable', 'Graph check unavailable', 'neutral'],
  ['unknown_future', 'Graph integrity not verified', 'neutral'],
  [undefined, 'Graph integrity not verified', 'neutral'],
]) {
  const res = box.graphVerification(status ? {status} : null);
  assert.equal(res.label, label);
  assert.equal(res.tone, tone);
  box.showVerifyBadge(status ? {status} : null);
  assert.equal(badge.className, 'wb-verify ' + tone);
  assert.ok(badge.textContent.includes(label), badge.textContent);
}
console.log('Evidence status: explicit graph verification states and unverified fallback passed.');
