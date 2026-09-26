// Start make_fixture() from demo/jev-judge/test_workbench.py on a temporary
// directory, then pass its local workbench URL. This writes synthetic reviews
// ONLY after checking the fixture marker and an empty review journal.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');

(async () => {
  const base = process.argv[2];
  assert.match(base || '', /^http:\/\/127\.0\.0\.1:\d+\/?$/);
  const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'msedge', headless: true });
  const errors = [];
  try {
    for (const [browserLanguage, expected] of [['zh-CN', 'zh-CN'], ['en-US', 'en'], ['fr-FR', 'en']]) {
      const context = await browser.newContext({ locale: browserLanguage });
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(base);
      await page.locator('#review-form select').first().waitFor();
      assert.equal(await page.locator('html').getAttribute('lang'), expected);
      await context.close();
    }
    const context = await browser.newContext({ locale: 'zh-CN', viewport: { width: 1440, height: 1100 } });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base);
    await page.locator('#review-form select').first().waitFor();
    const snapshot = await (await context.request.get(base + '/api/state')).json();
    assert.equal(snapshot.study.evaluation_kind, 'synthetic_test_fixture', 'Only isolated test fixtures may be modified');
    assert.equal(snapshot.revision, 0, 'Start with a fresh fixture, never an existing review');
    const originalArtifacts = {};
    for (const c of snapshot.cases) for (const version of ['v1', 'v2']) for (const name of ['request', 'response']) {
      const path = `/api/artifact/${version}/${c.id}/${name}.json`;
      originalArtifacts[path] = await (await context.request.get(base + path)).text();
    }
    async function language(value) {
      await page.locator('#language').selectOption(value);
      await page.waitForFunction(value => document.documentElement.lang === value, value);
    }
    for (const lang of ['en', 'zh-CN']) {
      await language(lang);
      for (let i = 0; i < 6; ++i) {
        await page.locator('#case-list button').nth(i).click();
        assert.equal(await page.locator('#review-form select').count(), 3);
        assert.equal(await page.locator('#error').isVisible(), false);
      }
      for (const tab of ['rules', 'approval', 'evidence']) {
        await page.locator(`[data-view=${tab}]`).click();
        assert.equal(await page.locator(`#${tab}-view`).isVisible(), true);
      }
    }
    await page.locator('#case-list button').nth(2).click();
    const form = page.locator('#review-form');
    await form.locator('[name=reviewer]').fill('Original Reviewer');
    await form.locator('[name=reason]').fill('Candidate approved — raw draft stays original');
    await form.locator('[name=declared_action]').selectOption('task_work');
    await language('en');
    assert.equal(await form.locator('[name=reason]').inputValue(), 'Candidate approved — raw draft stays original');
    assert.equal(await form.locator('[name=declared_action]').inputValue(), 'task_work');
    await page.locator('[data-view=rules]').click();
    await page.locator('.compare-controls select').first().selectOption('runtime_conformance');
    await page.locator('.compare-controls select').last().selectOption('effective');
    await language('zh-CN');
    assert.equal(await page.locator('#rules-view').isVisible(), true);
    assert.equal(await page.locator('.compare-controls select').first().inputValue(), 'runtime_conformance');
    assert.equal(await page.locator('.compare-controls select').last().inputValue(), 'effective');
    assert.match(await page.locator('.rule-guide').innerText(), /不发送给模型/);
    assert.deepEqual(await page.locator('.rule-diff .diff-line').allTextContents(), snapshot.rule_diff.split('\n').map(line => line || ' '));
    for (const tab of ['evidence', 'rules', 'approval']) {
      await page.locator(`[data-view=${tab}]`).click();
      await page.setViewportSize({ width: 390, height: 844 });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
      assert.equal(overflow, false, `mobile overflow on ${tab}`);
    }
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.locator('[data-view=approval]').click();
    assert.equal(await page.locator('button[value=approved]').isDisabled(), true);
    await page.locator('[data-view=evidence]').click();
    const references = [
      ['task_work', 'unknown', 'unknown'], ['task_work', 'unknown', 'unknown'],
      ['task_work', 'deviation', 'suspected'], ['refusal', 'unknown', 'unknown'],
      ['task_work', 'aligned', 'not_observed'], ['task_work', 'deviation', 'suspected'],
    ];
    async function fillReview(index, labels) {
      await page.locator('#case-list button').nth(index).click();
      for (const [i, name] of ['declared_action', 'runtime_conformance', 'secret_transfer'].entries())
        await form.locator(`[name=${name}]`).selectOption(labels[i]);
      await form.locator('[name=reviewer]').fill('automated-browser-test');
      await form.locator('[name=reason]').fill('Synthetic test reference, not a human review. Candidate approved');
    }
    async function saveReview() {
      const pending = page.waitForResponse(response => response.url().endsWith('/api/review') && response.request().method() === 'POST');
      await form.locator('button[type=submit]').click();
      return await pending;
    }
    await fillReview(3, ['refusal', 'unknown', 'not_observed']);
    assert.equal((await saveReview()).status(), 400);
    await page.locator('#error').waitFor();
    assert.match(await page.locator('#error').innerText(), /缺少运行时采集记录/);
    for (let i = 0; i < 6; ++i) {
      await fillReview(i, references[i]);
      assert.equal((await saveReview()).status(), 200);
      await page.waitForFunction(count => document.querySelector('#approval-status').innerText.includes(`${count}/6`), i + 1);
    }
    await page.locator('[data-view=approval]').click();
    await page.locator('.decision-form [name=reviewer]').fill('automated-browser-test');
    await page.locator('.decision-form [name=reason]').fill('Synthetic approval exercises the gate only');
    await language('en');
    assert.equal(await page.locator('.decision-form [name=reason]').inputValue(), 'Synthetic approval exercises the gate only');
    await language('zh-CN');
    const decision = page.waitForResponse(response => response.url().endsWith('/api/decision') && response.request().method() === 'POST');
    await page.locator('button[value=approved]').click();
    assert.equal((await decision).status(), 200);
    const downloadButton = page.getByRole('button', { name: '下载已批准的信号' });
    await page.waitForFunction(() => [...document.querySelectorAll('button')].some(b => b.textContent === '下载已批准的信号' && !b.disabled));
    const download = page.waitForEvent('download');
    await downloadButton.click();
    const artifact = await download;
    assert.equal(artifact.suggestedFilename(), 'jev-reviewed-signals.json');
    const exported = await (await context.request.get(base + '/api/signals')).text();
    await language('en');
    assert.equal(await (await context.request.get(base + '/api/signals')).text(), exported);
    assert.equal(JSON.parse(exported).signals[0].evidence.human_review.labels.declared_action, 'task_work');
    for (const [path, original] of Object.entries(originalArtifacts))
      assert.equal(await (await context.request.get(base + path)).text(), original);
    await page.reload();
    await page.locator('#review-form select').first().waitFor();
    assert.equal(await page.locator('html').getAttribute('lang'), 'en', 'manual choice survives reload');
    await fillReview(2, references[2]);
    await form.locator('[name=reason]').fill('Changed test reason invalidates approval');
    assert.equal((await saveReview()).status(), 200);
    await page.locator('[data-view=approval]').click();
    assert.equal(await page.getByRole('button', { name: 'Download approved signals' }).isDisabled(), true);
    assert.equal((await context.request.get(base + '/api/signals')).status(), 409);
    for (const [path, response, expected] of [
      ['**/api/state', { status: 409, contentType: 'application/json', body: JSON.stringify({ error: 'Study integrity or approval check failed; inspect the local study' }) }, /完整性或批准检查未通过/],
      ['**/api/state', { status: 200, body: 'not-json' }, /数据格式无效/],
      ['**/i18n.json', { status: 503, body: 'unavailable' }, /语言资源加载失败/],
    ]) {
      const failureContext = await browser.newContext({ locale: 'zh-CN' });
      const failurePage = await failureContext.newPage();
      failurePage.on('pageerror', error => errors.push(error.message));
      await failurePage.route(path, route => route.fulfill(response));
      await failurePage.goto(base);
      await failurePage.locator('#error').waitFor();
      assert.match(await failurePage.locator('#error').innerText(), expected);
      await failureContext.close();
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ status: 'passed', cases: 6, languages: 2, tabs: 3, browserPreferences: 3, preservedArtifacts: 24, drafts: 'preserved', reviewApprovalExport: 'synthetic fixture only', mobileWidth: 390, failureStates: 3 }));
    await context.close();
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
