// Run with playwright-cli against TestContextDashboardFixture's local server.
// These are explicit synthetic options, not evidence of live sensor coverage.
async (page) => {
  const checks = [], errors = [];
  const check = (ok, name) => { if (!ok) throw new Error(name); checks.push(name); };
  const base = new URL(page.url()).origin;
  page = await page.context().newPage();
  page.on('pageerror', error => errors.push(error.message));
  for (const name of ['basic', 'detailed', 'unknown']) {
    const run = name === 'unknown' ? 'ui-fixture' : 'ui-retention-' + name;
    await page.setViewportSize({width:1440, height:1050});
    await page.goto(base + '/?run=' + run + '&lang=en&live=0');
    await page.waitForFunction(run => window._lensManifest?.run_id === run, run);
    await page.locator('[data-context-open="coverage"]').click();
    const panel = page.locator('[data-capture-retention]');
    await panel.waitFor();
    check(!await panel.locator('details').evaluate(el => el.open), name + ': settings initially folded');
    await panel.locator('summary').click();
    const values = await panel.locator('[data-independent-capture] dd').allTextContents();
    const expected = name === 'unknown' ? Array(4).fill('Not recorded') : [
      'Not enabled', name === 'basic' ? 'Not enabled' : 'Enabled',
      name === 'basic' ? 'Hash and short preview only' : 'Retained when captured', 'Enabled',
    ];
    check(JSON.stringify(values) === JSON.stringify(expected), name + ': explicit independent values');
    check(await panel.innerText().then(text => text.includes(name === 'unknown'
      ? 'Independent settings were not recorded for this run.' : 'Recorded at launch; capture results are shown below.')),
      name + ': source and coverage distinction');
    for (const action of ['search', 'compare', 'export']) {
      check(await page.locator('[data-investigation="' + action + '"]').isVisible(), name + ': ' + action + ' available');
    }
    await panel.scrollIntoViewIfNeeded();
    await page.screenshot({path:'output/playwright/settings-' + name + '-desktop.png'});
    await page.setViewportSize({width:390, height:844});
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), name + ': mobile fits');
    await page.screenshot({path:'output/playwright/settings-' + name + '-mobile.png'});
    await page.getByRole('link', {name:'中文', exact:true}).click();
    await page.waitForFunction(run => window._lensManifest?.run_id === run, run);
    await page.locator('[data-context-open="coverage"]').click();
    if (!await panel.locator('details').evaluate(el => el.open)) await panel.locator('summary').click();
    check(await panel.locator('[data-independent-capture]').innerText().then(text =>
      text.includes('工作区快照与变更文件正文') && text.includes('TLS 完整正文') && !text.includes('Not recorded')),
      name + ': Chinese option names and values');
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), name + ': Chinese mobile fits');
    await panel.scrollIntoViewIfNeeded();
    await page.screenshot({path:'output/playwright/settings-' + name + '-zh-mobile.png'});
    if (name === 'unknown') continue;
    await page.setViewportSize({width:1440, height:1050});
    await page.locator('[data-investigation="export"]').click();
    await page.locator('#export-ack').check();
    const prepared = page.waitForResponse(r => r.url().endsWith('/api/replay/previews') && r.request().method() === 'POST');
    await page.locator('#export-prepare').click();
    const response = await prepared;
    check(response.status() === 201, name + ': export prepared');
    const result = await response.json(), settings = result.inventory.capture_settings;
    check(settings?.sensor_mode === 'off' && settings.workspace_snapshot === (name === 'detailed') &&
      settings.tls_full_body === (name === 'detailed') && settings.agent_context === true && !!settings.ref,
      name + ': exact settings in frozen inventory');
    const downloading = page.waitForEvent('download');
    await page.locator('#export-download').click();
    const download = await downloading;
    await download.saveAs('output/playwright/settings-' + name + '.zip');
    check(await download.failure() === null, name + ': ZIP downloaded');
    await page.locator('#export-discard').click();
    await page.waitForFunction(() => document.querySelector('#export-result').hidden);
    await page.locator('#export-close').click();
  }
  check(errors.length === 0, 'no page errors: ' + errors.join('; '));
  await page.close();
  return {source:'synthetic capture options; no live sensor claim', checks:checks.length, passed:checks};
}
