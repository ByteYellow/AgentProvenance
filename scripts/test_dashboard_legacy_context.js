// Run through playwright-cli against `agentprov demo --no-browser`.
// Exercises the six unchanged historical bundles, without patching responses.
async (page) => {
  const runs = ['run-snake-supervised', 'run-double-attempt', 'a2a-demo', 'claude-demo', 'run-grok-exfil', 'run-grok-3routes'];
  const checks = [], errors = [];
  const check = (ok, name) => { if (!ok) throw new Error(name); checks.push(name); };
  const base = await page.evaluate(() => location.origin);
  const context = page.context();
  for (const run of runs) {
    for (const lang of ['en', 'zh-CN']) {
      page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      const label = run + '/' + lang;
      const legacy = lang === 'en' ? 'Not recorded in this historical run' : '此历史执行未记录';
      await page.setViewportSize({width:1440,height:1050});
      await page.goto(base + '/?run=' + run + '&live=0&lang=' + lang);
      await page.waitForFunction(text => document.querySelector('#context-summary')?.textContent.includes(text), legacy);
      await page.waitForFunction(() => window._lensManifest?.query && document.querySelector('#dag svg'));
      check(await page.locator('#runsel').inputValue() === run, label + ': requested historical run');
      check(!await page.locator('#context-fold').evaluate(el => el.open), label + ': context initially collapsed');
      for (const id of ['graphcard','siglist','focusedevidence','outboundcard','tl','ptree','egtbl','compliancecard']) {
        check(await page.locator('#'+id).count() === 1, label + ': retains ' + id);
      }
      const lenses = await page.locator('#lenssel option').evaluateAll(nodes => nodes.map(n => n.value));
      check(lenses.length === 12, label + ': twelve existing lenses selectable');
      for (const lens of lenses) {
        await page.locator('#lenssel').selectOption(lens);
        await page.waitForFunction(value => window._lensManifest?.lens === value &&
          (document.querySelector('#dag svg') || (window._lensManifest?.query.node_count === 0 && document.querySelector('#dag .empty'))), lens);
        check(await page.locator('#loaderror').isHidden(), label + ': rendered ' + lens);
      }
      await page.locator('#context-fold > summary').click();
      await page.locator('#context-tab-coverage').click();
      await page.waitForSelector('[data-runtime-coverage]');
      check((await page.locator('#context-body').innerText()).includes(legacy), label + ': historical context coverage remains unknown');
      check(await page.locator('#context-body [data-entry]').count() === 0, label + ': no fabricated session entries');
      await page.locator('#lenssel').selectOption(run.includes('grok') ? 'network-egress' : run === 'a2a-demo' || run === 'claude-demo' ? 'substrate' : 'orchestration');
      await page.waitForFunction(() => window._lensManifest?.lens === document.querySelector('#lenssel')?.value);
      await page.locator('#graphcard').scrollIntoViewIfNeeded();
      await page.screenshot({path:'output/playwright/legacy-' + run + '-' + lang + '.png'});
      await page.setViewportSize({width:390,height:844});
      check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), label + ': no mobile page overflow');
      await page.close();
    }
  }
  check(errors.length === 0, 'no unhandled browser errors: ' + errors.join('; '));
  return {source:'six original historical bundles', renderedLensChecks:144, checks:checks.length, passed:checks};
}
