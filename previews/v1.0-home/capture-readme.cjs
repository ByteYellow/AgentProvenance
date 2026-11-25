// Capture public documentation from a built site, never from a live daemon.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

async function capture(page, home, lang, output) {
  const suffix = lang === 'en' ? '' : '-zh-CN';
  const save = async (name, subject = page) => {
    await page.evaluate(() => document.fonts.ready);
    await subject.screenshot({path: path.join(output, name + suffix + '.png'), animations: 'disabled'});
  };
  await page.goto(new URL('?lang=' + lang, home).href);
  await page.locator('.card[data-case=team] .stage-link img').waitFor();
  assert.equal(await page.locator('.card[data-case]').count(), 4);
  assert.equal(await page.locator('html').getAttribute('lang'), lang);
  const href = selector => page.locator(selector).first().evaluate(a => a.href);
  for (const selector of ['.top-nav a[href*="/guides/"]', '.card[data-case=team] a[href*="/demos/"]',
    '.card[data-case=team] .stage-link', 'footer a[href$="/library.html"],footer a[href$="/index.html"]']) {
    const link = await href(selector);
    const response = await page.request.head(link);
    assert.equal(response.status(), 200, link);
  }
  const compare = new URL(await href('.card[data-case=investigation] .stage-link'));
  const team = new URL(await href('.card[data-case=team] .stage-link'));
  const pairedA = compare.searchParams.get('compare_a'), pairedB = compare.searchParams.get('compare_b');
  assert.ok(pairedA && pairedB && pairedA !== pairedB);
  assert.equal(team.searchParams.get('run'), 'run-double-attempt');
  await page.locator('a[href="#featured"]').first().click();
  await save('demo-gallery', page.locator('#featured'));

  await page.goto(compare.href);
  const dialog = page.locator('#wb-compare-dlg[open]');
  const row = dialog.locator('details.cmp-row').filter({has: page.locator('summary strong', {hasText: /(^|\/)diagnostics\.json$/})}).first();
  const heading = row.locator(':scope > summary');
  await heading.waitFor();
  if (!await row.evaluate(el => el.open)) await heading.click();
  const sides = row.locator('.cmp-inline pre');
  await sides.nth(1).waitFor();
  assert.ok((await sides.nth(0).innerText()).trim() && (await sides.nth(1).innerText()).trim());
  assert.notEqual(await sides.nth(0).innerText(), await sides.nth(1).innerText());
  assert.equal(await dialog.locator('#cmp-a').inputValue(), pairedA);
  assert.equal(await dialog.locator('#cmp-b').inputValue(), pairedB);
  const [left, right] = await Promise.all([sides.nth(0).boundingBox(), sides.nth(1).boundingBox()]);
  assert.ok(right.x >= left.x + left.width - 1, 'Desktop comparison must show both columns');
  await save('workbench-compare', dialog);

  await page.goto(team.href);
  const dag = page.locator('#dag svg');
  async function checkGraphWidth() {
    const bounds = await dag.evaluate(svg => {
      const host = svg.parentElement, left = host.getBoundingClientRect().left + host.clientLeft;
      const frames = [...svg.querySelectorAll('[data-id] .frame')].map(n => n.getBoundingClientRect());
      return {count: frames.length, left: Math.min(...frames.map(r => r.left)) - left,
        right: Math.max(...frames.map(r => r.right)) - left, width: host.clientWidth,
        scale: svg.getScreenCTM().a};
    });
    assert.ok(bounds.count && bounds.left >= -1 && bounds.right <= bounds.width + 1,
      'Initial graph clips nodes: ' + JSON.stringify(bounds));
    assert.ok(bounds.scale >= 0.68, 'Desktop graph labels too small: ' + JSON.stringify(bounds));
  }
  await dag.getByText('alice', {exact:true}).first().waitFor();
  await dag.getByText('bob', {exact:true}).first().waitFor();
  const hint = page.locator('#page-tour-invite button');
  if (await hint.isVisible()) await hint.click();
  await checkGraphWidth();
  await save('workbench-team');

  const historical = new URL(team);
  historical.search = new URLSearchParams({run:'a2a-demo', lens:'substrate', live:'0'});
  await page.goto(historical.href);
  for (const id of ['368026', '368305']) await dag.locator('text').filter({hasText:id}).first().waitFor();
  if (await hint.isVisible()) await hint.click();
  await checkGraphWidth();
  await save('workbench-placement');

  historical.search = new URLSearchParams({run:'run-dbc2adf273d4', view:'session', live:'0'});
  await page.goto(historical.href);
  // The public DeepSeek recording contains a call and result with this same ID.
  const result = page.locator('#session-list .wb-card').filter({hasText:'call_00_ET_1nCD'})
    .filter({hasText:/tool_result|工具结果/});
  await result.locator('[data-read-entry]').click();
  const body = page.locator('#wb-info-body pre').first();
  await body.waitFor();
  assert.match(await body.innerText(), /Ran 7 tests/);
  await save('workbench-session', page.locator('#wb-info-dlg[open]'));
}

async function main() {
  const [url, output] = process.argv.slice(2);
  if (!url || !output) throw Error('Usage: node capture-readme.cjs LOCAL_SITE_URL OUTPUT_DIRECTORY');
  const home = new URL(url.endsWith('/') ? url : url + '/');
  assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(home.hostname));
  await fs.mkdir(output, {recursive:true});
  const browser = await chromium.launch(process.env.PLAYWRIGHT_CHANNEL ? {channel:process.env.PLAYWRIGHT_CHANNEL} : {});
  try {
    for (const lang of ['en', 'zh-CN']) {
      const ctx = await browser.newContext({viewport:{width:1440, height:900}, reducedMotion:'reduce',
        locale:lang, timezoneId:'UTC', deviceScaleFactor:1});
      await ctx.route('**/*', route => new URL(route.request().url()).origin === home.origin ? route.continue() : route.abort());
      const page = await ctx.newPage();
      const errors = [];
      page.on('pageerror', e => errors.push(e.message));
      await capture(page, home, lang, output);
      assert.deepEqual(errors, []);
      await ctx.close();
    }
  } finally { await browser.close(); }
}
main().catch(e => { console.error(e); process.exitCode = 1; });
