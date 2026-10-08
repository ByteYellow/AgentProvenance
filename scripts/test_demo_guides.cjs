// Browser regression for a running `agentprov demo --no-browser` instance.
// Uses the embedded guides and images; no external requests are allowed.
// Usage: node scripts/test_demo_guides.cjs http://127.0.0.1:PORT
const { chromium } = require('playwright');
const assert = require('node:assert/strict');

async function main() {
  const base = new URL(process.argv[2]);
  const browser = await chromium.launch({ headless: true, channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome' });
  const report = { pages: 0, images: 0, anchors: 0, mobilePages: 0 };
  const errors = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1060 } });
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin === base.origin) return route.continue();
      errors.push('Unexpected external request: ' + route.request().url());
      return route.abort();
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(new URL('/demos/?lang=en', base).href);
    const guides = await page.locator('a[href^="/demos/docs/"]').evaluateAll(links => [...new Set(links.map(link => link.pathname))]);
    assert.equal(guides.length, 9);
    for (const lang of ['en', 'zh-CN']) {
      for (const guide of guides) {
        await page.setViewportSize({ width: 1440, height: 1060 });
        const response = await page.goto(new URL(guide + '?lang=' + lang, base).href);
        assert.equal(response.status(), 200, guide);
        assert.equal(await page.locator('html').getAttribute('lang'), lang);
        assert.equal(await page.locator('article.document > h1').count(), 1, guide);
        assert.equal(await page.locator('#runsel').count(), 0, 'Guide must not fall back to the Dashboard');
        assert.equal(await page.locator('.document pre').count(), await page.locator('.code-toolbar button').count());
        const imageStates = await page.locator('.document img').evaluateAll(images => images.map(img => ({ src: img.src, loaded: img.complete && img.naturalWidth > 0 })));
        assert.ok(imageStates.every(img => img.loaded), JSON.stringify(imageStates.filter(img => !img.loaded)));
        report.images += imageStates.length;
        const anchors = await page.locator('.page-nav a').evaluateAll(links => links.map(link => ({ hash: link.hash, found: !!document.getElementById(decodeURIComponent(link.hash.slice(1))) })));
        assert.ok(anchors.every(anchor => anchor.found), JSON.stringify(anchors));
        report.anchors += anchors.length;
        assert.equal(await page.locator('.docs-sidebar a[aria-current="page"]').getAttribute('href'), guide + '?lang=' + lang);
        if (guide === '/demos/docs/grok-3routes') {
          const other = lang === 'en' ? 'zh-CN' : 'en';
          await page.locator(`.language-switch a[lang="${other}"]`).click();
          assert.equal(new URL(page.url()).pathname, guide, 'Language switch changed the selected capture');
        }
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Desktop overflow: ' + guide);
        await page.setViewportSize({ width: 390, height: 844 });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Mobile overflow: ' + guide);
        report.mobilePages++;
        report.pages++;
      }
    }
    for (const path of ['/demos/docs/missing', '/demos/assets/missing.png', '/README.md']) {
      assert.equal((await context.request.get(new URL(path, base).href)).status(), 404, path);
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ ...report, passed: true }, null, 2));
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
