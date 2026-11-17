const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.argv[2], output = path.resolve(process.argv[3]);
const preferenceKey = 'agentprov.onboarding.preview/v1';

(async () => {
  fs.mkdirSync(output, {recursive: true});
  const browser = await chromium.launch({channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true});
  const reports = [];
  try {
    for (const lang of ['zh-CN', 'en']) for (const width of [1440, 390, 320]) {
      const context = await browser.newContext({viewport: {width, height: width < 600 ? 844 : 1000}, locale: lang, reducedMotion: 'reduce'});
      const page = await context.newPage(), errors = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('response', response => { if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`); });
      const go = route => page.goto(new URL(route, base).href);
      const next = () => page.locator('.driver-popover-next-btn').click();
      const close = async () => { await page.keyboard.press('Escape'); await page.locator('.driver-popover').waitFor({state: 'detached'}); };
      const waitReady = () => page.waitForFunction(() => document.querySelector('#runsel')?.options.length && document.querySelector('#askgrid .qbtn'));
      const state = () => page.evaluate(() => ({
        run: document.querySelector('#runsel')?.value,
        lens: document.querySelector('#lenssel')?.value,
        detail: document.querySelector('#detailsel')?.value,
        fold: document.querySelector('#context-fold')?.open,
        tab: document.querySelector('[data-context-tab][aria-selected="true"]')?.dataset.contextTab,
        evidence: document.querySelector('#inspection')?.textContent,
        content: document.querySelector('#content-body')?.textContent,
        url: location.href,
        x: scrollX, y: scrollY
      }));
      async function inspectStep(current, total) {
        await page.waitForFunction(({current, total}) => document.querySelector('.driver-popover-progress-text')?.textContent === `${current} / ${total}`, {current, total});
        // Driver.js completes its focus/position transition on animation frames.
        await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
        const layout = await page.evaluate(() => {
          const popover = document.querySelector('.driver-popover');
          const active = document.querySelector('.driver-active-element');
          const p = popover.getBoundingClientRect(), a = active.getBoundingClientRect();
          return {
            popupFits: p.left >= 0 && p.top >= 0 && p.right <= innerWidth + 1 && p.bottom <= innerHeight + 1,
            targetVisible: a.width > 0 && a.height > 0 && a.bottom > 0 && a.top < innerHeight,
            pageFits: document.documentElement.scrollWidth <= innerWidth + 1,
            focusInside: popover.contains(document.activeElement),
            popupCount: document.querySelectorAll('.driver-popover').length
          };
        });
        assert.deepEqual(layout, {popupFits: true, targetVisible: true, pageFits: true, focusInside: true, popupCount: 1}, `${lang}/${width} step ${current}`);
        assert(await page.locator('.tour-skip').isVisible());
      }
      async function fullTour(total, name) {
        await page.locator('.driver-popover').waitFor();
        for (let i = 1; i <= total; i++) {
          await inspectStep(i, total);
          if (i === 1 || i === 4) await page.screenshot({path: path.join(output, `${name}-${lang}-${width}-${i}.png`)});
          if (i === 2) {
            await page.locator('.driver-popover-prev-btn').click();
            await inspectStep(1, total);
            await next();
            await inspectStep(2, total);
          }
          await next();
        }
        await page.locator('.driver-popover').waitFor({state: 'detached'});
        await page.waitForTimeout(100);
      }

      await go(`?lang=${lang}`);
      await fullTour(6, 'home');
      assert.equal(await page.locator('[data-case]').count(), 4);
      assert.equal(await page.locator('.journey-home-start, .journey-intro').count(), 0);
      await page.reload();
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0, 'completed tour stays dismissed');
      await page.locator('#page-tour-start').click();
      await page.locator('.tour-skip').click();
      assert(await page.evaluate(key => JSON.parse(localStorage.getItem(key)).skipped, preferenceKey));

      await go(`current/workspace/${lang}/index.html?live=0`);
      await waitReady();
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0, 'Skip all also suppresses the reader tour');
      assert.equal(await page.locator('#askgrid .qbtn').count(), 13);
      assert.equal(await page.locator('.investigation-actions button[data-investigation]').count(), 3);
      await page.evaluate(() => { document.querySelector('#context-fold').open = false; window.scrollTo(0, 100); });
      await page.locator('#page-tour-start').focus();
      const before = await state();
      // Programmatic activation avoids the test framework scrolling the header into view.
      await page.locator('#page-tour-start').evaluate(button => button.click());
      await fullTour(10, 'reader');
      assert.deepEqual(await state(), before, 'tour restores the existing reading state');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'page-tour-start');
      assert(await page.locator('.context-nav button[data-context-open="coverage"]').evaluate(button => button.getBoundingClientRect().height < 150), 'mobile shortcut remains readable');

      await page.locator('#page-tour-start').click();
      await inspectStep(1, 10);
      for (let i = 0; i < 10; i++) {
        await page.keyboard.press(i % 2 ? 'Shift+Tab' : 'Tab');
        assert(await page.evaluate(() => document.querySelector('.driver-popover').contains(document.activeElement)));
      }
      await page.keyboard.press('ArrowRight');
      await inspectStep(2, 10);
      await page.keyboard.press('ArrowLeft');
      await inspectStep(1, 10);
      await close();
      await page.locator('[data-investigation="search"]').click();
      await page.locator('#search-dialog[open]').waitFor();
      await page.keyboard.press('Escape');

      // A comparison deep link must retain priority over first-visit guidance.
      await page.evaluate(key => localStorage.removeItem(key), preferenceKey);
      await go(`current/investigation/${lang}/index.html?live=0&compare_a=run-860466af8a9a&compare_b=run-3bfc6838a9c6`);
      await page.waitForFunction(() => document.querySelector('#compare-dialog')?.open && !document.querySelector('#compare-refresh').disabled);
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0);
      assert.equal(await page.locator('#compare-a').inputValue(), 'run-860466af8a9a');
      assert.equal(await page.locator('#compare-b').inputValue(), 'run-3bfc6838a9c6');
      await page.keyboard.press('Escape');

      // First-visit guidance still works when no modal has claimed the page.
      await go(`current/browser/${lang}/index.html?live=0`);
      await page.locator('.driver-popover').waitFor();
      await inspectStep(1, 10);
      await close();
      await page.reload();
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0);
      assert.deepEqual(errors, []);
      reports.push({lang, width, passed: true, homepageSteps: 6, readerSteps: 10, skipAll: true, stateRestored: true, keyboard: true, compareDirect: true, errors});
      console.log(`PASS ${lang} ${width}px: tours, restoration, keyboard, search and comparison`);
      await context.close();
    }
    const context = await browser.newContext({reducedMotion: 'reduce'});
    await context.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Storage unavailable', 'SecurityError'); }});
    });
    const page = await context.newPage();
    await page.goto(new URL('en/?tour=1', base).href);
    await page.locator('.driver-popover').waitFor();
    await page.locator('.tour-skip').click();
    await page.locator('#page-tour-start').click();
    await page.locator('.driver-popover').waitFor();
    await page.keyboard.press('Escape');
    reports.push({storageUnavailable: true, passed: true});
    await context.close();
  } finally {
    await browser.close();
    fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({reports}, null, 2) + '\n');
  }
  console.log(JSON.stringify({reports}));
})().catch(error => {console.error(error); process.exitCode = 1;});
