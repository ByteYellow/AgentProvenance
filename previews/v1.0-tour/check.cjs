const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const base = process.argv[2], output = path.resolve(process.argv[3]);
const preferenceKey = 'agentprov.onboarding.preview/v2';

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
      async function invitation(name) {
        await page.locator('#page-tour-invite').waitFor();
        assert.equal(await page.locator('.agentprov-tour').count(), 0, 'the spotlight tour requires an explicit click');
        assert.equal(await page.locator('#page-tour-start.tour-invited').count(), 1);
        assert(await page.evaluate(() => {
          const box = document.querySelector('#page-tour-invite').getBoundingClientRect();
          const header = document.querySelector('#page-tour-start').closest('header').getBoundingClientRect();
          return box.left >= 0 && box.top >= 0 && box.right <= innerWidth + 1 && box.bottom <= innerHeight + 1 &&
            box.top >= header.bottom &&
            !document.querySelector('#page-tour-invite').contains(document.activeElement) && document.documentElement.scrollWidth <= innerWidth + 1;
        }), 'hint fits without taking focus');
        if (name) await page.screenshot({path: path.join(output, `${name}-invite-${lang}-${width}.png`)});
      }
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
        await page.locator('.agentprov-tour').waitFor();
        const targets = [];
        for (let i = 1; i <= total; i++) {
          await inspectStep(i, total);
          targets.push(await page.locator('.agentprov-tour').getAttribute('data-tour-target'));
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
        return targets;
      }
      const readerLength = async () => Number((await page.locator('.driver-popover-progress-text').innerText()).split('/')[1]);

      await go(`?lang=${lang}`);
      await invitation('home');
      // The invitation keeps the rest of the page interactive, including language switching.
      await page.locator(`[data-lang="${lang === 'en' ? 'zh-CN' : 'en'}"]`).click();
      await page.locator(`[data-lang="${lang}"]`).click();
      await invitation();
      assert.equal(await page.locator('.story .preview-link').count(), 4);
      assert(await page.locator('.story .preview-link').evaluateAll(previews => previews.every(preview => {
        const frame = preview.getBoundingClientRect(), card = preview.closest('.story').getBoundingClientRect();
        const style = getComputedStyle(preview);
        return frame.left > card.left + 16 && frame.right < card.right - 16 && style.borderTopWidth === '1px' && style.boxShadow !== 'none';
      })), 'screenshots use inset spacing and a fine edge without extra labels or panels');
      await page.locator('#page-tour-start').click();
      const homeTargets = await fullTour(7, 'home');
      const docsTarget = width < 600 ? '#capture .links a:first-child' : '.top-nav a:nth-child(2)';
      assert(homeTargets.includes(docsTarget), 'homepage tour points directly to the documentation');
      assert.equal((await page.request.get(await page.locator(docsTarget).evaluate(link => link.href))).status(), 200, 'the guided documentation link opens');
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
      assert.equal(await page.locator('.driver-popover').count(), 0, 'Skip all also suppresses the reader invitation');
      await page.evaluate(key => localStorage.removeItem(key), preferenceKey);
      await page.reload();
      await waitReady();
      await invitation('reader');
      await page.locator('#page-tour-invite .driver-popover-close-btn').click();
      await page.reload();
      await waitReady();
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0, 'dismissed reader hint stays dismissed');
      assert.equal(await page.locator('#askgrid .qbtn').count(), 13);
      assert.equal(await page.locator('.investigation-actions button[data-investigation]').count(), 3);
      await page.evaluate(() => { document.querySelector('#context-fold').open = false; window.scrollTo(0, 100); });
      await page.locator('#page-tour-start').focus();
      const before = await state();
      // Programmatic activation avoids the test framework scrolling the header into view.
      await page.locator('#page-tour-start').evaluate(button => button.click());
      const readerSteps = await readerLength();
      assert(readerSteps >= 21, 'the reader covers its detailed controls');
      const targets = await fullTour(readerSteps, 'reader');
      for (const target of ['#session-relations-open', '[data-investigation="search"]', '[data-investigation="compare"]', '#scrub', '.zoombar', '#context-nav-files', '.access-bar', '#context-tab-configuration', '#context-tab-coverage', '#portable-workspace-tab', '#portable-native-tab', '[data-investigation="export"]', '#portable-delivery-details', '#timeline-fold>summary']) {
        assert(targets.includes(target), `reader guide covers ${target}`);
      }
      assert.deepEqual(await state(), before, 'tour restores the existing reading state');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'page-tour-start');
      assert(await page.locator('.context-nav button[data-context-open="coverage"]').evaluate(button => button.getBoundingClientRect().height < 150), 'mobile shortcut remains readable');

      await page.locator('#page-tour-start').click();
      await inspectStep(1, readerSteps);
      for (let i = 0; i < 10; i++) {
        await page.keyboard.press(i % 2 ? 'Shift+Tab' : 'Tab');
        assert(await page.evaluate(() => document.querySelector('.driver-popover').contains(document.activeElement)));
      }
      await page.keyboard.press('ArrowRight');
      await inspectStep(2, readerSteps);
      await page.keyboard.press('ArrowLeft');
      await inspectStep(1, readerSteps);
      await close();
      await page.locator('[data-investigation="search"]').click();
      await page.locator('#search-dialog[open]').waitFor();
      await page.keyboard.press('Escape');

      // A comparison deep link must retain priority over first-visit guidance.
      await page.evaluate(key => localStorage.removeItem(key), preferenceKey);
      await page.addInitScript(() => {
        let api;
        Object.defineProperty(window, 'AgentCompareUI', {configurable: true, get: () => api, set(value) {
          api = value;
          const original = value.openFromURL;
          value.openFromURL = async function (...args) {
            if (new URLSearchParams(location.search).has('compare_a')) await new Promise(resolve => setTimeout(resolve, 1200));
            return original.apply(this, args);
          };
        }});
      });
      await go(`current/investigation/${lang}/index.html?live=0&compare_a=run-860466af8a9a&compare_b=run-3bfc6838a9c6`);
      await page.waitForTimeout(600);
      assert.equal(await page.locator('.driver-popover').count(), 0, 'no hint while the deep-linked comparison is starting');
      await page.waitForFunction(() => document.querySelector('#compare-dialog')?.open && !document.querySelector('#compare-refresh').disabled);
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0);
      assert.equal(await page.locator('#compare-a').inputValue(), 'run-860466af8a9a');
      assert.equal(await page.locator('#compare-b').inputValue(), 'run-3bfc6838a9c6');
      await page.locator('#compare-close').click();
      await invitation('after-compare');
      // Opening another dialog temporarily hides the hint, without marking it dismissed.
      await page.locator('[data-investigation="search"]').click();
      await page.locator('#search-dialog[open]').waitFor();
      await page.waitForFunction(() => !document.querySelector('#page-tour-invite'));
      const searchScroll = await page.evaluate(() => scrollY);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(500);
      assert.equal(await page.evaluate(() => scrollY), searchScroll, 'the hint never pulls the reader back to the header');
      assert.equal(await page.evaluate(key => localStorage.getItem(key), preferenceKey), null, 'opening a dialog does not dismiss the hint permanently');
      await page.evaluate(() => window.scrollTo({top: 0, behavior: 'instant'}));
      await invitation();
      await page.locator('#page-tour-start').click();
      await inspectStep(1, await readerLength());
      await close();

      // A review link reoffers the hint without automatically starting the full tour.
      await go(`current/browser/${lang}/index.html?live=0&tour=1`);
      await invitation();
      await page.locator('#page-tour-start').click();
      await inspectStep(1, await readerLength());
      await close();
      await page.reload();
      await page.waitForTimeout(700);
      assert.equal(await page.locator('.driver-popover').count(), 0);
      assert.deepEqual(errors, []);
      reports.push({lang, width, passed: true, homepageSteps: 7, readerSteps, documentationEntry: true, inviteRequiresClick: true, skipAll: true, stateRestored: true, keyboard: true, compareCloseThenHint: true, errors});
      console.log(`PASS ${lang} ${width}px: invitation, ${readerSteps} reader steps, restoration and comparison close`);
      await context.close();
    }
    const context = await browser.newContext({reducedMotion: 'reduce'});
    await context.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Storage unavailable', 'SecurityError'); }});
    });
    const page = await context.newPage();
    await page.goto(new URL('en/?tour=1', base).href);
    await page.locator('#page-tour-invite').waitFor();
    await page.locator('#page-tour-start').click();
    await page.locator('.agentprov-tour').waitFor();
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
