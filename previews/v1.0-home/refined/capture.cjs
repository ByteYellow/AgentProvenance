const {chromium} = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const base = process.argv[2] || 'http://127.0.0.1:58729/';
const output = path.join(__dirname, 'media');
fs.mkdirSync(output, {recursive:true});

(async()=>{
  const browser = await chromium.launch({channel:'chrome',headless:true});
  const sources = [];
  try {
    for(const language of ['zh-CN','en']) for(const name of ['investigation','remote','native','team']) {
      const page = await browser.newPage({viewport:{width:1000,height:900},deviceScaleFactor:2,locale:language});
      const routes = {
        investigation:`current/investigation/${language}/index.html?run=run-860466af8a9a&compare_a=run-860466af8a9a&compare_b=run-3bfc6838a9c6&live=0`,
        remote:`current/workspace/${language}/index.html?run=run-w01-445a3a164ae14723b82f90634cff96f5&live=0`,
        native:`current/browser/${language}/index.html?run=run-da25e015ca1f&live=0`,
        team:`archive/${language}/replay.html?run=run-double-attempt&lens=orchestration&live=0`
      };
      await page.goto(new URL(routes[name],base).href);
      await page.waitForFunction(()=>window.j&&document.querySelector('#dag')?.childElementCount>0);
      let selector, reference;
      if(name==='investigation') {
        await page.waitForFunction(()=>document.querySelector('#compare-refresh')?.disabled===false&&document.querySelector('[data-compare-row]'));
        await page.locator('[data-dimension="files"]').click();
        selector='#compare-results';
        reference=await page.locator('.compare-row').evaluateAll(rows=>rows.slice(0,3).map(row=>row.textContent));
        await page.locator(selector).evaluate(el=>{el.style.cssText='width:640px;height:252px;max-height:none;overflow:hidden;padding:0 24px;background:#fff';el.scrollTop=0;});
        await page.addStyleTag({content:'.compare-row summary{min-height:80px;padding:17px 0}.compare-row summary strong{font-size:16px}.compare-row summary small{font-size:12px}.compare-state{font-size:12px}'});
      } else if(name==='remote') {
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI);
        await page.locator('#context-fold>summary').click();
        await page.locator('#portable-workspace-tab').click();
        const row=page.locator('[data-workspace-entry]').filter({has:page.locator('h3',{hasText:'workspace_bash'})});
        await row.locator('[data-native-body]').click();
        await page.locator('[data-workspace-receipt]').waitFor();
        reference=await page.locator('[data-workspace-receipt]').getAttribute('data-workspace-receipt');
        // Excerpt actual rendered fields without changing their values or the reader.
        await page.evaluate(()=>{
          const section=document.querySelector('.portable-workspace-result');
          const excerpt=document.createElement('section');excerpt.id='cover-excerpt';
          excerpt.style.cssText='width:640px;height:252px;padding:25px 28px;box-sizing:border-box;background:#fff;color:#1d1d1f;font-size:15px';
          const heading=section.querySelectorAll('h3')[2].cloneNode(true);heading.style.margin='0 0 20px';excerpt.append(heading);
          const table=section.querySelector('table').cloneNode(true);excerpt.append(table);
          section.replaceChildren(excerpt);
        });
        selector='#cover-excerpt';
      } else if(name==='native') {
        await page.waitForFunction(()=>window.AgentPortableEvidenceUI);
        reference=await page.evaluate(async()=>{
          const {entries}=await j('/api/context/entries?run=run-da25e015ca1f&limit=100');
          const entry=entries.find(x=>x.attachments?.some(a=>a.media_type==='image/png'));
          if(!entry)throw Error('The browser recording has no saved screenshot');
          const attachment=entry.attachments.find(a=>a.media_type==='image/png');
          await window.AgentPortableEvidenceUI.openAttachment(attachment,'run-da25e015ca1f');
          return {entry:entry.id,attachment:attachment.ref,sha256:attachment.sha256};
        });
        selector='#portable-dialog-body img';
        await page.locator(selector).waitFor();
        await page.locator(selector).evaluate(img=>{img.style.cssText='display:block;width:640px;height:252px;max-height:none;max-width:none;object-fit:none;object-position:left top;background:#fff;border:0;border-radius:0';});
        await page.waitForFunction(()=>document.querySelector('#portable-dialog-body img')?.complete);
      } else {
        selector='#dag svg';
        reference=['agent/aa32ada3b63decade','agent/aad06879bc2b6ae95','sha256:40d320496289834b60ecbe0cc17f62ca4bce88e9028b9745e1f15efafeb428d5'];
        await page.locator(selector).evaluate(svg=>{
          svg.setAttribute('viewBox','270 0 760 299.25');svg.setAttribute('width','640');svg.setAttribute('height','252');
          svg.style.cssText='width:640px;height:252px;background:#fff;max-width:none';
        });
      }
      await page.locator(selector).evaluate(el=>{
        const clone=el.cloneNode(true),frame=document.createElement('div');
        frame.id='thumbnail-frame';frame.style.cssText='position:fixed;inset:0;width:640px;height:252px;overflow:hidden;background:#fff';frame.append(clone);
        document.querySelectorAll('dialog[open]').forEach(dialog=>dialog.close());
        document.body.replaceChildren(frame);document.body.style.cssText='margin:0;background:#fff;min-width:0';
      });
      const file=path.join(output,`${name}-${language}.png`);
      await page.locator('#thumbnail-frame').screenshot({path:file});
      sources.push({file:path.basename(file),route:routes[name],selector,reference,sha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')});
      console.log(`${name}-${language}`);
      await page.close();
    }
    fs.writeFileSync(path.join(output,'sources.json'),JSON.stringify({kind:'cropped-recording-excerpts',sources},null,2)+'\n');
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
