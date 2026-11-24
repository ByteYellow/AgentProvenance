const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');

const posArgs = process.argv.slice(2).filter(a => !a.startsWith('--'));
const [base, output, siteDir] = posArgs;
const results = [];
const joinRoute = route => new URL(route.replace(/^\//, ''), base.endsWith('/') ? base : base + '/').href;
const home = lang => '?lang=' + lang;
const workspace = lang => 'current/workspace/' + lang + '/index.html?view=workspace';
const native = 'current/browser/zh-CN/index.html?view=native';
const compare = lang => 'current/investigation/' + lang + '/index.html?run=run-3bfc6838a9c6&compare_a=run-860466af8a9a&compare_b=run-3bfc6838a9c6&compare_dim=files';
const wait = selector => page => page.locator(selector).waitFor({state:'visible'});

(async () => {
  const browser = await chromium.launch({...(process.env.PLAYWRIGHT_CHANNEL ? {channel: process.env.PLAYWRIGHT_CHANNEL} : {}), headless:true});
  async function test(name, check, width=1440) {
    const ctx = await browser.newContext({viewport:{width,height:width < 600 ? 844 : 900}, reducedMotion:'reduce'});
    const p = await ctx.newPage();
    p.setDefaultTimeout(4000);
    const errors=[];
    p.on('pageerror', e => errors.push(e.message));
    try {
      const detail=await check(p,route=>p.goto(joinRoute(route)));
      assert.deepEqual(errors,[]);
      results.push({name,pass:true,detail});
    } catch(e) { results.push({name,pass:false,detail:e.message.split('\n').slice(0,6).join(' ')}); }
    finally { await ctx.close(); }
    console.log(JSON.stringify(results.at(-1)));
  }
  try {
    await test('workspace card agrees with owned receipt',async(p,go)=>{
      await go(home('zh-CN'));
      const row=p.locator('.ws-step').filter({hasText:'result.txt'});
      const label=await row.locator('.ws-op').innerText(), text=await row.innerText();
      await go(workspace('zh-CN'));
      await p.getByRole('button',{name:/workspace_bash rev 3.*result.txt/}).click();
      const raw=JSON.parse(await p.locator('#ws-detail pre').innerText()), r=raw.view.last_receipt;
      assert.equal(r.ref,raw.operation_ref); assert.equal(r.tool_call_id,raw.tool_call_id);
      assert.equal(label,await p.locator('#ws-detail h3').first().innerText());
      const change=r.changes.find(x=>x.path==='result.txt');
      for(const expected of [r.input_revision+'→'+r.output_revision,change.after.Hash.slice(0,8),change.after.SizeBytes+' B']) assert.ok(text.includes(expected),expected);
      return {tool:label,id:r.tool_call_id,revision:[r.input_revision,r.output_revision]};
    });
    await test('saved count and per-attachment verification',async(p,go)=>{
      await go(native);
      await wait('#nat-inline-att img')(p);
      assert.equal(await p.locator('#nat-att-pill').innerText(),'已保存 2 份附件');
      await p.getByRole('button',{name:/^har .*HAR/i}).click();
      await p.getByText(/网络档案（SHA-256 已校验）/).waitFor();
      return 'PNG and HAR verified separately';
    });
    // Only intercept the browser's copy of the replay API. Original recordings stay untouched.
    async function override(p, body, before = '') {
      await p.route('**/assets/replay.js', async route=>{
        const source=await route.fetch();
        const wrapper='\n;{const original=window.AgentProvReplay;window.AgentProvReplay={...original, async query(path,opts){'+before+';const value=await original.query(path,opts);'+body+';return value;}}}';
        await route.fulfill({response:source,body:(await source.text())+wrapper});
      });
    }
    await test('related sessions retain the recorded evidence and destination scope',async(p,go)=>{
      await go('current/investigation/en/index.html?run=run-860466af8a9a&view=session');
      await p.locator('#wb-related').click();
      const row=p.locator('[data-related-list] article').first();
      await row.waitFor();
      await row.locator('summary').click();
      const proof=JSON.parse(await row.locator('pre').innerText());
      assert.ok(proof.evidence.some(e=>e.object_hash && e.source_id));
      const href=new URL(await row.locator('a').first().getAttribute('href'));
      assert.ok(href.searchParams.get('harness') && href.searchParams.get('session'));
      await p.goto(href.href);
      await p.locator('#dag svg').waitFor();
      return {run:href.searchParams.get('run'),evidence:proof.evidence.length};
    });
    await test('session reader pages real saved text in both directions',async(p,go)=>{
      await override(p,'',`if(path.startsWith('/api/context/content?')){const u=new URL(path,location.href);u.searchParams.set('limit','16');path=u.pathname+u.search;}`);
      await go('current/investigation/en/index.html?run=run-860466af8a9a&view=session');
      await p.locator('#session-list [data-read-entry]').first().click();
      const reader=p.locator('[data-session-reader]'), first=reader.locator('pre').first();
      const text=await first.innerText();
      await reader.locator('[data-page=next]').click();
      await reader.locator('[data-page=prev]').waitFor();
      assert.notEqual(await first.innerText(),text);
      await reader.locator('[data-page=prev]').click();
      await reader.locator('[data-page=next]').waitFor();
      assert.equal(await first.innerText(),text);
    });
    await test('unverified and failed states never claim success',async(p,go)=>{
      await override(p,"if(path.startsWith('/api/overview?'))delete value.verify; if(path.startsWith('/api/context/attachment?')&&value.data)value.data=(value.data[0]==='A'?'B':'A')+value.data.slice(1)");
      await go(native);
      await wait('#nat-inline-att .wb-alert')(p);
      assert.match(await p.locator('#nat-inline-att').innerText(),/mismatch|失败|不匹配/i);
      assert.equal(await p.locator('#nat-inline-att img').count(),0);
      await p.locator('#wb-verify').click();
      assert.match(await p.locator('#wb-info-body dd').nth(1).innerText(),/未校验/);
      assert.match(await p.locator('#wb-verify').innerText(),/未校验/);
      assert.equal(await p.locator('#nat-att-pill').innerText(),'已保存 2 份附件');
    });
    for (const [width,lang] of [[1440,'zh-CN'],[390,'zh-CN'],[320,'en']]) {
      await test('receipt fits '+width+' '+lang,async(p,go)=>{
        await go(workspace(lang));
        await p.getByRole('button',{name:/workspace_bash rev 3.*result.txt/}).click();
        const sizes=await p.evaluate(()=>{
          const table=document.querySelector('#ws-detail table'),box=table.parentElement, r=box.getBoundingClientRect();
          return {viewport:innerWidth,doc:document.documentElement.scrollWidth,boxRight:r.right,boxLeft:r.left,
            tableScrollable:box.scrollWidth>box.clientWidth,overflow:getComputedStyle(box).overflowX};
        });
        assert.ok(sizes.doc<=width+1 && sizes.boxLeft>=-1 && sizes.boxRight<=width+1,JSON.stringify(sizes));
        if(sizes.tableScrollable)assert.match(sizes.overflow,/auto|scroll/);
        if(width===390){await p.locator('#ws-detail .wb-table').scrollIntoViewIfNeeded();await p.screenshot({path:path.join(path.dirname(output),'receipt-mobile.png')});}
        return sizes;
      },width);
      await test('library tour and docs '+width+' '+lang,async(p,go)=>{
        await go(home(lang));
        await wait('#page-tour-invite')(p);
        assert.equal(await p.locator('.agentprov-tour').count(),0);
        await p.locator('#page-tour-start').click();
        let docs=false; let count=0;
        while(await p.locator('.agentprov-tour').count() && count++<24){
          const target=p.locator('.driver-active-element');
          docs ||= /guides\/(quickstart|start)\.html/.test(await target.getAttribute('href')||'');
          await p.locator('.driver-popover-next-btn').click();
        }
        assert.ok(count>=5 && count<24 && docs,'tour must include visible docs, steps='+count);
        await p.reload();await wait('#page-tour-start')(p);
        await p.locator('#page-tour-start').click();await p.locator('.tour-skip').click();
        await p.goto(joinRoute(workspace(lang)));await wait('#ws-detail pre')(p);
        assert.equal(await p.locator('#page-tour-invite').count(),0);
        return {steps:count,docs:true};
      },width);
    }
    await test('comparison first, reader tour after close',async(p,go)=>{
      await go(compare('zh-CN'));
      await p.locator('#wb-compare-dlg[open]').getByRole('button',{name:/文件证据/}).waitFor();
      assert.equal(await p.locator('#page-tour-invite,.agentprov-tour').count(),0);
      await p.locator('[data-close="wb-compare-dlg"]').click();
      await wait('#page-tour-invite')(p);
      const url=p.url(), tab=await p.locator('.wb-tab[aria-selected=true]').getAttribute('data-mode');
      await p.locator('#page-tour-start').click();
      await p.locator('.driver-popover-next-btn').click();
      await p.locator('.driver-popover-prev-btn').click();
      await p.locator('.tour-skip').click();
      assert.equal(await p.locator('.wb-tab[aria-selected=true]').getAttribute('data-mode'),tab);
      assert.equal(p.url(),url);
    });
    if (process.argv.includes('--extended')) {
      await test('home receipt stays readable in phone and two-column layouts',async(p,go)=>{
        const readings=[];
        for(const lang of ['zh-CN','en']){
          await go(home(lang));
          for(const w of [320,390,600,601,780,800,980,981,1024,1440]){
            await p.setViewportSize({width:w,height:844});
            const row=p.locator('.ws-step').filter({hasText:'result.txt'});
            const m=await row.evaluate(el=>{
              const detail=el.querySelector('.ws-detail'),hash=el.querySelector('.ws-hash');
              const r=document.createRange();r.selectNodeContents(detail);
              const stage=el.closest('.stage').getBoundingClientRect();
              const inside=box=>box.left>=stage.left-1 && box.right<=stage.right+1 && box.bottom<=stage.bottom+1;
              return {width:innerWidth,doc:document.documentElement.scrollWidth,text:detail.textContent,
                detail:detail.clientWidth,visible:detail.scrollWidth<=detail.clientWidth &&
                  [...r.getClientRects(),hash.getBoundingClientRect()].every(inside)};
            });
            assert.ok(m.visible && m.doc===w,JSON.stringify(m)); assert.equal(m.text,'result.txt · added (25 B)');
            readings.push([lang,w,m.detail]);
            if(w===390 && lang==='zh-CN'){
              await p.locator('.card[data-case=remote]').screenshot({path:path.join(path.dirname(output),'home-card-390.png')});
              await p.locator('.card[data-case=native]').screenshot({path:path.join(path.dirname(output),'browser-card-390.png')});
            }
          }
        }
        return readings;
      });
      await test('compact reader header and rounded opt-in guide',async(p,go)=>{
        await go(workspace('zh-CN')+'&tour=1');
        await wait('#page-tour-invite')(p);
        for(const w of [320,390,980,981,1440]){
          await p.setViewportSize({width:w,height:844});
          assert.equal(await p.locator('.wb-div').first().isVisible(),w>980);
        }
        await p.setViewportSize({width:390,height:844});
        const radius=sel=>p.locator(sel).evaluate(el=>parseFloat(getComputedStyle(el).borderTopLeftRadius));
        assert.ok(await radius('#page-tour-start')>=100);
        assert.equal(await radius('#page-tour-invite'),14);
        await p.locator('#page-tour-start').click();
        assert.equal(await radius('.agentprov-tour'),14);
        assert.ok(await radius('.driver-popover-next-btn')>=100);
        await p.screenshot({path:path.join(path.dirname(output),'reader-tour-390.png')});
        await p.locator('.driver-popover-next-btn').click();
        await p.locator('.tour-skip').click();
      },390);
      await test('featured snapshots and attachment labels agree with their linked runs',async(p,go)=>{
        for(const lang of ['zh-CN','en']){
          await go(home(lang));
          const cards=JSON.parse(await p.locator('#featured-card-data').textContent());
          const inv=p.locator('.card[data-case=investigation]'), nat=p.locator('.card[data-case=native]');
          const pair=new URL(await inv.locator('.stage-link').getAttribute('href'),p.url());
          assert.equal(pair.searchParams.get('compare_a'),cards.investigation.before.run);
          assert.equal(pair.searchParams.get('compare_b'),cards.investigation.after.run);
          assert.deepEqual(await inv.locator('.diff-stat').allTextContents(),lang==='en'?
            ['2 permission errors','2 off','0 diagnostic entries']:['2 条权限错误','2 项关闭','0 条诊断记录']);
          const read=nat.locator('.br-item[data-entry]').nth(1);
          assert.equal(await read.locator('.br-tag').textContent(),'read_text');
          assert.equal(await read.locator('.br-val').textContent(),'Regional totals');
          for(const key of ['har','png']){
            const meta=cards.browser[key];
            assert.match(await nat.locator('[data-ref="'+meta.ref+'"]').innerText(),new RegExp(meta.bytes.toLocaleString(lang)+' B'));
          }
          const file=await nat.locator('.br-shot img').getAttribute('src');
          const res=await p.request.get(new URL(file,p.url()).href);
          assert.ok(res.ok());assert.equal(require('node:crypto').createHash('sha256').update(await res.body()).digest('hex'),cards.browser.png.sha256);
          assert.equal(new URL(await nat.locator('.stage-link').getAttribute('href'),p.url()).searchParams.get('run'),cards.browser.run);
          assert.match(await p.locator('[data-case=team] .badge').innerText(),/2,308/);
        }
      });
      await test('explicit graph statuses and absent counts',async(p,go)=>{
        await override(p,"if(path.startsWith('/api/overview?'))value.verify={status:new URL(location.href).searchParams.get('test_status')}");
        for(const [status,text,tone] of [['ok','图完整性通过','ok'],['subset','选定证据副本','warn'],['failed','图完整性校验失败','bad'],['deferred','图校验已延后','neutral'],['unavailable','图校验结果不可用','neutral'],['new_status','图完整性未校验','neutral']]){
          await go(native+'&test_status='+status);
          await wait('#nat-inline-att img')(p);
          assert.ok((await p.locator('#wb-verify').innerText()).includes(text));
          assert.ok(await p.locator('#wb-verify').evaluate((e,c)=>e.classList.contains(c),tone));
          await p.locator('#wb-verify').click();
          assert.equal(await p.locator('#wb-info-body dd').nth(1).innerText(),text);
        }
      });
      await test('reader walkthrough on phone preserves receipt and scope',async(p,go)=>{
        await go(workspace('zh-CN'));
        await p.getByRole('button',{name:/workspace_bash rev 3.*result.txt/}).click();
        const url=p.url(); await p.locator('#page-tour-start').click();
        let count=0, workspaceSteps=0;
        while(await p.locator('.agentprov-tour').count() && count++<26) {
          const active=p.locator('.driver-active-element'), pop=p.locator('.agentprov-tour');
          if(await active.evaluate(e=>!!e.closest('[data-view=workspace]'))) workspaceSteps++;
          await p.waitForFunction(()=>{
            const r=document.querySelector('.agentprov-tour')?.getBoundingClientRect();
            return r && r.left>=-1 && r.right<=innerWidth+1 && r.top>=-1 && r.bottom<=innerHeight+1;
          },null,{timeout:2200});
          await pop.locator('.driver-popover-next-btn').click();
        }
        assert.ok(workspaceSteps>=2 && count<26);
        assert.equal(p.url(),url);
        assert.match(await p.locator('#ws-list .on').innerText(),/workspace_bash/);
        return {steps:count,workspaceSteps};
      },320);
      await test('file reader offline and without local storage',async p=>{
        await p.addInitScript(()=>{Object.defineProperty(window,'localStorage',{get(){throw new Error('unavailable')}});});
        const remote=[];
        p.on('request',req=>{if(/^https?:/.test(req.url()))remote.push(req.url());});
        await p.context().setOffline(true);
        const rootDir = siteDir ? path.resolve(siteDir) : path.resolve(__dirname, '../../output/site');
        const file=require('node:url').pathToFileURL(path.join(rootDir, 'current/browser/en/index.html'));
        file.search='?view=native';
        await p.goto(file.href);
        await wait('#nat-inline-att img')(p);
        assert.match(await p.locator('#nat-att-pill').innerText(),/^Saved attachments: 2$/);
        await wait('#page-tour-invite')(p);
        await p.locator('#page-tour-start').click();
        await p.locator('.driver-popover-next-btn').click();
        await p.keyboard.press('Escape');
        await p.locator('.agentprov-tour').waitFor({state:'detached'});
        assert.deepEqual(remote,[]);
      });
    }
  } finally {await browser.close(); fs.writeFileSync(output,JSON.stringify(results,null,2)+'\n');}
  if(results.some(r=>!r.pass)) process.exitCode=1;
})().catch(e=>{console.error(e);process.exitCode=1});
