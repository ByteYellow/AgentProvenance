// Run with playwright-cli run-code against TestArtifactDashboardFixture.
// These are saved synthetic objects, not a real model or filesystem capture.
async (page) => {
  const checks = [], errors = [];
  const check = (ok,name) => { if (!ok) throw new Error(name); checks.push(name); };
  const base = await page.evaluate(()=>location.origin);
  page = await page.context().newPage();
  page.on('pageerror', error=>errors.push(error.message));
  await page.setViewportSize({width:1440,height:1050});
  await page.goto(base+'/?run=artifact-ui&lens=file-artifact&detail=raw&live=0&lang=en');
  const file = name => page.locator('#dag [data-id="workspace_file/'+name+'"]');
  const body = () => page.locator('#content-body').innerText();
  const ready = async text => { await page.waitForFunction(value=>document.querySelector('#content-body')?.textContent.includes(value),text); };
  await file('large.txt').click();
  await ready('SYNTHETIC-FILE-START');
  check(!await page.locator('#context-fold').evaluate(el=>el.open),'artifact reading does not expand the session');
  check(!(await body()).includes('SYNTHETIC-FILE-TAIL'),'first artifact page is bounded');
  check((await page.locator('#runoverview').innerText()).includes('Artifacts: 5'),'text chunks are not counted as file artifacts');
  let pages = 1;
  while (!await page.locator('#content-next').isDisabled()) {
    const response = page.waitForResponse(r=>r.url().includes('/api/artifact?') && r.status()===200);
    await page.locator('#content-next').click();
    const value = await (await response).json();
    await page.waitForFunction(end=>document.querySelector('#content-page-label')?.textContent.includes('–'+end+' /'),value.next_offset);
    if (value.content.length>65536) throw new Error('unbounded artifact page '+pages);
    if (++pages > 140) throw new Error('unbounded paging');
  }
  check((await body()).endsWith('SYNTHETIC-FILE-TAIL'),'UI reaches stored tail beyond 8 MiB');
  check(pages>128,'UI traversed both 4 MiB and 8 MiB boundaries');
  check(true,'all artifact responses stayed within the page budget');
  const tail = await body();
  await page.getByRole('button',{name:'Expand saved content',exact:true}).click();
  check(await page.locator('#content-dialog').evaluate(el=>el.open),'long artifact expands');
  await page.screenshot({path:'output/playwright/artifact-long-en.png'});
  await page.getByRole('button',{name:'Close',exact:true}).click();
  check(await body()===tail,'closing keeps the last artifact page');
  await page.locator('#content-choice').selectOption({label:'Raw saved object'});
  await ready('content_ref');
  check((await body()).includes('agentprov.provenance.object.v1'),'raw shows saved descriptor, not the live file');
  await page.locator('#content-choice').selectOption({label:'Recorded graph content'});
  await ready('SYNTHETIC-FILE-START');
  await page.locator('#content-next').click();
  await page.waitForFunction(()=>document.querySelector('#content-page-label').textContent.includes('Bytes 65536–'));
  const second = await body();
  await page.getByRole('link',{name:'中文',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#content-page-label')?.textContent.includes('字节 65536–'));
  check(await body()===second,'language change preserves original artifact page');
  await page.setViewportSize({width:390,height:844});
  await page.getByRole('button',{name:'放大正文',exact:true}).click();
  check(await page.locator('#content-next').evaluate(el=>el.getBoundingClientRect().bottom<=innerHeight),'mobile artifact pager stays visible');
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile artifact view has no overflow');
  await page.screenshot({path:'output/playwright/artifact-long-zh-mobile.png'});
  await page.getByRole('button',{name:'关闭',exact:true}).click();
  await page.setViewportSize({width:1440,height:1050});
  await file('change.patch').click();
  await ready('diff --git');
  check(await page.locator('#content-body .add').allTextContents().then(lines=>lines.includes('+new')),'diff additions retain their styling');
  await page.locator('#savedcontent').scrollIntoViewIfNeeded();
  await page.screenshot({path:'output/playwright/artifact-diff-zh.png'});
  await file('metadata.txt').click();
  await ready('仅保存了制品元数据');
  check(await page.locator('#content-next').isDisabled(),'missing body is not an empty successful page');
  await page.locator('#content-choice').selectOption({label:'已保存对象原文'});
  await ready('synthetic-metadata-only');
  await file('versions.txt').click();
  await ready('存在多个已保存版本');
  const choices = await page.locator('#content-choice option').evaluateAll(nodes=>nodes.filter(n=>n.textContent.startsWith('已保存版本')).map(n=>n.value));
  check(choices.length===2,'ambiguous source offers exact saved versions');
  const values=[];
  for (const choice of choices) {
    const response = page.waitForResponse(r=>r.url().includes('/api/artifact?') && r.status()===200);
    await page.locator('#content-choice').selectOption(choice);
    const value = await (await response).json();
    await ready(value.content);
    values.push(await body());
  }
  check(new Set(values).size===2 && values.includes('VERSION-ONE') && values.includes('VERSION-TWO'),'version selection does not guess latest');
  check(!await page.locator('#context-fold').evaluate(el=>el.open),'all artifact controls remain independent of session expansion');
  check(errors.length===0,'no unhandled browser errors: '+errors.join('; '));
  return {fixture:'synthetic saved artifacts, not a live capture',pages,checks:checks.length,passed:checks,screenshots:'output/playwright/artifact-*.png'};
}
