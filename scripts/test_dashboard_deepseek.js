// Run through playwright-cli against `agentprov demo deepseek-context`.
// Uses only the real signed capture. No intercepted or synthetic API responses.
async (page) => {
  const run = 'run-dbc2adf273d4', checks = [], errors = [];
  const check = (ok, name) => { if (!ok) throw new Error(name); checks.push(name); };
  const base = await page.evaluate(() => location.origin);
  page = await page.context().newPage();
  page.on('pageerror', error => errors.push(error.message));
  const request = async path => {
    const response = await page.request.get(base + path);
    check(response.ok(), 'HTTP '+path.split('?')[0]);
    return response.json();
  };
  const readyContent = text => page.waitForFunction(value => document.querySelector('#content-body')?.textContent.includes(value), text);
  const records = () => page.locator('#context-body [data-entry]');
  await page.setViewportSize({width:1440,height:1050});
  await page.goto(base+'/?run='+run+'&live=0&lang=en');
  await page.waitForFunction(() => document.querySelector('#context-summary')?.textContent.includes('13 message records'));
  check(!(await page.locator('#context-summary').innerText()).includes('launch'), 'processing channel is not a transcript source');
  check((await page.locator('#context-summary').innerText()).includes('Session capture: Captured'), 'successful transcript capture has its own status');
  await page.waitForFunction(() => document.querySelector('#verify')?.textContent.includes('graph integrity'));
  check(!await page.locator('#context-fold').evaluate(el=>el.open), 'session initially collapsed');
  for (const id of ['graphcard','siglist','focusedevidence','outboundcard','tl','ptree','egtbl','compliancecard']) {
    check(await page.locator('#'+id).count()===1, 'retains '+id);
  }
  const lenses = await page.locator('#lenssel option').evaluateAll(nodes=>nodes.map(n=>n.value));
  check(lenses.length===12, 'all twelve existing lenses remain selectable');
  for (const lens of lenses) {
    await page.locator('#lenssel').selectOption(lens);
    await page.waitForFunction(value=>window._lensManifest?.lens===value &&
      (document.querySelector('#dag svg') || (window._lensManifest?.query.node_count===0 && document.querySelector('#dag .empty'))), lens);
    check(await page.locator('#loaderror').isHidden(), 'rendered lens '+lens);
  }
  await page.locator('#lenssel').selectOption('file-artifact');
  await page.locator('#detailsel').selectOption('raw');
  await page.waitForFunction(()=>window._lensManifest?.lens==='file-artifact' && window._lensManifest?.query.detail==='raw');
  const file = name => page.locator('#dag [data-id="workspace_file/'+name+'"]');
  await file('report.py').click();
  await readyContent('def daily_revenue');
  check(!await page.locator('#context-fold').evaluate(el=>el.open), 'real saved file works while session is collapsed');
  check((await page.locator('#content-body').innerText()).includes('Decimal'), 'recorded implementation body available offline');
  await page.locator('#content-choice').selectOption({label:'Raw saved object'});
  await readyContent('content_ref');
  check(true, 'file raw descriptor is distinct from its saved text');
  await file('test_report.py').click();
  await readyContent('test_cli_daily_output');
  check(true, 'switching files selects the recorded test source');
  await page.locator('#savedcontent').scrollIntoViewIfNeeded();
  await page.screenshot({path:'output/playwright/deepseek-file-en.png'});

  const resultPage = await request('/api/context/entries?run='+run+'&kind=tool_result&limit=200');
  let result;
  for (const entry of resultPage.entries) {
    const value = await request('/api/context/content?run='+run+'&ref='+encodeURIComponent(entry.content.ref));
    if (value.content.includes('Ran 7 tests') && value.content.includes('OK')) { result = entry; break; }
  }
  check(Boolean(result), 'real unit-test result found in saved evidence');
  await page.getByRole('button',{name:'Task & conversation 13',exact:true}).click();
  await page.waitForSelector('#context-body [data-entry]');
  const selected = () => page.locator('#context-body [data-entry="'+result.id+'"]');
  for (let i=0; i<4 && !await selected().count(); i++) {
    check(!await page.locator('#context-next').isDisabled(), 'next recorded page available');
    const response = page.waitForResponse(r=>r.url().includes('/api/context/entries?') && r.status()===200);
    await page.locator('#context-next').click();
    const data = await (await response).json();
    await page.waitForFunction(id=>document.querySelector('#context-body [data-entry="'+id+'"]'), data.entries[0].id);
  }
  check(await selected().count()===1, 'paged session reaches the recorded unit-test result');
  await selected().locator('[data-tool-body] summary').click();
  await selected().getByText('Ran 7 tests',{exact:false}).waitFor();
  await selected().getByRole('button',{name:'Open saved content',exact:true}).click();
  await readyContent('Ran 7 tests');
  check((await page.locator('#content-body').innerText()).includes('\nRan 7 tests'), 'structured tool output preserves readable line breaks');
  check(await page.locator('#content-format-note').isVisible(), 'display projection is labeled separately from saved bytes');
  await page.locator('#content-format').selectOption('bytes');
  const savedResult = await request('/api/context/content?run='+run+'&ref='+encodeURIComponent(result.content.ref));
  check(await page.locator('#content-body').textContent()===savedResult.content, 'saved-byte mode exactly matches the recorded response');
  await page.locator('#content-format').selectOption('readable');
  await page.locator('#content-expand').click();
  check(await page.locator('#content-dialog').evaluate(el=>el.open), 'real tool output expands');
  await page.screenshot({path:'output/playwright/deepseek-tests-en.png'});
  await page.locator('#content-close').click();
  await selected().getByRole('button',{name:'Raw source record',exact:true}).click();
  await readyContent('call');
  check(await page.locator('#content-format').isHidden(), 'raw source remains an unformatted byte view');
  check((await page.locator('#content-body').innerText()).includes(result.tool_call_id), 'raw tool record retains native call identity');
  await selected().getByRole('button',{name:'Locate in graph',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#detail')?.textContent.includes('python3 -m unittest -v test_report.py'));
  await page.locator('#detail-session').waitFor();
  check((await page.locator('#detail').innerText()).includes('unittest'), 'session locates the exact unit-test tool node');
  await page.locator('#detail-session').click();
  await page.waitForFunction(()=>document.querySelectorAll('#context-body [data-entry]').length===2);
  check(await page.locator('#context-linked').isVisible(), 'graph returns only the matching input and result');
  await page.locator('#context-return').click();
  await selected().waitFor();
  check(true, 'return restores the original session page');

  await page.getByRole('tab',{name:'Permissions & configuration',exact:true}).click();
  await page.waitForFunction(()=>document.querySelectorAll('#context-body [data-entry]').length===5);
  await page.waitForFunction(()=>document.querySelector('#context-body')?.textContent.includes('workspace-write'));
  const approval = records().filter({hasText:'Approval policy'}).locator('[data-entry-body] pre');
  await approval.waitFor();
  check(JSON.parse(await approval.innerText()).policy === 'ask', 'actual permission configuration is visible');
  await records().nth(0).getByRole('button',{name:'Compare snapshot',exact:true}).click();
  await records().nth(1).getByRole('button',{name:'Compare snapshot',exact:true}).click();
  await page.locator('#context-compare-run').click();
  await page.waitForFunction(()=>document.querySelector('#context-compare-result')?.textContent.includes('different'));
  check(true, 'real configuration records can be compared without inventing approval');
  await page.getByRole('tab',{name:'Collection status',exact:true}).click();
  check((await page.locator('[data-runtime-coverage]').innerText()).includes('Capture completeness unconfirmed'), 'real capture uncertainty remains visible');
  check(!await page.locator('[data-runtime-coverage] details').evaluate(el=>el.open), 'node diagnostics are initially collapsed');
  check(!(await page.locator('[data-runtime-coverage]').innerText()).includes('235'), 'node backlog is not presented as run event loss');
  await page.locator('[data-runtime-coverage] details > summary').click();
  check((await page.locator('[data-runtime-coverage]').innerText()).includes('235'), 'original backlog remains inspectable');
  check((await page.locator('[data-runtime-coverage]').innerText()).includes('Not recorded'), 'unknown run-specific losses remain unknown');
  await page.locator('[data-runtime-coverage] details > summary').click();
  const association = page.locator('[data-association-coverage]');
  check((await association.innerText()).includes('Partial tool association'), 'association has a distinct status');
  check(await association.locator('.context-counts').count()===0, 'association does not show fictitious transcript counters');
  check(await page.locator('[data-session-coverage]').count()===1, 'discovery is not shown as another empty transcript');
  check(!await page.locator('[data-source-discovery] details').evaluate(el=>el.open), 'successful discovery is a collapsed diagnostic');
  await association.locator('details > summary').click();
  check((await association.innerText()).includes('agentprov.command_time_process/v2'), 'original association method remains inspectable');
  await association.locator('details > summary').click();
  check((await page.locator('#context-body').innerText()).includes('approval'), 'missing approval is explicitly retained');
  await page.getByRole('link',{name:'中文',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#context-tab-coverage')?.getAttribute('aria-selected')==='true');
  await page.waitForSelector('[data-runtime-coverage]');
  check((await page.locator('[data-runtime-coverage]').innerText()).includes('采集完整性待确认'), 'coverage remains honest in Chinese');
  check((await page.locator('[data-association-coverage]').innerText()).includes('部分行为未关联工具'), 'Chinese association is distinct from capture');
  await page.locator('#agentcontext').scrollIntoViewIfNeeded();
  await page.screenshot({path:'output/playwright/deepseek-coverage-zh.png'});
  await page.setViewportSize({width:390,height:844});
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1), 'mobile has no page-wide overflow');
  await page.locator('#content-expand').click();
  check(await page.locator('#content-dialog').evaluate(el=>el.getBoundingClientRect().width<=innerWidth), 'mobile saved-content dialog fits');
  check(await page.locator('#content-close').evaluate(el=>el.getBoundingClientRect().bottom<=innerHeight), 'mobile close control stays visible');
  await page.screenshot({path:'output/playwright/deepseek-mobile-zh.png'});
  await page.locator('#content-close').click();
  check(errors.length===0, 'no unhandled browser errors: '+errors.join('; '));
  return {capture:'real DeepSeek Harness 0.1.7-rc.2, not a synthetic fixture',run,checks:checks.length,passed:checks,screenshots:'output/playwright/deepseek-*.png'};
}
