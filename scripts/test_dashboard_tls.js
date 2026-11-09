// Run against TestContextDashboardFixture. Uses saved synthetic evidence only.
async (page) => {
  const base=new URL(await page.url()).origin,passed=[],errors=[];
  page=await page.context().newPage();
  page.on('pageerror',error=>errors.push(error.message));
  const check=(value,label)=>{if(!value)throw new Error(label);passed.push(label);};
  const open=async(lang='en')=>{
    await page.goto(base+'/?run=ui-tls&lens=default&detail=raw&lang='+lang+'&live=0');
    await page.waitForFunction(()=>window._lg?.nodes?.some(n=>n.id==='runtime_event/ui-tls-fragment'));
  };
  const choose=async(name,runtime=false)=>{
    const id=await page.evaluate(({name,runtime})=>runtime?'runtime_event/ui-tls-'+name:window._lg.nodes.find(n=>n.data?.source_id==='llm_request/ui-tls-'+name).id,{name,runtime});
    await page.locator('g[data-id="'+id+'"]').click();
    await page.locator('#detail [data-tls-capture]').waitFor();
    await page.waitForFunction(()=>document.querySelector('#content-tls [data-tls-capture]'));
    return id;
  };
  try {
    await page.setViewportSize({width:1440,height:1080});
    await open();
    const id=await choose('fragment');
    check(await page.locator('#detail [data-tls-capture]').getAttribute('data-tls-capture')==='incomplete','fragment state visible in existing detail');
    check(await page.locator('[data-investigation]').count()===3,'existing investigation actions retained');
    check((await page.locator('#detail [data-tls-capture]').innerText()).includes('Per-call capture limit reached'),'capture-gap reason visible');
    await page.locator('#detail [data-tls-capture] summary').click();
    check((await page.locator('#detail .tls-fields').innerText()).includes('9007199254740993'),'64-bit call identity rendered without rounding');
    await page.locator('[data-inspection-tab="content"]').click();
    await page.waitForFunction(()=>document.getElementById('content-body').textContent.includes('PUBLIC-TLS-FRAGMENT'));
    check((await page.locator('#content-body').innerText()).startsWith('Retained fragment'),'fragment reader omits model summary');
    check(await page.locator('#content-body img').count()===0,'recorded markup stays text');
    check(await page.locator('#content-tls [data-tls-capture]').getAttribute('data-tls-capture')==='incomplete','reader uses same capture status');
    await page.locator('#content-expand').click();
    check(await page.locator('#content-dialog [data-tls-capture]').count()===1,'expanded reader carries capture status');
    await page.locator('#content-close').click();
    await page.locator('[data-investigation="search"]').click();
    await page.locator('#search-close').click();
    check(await page.locator('#detail').getAttribute('data-node')===id,'search return preserves selected evidence');
    await page.locator('[data-inspection-tab="summary"]').click();
    await page.locator('[data-expand="upstream"]').click();
    check(await page.locator('#detail [data-tls-capture]').count()===1,'redraw does not duplicate capture detail');
    await page.locator('[data-expand="lineage"]').click();
    await choose('complete');
    check(await page.locator('#detail [data-tls-capture]').getAttribute('data-tls-capture')==='complete','complete HTTP message retains parsed status');
    await page.locator('[data-inspection-tab="content"]').click();
    await page.waitForFunction(()=>!document.getElementById('content-next').disabled);
    check(await page.locator('#content-tls [data-tls-capture]').getAttribute('data-tls-capture')==='complete','page limit is separate from capture truncation');
    await page.locator('#content-next').click();
    await page.waitForFunction(()=>document.getElementById('content-body').textContent.includes('COMPLETE-TAIL'));
    check(await page.locator('#content-tls [data-tls-capture]').getAttribute('data-tls-capture')==='complete','next content page retains metadata');
    await page.locator('[data-inspection-tab="summary"]').click();
    await choose('historical');
    check(await page.locator('#detail [data-tls-capture]').getAttribute('data-tls-capture')==='unrecorded','historical completeness remains unknown');
    await choose('binary');
    check((await page.locator('#detail [data-tls-capture]').innerText()).includes('Undecoded HPACK fragment'),'HPACK fragment is identified');
    await page.locator('[data-inspection-tab="content"]').click();
    await page.waitForFunction(()=>document.getElementById('content-body').textContent.includes('AP8Q'));
    check((await page.locator('#content-body').innerText()).includes('(base64)'),'binary fragment encoding is labelled');
    await page.locator('[data-inspection-tab="summary"]').click();
    await choose('checkpoint');
    await page.locator('#detail [data-tls-capture] summary').click();
    check((await page.locator('#detail .tls-fields').innerText()).includes('Sequence checkpoint'),'checkpoint is distinct from a zero-byte body');
    await choose('fragment',true);
    check(await page.locator('#detail [data-tls-capture]').getAttribute('data-tls-capture')==='incomplete','runtime event carries capture metadata');
    await page.setViewportSize({width:390,height:844});
    await open('zh-CN');
    await choose('fragment');
    check((await page.locator('#detail [data-tls-capture]').innerText()).includes('单次调用达到采集上限'),'Chinese reason and state rendered');
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile detail has no horizontal overflow');
    await page.locator('[data-inspection-tab="content"]').click();
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'mobile reader has no horizontal overflow');
    check(errors.length===0,'no browser errors: '+errors.join('; '));
    return {fixture:'synthetic TLS capture details',checks:passed.length,passed};
  } finally {await page.close();}
}
