// Run with playwright-cli against TestContextDashboardFixture's local server.
// Controlled promises exercise response ordering without altering saved evidence.
async (page) => {
  const base = await page.evaluate(()=>location.origin);
  page = await page.context().newPage();
  await page.goto(base+'/?run=ui-fixture&lang=en&live=0');
  await page.waitForFunction(()=>window._lensManifest?.run_id==='ui-fixture' && document.querySelector('#timeline-count')?.textContent.includes('events'));
  const checks = await page.evaluate(async () => {
    const checks = [], original = j, pending = [];
    const check = (ok,name) => { if (!ok) throw new Error(name); checks.push(name); };
    const result = marker => ({events:[{id:marker,event_type:'tool.call',payload:marker}],total:1,offset:0,limit:50});
    j = url => new Promise((resolve,reject)=>pending.push({url,resolve,reject}));
    try {
      EV_FILTER = {title:'first',refs:['first']};
      const first = loadEvidenceDrilldown(0);
      pending[0].resolve(result('FIRST_RECORD')); await first;
      check(document.querySelector('#evtbl').textContent.includes('FIRST_RECORD'),'initial selection renders');
      EV_FILTER = {title:'second',refs:['second']};
      const second = loadEvidenceDrilldown(0);
      check(!document.querySelector('#evtbl').textContent.includes('FIRST_RECORD'),'new selection clears previous records while pending');
      check(document.querySelector('#evhead').textContent.includes('second'),'pending title follows current selection');
      EV_FILTER = {title:'third',refs:['third']};
      const third = loadEvidenceDrilldown(0);
      pending[2].resolve(result('THIRD_RECORD')); await third;
      pending[1].resolve(result('SECOND_RECORD')); await second;
      check(document.querySelector('#evtbl').textContent.includes('THIRD_RECORD') && !document.querySelector('#evtbl').textContent.includes('SECOND_RECORD'),'late success cannot replace current evidence');
      const refresh = loadEvidenceDrilldown(0);
      check(document.querySelector('#evtbl').textContent.includes('THIRD_RECORD'),'same-selection refresh keeps content visible while pending');
      const failed = refresh.catch(error=>error.message);
      pending[3].reject(new Error('synthetic failure'));
      check(await failed==='synthetic failure','current evidence failure propagates');
      check(!document.querySelector('#evtbl').textContent.includes('THIRD_RECORD') && document.querySelector('#evtbl').textContent.includes('Evidence could not be loaded.'),'failed selection does not retain previous evidence');
      check(document.querySelector('#inspection-event-count').textContent==='unknown','failed evidence count is unknown');
      check(!document.querySelector('#evpager').textContent,'failed evidence has no stale paging controls');
      EV_FILTER = {title:'obsolete',refs:['obsolete']};
      const obsolete = loadEvidenceDrilldown(0);
      EV_FILTER = {title:'current',refs:['current']};
      const current = loadEvidenceDrilldown(0);
      pending[5].resolve(result('CURRENT_RECORD')); await current;
      pending[4].reject(new Error('obsolete failure')); await obsolete;
      check(document.querySelector('#evtbl').textContent.includes('CURRENT_RECORD'),'late failure cannot invalidate current evidence');
      const timelineFirst = loadTimeline(cur,0), timelineSecond = loadTimeline(cur,50);
      pending[7].resolve({...result('CURRENT_TIMELINE'),offset:50,total:100}); await timelineSecond;
      pending[6].resolve(result('OLD_TIMELINE')); await timelineFirst;
      check(tlOffset===50 && document.querySelector('#tl').textContent.includes('CURRENT_TIMELINE'),'late timeline page cannot replace the selected page');
      const count = pending.length;
      await loadTimeline('obsolete-run',0);
      check(pending.length===count,'obsolete run cannot start a timeline request');
      const oldTimeline = loadTimeline(cur,0), newTimeline = loadTimeline(cur,50);
      pending[9].resolve({...result('LATEST_TIMELINE'),offset:50,total:100}); await newTimeline;
      pending[8].reject(new Error('obsolete timeline failure')); await oldTimeline;
      check(document.querySelector('#tl').textContent.includes('LATEST_TIMELINE'),'late timeline failure cannot invalidate current page');
      return checks;
    } finally { j = original; }
  });
  await page.close();
  return {source:'controlled browser response-order fixtures',checks:checks.length,passed:checks};
}
