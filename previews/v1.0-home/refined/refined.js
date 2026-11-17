'use strict';
(() => {
  const originalRender = render;
  const originalOpenStory = openStory;
  const captions = () => ({
    investigation: t('修复前后 · 文件证据对比节选', 'Before and after · File comparison excerpt'),
    remote: t('工作区 · 最终文件记录节选', 'Workspace · Recorded output file'),
    native: t('Browser · 保存的页面截图局部', 'Browser · Saved screenshot detail'),
    team: t('Alice 与 Bob · 协作关系局部', 'Alice and Bob · Collaboration detail')
  });
  const descriptions = () => ({
    investigation: t('从任务与工具调用追到文件、网络，直接对比修复前后的记录。', 'Follow a task through its tools, files and network activity. Compare the recordings before and after repair.'),
    remote: t('查看远端工作区中的输入、修改与最终文件，继续追踪执行交接。', 'Inspect the inputs, edits and final files in a remote workspace. Continue into the execution handoff.'),
    native: t('阅读网页操作、请求与截图，以及 Notebook 中保存的代码和输出。', 'Read browser actions, requests and screenshots, alongside saved notebook code and output.'),
    team: t('沿着消息、委派和工具调用，看清谁发起任务、谁实际执行。', 'Follow messages, delegation and tool calls to see who started the work and who carried it out.')
  });

  function refine() {
    const copy = descriptions(), caption = captions();
    root.querySelector('.brand-description')?.remove();
    root.querySelector('.header-divider')?.remove();
    const intro = root.querySelector('.intro-note');
    intro.innerHTML = `${icon('shield')}<span>${t('只读实录，无需 API Key', 'Read-only recordings. No API key needed.')}</span>`;
    root.querySelector('.saved-status')?.remove();
    const previous = document.createElement('a');
    previous.className = 'previous-preview';
    previous.href = `index.html?lang=${lang}`;
    previous.textContent = t('查看上一版', 'Previous design');
    root.querySelector('.languages').before(previous);

    const cards=stories().map(s=>s.id==='investigation'?{...s,actions:compareLink(comparison(currentInvestigation(),'run-860466af8a9a','run-3bfc6838a9c6'))}:s);
    root.querySelector('.grid').innerHTML = cards.map(s => `<article class="story" data-case="${s.id}">
      <div class="story-copy"><div class="story-head"><span class="story-icon">${icon(s.icon)}</span><span class="kicker">${s.kicker}</span>${s.fresh?`<span class="tag new">${t('1.0 新增','New in 1.0')}</span>`:''}</div>
      <h3>${s.title}</h3><p class="description">${copy[s.id]}</p></div>
      <figure class="story-preview">${link(s.href,`<img src="refined-media/${s.id}-${lang}.png" width="640" height="252" alt="${escapeHTML(caption[s.id])}" decoding="async" loading="${s.id==='investigation'||s.id==='remote'?'eager':'lazy'}">`,'preview-link')}<figcaption>${icon(s.id==='native'?'browser':s.id==='team'?'team':'file')}<span>${caption[s.id]}</span></figcaption></figure>
      <div class="story-actions"><div class="story-bottom">${s.actions}<button class="text-button" data-story="${s.id}">${t('案例经过','Case details')}${icon('chevron')}</button></div></div>
    </article>`).join('');
    root.querySelector('#featured .section-head p').textContent = t('真实记录，可直接探索', 'Real recordings, ready to explore');
    root.querySelector('#topics .section-head p').textContent = t('深入方法与接入', 'Methods and integrations');
    root.querySelector('.page-footer>span').textContent = t('v1.0 首页精修预览 · 本地审核', 'v1.0 refined homepage preview · Local review');
    const foot = root.querySelector('.page-footer>span:last-child');
    foot.innerHTML = link(`index.html?lang=${lang}`,t('上一版设计','Previous design'))+'<span aria-hidden="true">·</span>'+link('archive/'+lang+'/index.html',t('原版示例库','Original demo library'));
  }

  // The variant shares the existing case data, dialog navigation and run links.
  render = function() { originalRender(); refine(); };
  openStory = function(...args) {
    originalOpenStory(...args);
    document.querySelectorAll('#case-body .compare-action').forEach(a=>{
      const target=new URL(a.href);
      if(target.searchParams.get('compare_a')==='run-3bfc6838a9c6'){
        target.searchParams.set('compare_a','run-860466af8a9a');
        target.searchParams.set('compare_b','run-3bfc6838a9c6');
        a.href=target.href;
      }
    });
    if(args[0]==='archive') {
      const title = document.querySelector('[data-story="grok"] strong');
      if(title) title.textContent = t('Grok 外发调查', 'Grok outbound investigations');
    }
  };
  refine();
  if(activeStory) openStory(activeStory,false);
})();
