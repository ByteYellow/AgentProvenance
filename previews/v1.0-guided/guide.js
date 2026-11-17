/* Review-only guidance. Evidence and graph actions use the existing reader. */
(() => {
  'use strict';
  const $=id=>document.getElementById(id);
  const zh=()=>document.documentElement.lang.startsWith('zh');
  const t=(cn,en)=>zh()?cn:en;
  const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const script=new URL(document.currentScript.src);
  const rootURL=new URL('./',script);
  const home=()=>new URL('?lang='+document.documentElement.lang,rootURL).href;
  const route=(path,params={})=>{const u=new URL(path,rootURL);u.search=new URLSearchParams(params);return u.href;};

  if($('app')) {
    function guideHome() {
      if(document.querySelector('.journey-home-start'))return;
      const section=document.createElement('div');section.className='journey-home-start';
      const lang=zh()?'zh-CN':'en';
      section.innerHTML=`<span><strong>${t('第一次看？从一次报表修复开始','New here? Start with a report repair')}</strong><br>${t('先读任务，再检查文件与外联，最后比较修复结果。','Read the task, inspect files and connections, then compare the repair.')}</span><a href="${esc(route('current/investigation/'+lang+'/index.html',{run:'run-860466af8a9a',live:'0',read:'task'}))}">${t('跟随案例阅读','Follow the case')} →</a>`;
      document.querySelector('.section-nav')?.after(section);
      if(!section.isConnected)document.querySelector('#featured')?.before(section);
      const labels={investigation:t('报表为什么失败，修复改了什么？','Why did the report fail, and what changed?'),remote:t('远端修改和执行的是同一份文件吗？','Did remote edits and execution use the same files?'),native:t('浏览器实际访问了什么，拿到了什么？','What did the browser visit and return?'),team:t('谁发起任务，谁执行，消息如何传递？','Who requested and performed the work?')};
      document.querySelectorAll('[data-case]').forEach(card=>{
        const key=card.dataset.case;
        const description=card.querySelector('.description');
        if(description&&labels[key])description.textContent=labels[key];
        const primary=card.querySelector('.story-bottom>a');
        if(primary&&['remote','native'].includes(key)){
          const u=new URL(primary.href);u.searchParams.set('read',key==='remote'?'workspace':'native');primary.href=u;
        }
      });
      const mark=document.createElement('span');mark.className='journey-review';mark.textContent=t('引导预览','Guidance preview');document.querySelector('.top-nav')?.after(mark);
    }
    guideHome();
    new MutationObserver(guideHome).observe($('app'),{childList:true});
    return;
  }
  if(!$('runoverview')||!window.AgentContextUI)return;
  document.body.classList.add('journey-reading');
  const toolbar=document.querySelector('[data-site-navigation]')||document.createElement('nav');toolbar.className='journey-toolbar';toolbar.setAttribute('aria-label',t('案例阅读','Case guide'));
  toolbar.innerHTML=`<a href="${esc(home())}">← ${t('示例库','Demos')}</a><strong id="journey-name"></strong><button id="journey-next" hidden></button><button class="journey-back" id="journey-return">${t('返回案例概览','Back to case overview')}</button>`;
  if(!toolbar.isConnected)document.querySelector('body>header').before(toolbar);
  const intro=document.createElement('div');intro.className='journey-intro';intro.id='journey-intro';
  $('runoverview').querySelector('h2').after(intro);
  const more=document.createElement('details');more.className='journey-more';more.id='journey-more';
  more.innerHTML=`<summary>${t('更多调查视图与访问控制','More investigation views and access control')}</summary>`;
  $('askgrid').before(more);more.append($('askgrid'));more.append(document.querySelector('.access-bar'));
  $('journey-return').onclick=()=>{$('runoverview').scrollIntoView({block:'start',behavior:'smooth'});$('journey-intro').querySelector('button')?.focus({preventScroll:true});};
  let current='',sequence=0,first=true;
  const entryRoute=location.pathname;
  const initialAction=new URL(location.href).searchParams.get('read');
  const steps=(pairs)=>pairs.map(([id,cn,en])=>({id,label:t(cn,en)}));
  function scene(run) {
    if(entryRoute.includes('/workspace/')&&run==='run-w01-445a3a164ae14723b82f90634cff96f5')return {
      title:t('远端修改与执行，是否使用同一份文件？','Did remote editing and execution use the same files?'),
      summary:t('这次受控任务在远端读取、修改并运行文件，生成 result.txt。操作回执保存了输入与输出版本，最终文件也保留了正文。','This controlled task reads, edits and runs files remotely, producing result.txt. Operation receipts retain input and output revisions, and the final file has saved content.'),
      steps:steps([['workspace','核对读改跑','Inspect read, edit and run'],['file','阅读 result.txt','Read result.txt'],['coverage','检查采集范围','Inspect capture scope'],['delivery','查看交付信息','Inspect delivery']]),file:'workspace_file/result.txt'};
    if(entryRoute.includes('/browser/')&&run==='run-da25e015ca1f')return {
      title:t('浏览器访问了什么，返回了什么？','What did the browser visit and return?'),
      summary:t('Agent 执行网页任务，留下操作、请求和截图。这份实录采集应用上下文，未开启原生 Sensor。','An agent performed a web task, leaving operations, requests and screenshots. This recording captures application context with the native Sensor off.'),
      steps:steps([['task','阅读任务','Read the task'],['native','追踪浏览器操作','Inspect browser operations'],['image','查看保存截图','View saved screenshot'],['coverage','检查采集范围','Inspect capture scope']])};
    if(entryRoute.includes('/investigation/')&&['run-860466af8a9a','run-3bfc6838a9c6'].includes(run))return {
      title:t('报表为什么失败，修复改变了什么？','Why did the report fail, and what did the repair change?'),
      summary:t('DeepSeek 在检查与修复任务中记录了工具输出、文件和网络行为。先读当时的任务与结果，再对照两次执行。','DeepSeek recorded tool output, files and network activity during inspection and repair. Read the task and its results, then compare the two executions.'),
      steps:steps([['task','阅读任务与结果','Read task and results'],['files','追踪文件变化','Inspect file changes'],['compare','对比修复前后','Compare before and after'],['coverage','检查采集范围','Inspect capture scope']])};
    if(run==='run-double-attempt')return {
      title:t('谁发起任务，谁实际执行？','Who requested the work, and who executed it?'),
      summary:t('Alice 与 Bob 的消息、委派和工具调用保留在同一份历史实录中。沿已记录的关系查看任务传递与执行结果。','Alice and Bob exchanged messages, delegated work and invoked tools. Follow the recorded relationships to inspect the handoff and its results.'),
      steps:steps([['team','查看协作关系','Inspect collaboration'],['calls','阅读调用记录','Read recorded calls'],['search','检索证据','Search evidence'],['coverage','检查采集范围','Inspect capture scope']])};
    return {title:t('这次执行留下了哪些证据？','What evidence did this run leave?'),summary:t('从任务和工具结果开始，沿文件或运行时记录继续调查。执行结果、采集范围与交付状态分别查看。','Start with the task and tool results, then follow file or runtime records. Inspect execution results, capture scope and delivery separately.'),steps:steps([['task','任务与结果','Task and results'],['graph','关联图谱','Evidence graph'],['coverage','采集范围','Capture scope'],['delivery','交付信息','Delivery details']])};
  }
  function notice(text,error=false){const node=$('journey-selection');node.textContent=text;node.setAttribute('role',error?'alert':'status');}
  function reveal(id){$(id).style.scrollMarginTop='58px';$(id).scrollIntoView({block:'start',behavior:'smooth'});}
  async function act(id,run,data) {
    if(run!==current)return;
    intro.dataset.started='true';
    const index=data.steps.findIndex(step=>step.id===id),next=data.steps[index+1];
    $('journey-name').textContent=index<0?t('案例阅读','Case guide'):`${index+1}/${data.steps.length} · ${data.steps[index].label}`;
    $('journey-next').hidden=index<0||!next;
    if(index>=0&&next){$('journey-next').textContent=t('下一步：','Next: ')+next.label;$('journey-next').onclick=()=>act(next.id,run,data);}
    intro.querySelectorAll('[data-journey]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.journey===id)));
    notice('');
    try {
      if(id==='task'){window.AgentContextUI.open('conversation');reveal('agentcontext');}
      else if(id==='coverage'){window.AgentContextUI.open('coverage');reveal('agentcontext');}
      else if(id==='workspace'||id==='native'){
        window.AgentContextUI.open();$(id==='workspace'?'portable-workspace-tab':'portable-native-tab').click();reveal('agentcontext');
      } else if(id==='file'){
        await window.AgentContextUI.selectGraph(data.file,null,true);window.AgentWorkspaceUI.show('content');reveal('inspection');
      } else if(id==='files'||id==='team'||id==='calls'){
        const node={files:'overview/files',team:'overview/agent_network',calls:'overview/tool_calls'}[id];
        $('askgrid').querySelector(`[data-node="${node}"]`).click();reveal(id==='calls'?'inspection':'graphcard');
      } else if(id==='compare'){
        const u=new URL(location.href);u.searchParams.set('compare_a','run-860466af8a9a');u.searchParams.set('compare_b','run-3bfc6838a9c6');
        await window.AgentCompareUI.openFromURL(u.searchParams);
      } else if(id==='search')await window.AgentSearchUI.open();
      else if(id==='delivery')$('portable-delivery-details').click();
      else if(id==='image'){
        let cursor='',attachment=null;const seen=new Set();
        do {
          const page=await window.j('/api/context/entries?'+new URLSearchParams({run,limit:'100',cursor}));
          attachment=page.entries.flatMap(entry=>entry.attachments||[]).find(a=>a.media_type==='image/png'&&a.state==='stored');
          if(attachment||!page.has_more)break;
          if(!page.next_cursor||seen.has(page.next_cursor))throw Error('Invalid evidence continuation');
          cursor=page.next_cursor;seen.add(cursor);
        }while(run===current);
        if(run!==current)return;
        if(attachment)await window.AgentPortableEvidenceUI.openAttachment(attachment,run);
        else notice(t('这份记录中没有已保存的截图。','No saved screenshot is available in this recording.'));
      } else reveal('graphcard');
    } catch(error){if(run===current)notice(t('未能打开这条证据：','Could not open this evidence: ')+error.message,true);}
  }
  function mirrorStatus(){
    if(!$('journey-capture'))return;
    $('journey-capture').textContent=$('context-nav-coverage').textContent;
    const risk=$('askgrid').querySelector('[data-node="overview/risks"]');
    $('journey-risk').textContent=risk?.querySelector('.m')?.textContent||t('风险记录正在加载','Loading risk records');
  }
  async function refresh(run) {
    if(!run||run===current)return;
    current=run;const token=++sequence,data=scene(run);
    delete intro.dataset.started;
    $('journey-name').textContent=t('案例阅读','Case guide');
    $('journey-next').hidden=true;
    intro.innerHTML=`<h3>${esc(data.title)}</h3><p class="journey-description">${esc(data.summary)}</p><nav class="journey-steps" aria-label="${t('阅读路线','Reading path')}">${data.steps.map((step,i)=>`<button data-journey="${step.id}" aria-pressed="false"><span class="journey-number">${i+1}</span>${esc(step.label)}</button>`).join('')}</nav><div class="journey-status"><span id="journey-counts">${t('正在加载记录','Loading records')}</span><button id="journey-risk"></button><button id="journey-capture"></button></div><p class="journey-selection" id="journey-selection" role="status"></p>`;
    intro.querySelectorAll('[data-journey]').forEach(button=>button.onclick=()=>act(button.dataset.journey,run,data));
    $('journey-capture').onclick=()=>act('coverage',run,data);
    $('journey-risk').onclick=()=>{$('askgrid').querySelector('[data-node="overview/risks"]')?.click();reveal('graphcard');};
    mirrorStatus();
    try{
      const overview=await window.j('/api/context/overview?'+new URLSearchParams({run}));
      if(token!==sequence)return;
      const counts=[];
      if(Number.isSafeInteger(overview.messages))counts.push(t(`${overview.messages} 条消息`,`${overview.messages} messages`));
      if(Number.isSafeInteger(overview.tool_calls))counts.push(t(`${overview.tool_calls} 次工具调用`,`${overview.tool_calls} tool calls`));
      $('journey-counts').textContent=counts.length?counts.join(' · '):t('该实录未保存会话计数，可从图谱和原始事件查看执行记录','This recording has no session counts. Explore its graph and original events.');
      $('journey-counts').dataset.loaded='true';
      if(first&&initialAction&&data.steps.some(step=>step.id===initialAction)){first=false;await act(initialAction,run,data);}
      first=false;
    }catch(error){if(token===sequence)notice(t('案例计数加载失败：','Case counts could not be loaded: ')+error.message,true);}
  }
  const original=window.AgentContextUI.setRun;
  window.AgentContextUI.setRun=function(run,...args){const value=original.call(this,run,...args);refresh(run);return value;};
  new MutationObserver(mirrorStatus).observe($('context-nav-coverage'),{childList:true,subtree:true,characterData:true});
  new MutationObserver(mirrorStatus).observe($('askgrid'),{childList:true,subtree:true});
  function labelRuns(){
    const labels={'run-w01-445a3a164ae14723b82f90634cff96f5':t('远端工作区 · 读改跑','Remote workspace · Read, edit and run'),'run-da25e015ca1f':t('浏览器 · 网页任务','Browser · Web task')};
    for(const option of $('runsel').options){const label=labels[option.value];if(label&&option.textContent!==label){option.title=option.value;option.textContent=label;}}
  }
  new MutationObserver(labelRuns).observe($('runsel'),{childList:true,subtree:true});labelRuns();
  new MutationObserver(()=>{
    const host=$('portable-dialog-body'),section=host.querySelector('.portable-workspace-result');
    if(!section||section.dataset.guided)return;
    section.dataset.guided='true';
    const raw=section.nextElementSibling;
    if(raw?.tagName==='PRE'){
      const details=document.createElement('details');details.className='journey-raw';
      const summary=document.createElement('summary');summary.textContent=t('原始操作结果','Original operation result');
      raw.before(details);details.append(summary,raw);
    }
    const title=section.querySelector('h3'),identity=title?.nextElementSibling;
    if(identity?.tagName==='DL'){
      const details=document.createElement('details');details.className='journey-raw';
      const summary=document.createElement('summary');summary.textContent=t('工作区与版本身份','Workspace and revision identity');
      details.append(summary,title,identity);section.append(details);
    }
    const note=section.querySelector('.portable-note');
    if(note?.textContent.includes(t('下方保留了','Inspect the saved')))note.remove();
  }).observe($('portable-dialog-body'),{childList:true,subtree:true});
  refresh($('runsel').value||new URL(location.href).searchParams.get('run'));
})();
