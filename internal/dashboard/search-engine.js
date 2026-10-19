// One literal-text scanner for the live catalog and exported replay catalog.
// A search retains one catalog page, one body page and one result page.
window.AgentEvidenceSearch = (() => {
  'use strict';
  const encoder = new TextEncoder();
  const bytes = value => encoder.encode(value).length;
  const params = values => new URLSearchParams(Object.entries(values).filter(([,v])=>v !== '' && v != null));
  const expression = query => new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'iu');
  const check = signal => signal?.throwIfAborted();
  function snippet(text, match) {
    let start = Math.max(0,match.index-160), end = Math.min(text.length,match.index+match[0].length+240);
    if(start && /[\uDC00-\uDFFF]/.test(text[start])) start--;
    if(end<text.length && /[\uDC00-\uDFFF]/.test(text[end])) end++;
    const previous = text.lastIndexOf('\n',match.index), next = text.indexOf('\n',match.index+match[0].length);
    if(previous>=start) start=previous+1;
    if(next>=0 && next<end) { const second=text.indexOf('\n',next+1);if(second>=0 && second<end)end=second; }
    return {text:text.slice(start,end),start:match.index-start,end:match.index-start+match[0].length,from:start};
  }
  const metadata = source => [source.label,source.source_id,source.agent_id,source.tool_call_id].filter(Boolean).join('\n');
  async function scan(source, scope, query, get, signal, progress) {
    const re = expression(query), meta = metadata(source), metaMatch = re.exec(meta);
    if (!source.node && (source.content?.state !== 'stored' || !source.content.ref)) {
      const state=source.content?.state || 'unavailable';
      const reason=source.content?.reason;
      return {state,reason,hit:metaMatch ? {source,excerpt:snippet(meta,metaMatch),offset:0,matched_in:'metadata',state,reason} : null};
    }
    let offset=0,tail='',tailOffset=0,identity=null;
    for (;;) {
      check(signal);
      const route = source.node ? '/api/artifact?' : '/api/context/content?';
      const p = source.node ? {node:source.node,mode:'body',view_lang:scope.lang} : {ref:source.content.ref};
      const page=await get(route+params({...p,run:scope.run,offset,limit:65536}),{signal});
      check(signal);
      const state=page.content_state || 'stored';
      if (page.kind === 'unavailable' || page.kind === 'binary' || state !== 'stored') {
        return {state,reason:page.reason,hit:metaMatch ? {source,excerpt:snippet(meta,metaMatch),offset:0,matched_in:'metadata',state,reason:page.reason} : null};
      }
      const content=page.content ?? '';
      if(typeof content !== 'string' || page.offset !== offset || !Number.isSafeInteger(page.next_offset) || page.next_offset !== offset+bytes(content) || !Number.isSafeInteger(page.total_bytes) || page.total_bytes>33554432 || page.next_offset>page.total_bytes || (page.has_more && page.next_offset<=offset)) throw new Error('Invalid saved-content continuation');
      const revision=JSON.stringify([page.sha256,page.total_bytes]);
      if(identity!==null && identity!==revision)throw new Error('Saved content changed during search. Retry to continue.');
      identity=revision;
      progress(bytes(content));
      const text=tail+content,match=re.exec(text);
      if(match || metaMatch){
        const excerpt=snippet(match ? text : meta,match || metaMatch);
        const hit={source,excerpt,offset:match ? tailOffset+bytes(text.slice(0,excerpt.from)) : 0,
          matched_in:match ? 'body' : 'metadata',sha256:page.sha256,redacted:Boolean(page.redacted),state};
        return {state,hit};
      }
      if(!page.has_more)return {state,hit:null};
      // Keep enough overlap for a literal crossing the stored chunk boundary.
      let start=Math.max(0,text.length-query.length-240);
      if(start && /[\uDC00-\uDFFF]/.test(text[start]))start--;
      tail=text.slice(start);tailOffset=page.next_offset-bytes(tail);offset=page.next_offset;
    }
  }
  function create({query,category='',scope,get}) {
    if(typeof query!=='string' || !query.trim() || query.length>256)throw new Error('Enter a keyword of 1 to 256 characters.');
    if(!['','messages','tools','configuration','files','runtime'].includes(category))throw new Error('Invalid search category');
    let page=null,index=0,cursor='',done=false,busy=false;
    const stats={scanned:0,bytes:0,unavailable:0,policy_omitted:0,states:{},excluded:0};
    async function next({signal,onProgress=()=>{}}={}) {
      if(busy)throw new Error('Search is already running');
      busy=true;
      const hits=[],groups=new Map();let matched=0;
      try{
        while(!done && matched<50){
          check(signal);
          if(!page || index>=page.sources.length){
            if(page && !page.has_more){done=true;break;}
            const value=await get('/api/search/sources?'+params({run:scope.run,harness:scope.harness,session:scope.session_id,cursor}),{signal});
            check(signal);
            if(value.schema_version!=='agentprovenance.search_sources/v1' || value.run_id!==scope.run || !Array.isArray(value.sources) || value.sources.length>50 || (value.has_more && (!value.next_cursor || value.next_cursor===cursor)))throw new Error('Invalid search source page');
            page=value;index=0;cursor=value.next_cursor || '';
            if(!page.sources.length){onProgress({...stats});continue;}
          }
          const source=page.sources[index];
          if(category && source.category!==category){stats.excluded++;index++;continue;}
          const result=await scan(source,scope,query,get,signal,n=>{stats.bytes+=n;onProgress({...stats});});
          index++;stats.scanned++;
          if(result.state!=='stored'){
            if(result.reason==='capture_policy')stats.policy_omitted++;
            else{stats.unavailable++;stats.states[result.state]=(stats.states[result.state]||0)+1;}
          }
          if(result.hit){
            matched++;
            const hit=result.hit,key=hit.matched_in==='body' && hit.sha256 ? source.category+'/'+hit.sha256 : source.id;
            if(groups.has(key))groups.get(key).sources.push(source);
            else{hit.sources=[source];groups.set(key,hit);hits.push(hit);}
          }
          onProgress({...stats});
        }
        if(page && index>=page.sources.length && !page.has_more)done=true;
        return {hits,has_more:!done,stats:structuredClone(stats)};
      }catch(error){
        return {hits,has_more:!done,stats:structuredClone(stats),cancelled:Boolean(signal?.aborted),error:signal?.aborted ? '' : error.message};
      }finally{busy=false;}
    }
    return {next};
  }
  function highlight(element,query) {
    if(!query || query.length>256)return;
    const re=new RegExp(expression(query).source,'giu'),walker=document.createTreeWalker(element,NodeFilter.SHOW_TEXT),texts=[];
    while(walker.nextNode())texts.push(walker.currentNode);
    let count=0;
    for(const text of texts){
      const value=text.nodeValue,fragment=document.createDocumentFragment();let last=0,match;
      re.lastIndex=0;
      while(count<2000 && (match=re.exec(value))){
        fragment.append(document.createTextNode(value.slice(last,match.index)));
        const mark=document.createElement('mark');mark.textContent=match[0];fragment.append(mark);
        last=match.index+match[0].length;count++;
      }
      if(last){fragment.append(document.createTextNode(value.slice(last)));text.replaceWith(fragment);}
      if(count>=2000)break;
    }
  }
  return Object.freeze({create,scan,snippet,highlight});
})();
