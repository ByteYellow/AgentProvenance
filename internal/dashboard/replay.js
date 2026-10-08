'use strict';
// Static replay is a reader for server-exported evidence. It cannot collect,
// import private runs, execute commands or produce new attribution edges.
window.AgentProvReplay = (() => {
  const root = new URL(document.querySelector('meta[name="agentprov-site-root"]').content, location.href);
  const cache = new Map(), sizes=new Map(); let cacheBytes=0;
  const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', {fatal:true});
  let manifestPromise;
  const copy = value => structuredClone(value);
  function fail(message) { throw new Error(message); }
  async function asset(ref) {
    if (!ref || !/^data\/[a-f0-9]{64}\.json\.gz$/.test(ref.path) || ref.sha256!==ref.path.slice(5,69) || !Number.isSafeInteger(ref.bytes) || ref.bytes < 0 || ref.bytes > 64 * 1024 * 1024) fail('Invalid replay asset');
    if (cache.has(ref.path)) { const value=cache.get(ref.path);cache.delete(ref.path);cache.set(ref.path,value);return value; }
    const pending = (async()=>{
      const response=await fetch(new URL(ref.path,root));
      if(!response.ok)fail('Replay data could not be loaded: HTTP '+response.status);
      // Some static hosts transparently decode Content-Encoding: gzip.
      let bytes=new Uint8Array(await response.arrayBuffer());
      if(bytes[0]===0x1f&&bytes[1]===0x8b){
        const stream=new Response(bytes).body.pipeThrough(new DecompressionStream('gzip'));
        bytes=new Uint8Array(await new Response(stream).arrayBuffer());
      }
      if(bytes.length!==ref.bytes)fail('Replay data size check failed');
      const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(n=>n.toString(16).padStart(2,'0')).join('');
      if(digest!==ref.sha256)fail('Replay data integrity check failed');
      return JSON.parse(decoder.decode(bytes));
    })();
    cache.set(ref.path,pending);sizes.set(ref.path,ref.bytes);cacheBytes+=ref.bytes;
    const remove=key=>{cacheBytes-=sizes.get(key)||0;sizes.delete(key);cache.delete(key);};
    while(cache.size>1&&(cache.size>12||cacheBytes>32*1024*1024))remove(cache.keys().next().value);
    try{return await pending;}catch(error){remove(ref.path);throw error;}
  }
  async function manifest(){
    if(!manifestPromise)manifestPromise=fetch(new URL('replay-manifest.json',root)).then(r=>{if(!r.ok)fail('Replay catalog unavailable');return r.json();}).then(v=>{if(v.schema_version!=='agentprovenance.static_replay/v1')fail('Unsupported replay format');return v;});
    return manifestPromise;
  }
  const clamp=(v,def,min,max)=>{const n=/^-?\d+$/.test(v||'')?Number(v):def;return Math.max(min,Math.min(max,n));};
  function overlays(manifest,wanted,nodes,present){
    let tags=[];
    if(manifest.query.focus){
      for(const n of manifest.nodes){
        if(!present.has(n.id)&&n.kind!=='egress_group')continue;
        if(wanted.includes('risk')&&n.risk)tags.push({target_id:n.id,kind:'risk',label:n.risk,severity:n.risk});
        if(wanted.includes('trust')&&n.trust_origin)tags.push({target_id:n.id,kind:'trust_origin',label:n.trust_origin});
      }
    }else tags=(manifest.overlays||[]).filter(t=>wanted.includes(t.kind==='trust_origin'?'trust':t.kind));
    if(tags.length)manifest.overlays=tags;else delete manifest.overlays;
    if(wanted.length)manifest.query.overlays=wanted;else delete manifest.query.overlays;
  }
  function lensView(data,p){
    const lens=p.get('lens')||'default',detail=p.get('detail')||'summary',focus=(p.get('focus')||'').trim();
    const view=data.views[lens+'/'+detail];if(!view)fail('Unknown graph view');
    const result=copy(view.manifest),wanted=[...new Set(p.getAll('overlay').flatMap(s=>s.split(',')).filter(v=>v==='risk'||v==='trust'))];
    if(focus){
      if(!Object.hasOwn(data.nodes,focus))fail('The recorded node is not available in this replay');
      const ids=new Set([focus]),selected=[];
      (view.focus_edges||[]).forEach((e,i)=>{
        const direct=e.from_id===focus||e.to_id===focus||e.from_id.includes(focus)||e.to_id.includes(focus);
        const chain=['runtime_event_policy_decision','policy_decision_risk_signal','risk_signal_response_action'].includes(e.edge_type);
        if(direct||(chain&&(ids.has(e.from_id)||ids.has(e.to_id)))){ids.add(e.from_id);ids.add(e.to_id);selected.push({edge:e,priority:view.priorities[i]});}
      });
      selected.sort((a,b)=>a.priority-b.priority);
      const limited=selected.slice(0,500).map(v=>v.edge),used=new Set([focus]);limited.forEach(e=>{used.add(e.from_id);used.add(e.to_id);});
      const extras=new Set(limited.filter(e=>e.edge_type==='possible_sensitive_data_flow_summary').map(e=>e.to_id));
      result.nodes=[...used].map(id=>extras.has(id)?view.extra_nodes[id]:data.nodes[id]);
      const added=[...extras].filter(id=>(view.added_nodes||[]).includes(id)).length;
      result.nodes.sort((a,b)=>(a.kind<b.kind?-1:a.kind>b.kind?1:0)||(a.id<b.id?-1:a.id>b.id?1:0));
      result.edges=limited.filter(e=>!e.derived);result.derived_edges=limited.filter(e=>e.derived);if(!result.derived_edges.length)delete result.derived_edges;
      Object.assign(result.query,{focus,truncated:selected.length>500,node_count:result.nodes.length,edge_count:limited.length,derived_edge_count:limited.filter(e=>e.derived).length,omitted_nodes:Math.max(0,view.total_nodes+added-result.nodes.length),omitted_edges:Math.max(0,view.total_edges-limited.length)});
      for(const key of ['omitted_nodes','omitted_edges'])if(!result.query[key])delete result.query[key];
      result.summary=[`lens=${lens} layout=${result.query.layout_hint}`,`detail=${detail} raw_events=${result.query.raw_event_count} nodes=${result.nodes.length} edges=${result.edges.length} derived_edges=${result.query.derived_edge_count} omitted_nodes=${result.query.omitted_nodes||0} omitted_edges=${result.query.omitted_edges||0}`];
    }
    overlays(result,wanted,data.nodes,new Set(data.present));return result;
  }
  function pageEvents(events,p,extra={}){const total=events.length,limit=clamp(p.get('limit'),50,1,500),offset=clamp(p.get('offset'),0,0,extra.schema_version?1000000000:total);return {...extra,events:events.slice(offset,offset+limit),total,limit,offset};}
  function filterEvents(events,p,run){
    const refs=[...new Set([...p.getAll('ref'),p.get('refs')||''].flatMap(v=>v.split(',')).map(v=>v.trim()).filter(Boolean))];
    if(refs.length){const ids=new Set(refs.flatMap(ref=>ref.startsWith('runtime_event/')?[ref.slice(14)]:(run.event_refs[ref]||[])));return events.filter(e=>ids.has(e.id));}
    const lens=p.get('lens')||'',group=(p.get('group')||'').trim(),focus=(p.get('focus')||'').trim();
    const q=copy(run.filters[lens+'/'+group]||run.filters[lens+'/']||{});
    q.Type=p.get('type')||'';q.ToolCallID=p.get('tool_call')||'';q.ProcessID=p.get('process')||'';q.PID=p.get('pid')||'';
    if(focus.startsWith('runtime_event/'))q.IDs=[focus.slice(14)];else if(focus.startsWith('runtime_process/pid/'))q.PID=focus.slice(20);else if(focus.startsWith('process/'))q.ProcessID=focus;else if(focus&&!focus.includes('/'))q.ToolCallID=focus;
    return events.filter(e=>{
      if(q.None||(q.IDs?.length&&!q.IDs.includes(e.id))||(q.Types?.length&&!q.Types.includes(e.event_type)))return false;
      for(const [a,b] of [['Type','event_type'],['ToolCallID','tool_call_id'],['ProcessID','process_id'],['PID','pid']])if(q[a]&&String(e[b])!==String(q[a]))return false;
      const payload=String(e.payload||'').replace(/[A-Z]/g,c=>c.toLowerCase());
      return (!q.PayloadAny?.length||q.PayloadAny.some(v=>payload.includes(v)))&&!(q.PayloadNot||[]).some(v=>payload.includes(v));
    });
  }
  function contextEntries(data,p,run){
    const latest=new Set(data.latest),node=p.get('node'),linked=new Set(node?data.nodes[node]||[]:[]),group=p.get('group')||'';
    if(!['','conversation','configuration'].includes(group))fail('Unknown record group');
    const revisions=p.get('revisions')==='true';
    const entries=data.entries.filter(e=>{
      if(!revisions&&!latest.has(e.id))return false;if(node&&!linked.has(e.id))return false;
      for(const [key,value] of [['source',e.source.id],['session',e.source.session_id],['kind',e.kind],['entry',e.id],['tool_call',e.tool_call_id]])if(p.get(key)&&p.get(key)!==value)return false;
      return !group||(group==='configuration'?['configuration','approval'].includes(e.kind):['message','tool_call','tool_result','task','session'].includes(e.kind));
    });
    const limit=clamp(p.get('limit'),50,1,200),query=new URLSearchParams(p);query.delete('cursor');query.delete('limit');query.sort();const fingerprint=query.toString();
    let offset=0;if(p.get('cursor')){let c;try{c=JSON.parse(decodeURIComponent(atob(p.get('cursor'))));}catch{fail('Invalid replay cursor');}if(c.query!==fingerprint||!Number.isSafeInteger(c.offset)||c.offset<0||c.offset>entries.length)fail('Cursor does not match this query');offset=c.offset;}
    const page={schema_version:'agentprovenance.agent_context/v1',run_id:run,entries:entries.slice(offset,offset+limit),limit,has_more:offset+limit<entries.length};
    if(page.has_more)page.next_cursor=btoa(encodeURIComponent(JSON.stringify({query:fingerprint,offset:offset+limit})));return page;
  }
  function range(value,fallback,min,max,label){
    if(value===null)return fallback;
    if(!/^[0-9]+$/.test(value))fail('Invalid '+label);
    const n=Number(value);if(!Number.isSafeInteger(n)||n<min||n>max)fail('Invalid '+label);return n;
  }
  async function contentPage(pages,p,artifact){
    if(!pages)fail('Recorded content was not found in this replay');
    const offset=range(p.get('offset'),0,0,Number.MAX_SAFE_INTEGER,'content offset'),limit=range(p.get('limit'),65536,4,262144,'content limit');
    let index=pages.offsets.findLastIndex(n=>n<=offset);if(index<0)fail('Invalid content offset');
    const result=copy(await asset(pages.pages[index]));
    if(result.total_bytes==null)return result;
    if(offset>result.total_bytes)fail('Content offset is out of range');
    const chunks=[encoder.encode(result.content||'')];let end=pages.offsets[index]+chunks[0].length;
    while(end<Math.min(offset+limit,result.total_bytes)&&index+1<pages.pages.length){const next=await asset(pages.pages[++index]);const chunk=encoder.encode(next.content||'');chunks.push(chunk);end+=chunk.length;}
    const bytes=new Uint8Array(chunks.reduce((n,c)=>n+c.length,0));let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.length;}
    const start=offset-result.offset;if(start<bytes.length&&(bytes[start]&0xc0)===0x80)fail('Content offset is not a UTF-8 boundary');
    let finish=Math.min(start+limit,bytes.length);while(finish<bytes.length&&(bytes[finish]&0xc0)===0x80)finish--;
    result.content=decoder.decode(bytes.slice(start,finish));result.offset=offset;result.next_offset=offset+finish-start;result.has_more=result.next_offset<result.total_bytes;
    if(artifact){result.truncated=result.has_more;if(!result.content)delete result.content;}return result;
  }
  async function query(value){
    const u=new URL(value,location.href),p=u.searchParams,path=u.pathname.replace(/^\/api\//,''),catalog=await manifest();
    if(path==='runs')return copy(catalog.summaries);
    const id=p.get('run');let run=catalog.runs[id];
    if(path==='frameworks'&&!run)run=catalog.runs[catalog.summaries[0].run];
    if(!run)fail('The run was not found in this public demo');
    if(path==='lens'){
      const index=await asset(run.lenses),key=(p.get('lens')||'default')+'/'+(p.get('detail')||'summary');
      if(!index.views[key])fail('Unknown graph view');
      const [view,nodes]=await Promise.all([asset(index.views[key]),asset(p.get('focus')?index.focus_nodes:index.nodes)]);
      return lensView({views:{[key]:view},nodes,present:index.present},p);
    }
    if(path==='timeline')return pageEvents(await asset(run.timeline)||[],p);
    if(path==='events')return pageEvents(filterEvents(await asset(run.events),p,run),p,{schema_version:'agentprovenance.dashboard_events/v1',filter:{run:id,lens:p.get('lens')||'',group:p.get('group')||'',focus:p.get('focus')||'',type:p.get('type')||'',tool_call:p.get('tool_call')||'',pid:p.get('pid')||''}});
    if(path==='artifact'){const data=await asset(run.artifacts),key=(p.get('view_lang')||'en')+'/'+(p.get('mode')||'body')+'/'+p.get('node');return contentPage(data[key],p,true);}
    if(path.startsWith('context/')&&path!=='context/overview'){
      const data=await asset(run.context);
      if(path==='context/entries')return contextEntries(data,p,id);
      if(path==='context/content')return contentPage(data.content[p.get('ref')],p,false);
      if(path==='context/links'){const result=data.links[p.get('entry')];if(!result)fail('Session entry was not found');return copy(result);}
      if(path==='context/compare'){if(p.get('right_run')&&p.get('right_run')!==id)fail('Select snapshots from the current demo');const ref=data.comparisons[p.get('left')+'/'+p.get('right')];if(!ref)fail('Select two recorded snapshots of the same kind');return copy(await asset(ref));}
    }
    const key=path==='compliance'?path+'/'+p.get('framework'):path;
    if(!Object.hasOwn(run.api,key))fail('Unsupported public replay query');return copy(await asset(run.api[key]));
  }
  return Object.freeze({query});
})();
