(function(root){
  'use strict';
  const dimensions=['configuration','files','network','outbound','access_control'];
  const maxRecords=50000,maxSources=100000;
  async function load({run,get,signal,onProgress=()=>{}}){
    const result={run,records:[],issues:[],sources:0,complete:false,coverage:null};
    result.coverage=await get('/api/context/overview?'+new URLSearchParams({run}),{signal});
    let cursor='',seen=new Set();
    for(;;){
      if(signal?.aborted)throw new DOMException('Aborted','AbortError');
      const page=await get('/api/compare/records?'+new URLSearchParams({run,cursor}),{signal});
      if(page.schema_version!=='agentprovenance.comparison_records/v1'||page.run_id!==run||!Array.isArray(page.records)||!Array.isArray(page.issues))throw new Error('Invalid comparison records');
      const remaining=maxRecords-result.records.length;
      result.records.push(...page.records.slice(0,remaining));result.issues.push(...page.issues);result.sources+=page.sources_read;
      if(result.issues.length>2000)result.issues=[...result.issues.slice(0,1999),{dimension:'all',code:'additional_comparison_issues'}];
      onProgress(result.sources);
      if(page.records.length>remaining || page.has_more && (result.records.length>=maxRecords || result.sources>=maxSources)){
        result.issues.push({dimension:'all',code:'comparison_record_limit'});return result;
      }
      if(!page.has_more){result.complete=true;return result;}
      if(!page.next_cursor||seen.has(page.next_cursor))throw new Error('Comparison cursor did not advance');
      seen.add(page.next_cursor);cursor=page.next_cursor;
    }
  }
  function build(a,b){
    const groups=new Map();
    for(const [side,data] of [['a',a],['b',b]])for(const record of data.records){
      if(!dimensions.includes(record.dimension))continue;
      if(!groups.has(record.key))groups.set(record.key,{key:record.key,dimension:record.dimension,label:record.label,operation:record.operation,a:[],b:[]});
      groups.get(record.key)[side].push(record);
    }
    const limited=(data,row,records)=>!data.complete||data.issues.some(i=>
      ['all','runtime'].includes(i.dimension)||i.dimension===row.dimension&&(!i.source_id||records.some(r=>r.evidence.id===i.source_id)));
    const values=records=>[...new Set(records.map(r=>r.value?.sha256))].sort().join(',');
    const rows=[...groups.values()].map(row=>{
      if(![...row.a,...row.b].some(r=>r.value?.present&&r.value.sha256))row.status='unknown';
      else if(!row.a.length)row.status='only_b';
      else if(!row.b.length)row.status='only_a';
      else if([...row.a,...row.b].some(r=>!r.value?.present||!r.value.sha256||r.partial)||limited(a,row,row.a)||limited(b,row,row.b))row.status='unknown';
      else row.status=values(row.a)===values(row.b)?'common':'different';
      return row;
    });
    // Put inspectable content and decisions before lower-level observations.
    const priority=row=>({saved_file_version:0,recorded_file_change:1,audit_decision:0,configuration_declaration:1,state_snapshot:2,collection_status:3}[row.operation]??4);
    const statusOrder={different:0,only_a:1,only_b:1,unknown:2,common:3};
    rows.sort((a,b)=>dimensions.indexOf(a.dimension)-dimensions.indexOf(b.dimension)||priority(a)-priority(b)||statusOrder[a.status]-statusOrder[b.status]||a.label.localeCompare(b.label)||a.key.localeCompare(b.key));
    const counts={};
    for(const dimension of dimensions){const selected=rows.filter(r=>r.dimension===dimension);counts[dimension]={total:selected.length,differences:selected.filter(r=>r.status!=='common'&&r.status!=='unknown').length,unknown:selected.filter(r=>r.status==='unknown').length};}
    const tasks=data=>data.records.filter(r=>r.dimension==='task');
    const ta=tasks(a),tb=tasks(b);
    const taskRelation=a.complete&&b.complete&&ta.length&&tb.length&&ta.every(r=>r.value?.sha256&&!r.partial)&&tb.every(r=>r.value?.sha256&&!r.partial)
      ? values(ta)===values(tb)?'matching_recorded_tasks':'different_recorded_tasks':'task_not_recorded';
    return {rows,counts,taskRelation};
  }
  function taskRecord(data){
    const tasks=data.records.filter(r=>r.dimension==='task'&&r.evidence.entry?.content.state==='stored');
    const roots=tasks.filter(r=>!r.evidence.entry.source?.parent_session_id);
    const candidates=roots.length?roots:tasks;
    return candidates.find(r=>r.evidence.entry.execution_scope==='current_execution')
      ||candidates.find(r=>r.evidence.entry.execution_scope!=='prior_context')||candidates[0];
  }
  root.AgentRunCompare={load,build,dimensions,taskRecord};
})(typeof window==='undefined'?globalThis:window);
