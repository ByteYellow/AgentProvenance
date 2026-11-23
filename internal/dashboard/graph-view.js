// The caller owns evidence and layout. This view owns only its SVG and viewport.
window.AgentGraphView = function({host,find,next,count,activate,scale,zoomAt,translate}) {
  const ns='http://www.w3.org/2000/svg';
  let svg,layout,signature,nodes=[],edges=[],matches=[],cursor=-1,pan,tabStop;
  const element=(parent,tag,attrs={},text)=>{
    const node=document.createElementNS(ns,tag);
    for(const [key,value] of Object.entries(attrs))node.setAttribute(key,value);
    if(text!==undefined)node.textContent=text;
    parent.append(node);return node;
  };
  const attr=(el,key,value)=>{if(el.getAttribute(key)!==String(value))el.setAttribute(key,value);};
  function resize(){
    if(!svg)return;
    const z=scale(layout.W);
    attr(svg,'width',Math.round(layout.W*z));attr(svg,'height',Math.round(layout.H*z));
  }
  function search(reset){
    const query=find.value.trim().toLowerCase(),old=reset?null:matches[cursor];
    matches=query?nodes.filter(n=>n.el.style.display!=='none'&&n.search.includes(query)):[];
    cursor=old?matches.indexOf(old):-1;
    for(const n of nodes)n.el.classList.toggle('graph-match',Boolean(query)&&n.el.style.display!=='none'&&n.search.includes(query));
    next.disabled=!matches.length;
    count.textContent=!query?'':!matches.length?translate('No matching nodes'):cursor<0?String(matches.length):(cursor+1)+' / '+matches.length;
  }
  function step(){
    if(!matches.length)return;
    cursor=(cursor+1)%matches.length;const node=matches[cursor].el;
    node.focus({preventScroll:true});node.scrollIntoView({block:'nearest',inline:'nearest'});
    count.textContent=(cursor+1)+' / '+matches.length;
  }
  find.addEventListener('input',()=>search(true));
  find.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();step();}});
  next.addEventListener('click',step);
  host.addEventListener('click',e=>{const node=e.target.closest('[data-id]');if(node)activate(node.dataset.id);});
  function setTabStop(node){
    if(node===tabStop)return;
    tabStop?.setAttribute('tabindex','-1');tabStop=node;node?.setAttribute('tabindex','0');
  }
  host.addEventListener('focusin',e=>{const node=e.target.closest('[data-id]');if(node)setTabStop(node);});
  host.addEventListener('keydown',e=>{const node=e.target.closest('[data-id]');if(!node)return;
    if(e.key==='Enter'||e.key===' '){e.preventDefault();activate(node.dataset.id);}
    if(e.key==='F3'&&matches.length){e.preventDefault();step();}
    if(['ArrowDown','ArrowRight','ArrowUp','ArrowLeft','Home','End'].includes(e.key)){
      e.preventDefault();const items=nodes.filter(n=>n.el.style.display!=='none').map(n=>n.el),i=items.indexOf(node);
      const k=e.key==='Home'?0:e.key==='End'?items.length-1:(i+(['ArrowLeft','ArrowUp'].includes(e.key)?-1:1)+items.length)%items.length;
      items[k]?.focus();
    }
  });
  host.addEventListener('wheel',e=>{
    if(!svg||!(e.ctrlKey||e.metaKey))return;
    e.preventDefault();const rect=host.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top;
    const before=scale(layout.W),left=host.scrollLeft+x,top=host.scrollTop+y;
    zoomAt(e.deltaY<0?1.15:1/1.15);const ratio=scale(layout.W)/before;
    host.scrollLeft=left*ratio-x;host.scrollTop=top*ratio-y;
  },{passive:false});
  host.addEventListener('pointerdown',e=>{
    if(e.pointerType!=='mouse'||e.button!==0||e.target.closest('[data-id]'))return;
    pan={id:e.pointerId,x:e.clientX,y:e.clientY,left:host.scrollLeft,top:host.scrollTop};
    host.setPointerCapture(e.pointerId);host.classList.add('panning');
  });
  host.addEventListener('pointermove',e=>{if(pan?.id===e.pointerId){host.scrollLeft=pan.left+pan.x-e.clientX;host.scrollTop=pan.top+pan.y-e.clientY;}});
  host.addEventListener('lostpointercapture',()=>{pan=null;host.classList.remove('panning');});
  new ResizeObserver(resize).observe(host);
  function build(key,g,L,nodeStyle,edgeLabel){
    signature=key;layout=L;nodes=[];edges=[];tabStop=null;host.replaceChildren();
    if(!g.nodes.length){svg=null;const empty=document.createElement('div');empty.className='empty';empty.textContent=translate('no nodes for this lens');host.append(empty);search(true);return;}
    svg=element(host,'svg',{viewBox:'0 0 '+L.W+' '+L.H,'font-family':'-apple-system,sans-serif'});
    const defs=element(svg,'defs');
    for(const [id,fill] of [['ah','#bcbcc2'],['ahl','#0071e3'],['ahd','#ff375f']]){
      const marker=element(defs,'marker',{id,markerUnits:'userSpaceOnUse',markerWidth:10,markerHeight:8,refX:8,refY:3.5,orient:'auto'});
      element(marker,'path',{d:'M0,0 L8,3.5 L0,7 z',fill});
    }
    const paths=element(svg,'g'),labels=element(svg,'g',{'pointer-events':'none'});
    for(const [i,e] of g.edges.entries()){
      const a=L.pos[e.from],b=L.pos[e.to];if(!a||!b)continue;
      const x=a.x+a.w,y=a.y+a.h/2,x2=b.x-1,y2=b.y+b.h/2,m=(x+x2)/2;
      const path=element(paths,'path',{d:'M'+x+','+y+' C'+m+','+y+' '+m+','+y2+' '+x2+','+y2,fill:'none',class:e.derived?'derived':''});
      edges.push({i,e,path,createLabel:()=>{
        const {text,width}=edgeLabel(e),lx=(x+b.x)/2,ly=(y+y2)/2,col=e.derived?'#ff375f':'#0071e3';
        const pill=element(labels,'g');element(pill,'rect',{x:lx-width/2,y:ly-17,width,height:16,rx:8,fill:'#fff',stroke:col,'stroke-opacity':.35});
        element(pill,'text',{x:lx,y:ly-5.5,fill:col,'font-size':10,'font-weight':600,'text-anchor':'middle'},text);return pill;
      }});
    }
    for(const n of g.nodes){
      const p=L.pos[n.id],s=nodeStyle(n,p),el=element(svg,'g',{'data-id':n.id,role:'button',tabindex:-1,'aria-label':s.title});
      element(el,'title',{},s.title);
      element(el,'rect',{class:'halo',x:p.x-3,y:p.y-3,width:p.w+6,height:p.h+6,rx:12,fill:'none'});
      element(el,'rect',{class:'frame',x:p.x,y:p.y,width:p.w,height:p.h,rx:11,fill:'#fff',stroke:s.color});
      element(el,'rect',{x:p.x,y:p.y,width:p.w,height:p.h,rx:11,fill:s.color,opacity:.06});
      element(el,'circle',{cx:p.x+15,cy:p.y+16,r:3.5,fill:s.color});
      element(el,'text',{x:p.x+26,y:p.y+20,fill:'#1d1d1f','font-size':13,'font-weight':600},s.label);
      element(el,'text',{x:p.x+15,y:p.y+39,fill:'#686870','font-size':10.5},s.sub);
      if(s.risky)el.classList.add('risky');
      nodes.push({el,id:n.id,search:s.title.toLowerCase()});
    }
    resize();
  }
  function show({key,g,L,sel,focus,visible,edgeVisible,nodeStyle,edgeLabel}){
    if(key!==signature||!layout||(g.nodes.length&&!host.contains(svg)))build(key,g,L,nodeStyle,edgeLabel);
    for(const {el,id} of nodes){
      const on=visible(id);el.style.display=on?'':'none';attr(el,'aria-pressed',sel===id);
      el.classList.toggle('dimmed',!!focus&&!focus.nodes.has(id));
    }
    if(!tabStop||tabStop.style.display==='none')setTabStop(nodes.find(n=>n.el.style.display!=='none')?.el);
    for(const item of edges){
      const {path,e,i}=item,on=edgeVisible(e),active=!!focus&&focus.edges.has(i);
      path.style.display=on?'':'none';path.classList.toggle('highlight',active);path.classList.toggle('dimmed',!!focus&&!active);
      if(on&&(e.derived||active)&&!item.label)item.label=item.createLabel();
      if(item.label)item.label.style.display=on&&(e.derived||active)?'':'none';
    }
    search(false);
  }
  return {show,resize};
};
