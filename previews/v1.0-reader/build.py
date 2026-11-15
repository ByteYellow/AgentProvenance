from pathlib import Path
import argparse, base64, gzip, hashlib, html, json, re, shutil, zipfile

base=Path(__file__).resolve().parent
repo=base.parents[1]
parser=argparse.ArgumentParser(description='Build the v1.0 candidate reader without changing the formal Dashboard.')
parser.add_argument('--output', type=Path, required=True, help='new output directory')
args=parser.parse_args()
target=args.output.resolve()
target.mkdir(parents=True, exist_ok=False)
cases=[('investigation','task-investigation','Task investigation'),('execution','native-matrix','Cross-environment execution'),('browser','browser-detailed','Browser'),('notebook','notebook-detailed','Notebook')]
nav='<nav class="review-nav" aria-label="Candidate examples"><strong>v1.0 · PREVIEW</strong>'+''.join(f'<a href="../{slug}/index.html">{html.escape(title)}</a>' for slug,_,title in cases)+'<span>Saved evidence · Read only</span></nav>'
manifest=[]
for slug,name,title in cases:
    src=repo/'docs/benchmarks/v1.0-candidate/replays'/(name+'.zip')
    if slug=='notebook':src=base/'fixtures/notebook-attachments.zip'
    root=target/slug
    root.mkdir(exist_ok=True)
    with zipfile.ZipFile(src) as archive:
        for info in archive.infolist():
            path=Path(info.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in info.filename:raise ValueError('invalid archive path')
        archive.extractall(root)
    catalog=json.loads(base64.b64decode(re.search(r'"([A-Za-z0-9+/=]+)"',(root/'assets/catalog.js').read_text()).group(1)))
    def saved(ref):
        data=(root/ref['path'].replace('.json.gz','.js')).read_text()
        return json.loads(gzip.decompress(base64.b64decode(re.search(r',"([A-Za-z0-9+/=]+)"',data).group(1))))
    def score(item):
        run_id,run=item
        if slug=='execution':return sum(s['count'] for s in run.get('execution_links',{}).get('directions',{}).get('outgoing',[]))
        entries=saved(run['context']).get('entries',[]) if run.get('context') else []
        return sum(len(x.get('attachments',[]))*100+int(bool(x.get('browser') or x.get('notebook'))) for x in entries)
    selected=max(catalog['runs'].items(),key=score)[0]
    # Select the relevant recorded run before the existing reader boots.
    bootstrap='<script>if(!new URL(location.href).searchParams.has("run")){const u=new URL(location.href);u.searchParams.set("run",'+json.dumps(selected)+');history.replaceState(null,"",u);}</script>'
    index=root/'index.html'
    index.write_text(index.read_text().replace('<body>','<body>'+bootstrap))
    for language in ['en','zh-CN']:
        index=root/language/'index.html';text=index.read_text()
        text=text.replace('</head>','<link rel="stylesheet" href="../assets/evidence-preview.css"></head>')
        bar=nav.replace('href="../','href="../../')
        if language=='zh-CN':
            for en,cn in [('Task investigation','任务调查'),('Cross-environment execution','跨环境执行'),('Saved evidence · Read only','已保存的证据 · 只读'),('PREVIEW','候选预览')]:bar=bar.replace(en,cn)
        text=text.replace('<body>','<body>'+bootstrap+bar)
        text=text.replace('</body>','<script src="../assets/evidence-preview.js"></script></body>')
        index.write_text(text)
    for ext in ['css','js']:shutil.copy2(base/('evidence.'+ext),root/'assets'/('evidence-preview.'+ext))
    inventory=json.loads((root/'export-inventory.json').read_text())
    items=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or p.name=='export-inventory.json':continue
        raw=p.read_bytes();items.append({'path':str(p.relative_to(root)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    inventory['files']=items;inventory['bytes_excluding_inventory']=sum(x['bytes'] for x in items)
    inventory['ui_review']={'original_archive_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'source_branch':'feature/v1.0-portable-evidence','formal_ui_approval':'pending'}
    (root/'export-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
    manifest.append({'case':slug,'source':str(src.relative_to(repo)),'run':selected,'url':slug+'/index.html','files':len(items)})
(target/'review.json').write_text(json.dumps(manifest,indent=2)+'\n')
(target/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=execution/index.html"><title>AgentProvenance v1.0 preview</title><a href="execution/index.html">Open candidate preview</a></html>')
print(json.dumps(manifest))
