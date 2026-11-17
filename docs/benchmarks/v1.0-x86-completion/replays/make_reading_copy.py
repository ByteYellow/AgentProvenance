"""Make an unsigned reading copy while preserving every evidence shard."""
import argparse, hashlib, json, re, zipfile
from pathlib import Path

def convert(source, target):
    if target.exists():raise FileExistsError(target)
    with zipfile.ZipFile(source) as archive:
        files={n:archive.read(n) for n in archive.namelist()}
    inventory=json.loads(files.pop('export-inventory.json'))
    if inventory.get('delivery_mode')!='derived' or inventory.get('signed') is not True:
        raise ValueError('Expected an exporter-signed derived reader')
    files.pop('manifest.json');files.pop('manifest.signature')
    original_evidence={k:hashlib.sha256(v).hexdigest() for k,v in files.items() if k.startswith(('data/','assets/catalog.js')) or k=='record-selection.json'}
    for lang,label,status in [('en','Offline replay · unsigned sharing copy','Recipient verification: not run'),('zh-CN','离线回放 · 未签名的分享副本','接收方验证：尚未执行')]:
        name=lang+'/index.html';text=files[name].decode()
        match=re.search(r'<nav class="offline-replay-bar"[^>]*>.*?</nav>',text,re.S)
        if not match:raise ValueError('Missing delivery banner')
        banner=match.group().replace('data-delivery-mode="derived"','data-delivery-mode="reading"')
        banner,n=re.subn(r'<strong>.*?</strong>','<strong>'+label+'</strong>',banner,count=1,flags=re.S)
        if n!=1:raise ValueError('Missing delivery label')
        banner,n=re.subn(r'<span class="offline-signature-status">.*?</span>','<span class="offline-signature-status">'+status+'</span>',banner,count=1,flags=re.S)
        if n!=1:raise ValueError('Missing signature label')
        files[name]=(text[:match.start()]+banner+text[match.end():]).encode()
    inventory['signed']=False;inventory['delivery_mode']='reading';inventory.pop('signature',None)
    inventory['reading_copy']={'source_archive_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'source_delivery_mode':'derived','evidence_bytes_unchanged':True}
    inventory['files']=[{'path':k,'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in sorted(files.items())]
    inventory['bytes_excluding_inventory']=sum(len(v) for v in files.values())
    for k,digest in original_evidence.items():assert hashlib.sha256(files[k]).hexdigest()==digest
    files['export-inventory.json']=(json.dumps(inventory,indent=2,ensure_ascii=False)+'\n').encode()
    target.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for k,v in sorted(files.items()):
            item=zipfile.ZipInfo(k,date_time=(2026,11,17,0,0,0));item.compress_type=zipfile.ZIP_DEFLATED;item.external_attr=0o100644<<16
            archive.writestr(item,v,compresslevel=9)
    return {'file':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'run_id':inventory['run_id'],'evidence_shards_preserved':len(original_evidence)}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('target',type=Path);a=p.parse_args()
    print(json.dumps(convert(a.source,a.target)))
