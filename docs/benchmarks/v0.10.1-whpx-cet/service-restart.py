from pathlib import Path
import json,sqlite3,subprocess,time
root=Path('/var/tmp/cet-fix/integration')
runs=[json.loads((root/n).read_text())['run_id'] for n in ['guest-service.json','guest-k3s.json']]
def counts():
 with sqlite3.connect('/var/lib/agentprov-v0101/agentprov.db') as db:
  return {r:db.execute('SELECT COUNT(*) FROM events WHERE run_id=?',(r,)).fetchone()[0] for r in runs}
before=counts()
subprocess.run(['systemctl','restart','agentprov-sensor'],check=True)
for _ in range(100):
 try:
  s=json.loads(subprocess.check_output(['/usr/local/bin/agentprov','--data-dir','/var/lib/agentprov-v0101','sensor','status','--json'],text=True))
  if s.get('collector_running') and s.get('capabilities',{}).get('ready'):break
 except (subprocess.CalledProcessError,json.JSONDecodeError):pass
 time.sleep(.2)
else:raise RuntimeError('collector not ready after restart')
after=counts();r={'before':before,'after':after,'preserved':before==after,'service':'active','ready':True,'passed':before==after and all(before.values())}
(root/'service-restart.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r));assert r['passed']
