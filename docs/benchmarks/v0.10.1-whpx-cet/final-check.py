from pathlib import Path
import json, subprocess, time
root=Path('/var/tmp/cet-fix/integration')
while float(Path('/proc/uptime').read_text().split()[0]) < 600:
    time.sleep(1)
logs=[Path(f'/var/tmp/cet-fix/service-context-{i}.log').read_text() for i in range(1,5)]
assert all('seconds=300 failed=0 disabled=0' in log for log in logs)
status=json.loads(subprocess.check_output(['/usr/local/bin/agentprov','--data-dir','/var/lib/agentprov-v0101','sensor','status','--json'],text=True))
dmesg=subprocess.check_output(['dmesg'],text=True)
(root/'dmesg-final.txt').write_text(dmesg)
assert not any(x in dmesg for x in ('Kernel panic','segfault at','general protection fault'))
assert status.get('collector_running') and status.get('capabilities',{}).get('ready')
cet=subprocess.check_output(['/var/tmp/agentprov-procfs/bin/cet-check'],text=True)
assert 'status=1' in cet and 'disable=0' in cet
report={'uptime_seconds':float(Path('/proc/uptime').read_text().split()[0]),'cet_check':cet.strip(),'parallel_cet_checks_passed':4,'parallel_cet_seconds_each':300,'collector_running':True,'collector_ready':True,'kernel_panic_or_segfault_reported':False,'misordered_xstate_boot_warning':'misordered xstate' in dmesg,'passed':True}
(root/'final-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
