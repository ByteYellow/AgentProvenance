#!/usr/bin/env python3
"""Boot the pinned guest and exercise controller-owned evidence retirement.

Run as root on an isolated Linux amd64 host with KVM, iproute2, dnsmasq,
OpenSSH and e2fsprogs. Uses a private fixture network, new disks and synthetic
commands. No host service is changed. Failures always retain the evidence disk.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import sqlite3
import subprocess
import time
import urllib.request
import uuid


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def retirement_allowed(summary, target, expected, deliveries, receiver):
    """Require the controller's inventory as well as the guest's receipt totals."""
    if (not isinstance(expected, dict) or not expected
            or any(not isinstance(key, str) or not key or not isinstance(run, str) or not run
                   for key, run in expected.items())
            or not isinstance(target, dict) or set(target) != {'producer_id', 'instance_id', 'generation'}
            or any(not isinstance(value, str) or not value for value in target.values())
            or not isinstance(receiver, str) or not receiver
            or summary.get('target') != target or summary.get('receiver_id') != receiver
            or not isinstance(deliveries, list) or len(deliveries) != len(expected)):
        return False
    observed = {}
    for item in deliveries:
        if not isinstance(item, dict) or not isinstance(item.get('delivery'), dict):
            return False
        manifest = item['delivery'].get('manifest')
        if not isinstance(manifest, dict) or not isinstance(manifest.get('identity'), dict):
            return False
        identity = manifest['identity']
        attempt, run = identity.get('attempt_id'), identity.get('local_run_id')
        if (not isinstance(attempt, str) or attempt not in expected or attempt in observed
                or run != expected[attempt] or identity.get('target') != target
                or item.get('attempt_id') != attempt or item.get('run_id') != run
                or item.get('status') not in ('prepared', 'reused')
                or manifest.get('receiver_id') != receiver):
            return False
        observed[attempt] = run
    if observed != expected:
        return False
    count = summary.get('attempts')
    return (type(count) is int and count == len(expected) and summary.get('complete') is True
            and summary.get('delivery_complete') is True
            and type(summary.get('receipts_pending')) is int
            and type(summary.get('receipts_verified')) is int
            and summary.get('receipts_pending') == 0
            and summary.get('receipts_verified') == count)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'firecracker', 'kernel', 'rootfs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--reclaim', action='store_true', help='remove only the new fixture disks after all receipts verify')
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('run as root on Linux x86_64 with /dev/kvm')
    os.umask(0o077)
    for name in ('binary', 'firecracker', 'kernel', 'rootfs'):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    runtime = json.loads((Path(__file__).resolve().parents[1] / 'deploy/microvm/runtime.json').read_text())
    report = {'schema_version': 'agentprovenance.microvm_boot_acceptance/v1',
              'passed': False, 'may_reclaim': False, 'reclaimed': False,
              'host': platform.platform(), 'runtime': runtime,
              'inputs': {name: {'sha256': digest(getattr(args, name))} for name in ('binary', 'firecracker', 'kernel', 'rootfs')}}

    def save(path, data):
        path.write_text(json.dumps(data, indent=2) + '\n')

    def run(argv, expected=0, timeout=120):
        p = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=timeout)
        if p.returncode != expected:
            raise RuntimeError(f'{argv[0]} exit {p.returncode}: {p.stderr[-3000:]}')
        return p.stdout

    def cli(*argv, expected=0):
        return run([args.binary, *argv], expected)

    def image(path, size, tree):
        with path.open('xb') as stream:
            stream.truncate(size << 20)
        run(['mkfs.ext4', '-q', '-F', '-d', tree, path])

    nonce = uuid.uuid4().hex
    tap = 'apv1' + nonce[:8]
    guest_ip, host_ip = '192.0.2.2', '192.0.2.1'
    fc = dhcp = tunnel = None
    tap_created = False
    streams = []
    disks = [out / name for name in ('root.ext4', 'config.ext4', 'evidence.ext4')]
    try:
        # Keep DHCP and the fixture route separate from host/WSL services.
        os.unshare(os.CLONE_NEWNET)
        run(['ip', 'link', 'set', 'lo', 'up'])
        version = run([args.firecracker, '--version'])
        if 'Firecracker ' + runtime['version'] not in version:
            raise RuntimeError('Firecracker version differs from runtime.json')
        report['firecracker_version'] = version.strip()
        # A route in this subnet indicates another lab or an operator network.
        routes = json.loads(run(['ip', '-json', 'route', 'show', 'match', '192.0.2.0/30']))
        if any(row.get('dst') not in ('default', '0.0.0.0/0') for row in routes):
            raise RuntimeError('fixture subnet 192.0.2.0/30 is already routed')
        config_tree, evidence_tree = out / 'configuration', out / 'seed'
        config_tree.mkdir(); evidence_tree.mkdir()
        for owner in ('executor', 'receiver'):
            cli('forensics', 'keygen', '--priv', out / (owner + '.key'), '--pub', out / (owner + '.pub'))
        shutil.copyfile(out / 'executor.key', config_tree / 'executor.key')
        shutil.copyfile(out / 'receiver.pub', config_tree / 'receiver.pub')
        token = uuid.uuid4().hex + uuid.uuid4().hex
        (config_tree / 'daemon-token').write_text(token + '\n')
        config = {'target': {'producer_id': 'firecracker-acceptance', 'instance_id': nonce, 'generation': 'boot-1'},
                  'caller': {'principal_id': 'controller', 'producer_id': 'fixture-caller', 'namespace': 'acceptance'},
                  'capture': {'mode': 'native', 'placement': 'guest_kernel', 'auto_tls': False,
                              'apparmor_state': False, 'no_policy': True},
                  'delivery': {'receiver_id': 'fixture-receiver', 'sign_key_file': 'executor.key', 'receiver_public_key_file': 'receiver.pub'}}
        save(config_tree / 'execution.json', config)
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', out / 'client-key'])
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', config_tree / 'ssh_host_ed25519_key'])
        shutil.copyfile(out / 'client-key.pub', config_tree / 'authorized_keys')
        pub = (config_tree / 'ssh_host_ed25519_key.pub').read_text().split()
        (out / 'known_hosts').write_text(guest_ip + ' ' + ' '.join(pub[:2]) + '\n')
        work = evidence_tree / 'workspaces' / 'fixture'; work.mkdir(parents=True)
        (work / 'credentials-fixture.csv').write_text('name,value\nalpha,40\nalpha,2\nbeta,7\n')
        run(['cp', '--sparse=always', args.rootfs, disks[0]])
        image(disks[1], 16, config_tree); image(disks[2], 512, evidence_tree)
        run(['ip', 'tuntap', 'add', 'dev', tap, 'mode', 'tap']); tap_created = True
        run(['ip', 'addr', 'add', host_ip + '/30', 'dev', tap]); run(['ip', 'link', 'set', tap, 'up'])
        def log(name):
            stream = (out / name).open('w'); streams.append(stream); return stream
        dhcp = subprocess.Popen(['dnsmasq', '--keep-in-foreground', '--conf-file=/dev/null', '--user=root',
            '--port=0', '--interface=' + tap, '--bind-interfaces', '--dhcp-range=192.0.2.2,192.0.2.2,255.255.255.252,1h',
            '--dhcp-option=3', '--dhcp-option=6', '--dhcp-leasefile=' + str(out / 'leases'),
            '--pid-file=' + str(out / 'dnsmasq.pid')], stdout=log('dhcp.log'), stderr=subprocess.STDOUT)
        vm = {'boot-source': {'kernel_image_path': str(args.kernel), 'boot_args': 'console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw systemd.unified_cgroup_hierarchy=1'},
              'drives': [{'drive_id': name, 'path_on_host': str(path), 'is_root_device': i == 0, 'is_read_only': i == 1}
                         for i, (name, path) in enumerate(zip(('root', 'config', 'evidence'), disks))],
              'machine-config': {'vcpu_count': 2, 'mem_size_mib': 2048},
              'network-interfaces': [{'iface_id': 'eth0', 'host_dev_name': tap, 'guest_mac': '06:00:AC:10:00:02'}]}
        save(out / 'vm.json', vm)
        fc = subprocess.Popen([str(args.firecracker), '--no-api', '--config-file', str(out / 'vm.json')],
                              stdout=log('serial.log'), stderr=subprocess.STDOUT)
        ssh_base = ['ssh', '-i', str(out / 'client-key'), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=2',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(out / 'known_hosts')]
        def ssh(command, expected=0, timeout=120):
            return run(ssh_base + ['root@' + guest_ip, command], expected, timeout)
        deadline = time.monotonic() + 180
        while True:
            if fc.poll() is not None or dhcp.poll() is not None:
                raise RuntimeError('guest or DHCP exited before readiness; see serial.log/dhcp.log')
            try:
                if ssh('systemctl is-active agentprov-guest', timeout=5).strip() == 'active': break
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            if time.monotonic() > deadline: raise TimeoutError('guest boot readiness; see serial.log')
            time.sleep(1)
        report['guest'] = json.loads(ssh("python3 -c 'import json,os; print(json.dumps({\"uname\":list(os.uname()),\"btf\":os.path.isfile(\"/sys/kernel/btf/vmlinux\")}))'"))
        invocation = ssh('systemctl show agentprov-guest --property=InvocationID --value').strip()
        base = '/var/lib/agentprov-guest'
        lifecycle = base + '/guest-lifecycle/' + invocation
        ready = json.loads(ssh('cat ' + lifecycle + '.ready.json'))
        if ready['target'] != config['target'] or not report['guest']['btf']:
            raise RuntimeError('boot identity or BTF is missing')
        report['ready'] = ready
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0)); local_port = port.getsockname()[1]
        tunnel = subprocess.Popen(ssh_base + ['-N', '-o', 'ExitOnForwardFailure=yes', '-L',
            f'127.0.0.1:{local_port}:127.0.0.1:8574', 'root@' + guest_ip], stdout=log('tunnel.log'), stderr=subprocess.STDOUT)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def api(method, path, body=None):
            req = urllib.request.Request(f'http://127.0.0.1:{local_port}' + path,
                data=None if body is None else json.dumps(body).encode(), method=method,
                headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
            with opener.open(req, timeout=30) as response: return json.load(response)
        for _ in range(50):
            try:
                if api('GET', '/v1/ready')['ready']: break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('forwarded API readiness failed')
        # Hold each fixture task for a procfs sample before exercising finalization.
        # Short-lived task sampling gaps remain covered separately.
        code = "import csv,json,time; time.sleep(1); rows=list(csv.DictReader(open('credentials-fixture.csv'))); totals={}; [(totals.__setitem__(r['name'],totals.get(r['name'],0)+int(r['value']))) for r in rows]; open('totals.json','w').write(json.dumps(totals,sort_keys=True)); print(json.dumps(totals,sort_keys=True))"
        admissions, executions = [], []
        for name, program in [('success', code), ('failure', "import sys,time; time.sleep(1); print('expected failure',file=sys.stderr); sys.exit(7)")]:
            request = {'schema_version': 'agentprovenance.execution_handoff/v1',
                       'source': {'producer_id': 'fixture-caller', 'namespace': 'acceptance', 'run_id': 'microvm-source',
                                  'harness': 'http-fixture', 'session_id': nonce, 'tool_call_id': name},
                       'target': config['target'], 'dispatch_id': name, 'operation_id': name,
                       'valid_until': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat(),
                       'command': {'argv': ['python3', '-c', program], 'workdir': base + '/workspaces/fixture', 'capture_preset': 'detailed'}}
            admission = api('POST', '/v1/executions', request); admissions.append(admission)
            save(out / (name + '-admission.json'), admission)
            deadline = time.monotonic() + 60
            while True:
                execution = api('GET', '/v1/executions/' + admission['attempt']['id'])
                if execution['attempt']['state']['execution'] in ('succeeded', 'failed') and execution['attempt']['state']['capture'] in ('sealed', 'incomplete'): break
                if time.monotonic() > deadline: raise TimeoutError('execution did not finish')
                time.sleep(.1)
            save(out / (name + '-execution.json'), execution); executions.append(execution)
            if execution['attempt']['state']['execution'] != ('succeeded' if name == 'success' else 'failed'):
                raise RuntimeError('unexpected execution state')
            if execution['attempt']['state']['capture'] != 'sealed':
                raise RuntimeError('native capture incomplete; see ' + name + '-execution.json')
        ssh('systemctl stop agentprov-guest', timeout=310)
        stopped = json.loads(ssh('cat ' + lifecycle + '.stopped.json')); report['stopped'] = stopped
        if not stopped['sealed'] or stopped['may_reclaim'] or stopped['receiver_acknowledged'] is not None:
            raise RuntimeError('guest incorrectly authorized retirement')
        sealed = [json.loads(line) for line in ssh('cat ' + shlex.quote(stopped['package_results'])).splitlines()]
        save(out / 'sealed.json', sealed)
        expected = {a['attempt']['id']: a['attempt']['local_run_id'] for a in admissions}
        report['expected_executions'] = expected
        report['target'] = config['target']
        def may_reclaim(summary):
            return retirement_allowed(summary, config['target'], expected, sealed[:-1], 'fixture-receiver')
        seal_command = '/usr/local/bin/agentprov --data-dir ' + base + ' forensics seal-executions --execution-config /etc/agentprov-guest/execution.json --operation guest-stop-' + invocation + ' --require-receipts'
        gates = []
        def gate(expected):
            summary = json.loads(ssh(seal_command, expected).splitlines()[-1]); gates.append(summary)
            return summary
        if may_reclaim(gate(1)): raise RuntimeError('missing receipts permitted retirement')
        for i, name in enumerate(('success', 'failure')):
            item = next(row for row in sealed[:-1] if row['attempt_id'] == admissions[i]['attempt']['id'])
            package = out / ('package-' + name); package.mkdir()
            for remote, local in [(item['bundle_path'], 'bundle.json'), (str(Path(item['bundle_path']).with_name('manifest.dsse.json')), 'manifest.dsse.json')]:
                p = subprocess.run(ssh_base + ['root@' + guest_ip, 'cat ' + shlex.quote(remote)], capture_output=True, timeout=30, check=True)
                (package / local).write_bytes(p.stdout)
            shutil.copyfile(package / 'manifest.dsse.json', package / 'bundle.dsse.json')
            collected = json.loads(cli('--data-dir', out / 'receiver-store', 'forensics', 'collect-execution', out / (name + '-admission.json'),
                '--execution-config', config_tree / 'execution.json', '--package-dir', package, '--receiver', 'fixture-receiver',
                '--sign-key', out / 'receiver.key', '--pub-key', out / 'executor.pub'))
            if collected['status'] != 'receipt_persisted': raise RuntimeError('receiver receipt missing')
            receipt = json.dumps(collected['receipt']).encode()
            subprocess.run(ssh_base + ['root@' + guest_ip, 'cat > /var/lib/agentprov-guest/acceptance-receipt.json'], input=receipt, check=True, timeout=30)
            ssh('/usr/local/bin/agentprov --data-dir ' + base + ' forensics acknowledge-execution ' + shlex.quote(collected['delivery_id']) +
                ' /var/lib/agentprov-guest/acceptance-receipt.json --execution-config /etc/agentprov-guest/execution.json')
            summary = gate(0 if i == 1 else 1)
            if may_reclaim(summary) != (i == 1): raise RuntimeError('partial receipt or execution inventory mismatch')
        report['receipt_checks'] = gates
        # x86 Firecracker has no ACPI poweroff; reboot=k exits the VMM after
        # systemd has stopped services and unmounted the guest filesystems.
        ssh('sync; systemctl reboot')
        fc.wait(timeout=45)
        if fc.returncode != 0: raise RuntimeError('Firecracker did not shut down cleanly')
        # Read-only verification runs after the original guest and daemon stop.
        imported = out / 'independent-import'
        for name, admission in zip(('success', 'failure'), admissions):
            result = json.loads(cli('--data-dir', imported, 'forensics', 'import', out / ('package-' + name) / 'bundle.json', '--pub-key', out / 'executor.pub', '--json'))
            if not result['attestation_verified']: raise RuntimeError('independent import is unverified')
            verification = json.loads(cli('--data-dir', imported, 'graph', 'verify', '--run', admission['attempt']['local_run_id'], '--json'))
            if verification.get('error_count') != 0 or verification.get('warning_count') != 0:
                raise RuntimeError('imported graph verification failed')
        events = []
        with sqlite3.connect(f'file:{imported / "agentprov.db"}?mode=ro', uri=True) as db:
            for row in db.execute("SELECT id,event_type,cgroup_id,payload FROM events WHERE run_id=? AND source='agentprov_ebpf'", (admissions[0]['attempt']['local_run_id'],)):
                raw = (json.loads(row[3]).get('payload') or {}).get('raw') or {}
                if row[1] in ('secret_path', 'file_write') and Path(raw.get('path') or '').name in ('credentials-fixture.csv', 'totals.json'):
                    if str(row[2]) != executions[0]['checkpoint']['scope']['cgroup_id']: raise RuntimeError('native scope mismatch')
                    events.append({'id': row[0], 'event_type': row[1], 'cgroup_id': row[2], 'path': raw['path']})
        if {e['event_type'] for e in events} != {'secret_path', 'file_write'}: raise RuntimeError('native read/write evidence missing')
        report.update(native_file_events=events, executions=[e['attempt']['state'] for e in executions], may_reclaim=may_reclaim(gates[-1]))
        if args.reclaim and report['may_reclaim']:
            for disk in disks: disk.unlink()
            report['reclaimed'] = all(not disk.exists() for disk in disks)
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for proc in (tunnel, fc, dhcp):
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=10)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        if tap_created: subprocess.run(['ip', 'link', 'delete', tap], capture_output=True)
        for stream in streams: stream.close()
        report['evidence_disk_retained'] = disks[2].exists()
        save(out / 'report.json', report)
    print(json.dumps({'passed': report['passed'], 'reclaimed': report['reclaimed'], 'report': str(out / 'report.json')}))


if __name__ == '__main__':
    main()
