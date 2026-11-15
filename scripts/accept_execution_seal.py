#!/usr/bin/env python3
"""Exercise stopped-store sealing with a real command and independent signed import."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import sqlite3
import subprocess
import time
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory owned by this fixture')
    parser.add_argument('--native', action='store_true', help='require Linux native kernel capture')
    args = parser.parse_args()
    binary, root = args.binary.resolve(), args.output.resolve()
    if args.native and platform.system() != 'Linux':
        raise SystemExit('--native requires Linux')
    root.mkdir(parents=True, exist_ok=False)
    root.chmod(0o700)
    env = os.environ.copy()
    for key in ['AGENTPROV_DAEMON_URL', 'AGENTPROV_DAEMON_TOKEN']:
        env.pop(key, None)
    token = uuid.uuid4().hex + uuid.uuid4().hex
    daemon_env = dict(env, AGENTPROV_DAEMON_TOKEN=token)

    def cli(arguments, expected=0):
        result = subprocess.run([str(binary), *arguments], env=env, capture_output=True, text=True, timeout=90)
        if result.returncode != expected:
            raise RuntimeError(f'CLI exit {result.returncode}, expected {expected}: {result.stderr}')
        return result

    for name in ['executor', 'receiver']:
        cli(['forensics', 'keygen', '--priv', str(root / f'{name}.key'), '--pub', str(root / f'{name}.pub')])
    nonce = uuid.uuid4().hex
    config = {
        'target': {'producer_id': 'guest-seal-fixture', 'instance_id': nonce, 'generation': 'boot-1'},
        'caller': {'principal_id': 'fixture-router', 'producer_id': 'fixture-caller', 'namespace': 'fixture'},
        'delivery': {'receiver_id': 'fixture-receiver', 'sign_key_file': 'executor.key', 'receiver_public_key_file': 'receiver.pub'},
    }
    if args.native:
        config['capture'] = {'mode': 'native', 'auto_tls': False, 'no_policy': True}
    config_path = root / 'execution.json'
    config_path.write_text(json.dumps(config) + '\n')
    config_path.chmod(0o600)
    store = root / 'store'
    work = store / 'workspaces' / 'csv-fixture'
    work.mkdir(parents=True)
    # Native capture retains sensitive reads, not every read-only open. This
    # synthetic filename exercises that filter; the CSV contains no credentials.
    (work / 'credentials-fixture.csv').write_text('name,value\nalpha,20\nalpha,22\nbeta,7\n')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(method, path, body=None):
        raw = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url + path, data=raw, method=method,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with opener.open(request, timeout=5) as response:
            return json.load(response)

    command = [str(binary), '--data-dir', str(store), 'daemon', 'serve', '--listen', f'127.0.0.1:{port}',
               '--execution-config', str(config_path), '--sample-interval', '0', '--gc-interval', '0']
    process = None
    try:
        with (root / 'daemon.log').open('w') as log:
            process = subprocess.Popen(command, env=daemon_env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                raise RuntimeError('daemon exited before readiness: ' + (root / 'daemon.log').read_text())
            try:
                health = api('GET', '/v1/ready')
                if health['ready']:
                    break
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError('daemon readiness timeout')
            time.sleep(0.05)
        code = "import csv,json; rows=list(csv.DictReader(open('credentials-fixture.csv'))); totals={}; " \
               "[(totals.__setitem__(r['name'],totals.get(r['name'],0)+int(r['value']))) for r in rows]; " \
               "open('totals.json','w').write(json.dumps(totals,sort_keys=True)); print(json.dumps(totals,sort_keys=True))"
        valid_until = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)).isoformat()
        request = {'schema_version': 'agentprovenance.execution_handoff/v1',
                   'source': {'producer_id': 'fixture-caller', 'namespace': 'fixture', 'run_id': 'fixture-source',
                              'harness': 'http-fixture', 'session_id': nonce, 'tool_call_id': 'csv-analysis'},
                   'target': config['target'], 'dispatch_id': 'csv-dispatch', 'operation_id': 'csv-operation',
                   'valid_until': valid_until, 'command': {'argv': ['python3', '-c', code], 'workdir': str(work),
                       'disable_snapshot': False, 'capture_preset': 'detailed'}}
        admission = api('POST', '/v1/executions', request)
        attempt_id = admission['attempt']['id']
        deadline = time.monotonic() + 60
        while True:
            execution = api('GET', '/v1/executions/' + attempt_id)
            state = execution['attempt']['state']['execution']
            capture_ready = not args.native or execution['attempt']['state']['capture'] in {'sealed', 'incomplete'}
            if state == 'succeeded' and execution.get('checkpoint') and capture_ready:
                break
            if state in {'failed', 'unknown', 'cancelled'} or time.monotonic() > deadline:
                (root / 'failed-execution.json').write_text(json.dumps(execution, indent=2) + '\n')
                raise RuntimeError('command did not complete: ' + state)
            time.sleep(0.05)
        if args.native and execution['attempt']['state']['capture'] != 'sealed':
            raise RuntimeError('native capture did not seal: ' + json.dumps(execution['attempt']['state']))
        operation = 'retirement-' + nonce
        seal_command = ['--data-dir', str(store), 'forensics', 'seal-executions', '--execution-config', str(config_path), '--operation', operation]
        active = cli(seal_command, expected=1)
        if 'requires a stopped daemon' not in active.stderr:
            raise RuntimeError('active daemon was not rejected: ' + active.stderr)
        process.send_signal(signal.SIGTERM)
        if process.wait(timeout=60) != 0:
            raise RuntimeError('daemon shutdown failed')
        first, retry = cli(seal_command), cli(seal_command)
        (root / 'seal-first.jsonl').write_text(first.stdout)
        (root / 'seal-retry.jsonl').write_text(retry.stdout)
        results = [json.loads(line) for line in first.stdout.splitlines()]
        repeated = [json.loads(line) for line in retry.stdout.splitlines()]
        if len(results) != 2 or not results[-1]['complete'] or results[-1]['prepared'] != 1 or repeated[-1]['reused'] != 1:
            raise RuntimeError('unexpected sealing result')
        delivery = results[0]['delivery']
        if results[0]['status'] != 'prepared' or repeated[0]['status'] != 'reused' or delivery != repeated[0]['delivery']:
            raise RuntimeError('retry changed immutable delivery')
        if delivery['manifest']['state']['capture'] != execution['attempt']['state']['capture']:
            raise RuntimeError('sealing changed capture state')
        portable = root / 'portable'
        portable.mkdir()
        bundle = portable / 'bundle.json'
        shutil.copyfile(results[0]['bundle_path'], bundle)
        attestation = portable / 'bundle.dsse.json'
        attestation.write_text(json.dumps(delivery['envelope']))
        cli(['forensics', 'verify-attestation', str(bundle), str(attestation), '--pub-key', str(root / 'executor.pub')])
        work.rename(root / 'retained-source-work')
        store.rename(root / 'retained-source-store')
        receiver = root / 'independent-import'
        imported = json.loads(cli(['--data-dir', str(receiver), 'forensics', 'import', str(bundle), '--pub-key', str(root / 'executor.pub'), '--json']).stdout)
        if not imported['attestation_verified']:
            raise RuntimeError('import did not verify the signed package')
        run_id = admission['attempt']['local_run_id']
        verification = json.loads(cli(['--data-dir', str(receiver), 'graph', 'verify', '--run', run_id, '--json']).stdout)
        expected = {'alpha': 42, 'beta': 7}
        # Inspect the imported content by its signed content reference, without
        # access to the original execution workspace or object-store paths.
        stdout_ref = execution['checkpoint']['stdout']['ref']
        body = json.loads(cli(['--data-dir', str(receiver), 'context', 'content', '--run', run_id, '--ref', stdout_ref]).stdout)
        if json.loads(body['content']) != expected:
            raise RuntimeError('imported output content mismatch')
        native_events = []
        if args.native:
            scope = execution['checkpoint']['scope']
            wanted = {'credentials-fixture.csv': 'secret_path', 'totals.json': 'file_write'}
            with sqlite3.connect(f'{(receiver / "agentprov.db").as_uri()}?mode=ro', uri=True) as db:
                for event_id, kind, cgroup, payload in db.execute(
                    "SELECT id,event_type,cgroup_id,payload FROM events WHERE run_id=? AND source='agentprov_ebpf' AND event_type IN ('secret_path','file_write')", (run_id,)
                ):
                    raw = (json.loads(payload).get('payload') or {}).get('raw') or {}
                    path = raw.get('path') or ''
                    for name, event_type in wanted.items():
                        if kind == event_type and path in {name, str(work / name)}:
                            if str(cgroup) != scope['cgroup_id']:
                                raise RuntimeError('imported native file event belongs to another scope')
                            if raw.get('operation') != 'file_open' or not raw.get('operation_id'):
                                raise RuntimeError('imported native file event lost its operation identity')
                            native_events.append({'id': event_id, 'event_type': kind, 'path': path, 'cgroup_id': cgroup,
                                                  'operation_id': raw['operation_id']})
            if {entry['event_type'] for entry in native_events} != set(wanted.values()):
                raise RuntimeError('imported native input read or output write is missing')
        report = {'schema_version': 'agentprovenance.execution_seal_acceptance/v1',
                  'fixture': 'real-command-http', 'native_capture': args.native, 'platform': platform.platform(),
                  'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'request': request,
                  'admission': admission, 'execution': execution, 'seal': results[-1], 'retry': repeated[-1],
                  'bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest(),
                  'attestation_sha256': hashlib.sha256(attestation.read_bytes()).hexdigest(),
                  'verification': verification, 'output': expected, 'native_file_events': native_events, 'passed': True}
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'run_id': run_id, 'native_capture': args.native, 'report': str(root / 'report.json')}))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
