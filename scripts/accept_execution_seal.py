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
    parser.add_argument('--guest-service-dir', type=Path,
                        help='exercise the systemd unit and hooks from deploy/microvm (Linux root, --native)')
    args = parser.parse_args()
    binary, root = args.binary.resolve(), args.output.resolve()
    if args.native and platform.system() != 'Linux':
        raise SystemExit('--native requires Linux')
    if args.guest_service_dir and (not args.native or os.geteuid() != 0):
        raise SystemExit('--guest-service-dir requires root and --native on Linux')
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

    def await_execution(attempt_id, wanted):
        deadline = time.monotonic() + 60
        while True:
            execution = api('GET', '/v1/executions/' + attempt_id)
            state = execution['attempt']['state']['execution']
            capture = execution['attempt']['state']['capture']
            if state == wanted and execution.get('checkpoint') and (not args.native or capture in {'sealed', 'incomplete'}):
                if args.native and capture != 'sealed':
                    (root / ('unexpected-' + attempt_id + '.json')).write_text(json.dumps(execution, indent=2) + '\n')
                    raise RuntimeError('native capture did not seal: ' + json.dumps(execution['attempt']['state']))
                return execution
            if state in {'succeeded', 'failed', 'unknown', 'cancelled'} - {wanted} or time.monotonic() > deadline:
                (root / ('unexpected-' + attempt_id + '.json')).write_text(json.dumps(execution, indent=2) + '\n')
                raise RuntimeError('command did not reach ' + wanted + ': ' + state)
            time.sleep(0.05)

    command = [str(binary), '--data-dir', str(store), 'daemon', 'serve', '--listen', f'127.0.0.1:{port}',
               '--execution-config', str(config_path), '--sample-interval', '0', '--gc-interval', '0']
    process = None
    unit_path = None
    unit_created = False
    service_invocation = None
    lifecycle = None
    try:
        if args.guest_service_dir:
            deployment = args.guest_service_dir.resolve()
            token_file = root / 'daemon-token'
            token_file.write_text(token)
            token_file.chmod(0o600)
            unit_path = Path('/run/systemd/system') / ('agentprov-guest-fixture-' + nonce + '.service')
            def quoted(value):
                return json.dumps(str(value).replace('%', '%%'))
            settings = {'BINARY': binary, 'CONFIG': config_path, 'TOKEN_FILE': token_file,
                        'DATA_DIR': store, 'LISTEN': f'127.0.0.1:{port}'}
            unit = (deployment / 'agentprov-guest.service').read_text()
            unit += '\n[Unit]\nRequiresMountsFor=\nRequiresMountsFor=' + quoted(root) + '\n[Service]\n'
            unit += ''.join('Environment=' + quoted('AGENTPROV_GUEST_' + key + '=' + str(value)) + '\n'
                            for key, value in settings.items())
            for key, action in [('ExecStart', 'serve'), ('ExecStartPost', 'ready'), ('ExecStopPost', 'seal')]:
                unit += key + '=\n' + key + '=/usr/bin/python3 ' + quoted(deployment / 'guest_service.py') + ' ' + action + '\n'
            with unit_path.open('x') as stream:
                unit_created = True
                stream.write(unit)
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'start', unit_path.name], check=True, timeout=160)
            service_invocation = subprocess.check_output(['systemctl', 'show', unit_path.name,
                '--property=InvocationID', '--value'], text=True).strip()
            ready = json.loads((store / 'guest-lifecycle' / (service_invocation + '.ready.json')).read_text())
            if ready['target'] != config['target'] or ready['phase'] != 'ready':
                raise RuntimeError('service readiness has the wrong execution identity')
        else:
            with (root / 'daemon.log').open('w') as log:
                process = subprocess.Popen(command, env=daemon_env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while True:
            if process is not None and process.poll() is not None:
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
        # This fixture requires a complete procfs state sample as well as native
        # events. Keep its task alive long enough for the asynchronous sampler;
        # shorter tasks can correctly retain a sampling gap and stay incomplete.
        code = "import csv,json,time; time.sleep(1); rows=list(csv.DictReader(open('credentials-fixture.csv'))); totals={}; " \
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
        admission_path = root / 'admission.json'
        admission_path.write_text(json.dumps(admission) + '\n')
        attempt_id = admission['attempt']['id']
        execution = await_execution(attempt_id, 'succeeded')
        failed_request = json.loads(json.dumps(request))
        failed_request['source']['tool_call_id'] = 'expected-failure'
        failed_request['dispatch_id'], failed_request['operation_id'] = 'failed-dispatch', 'failed-operation'
        failed_request['command']['argv'] = ['python3', '-c', "import sys,time; time.sleep(1); print('expected failure', file=sys.stderr); sys.exit(7)"]
        failed_admission = api('POST', '/v1/executions', failed_request)
        failed_admission_path = root / 'failed-admission.json'
        failed_admission_path.write_text(json.dumps(failed_admission) + '\n')
        failed_execution = await_execution(failed_admission['attempt']['id'], 'failed')
        if failed_execution['checkpoint']['result']['exit_code'] != 7:
            raise RuntimeError('expected command exit 7 was not preserved')
        operation = 'guest-stop-' + service_invocation if service_invocation else 'retirement-' + nonce
        seal_command = ['--data-dir', str(store), 'forensics', 'seal-executions', '--execution-config', str(config_path), '--operation', operation]
        active = cli(seal_command, expected=1)
        if 'requires a stopped daemon' not in active.stderr:
            raise RuntimeError('active daemon was not rejected: ' + active.stderr)
        if unit_path:
            subprocess.run(['systemctl', 'stop', unit_path.name], check=True, timeout=310)
            lifecycle = json.loads((store / 'guest-lifecycle' / (service_invocation + '.stopped.json')).read_text())
            if not lifecycle['sealed'] or lifecycle['may_reclaim'] or lifecycle['receiver_acknowledged'] is not None:
                raise RuntimeError('unexpected systemd retirement result')
            first = subprocess.CompletedProcess([], 0, Path(lifecycle['package_results']).read_text())
            retry = cli(seal_command)
        else:
            process.send_signal(signal.SIGTERM)
            if process.wait(timeout=60) != 0:
                raise RuntimeError('daemon shutdown failed')
            first, retry = cli(seal_command), cli(seal_command)
        (root / 'seal-first.jsonl').write_text(first.stdout)
        (root / 'seal-retry.jsonl').write_text(retry.stdout)
        results = [json.loads(line) for line in first.stdout.splitlines()]
        repeated = [json.loads(line) for line in retry.stdout.splitlines()]
        if len(results) != 3 or not results[-1]['complete'] or results[-1]['prepared'] != 2 or repeated[-1]['reused'] != 2:
            raise RuntimeError('unexpected sealing result')
        delivery = results[0]['delivery']
        for item, replay, original in zip(results[:-1], repeated[:-1], [execution, failed_execution], strict=True):
            if item['status'] != 'prepared' or replay['status'] != 'reused' or item['delivery'] != replay['delivery']:
                raise RuntimeError('retry changed immutable delivery')
            if item['attempt_id'] != original['attempt']['id'] or item['delivery']['manifest']['state']['execution'] != original['attempt']['state']['execution']:
                raise RuntimeError('sealing changed execution identity or outcome')
        if delivery['manifest']['state']['capture'] != execution['attempt']['state']['capture']:
            raise RuntimeError('sealing changed capture state')

        def check_receipts(verified):
            checked = cli(seal_command + ['--require-receipts'], expected=0 if verified == 2 else 1)
            (root / f'receipt-check-{verified}.jsonl').write_text(checked.stdout)
            (root / f'receipt-check-{verified}.stderr').write_text(checked.stderr)
            summary = json.loads(checked.stdout.splitlines()[-1])
            if not summary['complete'] or summary['attempts'] != 2 or summary['reused'] != 2 or \
                    summary['receipts_verified'] != verified or summary['receipts_pending'] != 2 - verified or \
                    summary['delivery_complete'] != (verified == 2):
                raise RuntimeError('incorrect batch receipt summary: ' + json.dumps(summary))
            if verified < 2 and 'sealed packages await receiver receipts' not in checked.stderr:
                raise RuntimeError('receipt check failed for an unrelated reason: ' + checked.stderr)
            return summary

        receipt_checks = [check_receipts(0)]
        offline_deliveries = []
        for i, (item, saved_admission) in enumerate(zip(results[:-1], [admission_path, failed_admission_path], strict=True)):
            package = root / ('portable' if i == 0 else 'portable-failed')
            package.mkdir()
            shutil.copyfile(item['bundle_path'], package / 'bundle.json')
            manifest_path = Path(item['bundle_path']).with_name('manifest.dsse.json')
            shutil.copyfile(manifest_path, package / 'bundle.dsse.json')
            shutil.copyfile(manifest_path, package / 'manifest.dsse.json')
            if hashlib.sha256((package / 'manifest.dsse.json').read_bytes()).hexdigest() != item['delivery']['manifest_sha256']:
                raise RuntimeError('copied manifest bytes differ from the sealed package')
            cli(['forensics', 'verify-attestation', str(package / 'bundle.json'), str(package / 'bundle.dsse.json'), '--pub-key', str(root / 'executor.pub')])
            collect_command = ['--data-dir', str(root / 'receipt-store'), 'forensics', 'collect-execution', str(saved_admission),
                '--execution-config', str(config_path), '--package-dir', str(package), '--receiver', 'fixture-receiver',
                '--sign-key', str(root / 'receiver.key'), '--pub-key', str(root / 'executor.pub')]
            collected = json.loads(cli(collect_command).stdout)
            if collected['status'] != 'receipt_persisted' or collected != json.loads(cli(collect_command).stdout):
                raise RuntimeError('offline receipt was not persisted or retry changed it')
            receipt_path = package / 'receipt.dsse.json'
            receipt_path.write_text(json.dumps(collected['receipt']))
            acknowledge_command = ['--data-dir', str(store), 'forensics', 'acknowledge-execution', collected['delivery_id'],
                str(receipt_path), '--execution-config', str(config_path)]
            acknowledged = json.loads(cli(acknowledge_command).stdout)
            if json.loads(cli(acknowledge_command).stdout) != acknowledged or acknowledged['delivery']['receipt'] != collected['receipt']:
                raise RuntimeError('sender did not persist the exact signed receipt')
            offline_deliveries.append({'collection': collected, 'sender_acknowledgment': acknowledged})
            receipt_checks.append(check_receipts(i + 1))
        with sqlite3.connect(f'{(store / "agentprov.db").as_uri()}?mode=ro', uri=True) as db:
            for original in [execution, failed_execution]:
                state = db.execute('SELECT execution_state,capture_state,delivery_state FROM execution_attempts WHERE id=?', (original['attempt']['id'],)).fetchone()
                if state != (original['attempt']['state']['execution'], original['attempt']['state']['capture'], 'acknowledged'):
                    raise RuntimeError('offline acknowledgment changed execution/capture or did not settle delivery')
        work.rename(root / 'retained-source-work')
        store.rename(root / 'retained-source-store')
        portable = root / 'portable'
        bundle, attestation = portable / 'bundle.json', portable / 'bundle.dsse.json'
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
        failed_bundle = root / 'portable-failed' / 'bundle.json'
        failed_import = json.loads(cli(['--data-dir', str(receiver), 'forensics', 'import', str(failed_bundle), '--pub-key', str(root / 'executor.pub'), '--json']).stdout)
        failed_run = failed_admission['attempt']['local_run_id']
        failed_verification = json.loads(cli(['--data-dir', str(receiver), 'graph', 'verify', '--run', failed_run, '--json']).stdout)
        failed_body = json.loads(cli(['--data-dir', str(receiver), 'context', 'content', '--run', failed_run,
            '--ref', failed_execution['checkpoint']['stderr']['ref']]).stdout)
        if not failed_import['attestation_verified'] or failed_body['content'] != 'expected failure\n':
            raise RuntimeError('failed execution evidence did not survive independent import')
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
                  'verification': verification, 'output': expected, 'native_file_events': native_events,
                  'offline_delivery': offline_deliveries[0], 'failed_offline_delivery': offline_deliveries[1],
                  'failed_execution': failed_execution, 'failed_verification': failed_verification,
                  'failed_bundle_sha256': hashlib.sha256(failed_bundle.read_bytes()).hexdigest(),
                  'receipt_checks': receipt_checks,
                  'guest_service': lifecycle, 'passed': True}
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'run_id': run_id, 'native_capture': args.native, 'report': str(root / 'report.json')}))
    finally:
        if unit_created and unit_path.exists():
            subprocess.run(['systemctl', 'stop', unit_path.name], check=False, timeout=310)
            with (root / 'daemon.log').open('w') as log:
                subprocess.run(['journalctl', '--unit', unit_path.name, '--no-pager', '-o', 'cat'],
                               stdout=log, check=False)
            unit_path.unlink()
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'reset-failed', unit_path.name], check=False, capture_output=True)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
