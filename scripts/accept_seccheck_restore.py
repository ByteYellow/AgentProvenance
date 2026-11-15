#!/usr/bin/env python3
"""Verify evidence identities across pinned runsc memory restore and clones."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import tempfile

from accept_seccheck import digest, run_json, write_json
from accept_seccheck_faults import latest_status, wait_for, require_preserved_records


PHASES = (('original', '1'), ('original', '2'), ('clone-a', '1'), ('clone-b', '1'))


def runtime_command(command, path, timeout=30, expect_success=True, input_bytes=None):
    # Detached workloads retain stdio; waiting for pipe EOF would wait for the
    # whole sandbox instead of the command. Keep failures in the same log.
    with path.open('w') as log:
        result = subprocess.run(command, stdin=subprocess.DEVNULL if input_bytes is None else None,
                                input=input_bytes, stdout=log,
                                stderr=subprocess.STDOUT, timeout=timeout)
    if (result.returncode == 0) != expect_success:
        raise RuntimeError(f'unexpected runtime exit {result.returncode}; see {path}')
    return path.read_text()


def require_restore_identities(records, scopes, processes):
    if [(r['registration']['instance_id'], r['registration']['generation']) for r in records] != list(PHASES):
        raise RuntimeError('incomplete restore and clone phases')
    for field in ('memory_value', 'hostname', 'boot_id'):
        values = {r[field] for r in records}
        if len(values) != 1 or not next(iter(values)):
            raise RuntimeError(f'restored {field} changed or is missing')
    births = {r['context']['group_start_ns'] for r in records}
    if len(births) != 1 or next(iter(births)) <= 0:
        raise RuntimeError('restored root birth identity changed or is missing')
    expected_scopes, expected_processes = set(), set()
    for record in records:
        if record['context']['group_id'] != 1:
            raise RuntimeError('expected the original PID 1, not a new exec process')
        reg = record['registration']
        raw = json.dumps([reg[k] for k in ('namespace', 'instance_id', 'generation', 'sandbox_id', 'container_id')],
                         separators=(',', ':'), ensure_ascii=False).encode()
        scope = 'gvisor/' + hashlib.sha256(raw).hexdigest()
        expected_scopes.add(scope)
        expected_processes.add(f"runtime_process/{scope}/process/1:{record['context']['group_start_ns']}")
    if scopes != expected_scopes or processes != expected_processes:
        raise RuntimeError('restored identities merged or assigned to the wrong lifecycle')


def require_expired_endpoint(log, endpoint):
    if f'connect("{endpoint}")' not in log or not any(reason in log for reason in
            ('no such file or directory', 'connection refused')):
        raise RuntimeError('stale trace failed for a reason other than its expired endpoint')


def require_replay_receipt(result, registration, expected_ids, digest_value, ingested):
    receipts = result.get('receipts', [])
    if len(receipts) != 1:
        raise RuntimeError('expected one historical Run receipt')
    receipt = receipts[0]
    if (receipt['uploader'] != registration or receipt['file_sha256'] != digest_value
            or receipt['event_ids'] != expected_ids or receipt['records'] != len(expected_ids)
            or receipt['ingested'] != ingested or receipt['duplicates'] != len(expected_ids) - ingested
            or receipt['authority_basis'] != 'local_operator_registration'):
        raise RuntimeError('historical replay lost its original identity or uploader')
    return receipt


def require_signature_rejection(code, error, destination):
    if code != 1 or 'attestation verify failed: attest: no valid signature for key' not in error:
        raise RuntimeError('copied signing key did not fail at the current signature trust boundary')
    if destination.exists():
        raise RuntimeError('rejected copied signing key created a receiving store')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cli', 'runsc', 'rootfs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('isolated runsc acceptance requires root')
    for name in ('cli', 'runsc', 'rootfs', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    version = subprocess.check_output([str(args.runsc), '--version'], text=True, timeout=10)
    if 'runsc version release-20261109.0' not in version.splitlines():
        raise RuntimeError('unexpected runtime: ' + version)
    store = args.output / 'store'
    run_id, name = 'seccheck-restore', 'snapshot-workload'
    image = args.output / 'snapshot'
    collectors, sandboxes = [], []
    # The shell state and tmpfs are restored from memory. Each copy waits for
    # its own tmpfs gate until the external receiver has registered a new scope.
    workload = ('seed="$(date +%s%N)-$$"; printf "%s\\n" "$seed" > /tmp/snapshot-before; '
                'echo SNAPSHOT_READY; '
                'while [ ! -f /tmp/proceed ]; do sleep 0.1; done; '
                'printf "%s\\n" "$seed" > /tmp/snapshot-result; '
                'echo SNAPSHOT_RESTORED; sleep 300')

    def saved(directory=store):
        with sqlite3.connect(f"file:{directory / 'agentprov.db'}?mode=ro", uri=True) as db:
            return dict(db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'"))

    with tempfile.TemporaryDirectory(prefix='ap-scr-') as sockets, \
            tempfile.TemporaryDirectory(prefix='ap-scr-retired-') as old_keys:
        retired_private = Path(old_keys) / 'retired.key'
        retired_public = args.output / 'retired.pub'
        subprocess.run([str(args.cli), 'forensics', 'keygen', '--priv', str(retired_private),
                        '--pub', str(retired_public)], capture_output=True, check=True, timeout=10)
        retired_bytes = retired_private.read_bytes()
        try:
            records = []
            previous = None
            for index, (instance, generation) in enumerate(PHASES):
                bundle = args.output / f'phase-{index}'
                bundle.mkdir()
                state = bundle / 'state'
                endpoint = str(Path(sockets) / f'{index}.sock')
                registration = {'namespace': 'restore-acceptance', 'instance_id': instance,
                                'generation': generation, 'sandbox_id': name, 'container_id': name,
                                'peer_uid': os.geteuid()}
                config = args.output / f'registration-{index}.json'
                write_json(config, {'schema_version': 'agentprovenance.seccheck_collection/v1',
                    'runtime_release': 'release-20261109.0', 'targets': [{'run_id': run_id,
                    'socket_path': endpoint, 'registration': registration}]})
                trace = run_json(args.cli, store, 'telemetry', 'seccheck-config', '--socket', endpoint)
                write_json(bundle / 'trace.json', trace)
                write_json(bundle / 'config.json', {
                    'ociVersion': '1.0.2', 'hostname': 'same-snapshot-host',
                    'process': {'user': {'uid': 0, 'gid': 0}, 'terminal': False,
                        'args': ['/bin/sh', '-c', workload], 'env': ['PATH=/bin:/usr/bin'],
                        'cwd': '/', 'noNewPrivileges': True},
                    'root': {'path': str(args.rootfs), 'readonly': True},
                    'mounts': [{'destination': '/proc', 'type': 'proc', 'source': 'proc'},
                        {'destination': '/dev', 'type': 'tmpfs', 'source': 'tmpfs'},
                        {'destination': '/tmp', 'type': 'tmpfs', 'source': 'tmpfs',
                         'options': ['nosuid', 'nodev', 'size=16m']}],
                    'linux': {'cgroupsPath': f'/agentprov-{args.output.name}-phase-{index}',
                        'namespaces': [{'type': n} for n in ('pid', 'network', 'ipc', 'uts', 'mount')]}})
                status = args.output / f'collector-{index}.jsonl'
                with status.open('w') as out, (args.output / f'collector-{index}.stderr').open('w') as err:
                    collector = subprocess.Popen([str(args.cli), '--data-dir', str(store), 'telemetry',
                        'receive-seccheck', '--config', str(config), '--json', '--status-interval', '100ms',
                        '--batch-events', '8'], stdout=out, stderr=err)
                collectors.append(collector)

                def listening():
                    if collector.poll() is not None:
                        raise RuntimeError(f'collector stopped before listening: {collector.returncode}')
                    return latest_status(status).get('state') == 'listening'

                wait_for(listening, 'registered receiver listening')
                common = [str(args.runsc), '--root=' + str(state), '--platform=systrap', '--network=none']
                sandboxes.append((state, name))

                def runtime(command, logfile, timeout=30, expect_success=True, input_bytes=None):
                    return runtime_command(common + command, bundle / logfile, timeout, expect_success, input_bytes)

                if index == 0:
                    runtime(['--pod-init-config=' + str(bundle / 'trace.json'), 'run', '--detach',
                             '--bundle=' + str(bundle), name], 'run.log')
                else:
                    runtime(['restore', '--detach', '--background=false', '--image-path=' + str(image),
                             '--bundle=' + str(bundle), name], 'restore.log')
                    runtime(['exec', name, '/bin/sh', '-c', 'test ! -e /tmp/proceed'], 'before-rebind.log')
                    copied = subprocess.run(common + ['exec', name, '/bin/cat', '/tmp/copied-signing.key'],
                                            capture_output=True, check=True, timeout=10)
                    if copied.stdout != retired_bytes:
                        raise RuntimeError('snapshot did not retain the original signing credential')
                    copied_private = Path(old_keys) / 'copied.key'
                    copied_private.write_bytes(copied.stdout)
                    copied_private.chmod(0o600)
                    rejected = runtime(['trace', 'create', '--force', '--config=' + str(args.output / 'phase-0/trace.json'), name],
                                       'stale-trace.log', expect_success=False)
                    require_expired_endpoint(rejected, str(Path(sockets) / '0.sock'))
                    before_rebind = latest_status(status)
                    write_json(bundle / 'before-rebind.json', before_rebind)
                    target = before_rebind['targets'][0]
                    if target['state'] != 'listening' or target.get('accepted_records', 0) != 0:
                        raise RuntimeError('restored runtime accepted evidence before external rebind')
                    runtime(['trace', 'create', '--force', '--config=' + str(bundle / 'trace.json'), name], 'trace.log')
                wait_for(lambda: latest_status(status).get('targets', [{}])[0].get('state') == 'connected',
                         'new registered trace connection')

                def before_ready():
                    result = subprocess.run(common + ['exec', name, '/bin/cat', '/tmp/snapshot-before'],
                                            capture_output=True, text=True, timeout=10)
                    return result.stdout.strip() if result.returncode == 0 else None

                seed = wait_for(before_ready, 'saved memory workload ready')
                if index == 0:
                    # Deliberately place a synthetic retired key in memory-backed
                    # storage. Its bytes never enter argv, trace config or logs.
                    runtime(['exec', name, '/bin/sh', '-c', 'umask 077; cat > /tmp/copied-signing.key'],
                            'seed-credential.log', input_bytes=retired_bytes)
                hostname = runtime(['exec', name, '/bin/hostname'], 'hostname.log').strip()
                boot_id = runtime(['exec', name, '/bin/cat', '/proc/sys/kernel/random/boot_id'], 'boot-id.log').strip()
                if index:
                    if seed != records[0]['memory_value']:
                        raise RuntimeError('restore started a new workload instead of preserving memory')
                    runtime(['exec', name, '/bin/touch', '/tmp/proceed'], 'release.log')

                    def result_ready():
                        result = subprocess.run(common + ['exec', name, '/bin/cat', '/tmp/snapshot-result'],
                                                capture_output=True, text=True, timeout=10)
                        return result.returncode == 0 and result.stdout.strip() == seed

                    wait_for(result_ready, 'restored original shell result')
                marker = '/tmp/snapshot-before' if index == 0 else '/tmp/snapshot-result'

                def marker_saved():
                    for value in saved().values():
                        body = json.loads(value)
                        if body.get('path') == marker and body['sentry']['registration'] == registration:
                            if body['sentry'].get('context', {}).get('group_id') == 1:
                                return body
                    return None

                observed = wait_for(marker_saved, 'root-process marker in evidence')
                if index == 0:
                    # Keep one actual fsynced queue file before its first ingest.
                    # The trusted host retains its digest outside both copies.
                    with sqlite3.connect(store / 'agentprov.db') as db:
                        db.execute("CREATE TRIGGER hold_historical BEFORE INSERT ON events WHEN NEW.source='gvisor_seccheck' BEGIN SELECT RAISE(ABORT,'hold historical batch'); END")
                    try:
                        def pending_batch():
                            with sqlite3.connect(store / 'agentprov.db') as db:
                                return db.execute("SELECT id,spool_path,file_sha256,event_count FROM telemetry_spool_batches WHERE format='gvisor_seccheck' AND status='queued' AND file_sha256!='' AND event_count>0 ORDER BY created_at LIMIT 1").fetchone()

                        batch = wait_for(pending_batch, 'original sealed historical spool')
                        historical = args.output / 'historical-spool.jsonl'
                        shutil.copyfile(batch[1], historical)
                        if digest(historical) != batch[2]:
                            raise RuntimeError('copied spool differs from its host-retained digest')
                        history_records = [json.loads(line) for line in historical.read_text().splitlines()]
                        if len(history_records) != batch[3]:
                            raise RuntimeError('copied spool record count differs')
                        write_json(args.output / 'historical-spool.json', {'batch_id': batch[0], 'sha256': batch[2], 'records': batch[3]})
                        runtime(['checkpoint', '--image-path=' + str(image), name], 'checkpoint.log', timeout=60)
                    finally:
                        with sqlite3.connect(store / 'agentprov.db') as db:
                            db.execute('DROP TRIGGER hold_historical')
                else:
                    runtime(['kill', name, 'KILL'], 'stop.log')
                wait_for(lambda: latest_status(status).get('targets', [{}])[0].get('state') == 'disconnected',
                         'runtime trace disconnected')
                collector.send_signal(signal.SIGTERM)
                if collector.wait(timeout=45):
                    raise RuntimeError('collector did not drain successfully')
                final = latest_status(status)
                if final['node_spool']['pending_events'] or final['node_spool']['queued_bytes']:
                    raise RuntimeError('unsettled restored evidence')
                current = saved()
                if previous:
                    require_preserved_records(previous, current)
                previous = current
                records.append({'registration': registration, 'memory_value': seed,
                    'hostname': hostname, 'boot_id': boot_id,
                    'copied_signing_key_matches': True,
                    'context': observed['sentry']['context'], 'status': final})
                if index == 0:
                    retired_bundle = run_json(args.cli, store, 'forensics', 'export', run_id,
                                              '--sign-key', str(retired_private), '--json')

            with sqlite3.connect(f"file:{store / 'agentprov.db'}?mode=ro", uri=True) as db:
                scopes = {row[0] for row in db.execute("SELECT DISTINCT container_id FROM events WHERE source='gvisor_seccheck' AND pid=1")}
                processes = {row[0] for row in db.execute("SELECT DISTINCT from_id FROM graph_edges WHERE edge_type='runtime_process_event' AND to_id IN (SELECT 'runtime_event/'||id FROM events WHERE pid=1)")}
            require_restore_identities(records, scopes, processes)
            replay_store = args.output / 'replay-store'
            expected_ids = ['evt-seccheck-' + hashlib.sha256(r['RawEventID'].encode()).hexdigest() for r in history_records]
            historical_rows = {r['RawEventID']: previous[r['RawEventID']] for r in history_records}
            replay_results = []
            for index in (2, 3):
                copied = args.output / f'phase-{index}' / 'inherited-spool.jsonl'
                shutil.copyfile(historical, copied)
                if digest(copied) != batch[2]:
                    raise RuntimeError('clone changed its inherited spool')
                arguments = ('telemetry', 'replay-seccheck', '--config', str(args.output / f'registration-{index}.json'),
                             '--file', str(copied), '--sha256', batch[2], '--json')
                fresh = run_json(args.cli, replay_store, *arguments)
                receipt = require_replay_receipt(fresh, records[index]['registration'], expected_ids, batch[2], len(expected_ids) if index == 2 else 0)
                duplicate = run_json(args.cli, store, *arguments)
                require_replay_receipt(duplicate, records[index]['registration'], expected_ids, batch[2], 0)
                retry = run_json(args.cli, replay_store, *arguments)
                if retry['receipts'] != fresh['receipts'] or retry['reused_receipt_ids'] != [receipt['receipt_id']]:
                    raise RuntimeError('restarted uploader did not reuse its durable receipt')
                require_preserved_records(historical_rows, saved(replay_store))
                require_preserved_records(previous, saved())
                replay_results.append({'registration': records[index]['registration'], 'fresh_store': fresh,
                    'existing_store': duplicate, 'retry': retry})
            if replay_results[0]['fresh_store']['receipts'][0]['receipt_id'] == replay_results[1]['fresh_store']['receipts'][0]['receipt_id']:
                raise RuntimeError('two uploaders merged into one receipt')
            if len(saved(replay_store)) != len(expected_ids) + 2:
                raise RuntimeError('two clones duplicated historical execution observations')
            previous = saved()
            if any(retired_bytes.strip().decode('ascii') in payload for payload in previous.values()):
                raise RuntimeError('synthetic private signing key leaked into captured evidence')
            replay_verify = run_json(args.cli, replay_store, 'graph', 'verify', '--run', run_id, '--json')
            if replay_verify['error_count'] or replay_verify['warning_count']:
                raise RuntimeError('replayed historical graph verification failed')
            verify = run_json(args.cli, store, 'graph', 'verify', '--run', run_id, '--json')
            if verify['error_count'] or verify['warning_count']:
                raise RuntimeError('restored evidence graph verification failed')
            public_key = args.output / 'acceptance.pub'
            with tempfile.TemporaryDirectory(prefix='ap-scr-key-') as keys:
                private_key = Path(keys) / 'acceptance.key'
                subprocess.run([str(args.cli), 'forensics', 'keygen', '--priv', str(private_key),
                    '--pub', str(public_key)], capture_output=True, check=True, timeout=10)
                if digest(public_key) == digest(retired_public):
                    raise RuntimeError('external publisher did not rotate the retired signing credential')
                copied_signed = run_json(args.cli, store, 'forensics', 'export', run_id,
                                         '--sign-key', str(copied_private), '--json')
                # Positive control: this is a valid old-key signature, not a
                # corrupt package or unrelated CLI failure.
                for signed in (retired_bundle, copied_signed):
                    subprocess.run([str(args.cli), 'forensics', 'verify-attestation', signed['path'],
                        signed['attestation_path'], '--pub-key', str(retired_public)],
                        capture_output=True, check=True, timeout=30)
                rejected_store = args.output / 'copied-key-rejected-store'
                rejection = subprocess.run([str(args.cli), '--data-dir', str(rejected_store),
                    'forensics', 'import', copied_signed['path'], '--pub-key', str(public_key), '--json'],
                    capture_output=True, text=True, timeout=30)
                require_signature_rejection(rejection.returncode, rejection.stderr, rejected_store)
                write_json(args.output / 'copied-key-rejection.json', {
                    'exit_code': rejection.returncode, 'error': rejection.stderr,
                    'receiver_store_created': rejected_store.exists()})
                exported = run_json(args.cli, store, 'forensics', 'export', run_id,
                                    '--sign-key', str(private_key), '--json')
            receiver_store = args.output / 'receiver-store'
            imported = run_json(args.cli, receiver_store, 'forensics', 'import', exported['path'],
                                '--pub-key', str(public_key), '--json')
            if not exported['signed'] or not imported['attestation_verified']:
                raise RuntimeError('signed evidence round trip failed')
            with sqlite3.connect(f"file:{receiver_store / 'agentprov.db'}?mode=ro", uri=True) as db:
                imported_rows = dict(db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'"))
            if imported_rows != previous:
                raise RuntimeError('signed import changed restored evidence')
            imported_verify = run_json(args.cli, receiver_store, 'graph', 'verify', '--run', run_id, '--json')
            if imported_verify['error_count'] or imported_verify['warning_count']:
                raise RuntimeError('imported restored evidence graph verification failed')
            write_json(args.output / 'result.json', {'passed': True, 'runtime': version,
                'platform': list(os.uname()), 'binary_sha256': {key: digest(getattr(args, key)) for key in ('cli', 'runsc')},
                'rootfs': {'path': str(args.rootfs), 'busybox_sha256': digest(args.rootfs / 'bin/busybox'),
                    'os_release': (args.rootfs / 'etc/os-release').read_text()},
                'acceptance_script_sha256': digest(Path(__file__)),
                'phases': records, 'events': len(previous), 'scopes': sorted(scopes), 'process_nodes': sorted(processes),
                'historical_spool': {'sha256': batch[2], 'records': batch[3], 'event_ids': expected_ids,
                    'uploads': replay_results, 'verify': replay_verify},
                'reauthorization': {'policy': 'external_registration_and_host_signer_rotation',
                    'signer_scope': 'trusted_host_producer', 'copied_key_rejected': True,
                    'historical_signature_verified': True, 'current_import_verified': imported['attestation_verified'],
                    'retired_public_sha256': digest(retired_public), 'current_public_sha256': digest(public_key),
                    'historical_bundle': retired_bundle, 'copied_key_signed_bundle': copied_signed},
                'snapshot': {p.name: digest(p) for p in image.iterdir() if p.is_file()}, 'verify': verify,
                'bundle': exported, 'import': imported, 'import_verify': imported_verify})
        finally:
            for collector in collectors:
                if collector.poll() is None:
                    collector.send_signal(signal.SIGTERM)
                    try:
                        collector.wait(timeout=45)
                    except subprocess.TimeoutExpired:
                        collector.kill()
                        collector.wait(timeout=10)
            errors = []
            for state, sandbox in reversed(sandboxes):
                cleanup = subprocess.run([str(args.runsc), '--root=' + str(state), 'delete', '--force', sandbox],
                                         capture_output=True, timeout=15)
                (state.parent / 'cleanup.log').write_bytes(cleanup.stdout + cleanup.stderr)
                if cleanup.returncode:
                    errors.append(str(state))
                mount = state / 'null-netns'
                if mount.exists() and subprocess.run(['mountpoint', '-q', str(mount)]).returncode == 0:
                    subprocess.run(['umount', str(mount)], check=True, timeout=10)
            if errors:
                raise RuntimeError('runtime cleanup failed: ' + ', '.join(errors))
    print(json.dumps({'passed': True, 'output': str(args.output)}))


if __name__ == '__main__':
    main()
