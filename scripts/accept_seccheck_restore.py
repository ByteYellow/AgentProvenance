#!/usr/bin/env python3
"""Verify evidence identities across pinned runsc memory restore and clones."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile

from accept_seccheck import digest, run_json, write_json
from accept_seccheck_faults import latest_status, wait_for, require_preserved_records


PHASES = (('original', '1'), ('original', '2'), ('clone-a', '1'), ('clone-b', '1'))


def runtime_command(command, path, timeout=30, expect_success=True):
    # Detached workloads retain stdio; waiting for pipe EOF would wait for the
    # whole sandbox instead of the command. Keep failures in the same log.
    with path.open('w') as log:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
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

    def saved():
        with sqlite3.connect(f"file:{store / 'agentprov.db'}?mode=ro", uri=True) as db:
            return dict(db.execute("SELECT raw_event_id,payload FROM events WHERE source='gvisor_seccheck'"))

    with tempfile.TemporaryDirectory(prefix='ap-scr-') as sockets:
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

                def runtime(command, logfile, timeout=30, expect_success=True):
                    return runtime_command(common + command, bundle / logfile, timeout, expect_success)

                if index == 0:
                    runtime(['--pod-init-config=' + str(bundle / 'trace.json'), 'run', '--detach',
                             '--bundle=' + str(bundle), name], 'run.log')
                else:
                    runtime(['restore', '--detach', '--background=false', '--image-path=' + str(image),
                             '--bundle=' + str(bundle), name], 'restore.log')
                    runtime(['exec', name, '/bin/sh', '-c', 'test ! -e /tmp/proceed'], 'before-rebind.log')
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
                    runtime(['checkpoint', '--image-path=' + str(image), name], 'checkpoint.log', timeout=60)
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
                    'context': observed['sentry']['context'], 'status': final})

            with sqlite3.connect(f"file:{store / 'agentprov.db'}?mode=ro", uri=True) as db:
                scopes = {row[0] for row in db.execute("SELECT DISTINCT container_id FROM events WHERE source='gvisor_seccheck' AND pid=1")}
                processes = {row[0] for row in db.execute("SELECT DISTINCT from_id FROM graph_edges WHERE edge_type='runtime_process_event' AND to_id IN (SELECT 'runtime_event/'||id FROM events WHERE pid=1)")}
            require_restore_identities(records, scopes, processes)
            verify = run_json(args.cli, store, 'graph', 'verify', '--run', run_id, '--json')
            if verify['error_count'] or verify['warning_count']:
                raise RuntimeError('restored evidence graph verification failed')
            public_key = args.output / 'acceptance.pub'
            with tempfile.TemporaryDirectory(prefix='ap-scr-key-') as keys:
                private_key = Path(keys) / 'acceptance.key'
                subprocess.run([str(args.cli), 'forensics', 'keygen', '--priv', str(private_key),
                    '--pub', str(public_key)], capture_output=True, check=True, timeout=10)
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
