#!/usr/bin/env python3
"""systemd hooks for the single trusted in-guest execution service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request


def read_config(path):
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('execution configuration exceeds 64 KiB')
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise ValueError('execution configuration must be a JSON object')
    target = config.get('target', {})
    if not isinstance(target, dict) or not all(isinstance(target.get(key), str) and target[key].strip()
                                              for key in ('producer_id', 'instance_id', 'generation')):
        raise ValueError('external target producer, instance and generation are required')
    capture = config.get('capture')
    if not isinstance(capture, dict) or capture.get('mode') != 'native':
        raise ValueError('guest service requires native capture')
    if not config.get('delivery'):
        raise ValueError('guest service requires signed delivery configuration')
    return config, hashlib.sha256(raw).hexdigest()


def read_token(path):
    with path.open('rb') as stream:
        mode = os.fstat(stream.fileno()).st_mode
        if mode & 0o077:
            raise ValueError('daemon token file must be private (0600 or 0400)')
        raw = stream.read(4097)
    token = raw.decode('ascii').strip()
    if not token or len(raw) > 4096 or any(c.isspace() for c in token):
        raise ValueError('daemon token must be a nonempty single token of at most 4096 bytes')
    return token


def invocation():
    value = os.environ.get('INVOCATION_ID', '')
    if not re.fullmatch('[a-f0-9]{32}', value):
        raise ValueError('systemd INVOCATION_ID is required')
    return value


def paths(args):
    root = args.data_dir / 'guest-lifecycle'
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = invocation()
    return root, name


def write_json(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def command(args):
    return [str(args.binary), '--data-dir', str(args.data_dir)]


def serve(args):
    read_config(args.config)
    token = read_token(args.token_file)
    invocation()
    environment = os.environ.copy()
    environment.pop('AGENTPROV_DAEMON_URL', None)
    environment['AGENTPROV_DAEMON_TOKEN'] = token
    argv = command(args) + ['daemon', 'serve', '--listen', args.listen,
                           '--execution-config', str(args.config), '--sample-interval', '0']
    os.execve(args.binary, argv, environment)


def wait_ready(args):
    root, name = paths(args)
    config, digest = read_config(args.config)
    token = read_token(args.token_file)
    pid = int(os.environ.get('MAINPID', '0'))
    if pid <= 0:
        raise ValueError('systemd MAINPID is required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + args.ready_timeout
    while True:
        os.kill(pid, 0)
        try:
            lock = json.loads((args.data_dir / '.daemon.lock').read_text())
            if lock.get('pid') != pid or lock.get('addr') != args.listen:
                raise ValueError('readiness listener does not belong to this service')
            query = '/v1/executions?run=guest-readiness&harness=guest-init&session=' + name + '&tool_call=ready&limit=1'
            for endpoint in ('/v1/ready', query):
                request = urllib.request.Request('http://' + args.listen + endpoint,
                    headers={'Authorization': 'Bearer ' + token})
                with opener.open(request, timeout=min(2, args.ready_timeout)) as response:
                    body = json.load(response)
                if endpoint == '/v1/ready' and body.get('ready') is not True:
                    raise ValueError('daemon is not ready')
            report = {'schema_version': 'agentprovenance.guest_lifecycle/v1',
                      'invocation_id': name, 'phase': 'ready', 'pid': pid,
                      'target': config['target'], 'configuration_sha256': digest,
                      'kernel': os.uname().release, 'architecture': os.uname().machine,
                      'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'listen': args.listen, 'observed_at': time.time()}
            write_json(root / (name + '.ready.json'), report)
            print(json.dumps(report), flush=True)
            return
        except (OSError, ValueError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError('guest readiness timeout: ' + str(error)) from error
        time.sleep(0.1)


def seal(args):
    root, name = paths(args)
    report = {'schema_version': 'agentprovenance.guest_lifecycle/v1',
              'invocation_id': name, 'phase': 'stopped', 'sealed': False,
              'receiver_acknowledged': None, 'may_reclaim': False,
              'service_result': os.environ.get('SERVICE_RESULT', 'unknown'),
              'exit_code': os.environ.get('EXIT_CODE', 'unknown'),
              'exit_status': os.environ.get('EXIT_STATUS', 'unknown'),
              'observed_at': time.time()}
    temporary = None
    try:
        config, digest = read_config(args.config)
        ready = json.loads((root / (name + '.ready.json')).read_text())
        if ready.get('configuration_sha256') != digest or ready.get('target') != config['target']:
            raise ValueError('execution configuration changed since service readiness')
        report['target'] = config['target']
        environment = os.environ.copy()
        for key in ('AGENTPROV_DAEMON_URL', 'AGENTPROV_DAEMON_TOKEN'):
            environment.pop(key, None)
        # Preserve the complete paged CLI stream on disk, including failures.
        # Retrying this invocation reuses the original immutable packages.
        with tempfile.NamedTemporaryFile(mode='w+b', dir=root, delete=False) as stream:
            temporary = Path(stream.name)
            result = subprocess.run(command(args) + ['forensics', 'seal-executions',
                '--execution-config', str(args.config), '--operation', 'guest-stop-' + name],
                stdout=stream, env=environment, check=False)
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(0)
            summary = None
            for line in stream:
                summary = json.loads(line)
        output = root / (name + '.seal.jsonl')
        temporary.replace(output)
        report['package_results'] = str(output)
        report['seal_exit_code'] = result.returncode
        report['summary'] = summary
        if result.returncode != 0 or not summary or summary.get('complete') is not True:
            raise RuntimeError('guest sealing incomplete; retain the evidence volume')
        report['sealed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if temporary is not None and temporary.exists():
            temporary.replace(root / (name + '.seal-interrupted.jsonl'))
        write_json(root / (name + '.stopped.json'), report)
        print(json.dumps(report), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['serve', 'ready', 'seal'])
    defaults = {'binary': '/usr/local/bin/agentprov', 'data_dir': '/var/lib/agentprov-guest',
                'config': '/etc/agentprov-guest/execution.json', 'token_file': '/etc/agentprov-guest/daemon-token'}
    for key, value in defaults.items():
        parser.add_argument('--' + key.replace('_', '-'), type=Path,
            default=Path(os.environ.get('AGENTPROV_GUEST_' + key.upper(), value)))
    parser.add_argument('--listen', default=os.environ.get('AGENTPROV_GUEST_LISTEN', '127.0.0.1:8574'))
    parser.add_argument('--ready-timeout', type=float, default=120)
    args = parser.parse_args()
    try:
        host, port = args.listen.rsplit(':', 1)
        if host != '127.0.0.1' or not 1 <= int(port) <= 65535:
            raise ValueError('guest execution API requires an IPv4 loopback listener')
        if not 0 < args.ready_timeout <= 120:
            raise ValueError('readiness timeout must be within (0, 120] seconds')
        if any(not getattr(args, key).is_absolute() for key in defaults):
            raise ValueError('guest service paths must be absolute')
        os.umask(0o077)
        {'serve': serve, 'ready': wait_ready, 'seal': seal}[args.action](args)
    except (OSError, ValueError, RuntimeError) as error:
        print('agentprov guest: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
