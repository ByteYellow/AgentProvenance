#!/usr/bin/env python3
"""Live Pod -> informer binding -> in-guest collector -> verified graph gate."""
import argparse
import json
import platform
from pathlib import Path
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agentprov', default='/usr/local/bin/agentprov')
    parser.add_argument('--data-dir', default='/var/lib/agentprov')
    parser.add_argument('--image', default='busybox:1.37.0')
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    pod = 'agentprov-guest-' + uuid.uuid4().hex[:10]
    run = 'run-' + pod
    cli = [args.agentprov, '--data-dir', args.data_dir]
    kube = ['k3s', 'kubectl', '-n', 'default']

    def query(*command):
        return json.loads(subprocess.check_output(cli + list(command) + ['--json'], text=True))

    def wait_for(operation, predicate, description):
        deadline = time.monotonic() + 45
        while True:
            value = operation()
            if predicate(value):
                return value
            if time.monotonic() > deadline:
                raise RuntimeError(description + ': ' + str(value))
            time.sleep(0.25)

    manifest = {
        'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': pod, 'annotations': {'agentprov.io/run': run}},
        'spec': {'restartPolicy': 'Never', 'containers': [{
            'name': 'workload', 'image': args.image, 'imagePullPolicy': 'IfNotPresent',
            'command': ['sh', '-c', 'sleep 3600']}]},
    }
    subprocess.run(kube + ['apply', '-f', '-'], input=json.dumps(manifest), text=True, check=True)
    try:
        subprocess.run(kube + ['wait', '--for=condition=Ready', 'pod/' + pod, '--timeout=90s'], check=True)
        bindings = wait_for(lambda: (query('telemetry', 'bindings', '--run', run)['bindings'] or []),
                            lambda rows: any(not row['ended_at'] for row in rows), 'no live informer binding')
        subprocess.run(kube + ['exec', pod, '--', 'sh', '-ec',
            'cd /; id >/dev/null; printf "acceptance-only\\n" > agentprov-fixture.env; '
            'cat agentprov-fixture.env >/dev/null; mv agentprov-fixture.env agentprov-renamed.env; '
            'rm agentprov-renamed.env; nc -w 1 127.0.0.1 9 </dev/null || true'], check=True)
        required = {'execve', 'file_write', 'network_connect', 'file_rename', 'file_unlink'}
        native = wait_for(
            lambda: [row for row in (query('telemetry', 'list', '--run', run, '--limit', '1000')['events'] or [])
                     if row['source'] == 'agentprov_ebpf'],
            lambda rows: required <= {row['event_type'] for row in rows}, 'missing Pod kernel evidence')
        bound_cgroups = {row['cgroup_id'] for row in bindings}
        if any(row['cgroup_id'] not in bound_cgroups or row['binding_source'] != 'k8s_cgroup' for row in native):
            raise RuntimeError('Pod events were not attributed through their informer cgroup binding')
        subprocess.run(kube + ['delete', 'pod', pod, '--wait=true', '--timeout=60s'], check=True)
        closed = wait_for(lambda: (query('telemetry', 'bindings', '--run', run)['bindings'] or []),
                          lambda rows: bool(rows) and all(row['ended_at'] for row in rows), 'Pod bindings remain open')
        subprocess.run(cli + ['graph', 'materialize', '--run', run], check=True, stdout=subprocess.DEVNULL)
        verified = query('graph', 'verify', '--run', run)
        report = {
            'schema_version': 'agentprovenance.k3s_guest_acceptance/v1',
            'architecture': platform.machine(), 'kernel': platform.release(),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'run_id': run, 'native_events': len(native),
            'event_types': sorted({row['event_type'] for row in native}),
            'binding_source': 'k8s_cgroup', 'bindings_closed': len(closed),
            'verification': verified, 'passed': True,
        }
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        subprocess.run(kube + ['delete', 'pod', pod, '--ignore-not-found', '--wait=false'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
