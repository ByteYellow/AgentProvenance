"""Cleanup regressions: real owned processes and a local API/CRI-free Pod contract."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import common
import run
from test_contracts import pinned


POD_DRIVER = r'''
import json, os, signal, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv.pop(1))
import run
mode, journal = sys.argv.pop(1), Path(sys.argv.pop(1))
pod = None
interrupted = False
def kube(self, *argv, **kwargs):
    global pod, interrupted
    with journal.open('a') as out:
        out.write(json.dumps({'argv': argv, 'kwargs': kwargs}) + '\n')
    if argv[0] == 'create':
        pod = json.loads(kwargs['input'])
        pod['metadata']['uid'] = 'owned-api-uid'
        pod['status'] = {'phase': 'Pending'}
        (self.args.data_dir / 'boot-1/retained.txt').write_text('fixture evidence')
        if mode == 'foreign-owner':
            pod['metadata']['labels']['agentprov.io/acceptance-owner'] = 'someone-else'
        if mode == 'create-sigterm':
            interrupted = True
            os.kill(os.getpid(), signal.SIGTERM)
        if mode in ('response-lost', 'foreign-owner'):
            raise subprocess.TimeoutExpired('kubectl create', 30)
        return json.dumps(pod)
    if 'get' in argv:
        if mode == 'running-sigterm' and not interrupted:
            interrupted = True
            os.kill(os.getpid(), signal.SIGTERM)
        return json.dumps(pod)
    if 'logs' in argv:
        return 'retained fixture log\n'
    if argv[0] == 'delete':
        if mode == 'create-sigterm':
            os.kill(os.getpid(), signal.SIGTERM)
        return ''
    if 'wait' in argv:
        return ''
    raise AssertionError(argv)
run.Node.kubectl = kube
run.Node.preflight = lambda self: {'contract_only': True}
sys.exit(run.main())
'''


class OwnedGroupCleanupTests(unittest.TestCase):
    def test_unregistered_group_is_never_signalled(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'], start_new_session=True)
        try:
            with patch.object(common.os, 'killpg') as send:
                with self.assertRaises(common.Blocked):
                    common.stop_owned(process, timeout=.1)
                send.assert_not_called()
        finally:
            process.kill()
            process.wait(timeout=5)

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX process groups')
    def test_residual_child_after_leader_exit_is_killed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = r'''
import json, os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
if os.fork():
    while not (root / 'child.json').exists():
        time.sleep(.005)
    os._exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
(root / 'child.json').write_text(json.dumps({'pid': os.getpid(), 'pgid': os.getpgrp()}))
with (root / 'heartbeat').open('ab', buffering=0) as out:
    for _ in range(1000):
        out.write(b'x')
        time.sleep(.01)
'''
            stop = common.stop_owned
            try:
                with patch.object(common, 'stop_owned', side_effect=lambda p, **kw: stop(p, timeout=.1)):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        common.command([sys.executable, '-c', program, root], timeout=.3)
                child = common.load(root / 'child.json')
                self.assertNotEqual(child['pgid'], os.getpgrp())
                before = (root / 'heartbeat').stat().st_size
                time.sleep(.15)
                self.assertEqual((root / 'heartbeat').stat().st_size, before,
                                 'owned child survived leader exit and the command deadline')
            finally:
                if (root / 'child.json').exists():
                    pgid = common.load(root / 'child.json')['pgid']
                    if pgid != os.getpgrp():
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


class PodCleanupTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'agentprov'
            binary.write_bytes(b'contract-only; never executed')
            lock = pinned()
            lock['sensor']['sha256'] = common.digest(binary)
            common.save(root / 'lock.json', lock)
            journal = root / 'kubectl.jsonl'
            args = [sys.executable, '-B', '-c', POD_DRIVER, str(run.HERE), mode, str(journal),
                    'run', '--binary', str(binary), '--lock', str(root / 'lock.json'),
                    '--data-dir', str(root / 'data'), '--output', str(root / 'report'),
                    '--context', 'contract-only', '--namespace', 'fixture', '--node', 'node-1',
                    '--cri-endpoint', 'unix:///not-used', '--allow-privileged-guest']
            result = subprocess.run(args, text=True, capture_output=True, timeout=10, start_new_session=True)
            expected = 143 if 'sigterm' in mode else 2 if mode == 'foreign-owner' else 1
            self.assertEqual(result.returncode, expected, result.stderr)
            calls = [json.loads(row) for row in journal.read_text().splitlines()]
            report = common.load(root / 'report/report.json')
            stage = report['stages'][0]
            self.assertEqual((root / 'data/boot-1/retained.txt').read_text(), 'fixture evidence')
            self.assertTrue(any('get' in call['argv'] for call in calls), 'cleanup never reconciled the exact Pod name')
            for call in calls:
                self.assertFalse({'--all', '--selector', '-l'} & set(call['argv']))
                self.assertLessEqual(call['kwargs'].get('timeout', 30), 75)
                if 'get' in call['argv']:
                    i = call['argv'].index('get')
                    self.assertEqual(call['argv'][i + 1:i + 3], ['pod', stage['pod_name']])
            deletions = [call for call in calls if call['argv'][0] == 'delete']
            if mode == 'foreign-owner':
                self.assertEqual(deletions, [], 'unowned Pod was deleted')
                self.assertIn('cleanup_error', stage)
            else:
                self.assertEqual(len(deletions), 1, 'owned Pod cleanup did not issue exactly one DELETE')
                self.assertEqual(json.loads(deletions[0]['kwargs']['input'])['preconditions'], {'uid': 'owned-api-uid'})
                self.assertEqual(deletions[0]['argv'][1:3], ['--raw', '/api/v1/namespaces/fixture/pods/' + stage['pod_name']])
                self.assertTrue(stage['pod_deleted'])
                self.assertTrue(any('wait' in call['argv'] for call in calls), 'SIGTERM interrupted cleanup wait')
                self.assertEqual((root / 'data/boot-1/pod.log').read_text(), 'retained fixture log\n')

    def test_create_response_lost_reconciles_owned_uid(self):
        self.exercise('response-lost')

    def test_sigterm_after_creation_cleans_owned_uid(self):
        self.exercise('running-sigterm')

    def test_sigterm_during_create_and_cleanup_is_bounded(self):
        self.exercise('create-sigterm')

    def test_lost_response_cannot_delete_foreign_owner(self):
        self.exercise('foreign-owner')


if __name__ == '__main__':
    unittest.main()
