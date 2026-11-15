import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from accept_seccheck_restore import PHASES, require_expired_endpoint, require_restore_identities, runtime_command


class RestoreAcceptanceChecks(unittest.TestCase):
    def setUp(self):
        self.records, self.scopes, self.processes = [], set(), set()
        birth = 1794711967422000212
        for instance, generation in PHASES:
            values = ['restore-acceptance', instance, generation, 'snapshot-workload', 'snapshot-workload']
            registration = dict(zip(('namespace', 'instance_id', 'generation', 'sandbox_id', 'container_id'), values))
            self.records.append({'registration': registration, 'memory_value': 'seed-from-memory',
                'hostname': 'same-snapshot-host', 'boot_id': 'same-boot',
                'context': {'group_id': 1, 'group_start_ns': birth}})
            scope = 'gvisor/' + hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()
            self.scopes.add(scope)
            self.processes.add(f'runtime_process/{scope}/process/1:{birth}')

    def test_identical_local_identity_has_four_external_lifetimes(self):
        require_restore_identities(self.records, self.scopes, self.processes)

    def test_missing_or_repeated_phase_fails(self):
        for records in (self.records[:-1], self.records + [self.records[-1]],
                        [self.records[0]] * 4):
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                require_restore_identities(records, self.scopes, self.processes)

    def test_new_boot_or_workload_is_not_a_memory_restore(self):
        for field in ('memory_value', 'hostname', 'boot_id'):
            for value in ('different', ''):
                records = copy.deepcopy(self.records)
                records[3][field] = value
                with self.assertRaisesRegex(RuntimeError, field):
                    require_restore_identities(records, self.scopes, self.processes)

    def test_new_process_or_lost_birth_precision_fails(self):
        for field, value in (('group_id', 2), ('group_start_ns', 0),
                             ('group_start_ns', int(float(1794711967422000212)))):
            records = copy.deepcopy(self.records)
            records[1]['context'][field] = value
            with self.assertRaises(RuntimeError):
                require_restore_identities(records, self.scopes, self.processes)

    def test_count_alone_cannot_accept_wrong_graph_identity(self):
        for scopes, processes in (({'merged'}, self.processes), (self.scopes, {'merged'}),
                                  (self.scopes, {'wrong-' + p for p in self.processes})):
            with self.assertRaisesRegex(RuntimeError, 'identities merged or assigned'):
                require_restore_identities(self.records, scopes, processes)

    def test_exit_status_and_error_log_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'runtime.log'
            command = [sys.executable, '-c', 'print("expected failure"); raise SystemExit(3)']
            with self.assertRaisesRegex(RuntimeError, 'exit 3'):
                runtime_command(command, log)
            self.assertIn('expected failure', log.read_text())
            runtime_command(command, log, expect_success=False)
            with self.assertRaisesRegex(RuntimeError, 'exit 0'):
                runtime_command([sys.executable, '-c', 'pass'], log, expect_success=False)

    def test_stale_trace_must_fail_at_the_expected_endpoint(self):
        for reason in ('no such file or directory', 'connection refused'):
            require_expired_endpoint(f'creating session: connect("/private/old.sock"): {reason}', '/private/old.sock')
        for log in ('unknown flag', 'permission denied',
                    'connect("/private/other.sock"): no such file or directory'):
            with self.assertRaisesRegex(RuntimeError, 'expired endpoint'):
                require_expired_endpoint(log, '/private/old.sock')

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX detached child semantics')
    def test_detached_child_stdio_does_not_hold_parent_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_path = root / 'child.pid'
            command = [sys.executable, '-c',
                'import os,time; from pathlib import Path; '
                'pid=os.fork(); '
                f'Path({str(pid_path)!r}).write_text(str(pid)) if pid else None; '
                'time.sleep(30) if pid == 0 else None']
            try:
                runtime_command(command, root / 'runtime.log', timeout=2)
                self.assertGreater(int(pid_path.read_text()), 0)
            finally:
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text()), signal.SIGTERM)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
