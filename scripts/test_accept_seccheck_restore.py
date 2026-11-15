import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest

from accept_seccheck_restore import PHASES, require_expired_endpoint, require_replay_receipt, require_restore_identities, require_signature_rejection, runtime_command


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

    def test_fixture_secret_uses_stdin_without_log_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = b'synthetic-test-key-not-a-real-credential'
            command = [sys.executable, '-c',
                'import sys; from pathlib import Path; '
                f'Path({str(root / "private")!r}).write_bytes(sys.stdin.buffer.read())']
            runtime_command(command, root / 'runtime.log', input_bytes=secret)
            self.assertEqual((root / 'private').read_bytes(), secret)
            self.assertNotIn(secret, (root / 'runtime.log').read_bytes())

    def test_copied_key_rejection_requires_signature_failure_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'receiver'
            error = 'Error: attestation verify failed: attest: no valid signature for key'
            require_signature_rejection(1, error, destination)
            for code, reason in ((0, error), (1, 'file not found'), (1, 'unknown command')):
                with self.assertRaisesRegex(RuntimeError, 'signature trust boundary'):
                    require_signature_rejection(code, reason, destination)
            destination.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'created a receiving store'):
                require_signature_rejection(1, error, destination)

    def test_stale_trace_must_fail_at_the_expected_endpoint(self):
        for reason in ('no such file or directory', 'connection refused'):
            require_expired_endpoint(f'creating session: connect("/private/old.sock"): {reason}', '/private/old.sock')
        for log in ('unknown flag', 'permission denied',
                    'connect("/private/other.sock"): no such file or directory'):
            with self.assertRaisesRegex(RuntimeError, 'expired endpoint'):
                require_expired_endpoint(log, '/private/old.sock')

    def test_replay_checks_history_and_upload_source_separately(self):
        registration = self.records[2]['registration']
        receipt = {'uploader': registration, 'file_sha256': 'original-digest', 'event_ids': ['old-event'],
                   'records': 1, 'ingested': 0, 'duplicates': 1, 'authority_basis': 'local_operator_registration'}
        require_replay_receipt({'receipts': [receipt]}, registration, ['old-event'], 'original-digest', 0)
        for field, value in (('uploader', self.records[0]['registration']), ('event_ids', ['clone-event']),
                             ('ingested', 1), ('duplicates', 0), ('file_sha256', 'changed')):
            changed = copy.deepcopy(receipt)
            changed[field] = value
            with self.assertRaisesRegex(RuntimeError, 'original identity or uploader'):
                require_replay_receipt({'receipts': [changed]}, registration, ['old-event'], 'original-digest', 0)

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
