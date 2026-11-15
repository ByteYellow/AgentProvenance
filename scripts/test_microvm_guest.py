import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guest_service', ROOT / 'deploy/microvm/guest_service.py')
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)
BUILD_SPEC = importlib.util.spec_from_file_location('guest_image', ROOT / 'scripts/build_microvm_rootfs.py')
builder = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(builder)


class GuestHooksTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {'target': {'producer_id': 'vm', 'instance_id': 'one', 'generation': 'first'},
                       'capture': {'mode': 'native'}, 'delivery': {'receiver_id': 'receiver'}}
        self.args = argparse.Namespace(config=self.root / 'execution.json', binary=Path('/bin/false'),
            token_file=self.root / 'token', data_dir=self.root / 'data', listen='127.0.0.1:8574', ready_timeout=0.01)
        self.args.config.write_text(json.dumps(self.config))
        self.args.token_file.write_text('synthetic-test-token\n')
        self.args.token_file.chmod(0o600)
        self.environment = patch.dict(os.environ, {'INVOCATION_ID': 'a' * 32, 'MAINPID': str(os.getpid()),
            'SERVICE_RESULT': 'success', 'EXIT_CODE': 'exited', 'EXIT_STATUS': '0'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def ready_receipt(self):
        root, name = guest.paths(self.args)
        _, digest = guest.read_config(self.args.config)
        guest.write_json(root / (name + '.ready.json'),
            {'target': self.config['target'], 'configuration_sha256': digest})
        return root, name

    def test_config_requires_external_identity_native_capture_and_delivery(self):
        for field in ('producer_id', 'instance_id', 'generation'):
            value = json.loads(json.dumps(self.config))
            del value['target'][field]
            self.args.config.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'external target'):
                guest.read_config(self.args.config)
        for field, expected in [('capture', 'native capture'), ('delivery', 'signed delivery')]:
            value = dict(self.config)
            del value[field]
            self.args.config.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, expected):
                guest.read_config(self.args.config)
        for value in ([], {'target': None}, dict(self.config, capture=None)):
            self.args.config.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                guest.read_config(self.args.config)
        self.args.config.write_text(' ' * 65537)
        with self.assertRaisesRegex(ValueError, '64 KiB'):
            guest.read_config(self.args.config)

    def test_private_nonempty_external_token(self):
        self.assertEqual(guest.read_token(self.args.token_file), 'synthetic-test-token')
        self.args.token_file.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private'):
            guest.read_token(self.args.token_file)
        self.args.token_file.chmod(0o600)
        for value in ('\n', 'two tokens', 'x' * 4097):
            self.args.token_file.write_text(value)
            with self.assertRaises(ValueError):
                guest.read_token(self.args.token_file)

    def test_serve_executes_existing_daemon_without_token_in_argv(self):
        with patch.object(guest.os, 'execve') as execute:
            guest.serve(self.args)
        binary, argv, environment = execute.call_args.args
        self.assertEqual(binary, self.args.binary)
        self.assertIn('--execution-config', argv)
        self.assertNotIn('synthetic-test-token', ' '.join(argv))
        self.assertEqual(environment['AGENTPROV_DAEMON_TOKEN'], 'synthetic-test-token')

    def test_unrelated_listener_never_passes_readiness(self):
        self.args.data_dir.mkdir()
        (self.args.data_dir / '.daemon.lock').write_text(json.dumps({'pid': os.getpid() + 1, 'addr': self.args.listen}))
        with self.assertRaisesRegex(RuntimeError, 'does not belong'):
            guest.wait_ready(self.args)
        root, name = guest.paths(self.args)
        self.assertFalse((root / (name + '.ready.json')).exists())

    def test_readiness_without_a_live_service_fails(self):
        with patch.object(guest.os, 'kill', side_effect=ProcessLookupError):
            with self.assertRaises(ProcessLookupError):
                guest.wait_ready(self.args)

    def test_readiness_uses_complete_readonly_execution_scope(self):
        self.args.data_dir.mkdir()
        (self.args.data_dir / '.daemon.lock').write_text(json.dumps({'pid': os.getpid(), 'addr': self.args.listen}))
        class Opener:
            def open(inner, request, timeout):
                url = urlsplit(request.full_url)
                if url.path == '/v1/ready':
                    return io.BytesIO(b'{"ready":true}')
                query = parse_qs(url.query)
                for key in ('run', 'harness', 'session', 'tool_call'):
                    self.assertTrue(query.get(key), key)
                self.assertEqual(request.get_method(), 'GET')
                return io.BytesIO(b'{"attempts":[]}')
        original = Path.read_text
        def text(path, *args, **kwargs):
            if str(path) == '/proc/sys/kernel/random/boot_id':
                return 'fixture-boot'
            return original(path, *args, **kwargs)
        with patch.object(guest.urllib.request, 'build_opener', return_value=Opener()), patch.object(Path, 'read_text', text):
            guest.wait_ready(self.args)
        root, name = guest.paths(self.args)
        self.assertEqual(json.loads((root / (name + '.ready.json')).read_text())['phase'], 'ready')

    def test_changed_identity_does_not_seal_another_generation(self):
        root, name = self.ready_receipt()
        self.config['target']['generation'] = 'second'
        self.args.config.write_text(json.dumps(self.config))
        with patch.object(guest.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'changed'):
                guest.seal(self.args)
        run.assert_not_called()
        report = json.loads((root / (name + '.stopped.json')).read_text())
        self.assertFalse(report['sealed'])
        self.assertFalse(report['may_reclaim'])

    def test_missing_readiness_retains_failure(self):
        root, name = guest.paths(self.args)
        with self.assertRaises(FileNotFoundError):
            guest.seal(self.args)
        self.assertIn('error', json.loads((root / (name + '.stopped.json')).read_text()))

    def test_paged_results_and_repeat_use_one_operation(self):
        root, name = self.ready_receipt()
        seen = []
        def run(argv, *, stdout, env, check):
            seen.append(argv)
            self.assertNotIn('AGENTPROV_DAEMON_TOKEN', env)
            for number in range(270):
                stdout.write(json.dumps({'attempt': number}).encode() + b'\n')
            stdout.write(b'{"complete":true,"attempts":270}\n')
            return subprocess.CompletedProcess(argv, 0)
        with patch.object(guest.subprocess, 'run', side_effect=run):
            guest.seal(self.args)
            guest.seal(self.args)
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[0][-1], 'guest-stop-' + name)
        self.assertEqual(len((root / (name + '.seal.jsonl')).read_text().splitlines()), 271)
        report = json.loads((root / (name + '.stopped.json')).read_text())
        self.assertTrue(report['sealed'])
        self.assertIsNone(report['receiver_acknowledged'])
        self.assertFalse(report['may_reclaim'])

    def test_incomplete_export_is_visible_and_fails(self):
        root, name = self.ready_receipt()
        def run(argv, *, stdout, **kwargs):
            stdout.write(b'{"complete":false,"unfinished":1}\n')
            return subprocess.CompletedProcess(argv, 1)
        with patch.object(guest.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'retain the evidence volume'):
                guest.seal(self.args)
        report = json.loads((root / (name + '.stopped.json')).read_text())
        self.assertFalse(report['sealed'])
        self.assertEqual(report['summary']['unfinished'], 1)
        self.assertTrue((root / (name + '.seal.jsonl')).is_file())

    def test_invocation_is_not_generated_from_cloned_guest_identity(self):
        with patch.dict(os.environ, {'INVOCATION_ID': ''}):
            with self.assertRaisesRegex(ValueError, 'INVOCATION_ID'):
                guest.invocation()


class GuestImageDefinitionTest(unittest.TestCase):
    def test_image_tree_has_no_baked_identity_and_checks_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('etc/agentprov-guest', 'var/lib/agentprov-guest', 'etc/ssh',
                              'etc/systemd/system/multi-user.target.wants', 'etc/systemd/network', 'usr/local/bin'):
                (root / directory).mkdir(parents=True, exist_ok=True)
            (root / 'etc/machine-id').write_text('')
            (root / 'etc/systemd/system/multi-user.target.wants/agentprov-guest.service').symlink_to(
                '/etc/systemd/system/agentprov-guest.service')
            binary = root / 'usr/local/bin/agentprov'
            binary.write_bytes(b'fixture-binary')
            network = root / 'etc/systemd/network/80-guest.network'
            network.write_text('[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n')
            network.chmod(0o644)
            with patch.object(builder.subprocess, 'check_output', return_value='fixture-version\n'), \
                 patch.object(builder.subprocess, 'run') as run:
                builder.verify_tree(root, binary, 'fixture-version')
                self.assertIn('agentprov-guest.service', run.call_args.args[0])
                self.assertIn('ssh.service', run.call_args.args[0])
                self.assertIn('systemd-udevd.service', run.call_args.args[0])
                self.assertIn('systemd-udev-trigger.service', run.call_args.args[0])
                self.assertIn('systemd-networkd.service', run.call_args.args[0])
                network.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, 'readable by networkd'):
                    builder.verify_tree(root, binary, 'fixture-version')
                network.chmod(0o644)
                (root / 'etc/agentprov-guest/daemon-token').write_text('fixture-secret')
                with self.assertRaisesRegex(RuntimeError, 'instance configuration'):
                    builder.verify_tree(root, binary, 'fixture-version')

    def test_pinned_image_and_external_volumes(self):
        deployment = ROOT / 'deploy/microvm'
        runtime = json.loads((deployment / 'runtime.json').read_text())
        dockerfile = (deployment / 'Dockerfile').read_text()
        self.assertIn('FROM ' + runtime['base_image'], dockerfile)
        self.assertEqual(len(runtime['source_commit']), 40)
        self.assertIn('hardware_boot_acceptance', runtime)
        self.assertNotIn('COPY execution.json', dockerfile)
        self.assertNotIn('COPY daemon-token', dockerfile)
        mounts = (deployment / 'guest.fstab').read_text()
        self.assertIn('/dev/vdb /etc/agentprov-guest ext4 ro,', mounts)
        self.assertIn('/dev/vdc /var/lib/agentprov-guest', mounts)


if __name__ == '__main__':
    unittest.main()
