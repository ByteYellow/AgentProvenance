import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('guest_kernel', ROOT / 'scripts/build_microvm_kernel.py')
kernel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernel)


class KernelRecipeTest(unittest.TestCase):
    def test_effective_options_require_builtin_collection_and_boot_support(self):
        values = {'BPF_SYSCALL': 'y', 'DEBUG_INFO_BTF': 'y', 'VIRTIO_BLK': 'y'}
        kernel.require_options(values, values)
        for value in ('n', 'm', ''):
            with self.assertRaisesRegex(ValueError, 'DEBUG_INFO_BTF'):
                kernel.require_options(dict(values, DEBUG_INFO_BTF=value), values)
        with self.assertRaisesRegex(ValueError, 'VIRTIO_BLK'):
            kernel.require_options({'BPF_SYSCALL': 'y', 'DEBUG_INFO_BTF': 'y'}, values)

    def test_last_disabled_option_overrides_earlier_enabled_value(self):
        values = kernel.parse_config('CONFIG_BPF_JIT=y\n# CONFIG_BPF_JIT is not set\n'
                                     'CONFIG_LOCALVERSION="-agentprov"\n# heading\n')
        self.assertEqual(values, {'BPF_JIT': 'n', 'LOCALVERSION': '"-agentprov"'})

    def test_input_digest_rejects_changed_base_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config'
            config.write_text('CONFIG_DEBUG_INFO_BTF=y\n')
            expected = kernel.digest(config)
            kernel.require_digest(config, expected)
            config.write_text('# CONFIG_DEBUG_INFO_BTF is not set\n')
            with self.assertRaisesRegex(ValueError, 'digest'):
                kernel.require_digest(config, expected)

    def test_source_requires_exact_revision_and_clean_tree(self):
        revision = 'a' * 40
        with patch.object(kernel.subprocess, 'check_output', side_effect=[revision + '\n', '', '12345\n']):
            self.assertEqual(kernel.verify_source(Path('/source'), revision), '12345')
        for replies, message in [(['b' * 40 + '\n'], 'revision'),
                                 ([revision + '\n', ' M kernel/bpf/syscall.c\n'], 'clean')]:
            with patch.object(kernel.subprocess, 'check_output', side_effect=replies):
                with self.assertRaisesRegex(ValueError, message):
                    kernel.verify_source(Path('/source'), revision)

    def test_artifact_checks_read_real_btf_and_arm64_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = bytearray(128)
            raw[:2] = b'MZ'
            raw[56:60] = b'ARM\x64'
            (root / 'Image').write_bytes(raw)
            (root / 'kernel.btf').write_bytes(b'\x9f\xeb\x01\x00' + b'\x00' * 24)
            with patch.object(kernel.subprocess, 'run') as run:
                kernel.verify_artifacts(root, 'aarch64')
                self.assertEqual(run.call_args.args[0][:3], ['bpftool', 'btf', 'dump'])
            (root / 'kernel.btf').write_bytes(b'not-btf')
            with self.assertRaisesRegex(ValueError, 'BTF'):
                kernel.verify_artifacts(root, 'aarch64')
            (root / 'kernel.btf').write_bytes(b'\x9f\xeb\x01\x00' + b'\x00' * 24)
            raw[56:60] = b'fake'
            (root / 'Image').write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'arm64'):
                kernel.verify_artifacts(root, 'aarch64')

    def test_x86_boot_image_requires_correct_elf_machine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = bytearray(128)
            raw[:6] = b'\x7fELF\x02\x01'
            raw[18:20] = (62).to_bytes(2, 'little')
            (root / 'vmlinux').write_bytes(raw)
            (root / 'kernel.btf').write_bytes(b'\x9f\xeb\x01\x00' + b'\x00' * 24)
            with patch.object(kernel.subprocess, 'run'):
                kernel.verify_artifacts(root, 'x86_64')
            raw[18:20] = (183).to_bytes(2, 'little')
            (root / 'vmlinux').write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'x86_64'):
                kernel.verify_artifacts(root, 'x86_64')

    def test_manifest_pins_inputs_and_fragment_requests_sensor_features(self):
        deployment = ROOT / 'deploy/microvm'
        profile = json.loads((deployment / 'runtime.json').read_text())
        source = profile['guest_kernel']
        self.assertEqual(len(source['source_commit']), 40)
        self.assertEqual(source['version'], '6.18.62')
        self.assertEqual(set(source['configs']), {'aarch64', 'x86_64'})
        for config in source['configs'].values():
            self.assertIn(profile['source_commit'], config['url'])
            self.assertEqual(len(config['sha256']), 64)
        fragment = kernel.parse_config((deployment / 'sensor-kernel.config').read_text())
        kernel.require_options(fragment, {name: 'y' for name in (
            'BPF_JIT', 'DEBUG_INFO_BTF', 'FTRACE_SYSCALLS', 'KPROBE_EVENTS', 'UPROBE_EVENTS')})
        self.assertEqual(fragment['MODULES'], 'n')

    def test_build_rejects_changed_base_before_running_make(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment, source = root / 'deployment', root / 'source'
            deployment.mkdir()
            source.mkdir()
            (deployment / 'runtime.json').write_text(json.dumps({
                'guest_kernel': {'source_commit': 'a' * 40, 'configs': {
                    'aarch64': {'sha256': '0' * 64}}}}))
            base = root / 'base.config'
            base.write_text('CONFIG_BPF_JIT=y\n')
            with patch.object(kernel, 'verify_source', return_value='12345'), \
                    patch.object(kernel.shutil, 'which', return_value='/usr/bin/tool'), \
                    patch.object(kernel.subprocess, 'check_output', return_value='version'), \
                    patch.object(kernel.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'digest'):
                    kernel.build(source, root / 'output', deployment, 'aarch64', 2, base)
                run.assert_not_called()
            self.assertFalse((root / 'output/manifest.json').exists())

    def test_configure_failure_keeps_log_without_publishing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment, source = root / 'deployment', root / 'source'
            deployment.mkdir()
            source.mkdir()
            base = root / 'base.config'
            base.write_text('CONFIG_BPF_JIT=y\n')
            (deployment / 'sensor-kernel.config').write_text('CONFIG_DEBUG_INFO_BTF=y\n')
            (deployment / 'runtime.json').write_text(json.dumps({
                'guest_kernel': {'source_commit': 'a' * 40, 'configs': {
                    'aarch64': {'sha256': kernel.digest(base)}}}}))
            with patch.object(kernel, 'verify_source', return_value='12345'), \
                    patch.object(kernel.shutil, 'which', return_value='/usr/bin/tool'), \
                    patch.object(kernel.subprocess, 'check_output', return_value='version'), \
                    patch.object(kernel.subprocess, 'run', side_effect=kernel.subprocess.CalledProcessError(2, 'merge')):
                with self.assertRaises(kernel.subprocess.CalledProcessError):
                    kernel.build(source, root / 'output', deployment, 'aarch64', 2, base)
            self.assertTrue((root / 'output/merge.log').exists())
            self.assertFalse((root / 'output/manifest.json').exists())

    def test_disabled_effective_sensor_option_stops_before_compile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment, source, output = root / 'deployment', root / 'source', root / 'output'
            deployment.mkdir()
            source.mkdir()
            base = root / 'base.config'
            base.write_text('CONFIG_BPF_SYSCALL=y\n')
            (deployment / 'sensor-kernel.config').write_text('CONFIG_DEBUG_INFO_BTF=y\n')
            (deployment / 'runtime.json').write_text(json.dumps({
                'kernel_requirements': ['BPF_SYSCALL', 'DEBUG_INFO_BTF'],
                'guest_kernel': {'source_commit': 'a' * 40, 'configs': {
                    'aarch64': {'sha256': kernel.digest(base)}}}}))

            def configure(command, **kwargs):
                if command[-1] == 'olddefconfig':
                    (output / 'build/.config').write_text(
                        'CONFIG_BPF_SYSCALL=y\n# CONFIG_DEBUG_INFO_BTF is not set\n')

            with patch.object(kernel, 'verify_source', return_value='12345'), \
                    patch.object(kernel.shutil, 'which', return_value='/usr/bin/tool'), \
                    patch.object(kernel.subprocess, 'check_output', return_value='version'), \
                    patch.object(kernel.subprocess, 'run', side_effect=configure) as run:
                with self.assertRaisesRegex(ValueError, 'DEBUG_INFO_BTF'):
                    kernel.build(source, output, deployment, 'aarch64', 2, base)
                self.assertEqual(run.call_count, 2)
            self.assertFalse((output / 'build.log').exists())
            self.assertFalse((output / 'manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
