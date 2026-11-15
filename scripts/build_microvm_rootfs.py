#!/usr/bin/env python3
"""Build a credential-free systemd rootfs for the pinned Firecracker profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import uuid


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def verify_tree(root, binary, version):
    for directory in ('etc/agentprov-guest', 'var/lib/agentprov-guest'):
        if any((root / directory).iterdir()):
            raise RuntimeError('reusable rootfs contains instance configuration or evidence')
    if any((root / 'etc/ssh').glob('ssh_host_*')) or (root / 'etc/machine-id').stat().st_size:
        raise RuntimeError('reusable rootfs contains machine identity or SSH host keys')
    enabled = root / 'etc/systemd/system/multi-user.target.wants/agentprov-guest.service'
    if not enabled.is_symlink() or os.readlink(enabled) != '/etc/systemd/system/agentprov-guest.service':
        raise RuntimeError('guest service is not enabled for boot')
    if digest(root / 'usr/local/bin/agentprov') != digest(binary):
        raise RuntimeError('guest CLI differs from the selected binary')
    installed_version = subprocess.check_output(['chroot', str(root), '/usr/local/bin/agentprov', '--version'], text=True).strip()
    if installed_version != version:
        raise RuntimeError('guest CLI version differs inside the image')
    subprocess.run(['systemd-analyze', '--root=' + str(root), '--man=no', 'verify',
                    'agentprov-guest.service', 'ssh.service'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='new output directory')
    parser.add_argument('--size-mib', type=int, default=1536)
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.geteuid() != 0:
        parser.error('run as root on Linux with Docker, systemd-analyze and mkfs.ext4')
    if not 512 <= args.size_mib <= 16384:
        parser.error('rootfs size must be between 512 and 16384 MiB')
    binary, output = args.binary.resolve(), args.output.resolve()
    version = subprocess.check_output([str(binary), '--version'], text=True).strip()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    deployment = Path(__file__).resolve().parents[1] / 'deploy' / 'microvm'
    runtime = json.loads((deployment / 'runtime.json').read_text())
    tag = 'agentprov-guest-build:' + uuid.uuid4().hex
    container = None
    try:
        with tempfile.TemporaryDirectory(prefix='agentprov-guest-build-') as temporary:
            context = Path(temporary) / 'context'
            shutil.copytree(deployment, context, ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copy2(binary, context / 'agentprov')
            subprocess.run(['docker', 'build', '--tag', tag, str(context)], check=True)
            image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
            container = subprocess.check_output(['docker', 'create', tag], text=True).strip()
            archive = Path(temporary) / 'rootfs.tar'
            subprocess.run(['docker', 'export', '--output', str(archive), container], check=True)
            root = Path(temporary) / 'root'
            root.mkdir()
            subprocess.run(['tar', '--numeric-owner', '-xf', str(archive), '-C', str(root)], check=True)
            verify_tree(root, binary, version)
            shutil.copyfile(root / 'usr/share/agentprov-guest-packages.txt', output / 'packages.txt')
            rootfs = output / 'rootfs.ext4'
            with rootfs.open('xb') as stream:
                stream.truncate(args.size_mib * (1 << 20))
            subprocess.run(['mkfs.ext4', '-F', '-L', 'agentprov-root', '-d', str(root), str(rootfs)], check=True)
            subprocess.run(['e2fsck', '-fn', str(rootfs)], check=True)
            manifest = {'schema_version': 'agentprovenance.guest_image/v1', 'runtime': runtime,
                        'architecture': image['Architecture'], 'image_id': image['Id'],
                        'cli_version': version, 'cli_sha256': digest(binary),
                        'rootfs_sha256': digest(rootfs), 'rootfs_bytes': rootfs.stat().st_size,
                        'packages_sha256': digest(output / 'packages.txt'),
                        'deployment_sha256': {path.name: digest(path) for path in sorted(deployment.iterdir()) if path.is_file()},
                        'boot_tested': False}
            (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            print(json.dumps(manifest))
    finally:
        if container:
            subprocess.run(['docker', 'rm', container], check=False)
        subprocess.run(['docker', 'image', 'rm', tag], check=False)


if __name__ == '__main__':
    main()
