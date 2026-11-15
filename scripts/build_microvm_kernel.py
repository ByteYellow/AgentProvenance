#!/usr/bin/env python3
"""Build a pinned native guest kernel with Sensor support, without installing it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import urllib.request


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def require_digest(path, expected):
    if digest(path) != expected:
        raise ValueError('input digest mismatch: ' + str(path))


def parse_config(text):
    values = {}
    for line in text.splitlines():
        enabled = re.fullmatch(r'CONFIG_([A-Z0-9_]+)=(.*)', line)
        disabled = re.fullmatch(r'# CONFIG_([A-Z0-9_]+) is not set', line)
        if enabled:
            values[enabled[1]] = enabled[2]
        elif disabled:
            values[disabled[1]] = 'n'
    return values


def require_options(values, required):
    for name, expected in required.items():
        if values.get(name, 'n') != expected:
            raise ValueError('effective CONFIG_' + name + ' must be ' + expected)


def verify_source(source, revision):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    if git('rev-parse', 'HEAD') != revision:
        raise ValueError('kernel source revision does not match runtime.json')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('kernel source must be a clean checkout')
    return git('log', '-1', '--format=%ct')


def verify_artifacts(output, architecture):
    with (output / 'kernel.btf').open('rb') as stream:
        header = stream.read(24)
    if len(header) != 24 or header[:3] != b'\x9f\xeb\x01':
        raise ValueError('invalid BTF artifact header')
    if architecture == 'aarch64':
        with (output / 'Image').open('rb') as stream:
            header = stream.read(64)
        if len(header) != 64 or header[:2] != b'MZ' or header[56:60] != b'ARM\x64':
            raise ValueError('invalid arm64 PE boot image')
    elif architecture == 'x86_64':
        with (output / 'vmlinux').open('rb') as stream:
            header = stream.read(64)
        if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
            raise ValueError('invalid x86_64 ELF boot image')
    else:
        raise ValueError('unsupported architecture: ' + architecture)
    subprocess.run(['bpftool', 'btf', 'dump', 'file', str(output / 'kernel.btf'),
                    'format', 'raw'], check=True, stdout=subprocess.DEVNULL)


def build(source, output, deployment, architecture, jobs, base_config=None):
    runtime = json.loads((deployment / 'runtime.json').read_text())
    selected = runtime['guest_kernel']
    epoch = verify_source(source, selected['source_commit'])
    if source == output or source in output.parents or output in source.parents:
        raise ValueError('output and source must be separate directories')
    if architecture not in selected['configs']:
        raise ValueError('unsupported architecture: ' + architecture)
    tools = {}
    for name in ('git', 'make', 'gcc', 'ld', 'objcopy', 'pahole', 'flex', 'bison', 'bc', 'bpftool'):
        if not shutil.which(name):
            raise ValueError('required build tool is missing: ' + name)
        tools[name] = subprocess.check_output([name, '--version'], text=True).strip()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    work = output / 'build'
    work.mkdir()
    config = selected['configs'][architecture]
    base = output / 'upstream.config'
    if base_config is not None:
        shutil.copyfile(base_config, base)
    else:
        with urllib.request.urlopen(config['url'], timeout=60) as response:
            contents = response.read((4 << 20) + 1)
        if len(contents) > 4 << 20:
            raise ValueError('upstream configuration exceeds 4 MiB')
        base.write_bytes(contents)
    require_digest(base, config['sha256'])
    fragment = output / 'sensor.config'
    shutil.copyfile(deployment / 'sensor-kernel.config', fragment)
    env = os.environ.copy()
    for name in ('MAKEFLAGS', 'CROSS_COMPILE', 'LLVM', 'LLVM_IAS', 'KBUILD_OUTPUT',
                 'KCONFIG_ALLCONFIG', 'KBUILD_BUILD_TIMESTAMP'):
        env.pop(name, None)
    env.update({'ARCH': 'arm64' if architecture == 'aarch64' else 'x86',
                'KCONFIG_CONFIG': str(work / '.config'), 'KBUILD_BUILD_USER': 'agentprov',
                'KBUILD_BUILD_HOST': 'guest-builder', 'KBUILD_BUILD_VERSION': '1',
                'KBUILD_BUILD_TIMESTAMP': datetime.fromtimestamp(int(epoch), timezone.utc).strftime('%a %b %d %H:%M:%S UTC %Y')})
    make = ['make', '-C', str(source), 'O=' + str(work), 'CC=gcc', 'HOSTCC=gcc', 'LD=ld', 'OBJCOPY=objcopy']

    def run(command, log):
        print('Running ' + ' '.join(command) + ' (log: ' + log + ')', flush=True)
        with (output / log).open('w') as stream:
            subprocess.run(command, check=True, env=env, stdout=stream, stderr=subprocess.STDOUT)

    run(['bash', str(source / 'scripts/kconfig/merge_config.sh'), '-m', '-O', str(work),
         str(base), str(fragment)], 'merge.log')
    run(make + ['olddefconfig'], 'configure.log')
    effective = work / '.config'
    required = {name: 'y' for name in runtime['kernel_requirements']}
    required.update({'MODULES': 'n'})
    if architecture == 'aarch64':
        required.update({'ARM64_4K_PAGES': 'y', 'EFI': 'y'})
    require_options(parse_config(effective.read_text()), required)
    version = subprocess.check_output(make + ['-s', 'kernelversion'], env=env, text=True).strip()
    if version != selected['version']:
        raise ValueError('effective kernel version differs from runtime.json: ' + version)
    run(make + ['-j' + str(jobs), 'Image' if architecture == 'aarch64' else 'vmlinux'], 'build.log')
    run(['objcopy', '--strip-debug', '--dump-section', '.BTF=' + str(output / 'kernel.btf'),
         str(work / 'vmlinux'), str(output / 'vmlinux')], 'extract.log')
    if architecture == 'aarch64':
        shutil.copyfile(work / 'arch/arm64/boot/Image', output / 'Image')
    shutil.copyfile(effective, output / 'kernel.config')
    shutil.copyfile(work / 'System.map', output / 'System.map')
    verify_artifacts(output, architecture)
    verify_source(source, selected['source_commit'])
    files = ['upstream.config', 'sensor.config', 'kernel.config', 'System.map', 'kernel.btf', 'vmlinux']
    if architecture == 'aarch64':
        files.append('Image')
    manifest = {'schema_version': 'agentprovenance.guest_kernel/v1', 'runtime': runtime,
                'architecture': architecture, 'kernel_version': version,
                'source_epoch': epoch, 'tools': tools,
                'builder_sha256': digest(Path(__file__)),
                'runtime_sha256': digest(deployment / 'runtime.json'),
                'artifacts': {name: {'sha256': digest(output / name), 'bytes': (output / name).stat().st_size}
                              for name in files},
                'boot_image': 'Image' if architecture == 'aarch64' else 'vmlinux',
                'boot_tested': False}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest), flush=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path, help='clean checkout of the pinned kernel commit')
    parser.add_argument('--output', required=True, type=Path, help='new output directory, outside the kernel source')
    parser.add_argument('--base-config', type=Path, help='optional local copy, checked against the pinned digest')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    architecture = platform.machine()
    if platform.system() != 'Linux' or architecture not in ('aarch64', 'x86_64'):
        parser.error('build natively on Linux aarch64 or x86_64')
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    deployment = Path(__file__).resolve().parents[1] / 'deploy/microvm'
    try:
        build(args.source.resolve(strict=True), args.output.resolve(), deployment,
              architecture, args.jobs, args.base_config)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
