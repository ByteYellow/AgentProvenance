#!/usr/bin/env python3
"""Build a portable CLI archive from tracked examples and committed BPF bindings."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--os', choices=['linux', 'darwin'], required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', args.version):
        parser.error('version must be a v-prefixed semantic version')
    commit = output('git', 'rev-parse', 'HEAD')
    epoch = int(output('git', 'show', '-s', '--format=%ct', 'HEAD'))
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()
    env = dict(os.environ, CGO_ENABLED='0', GOOS=args.os, GOARCH=args.arch)
    prefix = 'github.com/byteyellow/agentprovenance/internal/buildinfo'
    ldflags = f'-s -w -X {prefix}.Version={args.version} -X {prefix}.Commit={commit} -X {prefix}.Date={date}'
    args.output.mkdir(parents=True, exist_ok=True)
    name = f'agentprov_{args.version}_{args.os}_{args.arch}.tar.gz'
    archive = args.output / name
    with tempfile.TemporaryDirectory(prefix='agentprov-release-') as work:
        work = Path(work)
        programs = ['agentprov'] + (['agentprov-sensor'] if args.os == 'linux' else [])
        for program in programs:
            subprocess.run(['go', 'build', '-trimpath', '-ldflags', ldflags, '-o', str(work / program), './cmd/' + program], cwd=ROOT, env=env, check=True)
        (work / 'build-info.json').write_text(json.dumps({
            'version': args.version, 'commit': commit, 'build_date': date,
            'go': output('go', 'version'), 'os': args.os, 'arch': args.arch,
            'cgo_enabled': False, 'programs': programs,
        }, indent=2) + '\n')
        for source, guide_name in [
            ('docs/release-start.md', 'START_HERE.md'),
            ('docs/zh-CN/release-start.md', 'START_HERE.zh-CN.md'),
        ]:
            guide = (ROOT / source).read_text(encoding='utf-8')
            # Source-document links also work after extraction at archive root.
            guide = guide.replace('(zh-CN/release-start.md)', '(START_HERE.zh-CN.md)')
            guide = guide.replace('(../release-start.md)', '(START_HERE.md)')
            guide = guide.replace('(../../demo/', '(demo/')
            (work / guide_name).write_text(guide, encoding='utf-8')
        def normalize(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = epoch
            return info
        with tarfile.open(archive, 'w:gz') as tar:
            for p in sorted(work.iterdir()):
                tar.add(p, arcname=p.name, filter=normalize)
            tar.add(ROOT / 'LICENSE', arcname='LICENSE', filter=normalize)
            # Only tracked files, never local credentials or regenerated raw captures.
            for file in output('git', 'ls-files', 'demo').splitlines():
                if file.endswith('.go'):
                    continue
                tar.add(ROOT / file, arcname=file, filter=normalize)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(name + '.sha256').write_text(f'{digest}  {name}\n')
    print(archive)


if __name__ == '__main__':
    main()
