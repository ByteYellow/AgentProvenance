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
        (work / 'START_HERE.md').write_text('''# AgentProvenance

From this extracted directory:

```sh
./agentprov --version
./agentprov demo
./agentprov demo --list
./agentprov demo multiagent-provenance
```

The CLI embeds all six signed captures and all demo guides. Replay is offline,
read-only, and uses a temporary store removed on Ctrl-C. The browser opens
on a loopback address. Use `--no-browser` on a headless machine.

The `demo/` directory contains every existing example, its original signatures,
public keys, scripts and documentation. Replaying never executes captured commands.
LLM Judge and Jev are optional Python examples, not prerecorded verdicts:

```sh
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline
```

Jev needs Python 3.9+ and separate live credentials/raw-evidence consent; see
`demo/jev-judge/README.md`. In its commands use this archive's absolute
`agentprov` path instead of the source-build step. Reopening a completed Jev
study is offline. Live capture scripts have additional requirements in their guides.

Linux archives include the optional sensor; its kernel and privilege requirements
still apply. macOS supports replay and application recording, not Linux eBPF.
Windows users should use the matching Linux archive inside WSL.

SHA256SUMS and per-archive .sha256 files verify download integrity; they are not
publisher signatures. The CLI verifies example evidence using the bundled public
keys. This proves evidence integrity, not capture completeness or causal certainty.

These CLI binaries are not Apple Developer ID signed or notarized.
''')
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
