#!/usr/bin/env python3
"""Smoke-test an extracted native release without Go or source checkout access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tarfile
import tempfile
import threading
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    archive = args.archive.resolve()
    expected = archive.with_name(archive.name + '.sha256').read_text().split()[0]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected, 'archive checksum mismatch'
    with tempfile.TemporaryDirectory(prefix='agentprov release test ') as tmp:
        root = Path(tmp)
        with tarfile.open(archive) as tar:
            tar.extractall(root, filter='data')
        cli = root / 'agentprov'
        meta = json.loads((root / 'build-info.json').read_text())
        home = root / 'private home'
        home.mkdir()
        scratch = root / 'temporary state'
        scratch.mkdir()
        env = dict(os.environ, PATH=str(root / 'no-tools'), HOME=str(home), TMPDIR=str(scratch))
        env.pop('AGENTPROV_DAEMON_URL', None)
        def run(*args):
            return subprocess.check_output([str(cli), *args], cwd=root, env=env, text=True, timeout=30)
        version = run('--version')
        assert meta['version'] in version and meta['commit'] in version, version
        catalog = json.loads(run('demo', '--list', '--json'))
        replay = [d for d in catalog if d.get('run')]
        assert len(replay) == 6 and len(catalog) == 8, catalog
        assert (root / 'demo/jev-judge/workbench.py').is_file()
        assert (root / 'demo/llm-judge/judge.py').is_file()
        process = subprocess.Popen([str(cli), 'demo', '--json'], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        try:
            try:
                line = ready.get(timeout=120)
            except queue.Empty:
                raise AssertionError('demo did not become ready in 120 seconds')
            if not line:
                raise AssertionError('demo exited before ready: ' + process.stderr.read())
            report = json.loads(line)
            assert len(report['verifications']) == len(replay)
            for result in report['verifications']:
                assert result['signature_verified'] and result['graph']['error_count'] == 0, result
            base = report['url'].removesuffix('/demos/')
            # Do not use host proxy configuration for loopback acceptance requests.
            http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def get(path):
                with http.open(base + path, timeout=30) as response:
                    return response.read().decode()
            gallery = get('/demos/')
            runs = json.loads(get('/api/runs'))
            assert {r['run'] for r in runs} == {d['run'] for d in replay}
            for entry in replay:
                assert entry['run'] in gallery
                query = urllib.parse.urlencode({'run': entry['run'], 'lens': entry['lens']})
                overview = json.loads(get('/api/overview?' + query))
                assert overview['verify']['error_count'] == 0, overview['verify']
                lens = json.loads(get('/api/lens?' + query))
                assert lens['nodes'], entry
            for entry in catalog:
                guide = get('/demos/docs/' + entry['id'])
                assert '<article class="document">' in guide and '<h1' in guide
            assert '--bg:#f5f5f7' in get('/assets/theme.css')
            assert 'code-toolbar' in get('/demos/guide.js')
            assert '.document' in get('/demos/demo.css')
            with http.open(base + '/demos/assets/jev-judge/review.png', timeout=30) as response:
                assert response.read(8) == b'\x89PNG\r\n\x1a\n', 'embedded guide image missing'
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == 0
            assert not list(scratch.iterdir()), 'temporary demo state not removed'
            assert not (root / '.agentprov').exists(), 'demo wrote into current directory'
            assert not list(home.iterdir()), 'demo modified user home'
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        print(json.dumps({'archive': archive.name, 'platform': meta['os'] + '/' + meta['arch'], 'signed_replays': len(replay), 'guides': len(catalog), 'no_go_required': True, 'cleanup': 'passed'}))


if __name__ == '__main__':
    main()
