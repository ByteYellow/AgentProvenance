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
import sys
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
        expected_replays = {
            'snake-supply-chain', 'multiagent-provenance', 'k8s-cross-pod-a2a',
            'k8s-substrate', 'grok-codebase-exfil', 'grok-3routes', 'deepseek-context',
        }
        expected_catalog = expected_replays | {'llm-judge', 'jev-judge'}
        assert {entry['id'] for entry in replay} == expected_replays, catalog
        assert {entry['id'] for entry in catalog} == expected_catalog, catalog
        assert len(catalog) == len(expected_catalog), 'duplicate demo entries'
        assert (root / 'demo/jev-judge/workbench.py').is_file()
        assert (root / 'demo/llm-judge/judge.py').is_file()
        # Optional Python evaluators must resolve their shared language assets
        # from the extracted archive, without the repository or Go on PATH.
        for script in ('demo/llm-judge/judge.py', 'demo/jev-judge/judge.py', 'demo/jev-judge/workbench.py'):
            help_text = subprocess.check_output([sys.executable, str(root / script), '--help', '--lang', 'zh-CN'],
                                                cwd=root, env=env, text=True, timeout=15)
            assert '显示帮助并退出' in help_text, script
        assert (root / 'demo/jev-judge/review.zh-CN.png').is_file()

        assert '(START_HERE.zh-CN.md)' in (root / 'START_HERE.md').read_text()
        chinese_start = (root / 'START_HERE.zh-CN.md').read_text(encoding='utf-8')
        assert '(START_HERE.md)' in chinese_start and '使用入门' in chinese_start
        assert '(demo/jev-judge/README.zh-CN.md)' in chinese_start
        assert 'demo deepseek-context' in chinese_start
        for entry in catalog:
            assert (root / 'demo' / entry['directory'] / 'README.zh-CN.md').is_file()
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
            def get(path, headers=None):
                request = urllib.request.Request(base + path, headers=headers or {})
                with http.open(request, timeout=30) as response:
                    return response.read().decode()
            gallery = get('/demos/')
            assert '<html lang="en">' in gallery
            assert '示例库' in get('/demos/', {'Accept-Language': 'zh-CN,en;q=0.8'})
            assert '<html lang="en">' in get('/demos/', {'Accept-Language': 'fr-FR'})
            assert '<html lang="en">' in get('/demos/', {'Accept-Language': 'zh-CN', 'Cookie': 'agentprov_language=en'})
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
                for language in ['en', 'zh-CN']:
                    guide = get('/demos/docs/' + entry['id'] + '?lang=' + language)
                    assert '<article class="document">' in guide and '<h1' in guide
                    assert '<html lang="' + language + '">' in guide
                    if language == 'zh-CN':
                        assert '本页目录' in guide and '证据' in guide
            context_run = next(entry['run'] for entry in replay if entry['id'] == 'deepseek-context')
            query = urllib.parse.urlencode({'run': context_run})
            context_report = json.loads(get('/api/context/overview?' + query))
            assert context_report['messages'] > 0 and context_report['tool_results'] > 0
            assert context_report['runtime_coverage']['capture']['status'] == 'partial'
            assert context_report['runtime_coverage']['capture']['run_dropped_events'] is None
            results = json.loads(get('/api/context/entries?' + query + '&kind=tool_result&limit=1'))
            result = results['entries'][0]
            assert result['content']['state'] == 'stored' and result['raw_content']['state'] == 'stored'
            body_query = urllib.parse.urlencode({'run': context_run, 'ref': result['content']['ref'], 'limit': 1024})
            body = json.loads(get('/api/context/content?' + body_query))
            assert body['content'] and body['total_bytes'] > 0
            assert len(body['content'].encode('utf-8')) <= 1024
            assert '"locale":"zh-CN"' in get('/assets/i18n.js?lang=zh-CN')
            assert '--bg:#f5f5f7' in get('/assets/theme.css')
            for guide_id in ('start', 'quickstart', 'capabilities', 'agent-session', 'capture', 'deployment', 'durable-capture', 'graph', 'security', 'compliance', 'supply-chain', 'ai-tools', 'ai-access', 'python', 'telemetry', 'comparisons', 'falco', 'release-notes', 'changelog'):
                for language in ('en', 'zh-CN'):
                    guide = get('/demos/guide/' + guide_id + '?lang=' + language)
                    assert '<article class="document">' in guide and '<h1' in guide
                    assert '<html lang="' + language + '">' in guide
                    assert '/demos/guide/start' in guide
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
        print(json.dumps({'archive': archive.name, 'platform': meta['os'] + '/' + meta['arch'], 'signed_replays': len(replay), 'guides': len(catalog), 'user_guides': 19, 'guide_languages': ['en', 'zh-CN'], 'recorded_context': 'passed', 'no_go_required': True, 'cleanup': 'passed'}))


if __name__ == '__main__':
    main()
