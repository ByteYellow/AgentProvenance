#!/usr/bin/env python3
"""Select the tested site belonging to the latest published stable release."""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request


def select_run(runs, commit, repository, get):
    for run in runs:
        if (run['head_sha'] != commit or run['status'] != 'completed'
                or run['event'] not in ('push', 'workflow_dispatch')
                or run['head_repository']['full_name'] != repository
                or run['path'] != '.github/workflows/release.yml'):
            continue
        jobs = get(f"actions/runs/{run['id']}/jobs?per_page=100")['jobs']
        passed = {job['name'] for job in jobs if job['conclusion'] == 'success'}
        if not {'validate', 'site', 'publish'} <= passed:
            continue
        artifacts = get(f"actions/runs/{run['id']}/artifacts?per_page=100")['artifacts']
        sites = [item for item in artifacts if item['name'] == 'github-pages' and not item['expired']]
        if len(sites) == 1:
            return run['id']
    return None


def main():
    repository = os.environ['GITHUB_REPOSITORY']
    headers = {'Accept': 'application/vnd.github+json'}
    if os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']

    def get(path):
        request = urllib.request.Request(f'https://api.github.com/repos/{repository}/{path}', headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    release = get('releases/latest')
    version = release['tag_name']
    if release['draft'] or release['prerelease'] or not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise SystemExit('Pages requires a published stable release')
    commit = get(f'commits/{version}')['sha']
    subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'origin/main'], check=True)
    if os.environ['GITHUB_EVENT_NAME'] == 'workflow_run':
        runs = [json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())['workflow_run']]
    else:
        runs = get(f'actions/workflows/release.yml/runs?head_sha={commit}&per_page=100')['workflow_runs']
    run_id = select_run(runs, commit, repository, get)
    if run_id is None:
        if os.environ['GITHUB_EVENT_NAME'] == 'workflow_run':
            print('No published stable site in this workflow run; skipping deployment.')
            return
        raise SystemExit('No unexpired, validated site artifact for the latest release')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write(f'run_id={run_id}\ncommit={commit}\nversion={version}\n')
    print(f'Deploy {version} ({commit}) from validated release run {run_id}')


if __name__ == '__main__':
    main()
