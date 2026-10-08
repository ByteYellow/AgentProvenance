#!/usr/bin/env python3
"""Build and validate the same static artifact that will be deployed to Pages."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--site', required=True)
    args = parser.parse_args()
    binary, site = Path(args.binary).resolve(), Path(args.site).resolve()
    subprocess.run([str(binary), 'demo', 'export', '--output', str(site)], check=True)
    size = sum(p.stat().st_size for p in site.rglob('*') if p.is_file())
    if size > 900 * 1024 * 1024:
        raise SystemExit('Static website exceeds the publication budget')
    with tempfile.TemporaryDirectory(prefix='agentprov-site-check-') as temp:
        log_path = Path(temp) / 'demo.log'
        with log_path.open('w') as log:
            process = subprocess.Popen([str(binary), 'demo', '--no-browser', '--json'], stdout=log, stderr=log)
            server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(site.parent)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                deadline, local = time.monotonic() + 180, None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    for line in log_path.read_text().splitlines():
                        if line.startswith('{'):
                            local = json.loads(line).get('url')
                    if local:
                        break
                    time.sleep(0.2)
                if not local:
                    raise RuntimeError('Local signed replay did not start')
                public = f'http://127.0.0.1:{server.server_port}/{site.name}/'
                subprocess.run(['node', 'scripts/test_static_reader.cjs'], check=True)
                subprocess.run(['node', 'scripts/accept_static_demo.cjs', public, local], check=True)
                print(json.dumps({'site_bytes': size, 'passed': True}))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    main()
