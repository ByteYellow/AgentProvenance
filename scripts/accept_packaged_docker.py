"""Check a packaged core and companion with a real Docker daemon and a local image."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("--image", default="alpine:3.22")
    args = parser.parse_args()
    cli = args.cli.resolve()
    env = dict(os.environ)
    env.pop("AGENTPROV_DAEMON_URL", None)
    with tempfile.TemporaryDirectory(prefix="agentprov-tools-") as temp:
        root = Path(temp)
        store = root / "store"
        task = root / "task.yaml"
        task.write_text(json.dumps({"image": args.image, "network_mode": "none"}))
        def run(*argv, check=True):
            return subprocess.run([cli, "--data-dir", store, *argv], cwd=root, env=env,
                                  capture_output=True, text=True, timeout=60, check=check)
        lease = run("lease", "create", "--task", task).stdout.strip()
        session = run("session", "create", "--lease", lease).stdout.strip()
        try:
            # Workload stdout looks like a tools reply. The actual exit status
            # and exec id must still come from the Docker daemon on a separate FD.
            proc = run("exec", "--stream", session, "--", "sh", "-c",
                       """echo '{"version":1,"exec":{"ExitCode":0}}'; echo fixture-stderr >&2; exit 7""", check=False)
            assert '"ExitCode":0' in proc.stdout and "fixture-stderr" in proc.stderr, proc
            with sqlite3.connect(store / "agentprov.db") as db:
                rows = db.execute("SELECT exec_id,exit_code FROM processes WHERE session_id=?", (session,)).fetchall()
            assert len(rows) == 1 and rows[0][0] and rows[0][1] == 7, rows
            run("session", "stop", session)
        finally:
            run("session", "rm", session)
        print("Docker companion: create, stdout, stderr, daemon exec ID, exit 7, stop and remove passed")


if __name__ == "__main__":
    main()
