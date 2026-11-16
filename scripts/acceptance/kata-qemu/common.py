"""Small, bounded helpers shared by the node and guest acceptance fixtures."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


class Blocked(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def redact(text, secrets=()):
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    text = re.sub(r'(?i)(["\']?(?:token|password|secret|api[_-]?key)["\']?\s*[:=]\s*)[^\s,}]+',
                  r"\1[REDACTED]", text)
    return text


def clean_env():
    env = dict(os.environ, LC_ALL="C", PYTHONDONTWRITEBYTECODE="1")
    for key in list(env):
        if key.startswith("AGENTPROV_") or key.lower().endswith("_proxy"):
            env.pop(key)
    return env


def start_owned(argv, **kwargs):
    process = subprocess.Popen([str(x) for x in argv], start_new_session=True, **kwargs)
    # setsid succeeds before Popen returns, even if the leader exits immediately.
    process._acceptance_pgid = process.pid
    process._acceptance_stopped = False
    return process


def stop_owned(process, timeout=15):
    if getattr(process, "_acceptance_stopped", False):
        return
    pgid = getattr(process, "_acceptance_pgid", None)
    require(pgid == process.pid and pgid != os.getpgrp(), "refuse to signal an unowned process group")
    def send(signum):
        try:
            os.killpg(pgid, signum)
            return True
        except ProcessLookupError:
            return False
    if send(signal.SIGTERM):
        deadline = time.monotonic() + timeout
        while True:
            process.poll()
            if not send(0):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                send(signal.SIGKILL)
                break
            time.sleep(min(.02, remaining))
    process.wait(timeout=5)
    process._acceptance_stopped = True


def command(argv, timeout=30, env=None, input=None, allowed=(0,), secrets=()):
    process = start_owned(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, env=env)
    try:
        stdout, stderr = process.communicate(input, timeout=timeout)
    finally:
        try:
            stop_owned(process)
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    if process.returncode not in allowed:
        raise RuntimeError(redact(f"{Path(str(argv[0])).name} exit {process.returncode}: {stderr[-2000:]}", secrets))
    return stdout


def artifact_inventory(root):
    # Private keys and bearer credentials are never part of the shareable index.
    return {str(p.relative_to(root)): digest(p) for p in sorted(Path(root).rglob("*"))
            if p.is_file() and not p.is_symlink() and p.suffix != ".key"
            and p.name not in {"daemon-token", "report.json", "inventory.json"}}
