#!/usr/bin/env python3
"""Opt-in root acceptance against real syscalls, OpenSSL and Go TLS on Linux.

Build the two clients in internal/sensor/testdata first. No external services
or API credentials are used. --report writes the machine-readable result.
"""
import argparse
import collections
import ctypes
import errno
from datetime import datetime
import http.server
import json
import os
from pathlib import Path
import platform
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def lifecycle_worker(directory):
    fixtures = {}

    def finish_child(pid, name):
        _, status = os.waitpid(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError(f"{name} child failed: {status}")
        fixtures[name] = {"caller_pid": pid}

    def write_child(name):
        Path(name + ".env").write_text("FAKE_TOKEN=lifecycle-only\n")

    pid = os.fork()
    if pid == 0:
        try:
            write_child("fork-child")
        except BaseException:
            os._exit(1)
        os._exit(0)
    finish_child(pid, "fork-child")

    group = Path("/sys/fs/cgroup") / ("agentprov-" + Path(directory).name)
    try:
        group.mkdir()
    except OSError as error:
        if error.errno not in {errno.EPERM, errno.EACCES, errno.EROFS, errno.ENOENT}:
            raise
        return fixtures, {"cgroup_lifecycle": str(error)}
    gaps = {}
    try:
        fixtures["target_cgroup_id"] = str(group.stat().st_ino)
        pid = os.fork()
        if pid == 0:
            try:
                write_child("migration-before")
                (group / "cgroup.procs").write_text("0")
                write_child("migration-after")
            except BaseException:
                os._exit(1)
            os._exit(0)
        finish_child(pid, "migration-child")

        class CloneArgs(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "flags", "pidfd", "child_tid", "parent_tid", "exit_signal",
                "stack", "stack_size", "tls", "set_tid", "set_tid_size", "cgroup")]

        fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
        try:
            args = CloneArgs(flags=0x200000000, exit_signal=signal.SIGCHLD, cgroup=fd)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long
            pid = libc.syscall(435, ctypes.byref(args), ctypes.sizeof(args))
            if pid < 0:
                error = ctypes.get_errno()
                if error not in {errno.ENOSYS, errno.EPERM, errno.EACCES, errno.EOPNOTSUPP}:
                    raise OSError(error, "clone3(CLONE_INTO_CGROUP)")
                gaps["clone_into_cgroup"] = os.strerror(error)
            elif pid == 0:
                try:
                    write_child("clone-child")
                except BaseException:
                    os._exit(1)
                os._exit(0)
            else:
                finish_child(pid, "clone-child")
        finally:
            os.close(fd)
    finally:
        group.rmdir()
    return fixtures, gaps


def worker(directory, port):
    os.chdir(directory)
    # Absolute /tmp paths are deliberately excluded by the sensor's tamper
    # noise filter. Exercise normal workload-relative file operations.
    secret = Path("fixture.env")
    secret.write_text("FAKE_TOKEN=acceptance-only\n")
    secret.read_text()
    renamed = Path("renamed.env")
    secret.rename(renamed)
    renamed.unlink()
    # Same-identity calls and an invalid ptrace request exercise syscall
    # argument capture without changing privileges or tracing another process.
    os.setgid(os.getgid())
    os.setuid(os.getuid())
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace(-1, 0, None, None)
    if platform.machine() == "x86_64":
        # x86 has the legacy open syscall in addition to openat. Modern libc
        # otherwise hides this ABI path by implementing open() with openat().
        fd = libc.syscall(2, b"legacy-open.env", os.O_WRONLY | os.O_CREAT, 0o600)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "legacy open")
        os.close(fd)
        os.unlink("legacy-open.env")
    socket.getaddrinfo("localhost", int(port))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.sendto(bytes.fromhex("123401000001000000000000") +
               b"\x09agentprov\x07invalid\0\0\x01\0\x01", ("127.0.0.1", 53))
    udp.close()
    conn = ssl._create_unverified_context().wrap_socket(socket.socket(), server_hostname="localhost")
    conn.connect(("127.0.0.1", int(port)))
    body = b'{"marker":"python-openssl-ex"}'
    conn.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n"
                 b"Connection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    while conn.recv(4096):
        pass
    conn.close()
    fixtures, gaps = lifecycle_worker(directory)
    Path("lifecycle.json").write_text(json.dumps({"fixtures": fixtures, "gaps": gaps}))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--go-client", required=True)
    parser.add_argument("--c-client", required=True)
    parser.add_argument("--ssl-lib", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--pause-drain", type=float, default=0,
                        help="hold userspace draining until this many seconds after the clients exit (kernel capture-time gate)")
    parser.add_argument("--require-cgroup-lifecycle", action="store_true",
                        help="fail unless migration and clone3 into a distinct cgroup were exercised")
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != "Linux":
        parser.error("run explicitly as root on Linux")
    report_path = Path(args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="agentprov-live-") as directory:
        root = Path(directory)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=localhost", "-days", "1", "-keyout", str(key),
                        "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_port
        env = os.environ.copy()
        env.update(AGENTPROV_SSL_LIB=str(Path(args.ssl_lib).resolve()),
                   AGENTPROV_GO_TLS_BIN=str(Path(args.go_client).resolve()),
                   AGENTPROV_AUTO_TLS="false")
        events_path, error_path = root / "events.jsonl", root / "sensor.err"
        pids = {}
        with events_path.open("w") as out, error_path.open("w") as err:
            sensor = subprocess.Popen([str(Path(args.sensor).resolve())], env=env, stdout=out, stderr=err)
            try:
                deadline = time.monotonic() + 15
                while "agentprov-sensor: ready" not in error_path.read_text():
                    if sensor.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("sensor did not attach: " + error_path.read_text())
                    time.sleep(0.05)
                jobs = {
                    "python-openssl-ex": [sys.executable, __file__, "--worker", directory, str(port), "python-openssl-ex"],
                    "c-openssl-legacy": [args.c_client, str(port), "legacy", "c-openssl-legacy"],
                    "c-openssl-ex": [args.c_client, str(port), "ex", "c-openssl-ex"],
                    "go-abiinternal": [args.go_client, f"https://127.0.0.1:{port}/v1/chat/completions", "go-abiinternal"],
                }
                if args.pause_drain > 0:
                    sensor.send_signal(signal.SIGSTOP)
                for name, command in jobs.items():
                    proc = subprocess.Popen(command)
                    pids[name] = proc.pid
                    try:
                        if proc.wait(timeout=15) != 0:
                            raise RuntimeError(f"client {name} failed")
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.wait()
                if args.pause_drain > 0:
                    time.sleep(args.pause_drain)
                    resumed_at = time.time()
                    sensor.send_signal(signal.SIGCONT)
                time.sleep(1)  # drain the ring buffer before signal shutdown
            finally:
                if sensor.poll() is None:
                    sensor.send_signal(signal.SIGCONT)
                    sensor.send_signal(signal.SIGINT)
                try:
                    sensor.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    sensor.kill()
                    sensor.wait()
                server.shutdown()
                server.server_close()
        rows = [json.loads(line) for line in events_path.read_text().splitlines()]
        # BPF emits initial-kernel-namespace PIDs. WSL can expose a nested PID
        # namespace to the caller; identify fixtures by their unique exec argv,
        # then check all subsequent facts using the observed kernel identity.
        caller_pids = pids.copy()
        pids = {}
        for name in caller_pids:
            matches = {row["pid"] for row in rows if row.get("event_type") == "execve" and name in row.get("command", "")}
            if len(matches) != 1:
                raise RuntimeError(f"expected one exec identity for {name}, got {matches}")
            pids[name] = matches.pop()
        checks = {}
        worker_rows = [row for row in rows if row.get("pid") == pids["python-openssl-ex"]]
        types = {row["event_type"] for row in worker_rows}
        for kind in ("execve", "file_open", "file_rename", "file_unlink", "network_connect", "dns_query", "process_exit"):
            checks[kind] = kind in types
        checks["sensitive_read"] = any(row.get("mode") == "read" and row.get("path", "").endswith("fixture.env") for row in worker_rows)
        checks["file_write"] = any(row.get("mode") == "write" and row.get("path", "").endswith("fixture.env") for row in worker_rows)
        for kind in ("setuid", "setgid", "ptrace"):
            checks[kind] = kind in types
        if platform.machine() == "x86_64":
            checks["legacy_open_x86"] = any(row.get("event_type") == "file_open" and row.get("path") == "legacy-open.env" for row in worker_rows)
        checks["cgroup_identity"] = bool(worker_rows) and all(str(row.get("cgroup_id", "")).isdigit() and row["cgroup_id"] != "0" for row in worker_rows)
        checks["dns_glibc_c_abi"] = any(row.get("pid") == pids["c-openssl-legacy"] and row.get("event_type") == "dns_query" and row.get("host") == "localhost" for row in rows)
        checks["dns_udp"] = any(row.get("host") == "agentprov.invalid" for row in worker_rows)
        for name, pid in pids.items():
            directions = ("tls_write", "tls_read")
            # Go Read return-site probes are currently supported on amd64.
            if name == "go-abiinternal" and platform.machine() != "x86_64":
                directions = ("tls_write",)
            for kind in directions:
                checks[f"{name}:{kind}"] = any(row.get("pid") == pid and row.get("event_type") == kind and name in row.get("data", "") for row in rows)
        checks["sensor_clean_exit"] = sensor.returncode == 0
        checks["no_tls_attach_warning"] = "not attached" not in error_path.read_text() and "partial TLS" not in error_path.read_text()
        lifecycle = json.loads((root / "lifecycle.json").read_text())
        child_pids = {}
        parent_instance = next((row.get("process_instance_id") for row in worker_rows
                                if row.get("event_type") == "execve"), None)
        checks["parent_process_instance"] = bool(parent_instance) and all(
            row.get("process_instance_id") == parent_instance for row in worker_rows)
        for name, marker in (("fork-child", "fork-child.env"),
                             ("migration-child", "migration-before.env"),
                             ("clone-child", "clone-child.env")):
            if name not in lifecycle["fixtures"]:
                continue
            matches = {row["pid"] for row in rows if row.get("path") == marker}
            if len(matches) != 1:
                raise RuntimeError(f"expected one child identity for {name}, got {matches}")
            child_pid = matches.pop()
            child_pids[name] = child_pid
            child_rows = [row for row in rows if row.get("pid") == child_pid]
            birth = next((row for row in child_rows if row.get("observation") == "kernel_fork"), None)
            exit_event = next((row for row in child_rows if row.get("event_type") == "process_exit"), None)
            file_event = next(row for row in child_rows if row.get("path") == marker)
            identity = file_event.get("process_instance_id")
            checks[f"{name}:lifetime"] = bool(identity) and bool(birth) and bool(exit_event) and all(
                row.get("process_instance_id") == identity for row in child_rows)
            checks[f"{name}:parent"] = bool(birth) and birth.get("ppid") == pids["python-openssl-ex"] and birth.get("parent_process_instance_id") == parent_instance
            checks[f"{name}:ordering"] = bool(birth) and bool(exit_event) and (
                datetime.fromisoformat(birth["timestamp"]) <= datetime.fromisoformat(file_event["timestamp"]) <= datetime.fromisoformat(exit_event["timestamp"]))
            checks[f"{name}:birth_cgroup"] = bool(birth) and birth.get("cgroup_id") == file_event.get("cgroup_id")
            if name == "migration-child":
                after = next((row for row in child_rows if row.get("path") == "migration-after.env"), {})
                checks["cgroup_migration"] = after.get("cgroup_id") == lifecycle["fixtures"]["target_cgroup_id"] and after.get("cgroup_id") != file_event.get("cgroup_id") and after.get("process_instance_id") == identity
            if name == "clone-child":
                checks["clone_into_cgroup"] = file_event.get("cgroup_id") == lifecycle["fixtures"]["target_cgroup_id"] and file_event.get("cgroup_id") != worker_rows[0].get("cgroup_id")
        if args.require_cgroup_lifecycle:
            checks["required_cgroup_lifecycle"] = "migration-child" in child_pids and "clone-child" in child_pids and not lifecycle["gaps"]
        fixture_pids = set(pids.values()) | set(child_pids.values())
        if args.pause_drain > 0:
            checks["capture_time_before_drain"] = all(
                datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp() < resumed_at - args.pause_drain / 2
                for row in rows if row.get("pid") in fixture_pids)
        report = {
            "schema_version": "agentprovenance.sensor_live_acceptance/v1",
            "architecture": platform.machine(), "kernel": platform.release(), "pause_drain_seconds": args.pause_drain,
            "checks": checks, "passed": all(checks.values()), "kernel_pids": pids, "caller_pids": caller_pids,
            "lifecycle": lifecycle, "child_kernel_pids": child_pids,
            "event_types": dict(collections.Counter(row["event_type"] for row in rows)),
            "event_count": len(rows), "sensor_stderr": error_path.read_text(),
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        # Retain only fixture process evidence, not unrelated host activity.
        report_path.with_suffix(".events.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows if row.get("pid") in fixture_pids))
        print(json.dumps(report, indent=2))
        if not report["passed"]:
            raise SystemExit("FAIL: " + ", ".join(name for name, passed in checks.items() if not passed))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(sys.argv[2], sys.argv[3])
    else:
        main()
