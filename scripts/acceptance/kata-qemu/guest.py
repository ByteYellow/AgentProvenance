#!/usr/bin/env python3
"""Run the existing Guest handoff pipeline in one explicitly privileged Kata Pod.

Uses the handoff guest backend and its persisted platform binding.
It never mounts filesystems, installs packages, or changes kernel/host policy.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

from common import Blocked, artifact_inventory, clean_env, command, digest, load, redact, require, save, start_owned, stop_owned
from binding import expected_platform, rejection_checks, trusted_read, validate_checkpoint, validate_receipt
from reader import verify_reader
from workspace_case import run_case


HERE = Path(__file__).resolve().parent


def guest_probe(lock):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Guest must be Linux x86_64")
    require(os.geteuid() == 0, "Guest fixture needs explicitly authorized root privileges")
    kernel = lock["artifacts"]["guest_kernel"]
    require(platform.release() == kernel["release"], "running Guest kernel release differs from lock")
    require(digest("/sys/kernel/btf/vmlinux") == kernel["btf_sha256"], "running Guest BTF differs from lock")
    require(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "Guest cgroup v2 is unavailable")
    try:
        feature = json.loads(command(["bpftool", "-j", "feature", "probe", "kernel"], timeout=30))
    except (OSError, RuntimeError) as error:
        raise Blocked("Guest BPF feature probe unavailable: " + str(error)) from error
    for key in ("have_kprobe_prog_type", "have_tracepoint_prog_type"):
        require(feature.get("program_types", {}).get(key) is True, "Guest BPF missing " + key)
    for key in ("have_ringbuf_map_type", "have_hash_map_type"):
        require(feature.get("map_types", {}).get(key) is True, "Guest BPF missing " + key)
    for key in ("CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_EVENTS", "CONFIG_DEBUG_INFO_BTF"):
        require(feature.get("system_config", {}).get(key) == "y", "Guest kernel config unavailable or disabled: " + key)
    trace = next((p for p in (Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing"))
                  if (p / "events/sched/sched_process_fork/id").is_file()), None)
    require(trace is not None, "Guest tracefs tracepoints not visible; no automatic mount is attempted")
    status = Path("/proc/self/status").read_text().splitlines()
    return {"status": "PASS", "kernel": platform.release(), "btf_sha256": kernel["btf_sha256"],
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "namespaces": {k: os.readlink("/proc/self/ns/" + k) for k in ("pid", "mnt", "user", "cgroup")},
            "container_cgroup": Path("/proc/self/cgroup").read_text().strip(),
            "privileges": [line for line in status if line.startswith(("CapEff:", "Seccomp:", "NoNewPrivs:"))],
            "tracefs": str(trace), "bpf_features": feature,
            "scope": "privileged fixture container observing the Kata guest kernel"}


def validate_capture(report):
    checkpoint = report["checkpoint"]
    if report["attempt"]["state"]["capture"] != "sealed":
        raise RuntimeError("capture did not seal; retain gaps in the execution report")
    scope = checkpoint["scope"]
    if scope.get("scope_kind") != "cgroup" or not str(scope.get("cgroup_id", "")).isdigit() or str(scope["cgroup_id"]) == "0":
        raise RuntimeError("command lacks an owned nonzero Guest cgroup scope")
    return scope


def validate_recovery(report, replay, attempt_id):
    state = report["attempt"]["state"]
    if state["execution"] != "unknown" or state["capture"] != "incomplete":
        raise RuntimeError("daemon crash did not retain Unknown/Incomplete")
    if any(report["checkpoint"].get(key, {}).get("state") != "unknown" for key in ("stdout", "stderr")):
        raise RuntimeError("restart fabricated known stdout/stderr")
    if replay["attempt"]["id"] != attempt_id or not replay.get("reused"):
        raise RuntimeError("transport replay after crash started a new attempt")


class Guest:
    def __init__(self, args, lock, report):
        self.args, self.lock, self.report = args, lock, report
        self.root = args.data_dir
        self.store = self.root / "store"
        self.env = clean_env()
        self.token = uuid.uuid4().hex + uuid.uuid4().hex
        self.process = None
        self.logs = []
        self.attempts = []
        self.parent = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.control = args.binding_dir
        self.config_path = self.control / "execution.json"
        deadline = time.monotonic() + 120
        while not (self.control / "receipt.json").exists():
            if time.monotonic() > deadline:
                raise Blocked("operator binding receipt did not arrive within 120s")
            time.sleep(0.1)
        receipt_raw = trusted_read(self.control / "receipt.json")
        self.receipt = json.loads(receipt_raw)
        config_raw = trusted_read(self.config_path)
        observed = {"pod_uid": os.environ["AP_POD_UID"], "guest_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "lock_sha256": digest(args.lock), "binary_sha256": digest(args.binary)}
        self.config = validate_receipt(self.receipt, config_raw, observed, lock)
        for key in ("executor", "receiver"):
            require(digest(self.control / (key + ".pub")) == self.receipt["key_sha256"][key], "operator public key changed")
        self.report.update(target=self.config["target"], binding_receipt_sha256=digest(self.control / "receipt.json"),
                           platform_binding=expected_platform(self.config), operator_receipt=self.receipt)
        self.report["binding_rejections"] = rejection_checks(self.receipt, config_raw, observed, lock)
        with socket.socket() as port:
            port.bind(("127.0.0.1", 0))
            self.port = port.getsockname()[1]
        self.url = "http://127.0.0.1:" + str(self.port)

    def cli(self, *argv, timeout=60):
        return command([self.args.binary, *argv], timeout=timeout, env=self.env, secrets=(self.token,))

    def api(self, method, path, body=None):
        request = urllib.request.Request(self.url + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with self.opener.open(request, timeout=5) as response:
            return json.load(response)

    def setup(self):
        require(digest(self.args.binary) == self.lock["sensor"]["sha256"], "Guest binary hash mismatch")
        self.report["checks"]["guest_kernel"] = guest_probe(self.lock)
        self.parent = Path("/sys/fs/cgroup") / ("ap-kata-" + uuid.uuid4().hex)
        try:
            self.parent.mkdir()
        except OSError as error:
            self.parent = None
            raise Blocked("Guest cgroup v2 is not delegated/writable; no remount attempted") from error
        self.env["AGENTPROV_CGROUP_PARENT"] = str(self.parent)
        self.report["checks"]["guest_kernel"]["owned_cgroup_parent"] = str(self.parent)
        (self.root / "daemon-token").write_text(self.token)

    def start(self):
        require(digest(self.control / "receipt.json") == self.report["binding_receipt_sha256"] and
                digest(self.config_path) == self.receipt["configuration_sha256"], "operator binding changed before daemon start")
        log = self.root / ("daemon-" + str(len(self.logs) + 1) + ".log")
        self.logs.append(log)
        with log.open("w") as stream:
            self.process = start_owned([str(self.args.binary), "--data-dir", str(self.store), "daemon", "serve",
                "--listen", "127.0.0.1:" + str(self.port), "--execution-config", str(self.config_path),
                "--sample-interval", "0", "--gc-interval", "0"], stdout=stream, stderr=subprocess.STDOUT,
                env=dict(self.env, AGENTPROV_DAEMON_TOKEN=self.token))
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            require(self.process.poll() is None, "Guest daemon exited before native probes were ready; see retained redacted log")
            try:
                if self.api("GET", "/v1/ready").get("ready"):
                    lock = load(self.store / ".daemon.lock")
                    require(lock.get("pid") == self.process.pid and lock.get("addr") == "127.0.0.1:" + str(self.port), "listener ownership mismatch")
                    status = json.loads(self.cli("--data-dir", self.store, "sensor", "status", "--json"))
                    capability = status["capabilities"]
                    require(capability and capability.get("ready"), "Guest Sensor capability snapshot is not ready")
                    producer = capability["producer"]
                    for key, value in (("version", self.lock["sensor"]["version"]), ("commit", self.lock["sensor"]["source_sha"]),
                                       ("placement", "guest_kernel"), ("boot_id", self.report["checks"]["guest_kernel"]["boot_id"])):
                        require(producer.get(key) == value, "Guest Sensor producer " + key + " differs from lock/scope")
                    required = [p for p in capability.get("probes", []) if p.get("required")]
                    require(bool(required) and all(p["status"] == "attached" for p in required), "required native probes are not attached")
                    self.report.setdefault("capabilities", []).append(capability)
                    return
            except (OSError, KeyError):
                pass
            time.sleep(0.2)
        raise Blocked("Guest native capture readiness deadline expired")

    def fixture(self, name, argv, timeout):
        program = [sys.executable, HERE / name]
        if name == "accept_execution_delivery.py":
            # Allow the native state sampler to see this otherwise very short CSV task.
            # The reused script bytes are unchanged; retain the exact workload prelude.
            prelude = "import time; time.sleep(2)\n"
            program = [sys.executable, "-c", "import sys; sys.path.insert(0," + repr(str(HERE)) +
                       "); import accept_execution_delivery as fixture; fixture.TASK=" + repr(prelude) +
                       "+fixture.TASK; fixture.main()"]
            self.report["delivery_task_prelude"] = prelude
        output = command([*program, *argv], timeout=timeout, env=self.env, secrets=(self.token,))
        (self.root / (name + ".log")).write_text(redact(output, (self.token,)))

    def wait(self, attempt, state, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            report = self.api("GET", "/v1/executions/" + attempt)
            if report["attempt"]["state"]["execution"] == state:
                if state == "running" or report["attempt"]["state"]["capture"] in {"sealed", "incomplete"}:
                    validate_checkpoint(report["checkpoint"], self.config)
                    return report
            time.sleep(0.1)
        raise TimeoutError("execution did not reach " + state)

    def request(self, argv):
        nonce = uuid.uuid4().hex
        return {"schema_version": "agentprovenance.execution_handoff/v1", "target": self.config["target"],
                "source": {"producer_id": "fixture-caller", "namespace": "fixture", "run_id": "recovery-" + nonce,
                           "harness": "kata-fixture", "session_id": nonce, "tool_call_id": "recovery"},
                "operation_id": nonce, "dispatch_id": nonce,
                "valid_until": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)).isoformat(),
                "command": {"argv": argv, "disable_snapshot": True}}

    def submit(self, request):
        admission = self.api("POST", "/v1/executions", request)
        self.attempts.append(admission["attempt"]["id"])
        return admission

    def exercise(self):
        args = ["--url", self.url, "--config", self.config_path, "--token-file", self.root / "daemon-token"]
        self.fixture("accept_execution_delivery.py", [*args, "--receiver", "fixture-receiver", "--agentprov", self.args.binary,
            "--sign-key", self.control / "receiver.key", "--pub-key", self.control / "executor.pub",
            "--data-dir", self.root / "receiver", "--output", self.root / "single.json"], 180)
        single = load(self.root / "single.json")
        validate_capture(single["execution"])
        validate_checkpoint(single["execution"]["checkpoint"], self.config)
        self.report["checks"]["single_delivery"] = {"status": "PASS", "report": "single.json", "sha256": digest(self.root / "single.json")}
        self.fixture("accept_execution_handoff.py", [*args, "--require-sealed", "--output", self.root / "concurrent.json"], 150)
        handoff_report = load(self.root / "concurrent.json")
        for execution in handoff_report["completed"]:
            validate_capture(execution)
            validate_checkpoint(execution["checkpoint"], self.config)
        # The reused fixture checks native scopes; distinct payloads also catch output cross-talk.
        markers = [uuid.uuid4().hex for _ in range(2)]
        requests = [self.request(["python3", "-c", "import json,time; time.sleep(2); marker=" + repr(marker) +
                    "; open('marker.txt','w').write(marker); print(json.dumps({'marker':marker}))"]) for marker in markers]
        for request in requests:
            request["command"]["disable_snapshot"] = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            admissions = list(pool.map(self.submit, requests))
        executions = [self.wait(a["attempt"]["id"], "succeeded") for a in admissions]
        scopes = [validate_capture(execution) for execution in executions]
        if len({s["cgroup_id"] for s in scopes}) != 2 or len({s["run_id"] for s in scopes}) != 2:
            raise RuntimeError("concurrent marker operations shared a scope")
        for marker, execution in zip(markers, executions):
            checkpoint = execution["checkpoint"]
            body = json.loads(self.cli("--data-dir", self.store, "context", "content", "--run", checkpoint["scope"]["run_id"],
                                       "--ref", checkpoint["stdout"]["ref"]))
            if json.loads(body["content"]) != {"marker": marker} or "marker.txt" not in checkpoint["result"]["changed_files"]:
                raise RuntimeError("concurrent marker output or artifact was cross-attributed")
        save(self.root / "isolation.json", {"markers": markers, "requests": requests, "executions": executions})
        self.report["checks"]["concurrent_isolation"] = {"status": "PASS", "report": "concurrent.json",
            "sha256": digest(self.root / "concurrent.json"), "distinct_payload_report": "isolation.json"}
        for field in ("instance_id", "generation"):
            request = self.request(["true"])
            request["target"] = dict(request["target"], **{field: "mismatched-" + uuid.uuid4().hex})
            try:
                self.submit(request)
            except urllib.error.HTTPError as error:
                if error.code != 403:
                    raise RuntimeError("wrong Pod/Target rejected for an unrelated error") from error
                self.report["binding_rejections"].append("http_target_" + field + "_403")
            else:
                raise RuntimeError("executor accepted mismatched Pod/Target " + field)
        if self.args.previous_target:
            request = self.request(["true"])
            request["target"] = json.loads(self.args.previous_target)
            try:
                self.submit(request)
            except urllib.error.HTTPError as error:
                if error.code != 403:
                    raise RuntimeError("stale target failed for a reason other than authorization") from error
                self.report["checks"]["stale_target"] = {"status": "PASS", "http_status": error.code, "old_target": request["target"]}
            else:
                raise RuntimeError("rebuilt Guest accepted the old generation")
        request = self.request(["sleep", "15"])
        admission = self.submit(request)
        attempt = admission["attempt"]["id"]
        before_crash = self.wait(attempt, "running")
        old_collector = self.report["capabilities"][-1]["collector_id"]
        self.process.kill()
        self.process.wait(timeout=5)
        self.start()
        require(self.report["capabilities"][-1]["collector_id"] != old_collector, "collector restart reused its epoch")
        recovered = self.wait(attempt, "unknown", timeout=40)
        replay = self.api("POST", "/v1/executions", request)
        validate_recovery(recovered, replay, attempt)
        retry = json.loads(json.dumps(request))
        retry.update(operation_id=uuid.uuid4().hex, previous_attempt_id=attempt)
        retry["command"]["argv"] = ["sleep", "2"]
        next_attempt = self.submit(retry)["attempt"]
        require(next_attempt["id"] != attempt, "explicit retry reused old attempt")
        completed = self.wait(next_attempt["id"], "succeeded")
        validate_capture(completed)
        require(completed["attempt"]["request"].get("previous_attempt_id") == attempt, "explicit retry lost previous attempt identity")
        save(self.root / "recovery.json", {"request": request, "admission": admission, "recovered": recovered,
             "before_crash": before_crash, "replay": replay, "explicit_retry": completed,
             "fault": "SIGKILL owned daemon including its embedded collector"})
        self.report["checks"]["recovery"] = {"status": "PASS", "report": "recovery.json", "sha256": digest(self.root / "recovery.json")}
        # Re-query the delivered attempt after a collector restart without executing it again.
        saved = self.api("GET", "/v1/executions/" + single["admission"]["attempt"]["id"])
        if saved["attempt"]["state"]["delivery"] != "acknowledged":
            raise RuntimeError("delivery receipt did not survive restart")
        self.stop()
        seal = self.cli("--data-dir", self.store, "forensics", "seal-executions", "--execution-config", self.config_path,
                        "--operation", "kata-final-" + self.report["target"]["generation"], timeout=90)
        (self.root / "seal.jsonl").write_text(seal)
        rows = [json.loads(line) for line in seal.splitlines()]
        if not rows or not rows[-1].get("complete"):
            raise RuntimeError("stopped Guest store did not seal")
        recovered_package = next(row for row in rows[:-1] if row["attempt_id"] == attempt)
        recovered_state = recovered_package["delivery"]["manifest"]["state"]
        if recovered_state["execution"] != "unknown" or recovered_state["capture"] != "incomplete":
            raise RuntimeError("sealing changed crash recovery uncertainty")
        package = next(row for row in rows[:-1] if row["attempt_id"] == single["admission"]["attempt"]["id"])
        # Reuse the stopped-store export/import protocol from accept_execution_seal.py.
        bundle = Path(package["bundle_path"])
        envelope = bundle.with_name("manifest.dsse.json")
        portable = self.root / "portable"
        portable.mkdir()
        shutil.copyfile(bundle, portable / "bundle.json")
        shutil.copyfile(envelope, portable / "bundle.dsse.json")
        shutil.copyfile(self.control / "executor.pub", portable / "executor.pub")
        self.store.rename(self.root / "retained-source-store")
        imported = json.loads(self.cli("--data-dir", self.root / "offline", "forensics", "import", portable / "bundle.json",
                                      "--pub-key", portable / "executor.pub", "--json"))
        require(imported.get("attestation_verified") is True, "offline import did not verify pinned executor key")
        run_id = single["admission"]["attempt"]["local_run_id"]
        verification = json.loads(self.cli("--data-dir", self.root / "offline", "graph", "verify", "--run", run_id, "--json"))
        content = json.loads(self.cli("--data-dir", self.root / "offline", "context", "content", "--run", run_id,
                                     "--ref", single["execution"]["checkpoint"]["stdout"]["ref"]))
        if json.loads(content["content"])["totals"] != {"alpha": 40, "beta": 20}:
            raise RuntimeError("offline signed command output differs from fixture")
        checkpoint_ref = single["execution"]["checkpoint_ref"]
        with sqlite3.connect((self.root / "offline/agentprov.db").as_uri() + "?mode=ro", uri=True) as db:
            row = db.execute("SELECT path FROM provenance_objects WHERE run_id=? AND hash=?", (run_id, checkpoint_ref)).fetchone()
            require(row and "sha256:" + digest(Path(row[0])) == checkpoint_ref, "signed imported checkpoint object missing or changed")
            validate_checkpoint(load(Path(row[0]))["payload"], self.config)
        self.report["checks"]["runtimeadapter_binding"] = {"status": "PASS", "platform_binding": expected_platform(self.config),
            "receipt_sha256": self.report["binding_receipt_sha256"], "rejections": self.report["binding_rejections"],
            "signed_imported_checkpoint_ref": checkpoint_ref}
        self.report["checks"]["offline_delivery"] = {"status": "PASS", "bundle_sha256": digest(portable / "bundle.json"),
            "attestation_sha256": digest(portable / "bundle.dsse.json"), "verification": verification,
            "retirement": "retained; final packages for other attempts still require receipts"}
        if self.args.verifier:
            require(digest(self.args.verifier) == self.lock["verifier"]["sha256"], "Guest standalone verifier hash mismatch")
            version = command([self.args.verifier, "--version"], env=self.env)
            require(self.lock["verifier"]["version"] in version and self.lock["verifier"]["source_sha"] in version,
                    "Guest standalone verifier build metadata mismatch")
            self.report["checks"]["derived_verifier"] = verify_reader(self.args.binary, self.args.verifier,
                self.root / "offline", run_id, self.root / "reader", source=self.receipt["source"])
        if self.args.workspace_case:
            require(json.loads(trusted_read(self.control / "workspace-target.json")) == self.config["target"],
                    "workspace operator target differs from the bound Guest")
            self.report["checks"]["workspace_case"] = run_case(self.args.binary, self.args.verifier,
                HERE / "accept_workspace.py", HERE / "python", self.control, self.root / "workspace",
                self.config, self.lock, self.receipt["source"], self.args.workspace_case)

    def stop(self):
        if self.process:
            stop_owned(self.process, timeout=25)

    def cleanup(self):
        if self.process and self.process.poll() is None:
            for attempt in self.attempts:
                try:
                    self.api("POST", "/v1/executions/" + attempt + "/stop", {"operation_id": "cleanup-" + attempt})
                except OSError:
                    pass
        self.stop()
        for path in self.logs:
            path.write_text(redact(path.read_text(errors="replace"), (self.token,)))
        if self.parent:
            try:
                self.parent.rmdir()
            except OSError:
                self.report["retained_cgroup"] = str(self.parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("binary", "data-dir", "lock"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--binding-dir", type=Path, required=True)
    parser.add_argument("--verifier", type=Path)
    parser.add_argument("--previous-target")
    parser.add_argument("--workspace-case", choices=("contract", "harness"))
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    os.umask(0o077)
    report = {"schema_version": "agentprovenance.kata_guest_fixture/v1", "status": "BLOCKED", "checks": {},
              "identity_authority": "operator-owned API/CRI binding receipt and read-only execution configuration"}
    guest = None
    code = 2
    def expired(signum, frame):
        raise TimeoutError("Guest fixture exceeded its bounded deadline")
    try:
        require(60 <= args.timeout <= 600, "timeout must be 60..600 seconds")
        require(args.data_dir.is_dir() and not any(args.data_dir.iterdir()), "Guest data directory must be empty")
        require(bool(os.environ.get("AP_POD_UID")), "Kubernetes downward API Pod UID missing")
        signal.signal(signal.SIGALRM, expired)
        signal.signal(signal.SIGTERM, expired)
        signal.alarm(args.timeout)
        guest = Guest(args, load(args.lock), report)
        guest.setup()
        guest.start()
        guest.exercise()
        report["status"], code = "PASS", 0
    except (Blocked, FileNotFoundError, PermissionError) as error:
        report["error"] = redact(str(error), (guest.token,) if guest else ())
    except Exception as error:
        report["status"], report["error"], code = "FAIL", redact(str(error), (guest.token,) if guest else ()), 1
    finally:
        signal.alarm(0)
        if guest:
            try:
                guest.cleanup()
            except Exception as error:
                report["status"], report["cleanup_error"], code = "FAIL", redact(str(error), (guest.token,)), 1
        if args.data_dir.is_dir():
            save(args.data_dir / "report.json", report)
            save(args.data_dir / "inventory.json", artifact_inventory(args.data_dir))
        print(json.dumps({"status": report["status"], "report": str(args.data_dir / "report.json")}))
    return code


if __name__ == "__main__":
    sys.exit(main())
