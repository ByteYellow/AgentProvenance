#!/usr/bin/env python3
"""Bounded, opt-in Kata/QEMU acceptance on the selected Kubernetes node."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import uuid

from common import Blocked, clean_env, command, digest, load, require, save, redact
from binding import SCHEMA as BINDING_SCHEMA, configuration, expected_platform, validate_receipt
from workspace_case import WORKSPACE_INPUTS, option_issues


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ARTIFACTS = ("kata", "qemu", "guest_kernel", "guest_image", "kata_config")
FIXTURES = ("scripts/accept_execution_handoff.py", "scripts/accept_execution_delivery.py")
REFERENCED_PIPELINE = ("scripts/accept_execution_seal.py", "scripts/accept_kvm_guest.py", "deploy/microvm/guest_service.py")
MATRIX = {
    "guest_kernel": "Guest kernel, BTF, BPF feature probe, namespaces and writable cgroup v2",
    "single_delivery": "One real command, signed transfer, receipt, artifact and graph verification",
    "concurrent_isolation": "Concurrent operations, distinct cgroups, source identity and native file writes",
    "recovery": "Owned daemon/collector crash, unknown output, incomplete capture and explicit retry",
    "pod_rebuild": "Same-name Pod rebuild, new UID/container/boot and stale Target rejection",
    "offline_delivery": "Stopped-source signed bundle import, pinned key, graph and output verification",
    "runtimeadapter_binding": "Operator-authorized RuntimeClass/Pod/container/Guest to Target, rejection tests and signed checkpoint",
    "late_evidence": "Late evidence and generation quarantine across platform lifecycle",
    "forced_reclaim": "Receipt-gated retirement and forced-reclaim gaps",
    "restore_clone": "Restore/clone only when supported by the pinned runtime combination",
    "soak_24h": "Resource trends, backpressure, loss, recovery and integrity over 24h",
    "workspace_case": "Remote-authoritative read/edit/run plus independently verified export",
    "browser_case": "Durable receipts and concurrent/background request attribution with Sensor on",
    "compatibility": "Old-data upgrade and rollback rehearsal",
    "derived_verifier": "E-01/E-02 signed reader export and standalone verifier with recipient-owned trust policy",
}


# Explicit operator preparation inside the newly created fixture container.
# The boot check precedes the mount so a host/Guest identity mistake fails closed.
TRACEFS_PREPARATION = """import json,os,subprocess,sys
from pathlib import Path
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
assert boot == sys.argv[1] and boot != sys.argv[2] and os.geteuid() == 0
path=Path('/sys/kernel/tracing')
assert path.is_dir() and not path.is_symlink() and path.resolve() == path
probe=path/'events/sched/sched_process_fork/id'
already=probe.is_file()
if not already:
    subprocess.run(['mount','-t','tracefs','-o','nosuid,nodev,noexec','tracefs',str(path)],check=True,timeout=10)
assert probe.is_file()
mounts=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] == str(path)]
assert len(mounts) == 1 and ' - tracefs ' in mounts[0]
print(json.dumps({'guest_boot_id':boot,'tracefs':str(path),'already_mounted':already,'mountinfo':mounts[0]}))
"""


@contextmanager
def defer_sigterm():
    received = False
    def defer(signum, frame):
        nonlocal received
        received = True
    previous = signal.signal(signal.SIGTERM, defer)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
        if received:
            if callable(previous):
                previous(signal.SIGTERM, None)
            elif previous != signal.SIG_IGN:
                raise InterruptedError("acceptance runner received SIGTERM during cleanup")


def lock_issues(lock):
    errors = []
    def check(ok, field):
        if not ok:
            errors.append(field)
    check(lock.get("schema_version") == "agentprovenance.kata_acceptance_lock/v1", "schema_version")
    check(lock.get("platform") == "linux/amd64", "platform")
    for key in ("runtime_class", "runtime_handler"):
        check(lock.get(key) == "kata-qemu-runtime-rs", key)
    check(lock.get("runtime_type") == "io.containerd.kata-qemu-runtime-rs.v2", "runtime_type")
    for name in ARTIFACTS:
        value = lock.get("artifacts", {}).get(name, {})
        check(bool(value.get("version")) and value.get("version") not in {"latest", "dev"}, name + ".version")
        check(isinstance(value.get("path"), str) and Path(value["path"]).is_absolute(), name + ".path")
        check(bool(re.fullmatch(r"[a-f0-9]{64}", value.get("sha256") or "")), name + ".sha256")
    for name, size in (("source_sha", 40),):
        check(bool(re.fullmatch(r"[a-f0-9]{%d}" % size, lock.get("artifacts", {}).get("kata", {}).get(name) or "")), "kata." + name)
    kernel = lock.get("artifacts", {}).get("guest_kernel", {})
    check(bool(kernel.get("release")), "guest_kernel.release")
    check(bool(re.fullmatch(r"[a-f0-9]{64}", kernel.get("btf_sha256") or "")), "guest_kernel.btf_sha256")
    sensor = lock.get("sensor", {})
    check(bool(sensor.get("version")) and sensor.get("version") != "dev", "sensor.version")
    check(sensor.get("packaging") == "embedded-in-agentprov", "sensor.packaging")
    for key, size in (("source_sha", 40), ("sha256", 64)):
        check(bool(re.fullmatch(r"[a-f0-9]{%d}" % size, sensor.get(key) or "")), "sensor." + key)
    for key in ("server_version", "kubelet_version"):
        check(bool(lock.get("kubernetes", {}).get(key)), "kubernetes." + key)
    check(bool(lock.get("containerd", {}).get("version")), "containerd.version")
    check(bool(re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", lock.get("workload_image") or "")), "workload_image")
    return errors


def validate_handler(lock, runtimeclass, info):
    require(runtimeclass.get("handler") == lock["runtime_handler"], "RuntimeClass handler mismatch")
    runtime = info.get("config", {}).get("containerd", {}).get("runtimes", {}).get(lock["runtime_handler"], {})
    require(runtime.get("runtimeType") == lock["runtime_type"], "CRI runtimeType mismatch or unavailable")
    require(runtime.get("privileged_without_host_devices", runtime.get("privilegedWithoutHostDevices")) is True,
            "CRI must already have privileged_without_host_devices=true for the selected handler")
    require(Path(runtime.get("runtimePath", "")).resolve() == Path(lock["artifacts"]["kata"]["path"]).resolve(),
            "CRI runtimePath differs from pinned runtime-rs binary")
    require(Path(runtime.get("options", {}).get("ConfigPath", "")).resolve() ==
            Path(lock["artifacts"]["kata_config"]["path"]).resolve(), "CRI ConfigPath mismatch")
    return {"handler": lock["runtime_handler"], "runtime_type": runtime["runtimeType"],
            "runtime_path": runtime["runtimePath"], "config_path": runtime["options"]["ConfigPath"]}


def cri_version(text):
    # crictl version has no JSON/output flag; use its documented four labeled lines.
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"Version", "RuntimeName", "RuntimeVersion", "RuntimeApiVersion"}:
            require(key not in fields, "duplicate CRI version field")
            fields[key] = value.strip()
    require(set(fields) == {"Version", "RuntimeName", "RuntimeVersion", "RuntimeApiVersion"}, "unrecognized crictl version output")
    return fields


def containerd_version(value):
    # Kubelet strips the leading v that containerd's CRI Version RPC retains.
    # Preserve every release/prerelease/build component in the comparison.
    require(isinstance(value, str) and re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?", value),
            "invalid containerd version")
    return value.removeprefix("v")


def pod_manifest(args, lock, name, assets, data, previous=None, binding_dir=None, workspace_case=None):
    argv = ["python3", "/fixture/guest.py", "--binary", "/fixture/agentprov", "--data-dir", "/evidence",
            "--lock", "/fixture/lock.json", "--binding-dir", "/binding", "--timeout", "600"]
    if getattr(args, "verifier", None):
        argv += ["--verifier", "/fixture/agentprov-verify"]
    if getattr(args, "stage_guest_binaries", False):
        argv.append("--stage-guest-binaries")
    if previous:
        argv += ["--previous-target", json.dumps(previous)]
    if workspace_case:
        argv += ["--workspace-case", workspace_case]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {
        "name": name, "namespace": args.namespace, "labels": {
            "agentprov.io/acceptance": name, "agentprov.io/acceptance-owner": uuid.uuid4().hex}},
        "spec": {"nodeName": args.node, "runtimeClassName": lock["runtime_class"],
            "automountServiceAccountToken": False, "enableServiceLinks": False,
            "restartPolicy": "Never", "activeDeadlineSeconds": 720, "terminationGracePeriodSeconds": 30,
            "containers": [{"name": "fixture", "image": lock.get("workload_image") or "UNPINNED",
                "imagePullPolicy": "Never", "command": argv,
                "env": [{"name": "AP_POD_UID", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.uid"}}},
                        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                "securityContext": {"privileged": True, "runAsUser": 0},
                "resources": {"requests": {"cpu": "1", "memory": "1Gi"}, "limits": {"cpu": "2", "memory": "2Gi"}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                 {"name": "binding", "mountPath": "/binding", "readOnly": True},
                                 {"name": "evidence", "mountPath": "/evidence"}]}],
            "volumes": [{"name": "fixture", "hostPath": {"path": str(assets), "type": "Directory"}},
                        {"name": "binding", "hostPath": {"path": str(binding_dir or data.parent / "binding-1"), "type": "Directory"}},
                        {"name": "evidence", "hostPath": {"path": str(data), "type": "Directory"}}]}}


def validate_pod(pod, manifest, uid):
    require(pod["metadata"]["uid"] == uid, "Pod UID changed")
    require(not any(key.startswith("io.katacontainers.") for key in pod["metadata"].get("annotations", {})),
            "Pod Kata override annotations are outside the pinned profile")
    expected, spec = manifest["spec"], pod["spec"]
    for key in ("nodeName", "runtimeClassName", "automountServiceAccountToken", "restartPolicy", "activeDeadlineSeconds"):
        require(spec.get(key) == expected[key], "Pod " + key + " changed")
    require(not any(spec.get(key) for key in ("hostPID", "hostIPC", "hostNetwork", "initContainers", "ephemeralContainers")),
            "Pod gained an unexpected namespace or container")
    require(len(spec["containers"]) == 1, "Pod gained an unexpected container")
    container, original = spec["containers"][0], expected["containers"][0]
    for key in ("name", "image", "imagePullPolicy", "command", "env", "securityContext"):
        require(container.get(key) == original[key], "Pod fixture " + key + " changed")
    # API defaulting can add mount fields, but cannot change these trust boundaries.
    require(len(spec["volumes"]) == len(expected["volumes"]), "Pod volumes changed")
    for volume in expected["volumes"]:
        require(volume in spec["volumes"], "Pod hostPath changed")
    mounts = container.get("volumeMounts", [])
    require(len(mounts) == len(original["volumeMounts"]), "Pod mounts changed")
    for mount in original["volumeMounts"]:
        matches = [v for v in mounts if v["name"] == mount["name"]]
        require(len(matches) == 1 and all(matches[0].get(k) == v for k, v in mount.items()) and
                not any(matches[0].get(k) for k in ("subPath", "subPathExpr")), "Pod binding mount changed")


class Node:
    def __init__(self, args, lock, source=None):
        self.args, self.lock = args, lock
        self.source = source
        self.kube = [args.kubectl, "--context", args.context, "--request-timeout=15s"]
        self.cri = [args.crictl, "--runtime-endpoint", args.cri_endpoint, "--timeout", "15s"]

    def kubectl(self, *argv, **kwargs):
        return command(self.kube + list(argv), **kwargs)

    def preflight(self):
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "requires the selected Linux x86_64 node")
        require(os.geteuid() == 0, "operator-owned Guest execution configuration requires root on the selected node")
        import fcntl
        require(Path("/dev/kvm").exists(), "missing /dev/kvm; x86 hardware execution deferred")
        with open("/dev/kvm", "rb+", buffering=0) as kvm:
            require(fcntl.ioctl(kvm, 0xAE00, 0) == 12, "KVM_GET_API_VERSION failed")
        for name in ARTIFACTS:
            item = self.lock["artifacts"][name]
            require(digest(item["path"]) == item["sha256"], name + " bytes differ from lock")
        for name in ("kata", "qemu"):
            item = self.lock["artifacts"][name]
            observed = command([item["path"], "--version"])
            require(re.search(r"(?<![\d.])" + re.escape(item["version"]) + r"(?![\d.])", observed), name + " version mismatch")
        config = tomllib.loads(Path(self.lock["artifacts"]["kata_config"]["path"]).read_text())
        hypervisor = config.get("hypervisor", {}).get("qemu", {})
        require(config.get("runtime", {}).get("hypervisor_name") == "qemu", "Kata config must select QEMU")
        for key, name in (("path", "qemu"), ("kernel", "guest_kernel"), ("image", "guest_image")):
            require(Path(hypervisor.get(key, "")).resolve() == Path(self.lock["artifacts"][name]["path"]).resolve(),
                    "Kata hypervisor." + key + " differs from lock")
        require(not hypervisor.get("initrd"), "this image profile does not accept an initrd override")
        node = json.loads(self.kubectl("get", "node", self.args.node, "-o", "json"))
        identity = node["status"]["nodeInfo"]
        require(identity.get("bootID") == Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "kubectl node is not this booted node")
        require(identity.get("architecture") == "amd64" and identity.get("operatingSystem") == "linux", "node architecture mismatch")
        require(identity.get("kubeletVersion") == self.lock["kubernetes"]["kubelet_version"], "kubelet version mismatch")
        locked_containerd = containerd_version(self.lock["containerd"]["version"])
        node_runtime = identity.get("containerRuntimeVersion", "")
        require(node_runtime.startswith("containerd://") and
                containerd_version(node_runtime.removeprefix("containerd://")) == locked_containerd,
                "node containerd version mismatch")
        version = json.loads(self.kubectl("version", "-o", "json"))
        require(version["serverVersion"]["gitVersion"] == self.lock["kubernetes"]["server_version"], "API server version mismatch")
        observed_cri = cri_version(command(self.cri + ["version"]))
        require(observed_cri["RuntimeName"] == "containerd" and
                containerd_version(observed_cri["RuntimeVersion"]) == locked_containerd, "CRI version mismatch")
        rc = json.loads(self.kubectl("get", "runtimeclass", self.lock["runtime_class"], "-o", "json"))
        handler = validate_handler(self.lock, rc, json.loads(command(self.cri + ["info", "-o", "json"])))
        self.kubectl("get", "namespace", self.args.namespace, "-o", "name")
        self.observed = {"node_uid": node["metadata"]["uid"], "node_info": identity,
                "runtimeclass_uid": rc["metadata"]["uid"], "handler": handler,
                "cri_version": observed_cri, "kubectl_version": version["clientVersion"]}
        return self.observed

    def sandbox(self, pod):
        rows = json.loads(command(self.cri + ["pods", "-o", "json"]))["items"]
        rows = [r for r in rows if r.get("metadata", {}).get("uid") == pod["metadata"]["uid"]
                and r.get("state") == "SANDBOX_READY"]
        require(len(rows) == 1, "no unique ready CRI sandbox for this Pod UID")
        observed = json.loads(command(self.cri + ["inspectp", "-o", "json", rows[0]["id"]]))
        require(observed.get("status", {}).get("metadata", {}).get("uid") == pod["metadata"]["uid"], "CRI sandbox Pod UID mismatch")
        require(observed.get("status", {}).get("runtimeHandler") == self.lock["runtime_handler"], "live sandbox runtimeHandler missing or wrong")
        return {"sandbox_id": rows[0]["id"], "runtime_handler": observed["status"]["runtimeHandler"]}

    def authorize(self, pod, binding_dir):
        native = self.sandbox(pod)
        containers = [c for c in pod["status"].get("containerStatuses", []) if c["name"] == "fixture"]
        require(len(containers) == 1, "missing unique fixture container")
        container_id = containers[0].get("containerID", "")
        require(re.fullmatch(r"containerd://[a-f0-9]{64}", container_id), "unsupported or missing container identity")
        raw_id = container_id.removeprefix("containerd://")
        container = json.loads(command(self.cri + ["inspect", "-o", "json", raw_id]))
        require(container.get("status", {}).get("id") == raw_id and container.get("info", {}).get("sandboxID") == native["sandbox_id"],
                "CRI container belongs to a different sandbox")
        probe = "from pathlib import Path; print(Path('/proc/sys/kernel/random/boot_id').read_text().strip())"
        boot = self.kubectl("-n", self.args.namespace, "exec", pod["metadata"]["name"], "-c", "fixture", "--", "python3", "-c", probe).strip()
        require(str(uuid.UUID(boot)) == boot and boot != self.observed["node_info"]["bootID"], "invalid Guest boot identity")
        preparation = None
        if getattr(self.args, "mount_guest_tracefs", False):
            preparation = json.loads(self.kubectl("-n", self.args.namespace, "exec", pod["metadata"]["name"],
                "-c", "fixture", "--", "python3", "-c", TRACEFS_PREPARATION, boot,
                self.observed["node_info"]["bootID"], timeout=30))
            require(preparation.get("guest_boot_id") == boot, "Guest preparation identity changed")
        after = json.loads(self.kubectl("-n", self.args.namespace, "get", "pod", pod["metadata"]["name"], "-o", "json"))
        after_containers = [c for c in after["status"].get("containerStatuses", []) if c["name"] == "fixture"]
        require(after["metadata"]["uid"] == pod["metadata"]["uid"] and after["spec"]["nodeName"] == self.args.node and
                len(after_containers) == 1 and after_containers[0].get("containerID") == container_id, "Pod/container changed during Guest observation")
        rc = json.loads(self.kubectl("get", "runtimeclass", self.lock["runtime_class"], "-o", "json"))
        require(rc["metadata"]["uid"] == self.observed["runtimeclass_uid"], "RuntimeClass replaced during binding")
        validate_handler(self.lock, rc, json.loads(command(self.cri + ["info", "-o", "json"])))
        identity = {"runtime_class": self.lock["runtime_class"], "runtime_handler": native["runtime_handler"],
                    "pod_uid": pod["metadata"]["uid"], "container_id": raw_id, "guest_boot_id": boot}
        target = {"producer_id": "kata-acceptance-fixture", "instance_id": identity["pod_uid"], "generation": "g-" + uuid.uuid4().hex}
        config = configuration(target, identity)
        for name in ("executor", "receiver"):
            command([self.args.binary, "forensics", "keygen", "--priv", binding_dir / (name + ".key"),
                     "--pub", binding_dir / (name + ".pub")], env=clean_env())
        save(binding_dir / "execution.json", config)
        if getattr(self.args, "workspace_case", None):
            save(binding_dir / "workspace-target.json", target)
        receipt = {"schema_version": BINDING_SCHEMA, "authority": "operator_kubernetes_cri", "identity": identity,
                   "target": target, "source": self.source, "configuration_sha256": digest(binding_dir / "execution.json"),
                   "lock_sha256": digest(self.args.data_dir / "assets/lock.json"), "binary_sha256": digest(self.args.binary),
                   "control_plane": {"node_uid": self.observed["node_uid"], "node_boot_id": self.observed["node_info"]["bootID"],
                       "runtimeclass_uid": rc["metadata"]["uid"], "namespace": self.args.namespace, "pod_name": pod["metadata"]["name"],
                       "pod_uid": identity["pod_uid"], "container_id": raw_id, "sandbox_id": native["sandbox_id"]},
                   "key_sha256": {name: digest(binding_dir / (name + ".pub")) for name in ("executor", "receiver")}}
        validate_receipt(receipt, (binding_dir / "execution.json").read_bytes(),
                         dict(identity, lock_sha256=receipt["lock_sha256"], binary_sha256=receipt["binary_sha256"]), self.lock)
        # Publish the receipt last; the waiting Guest reads this root-owned, read-only mount.
        for path in binding_dir.iterdir():
            path.chmod(0o400)
        save(binding_dir / "receipt.json", receipt)
        (binding_dir / "receipt.json").chmod(0o400)
        return {**native, "container_ids": [container_id], "operator_receipt": receipt, "guest_preparation": preparation,
                "receipt_sha256": digest(binding_dir / "receipt.json"), "platform_binding": expected_platform(config)}

    def recover_created_uid(self, manifest, report):
        name = manifest["metadata"]["name"]
        owner = manifest["metadata"]["labels"]["agentprov.io/acceptance-owner"]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            raw = self.kubectl("-n", self.args.namespace, "get", "pod", name, "--ignore-not-found", "-o", "json",
                               timeout=max(.1, min(15, deadline - time.monotonic())))
            if raw.strip():
                pod = json.loads(raw)
                metadata = pod["metadata"]
                require(metadata.get("name") == name and metadata.get("namespace") == self.args.namespace and
                        metadata.get("labels", {}).get("agentprov.io/acceptance-owner") == owner,
                        "refuse cleanup: uncertain create resolved to an unowned Pod")
                uid = metadata.get("uid")
                require(isinstance(uid, str) and bool(uid), "uncertain create returned no Pod UID")
                validate_pod(pod, manifest, uid)
                report.update(pod_uid=uid, pod_uid_recovered=True)
                return uid
            time.sleep(.2)
        raise Blocked("Pod creation outcome unresolved after bounded exact-name lookup; retain cleanup ownership record")

    def delete_owned(self, name, uid, owner=None):
        current = json.loads(self.kubectl("-n", self.args.namespace, "get", "pod", name, "-o", "json"))
        require(current["metadata"]["uid"] == uid and current["metadata"].get("labels", {}).get("agentprov.io/acceptance") == name,
                "refuse deletion: Pod ownership changed")
        if owner is not None:
            require(current["metadata"].get("labels", {}).get("agentprov.io/acceptance-owner") == owner,
                    "refuse deletion: Pod creation owner changed")
        # A raw DELETE with UID preconditions prevents a same-name replacement race.
        uri = f"/api/v1/namespaces/{self.args.namespace}/pods/{name}"
        body = json.dumps({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "gracePeriodSeconds": 30})
        self.kubectl("delete", "--raw", uri, "-f", "-", input=body)
        self.kubectl("-n", self.args.namespace, "wait", "--for=delete", "pod/" + name, "--timeout=60s", timeout=75)

    def observe_pod(self, name, deadline, report):
        # Nested VM boot can temporarily starve the local API server. Retry
        # this read only, within the existing stage deadline, and retain each
        # timeout. Creation, execution and deletion are never replayed here.
        for attempt in range(3):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded Pod acceptance exceeded its deadline")
            try:
                return json.loads(self.kubectl("-n", self.args.namespace, "get", "pod", name, "-o", "json",
                                              timeout=min(30, remaining)))
            except subprocess.TimeoutExpired:
                report.setdefault("pod_read_timeouts", []).append({"attempt": attempt + 1, "at_unix": time.time()})
                if attempt == 2 or len(report["pod_read_timeouts"]) >= 6:
                    raise

    def stage(self, manifest, data, report, binding_dir):
        name = manifest["metadata"]["name"]
        owner = manifest["metadata"]["labels"]["agentprov.io/acceptance-owner"]
        uid = None
        report["pod_name"] = name
        report["cleanup_owner"] = owner
        try:
            pod = json.loads(self.kubectl("create", "-f", "-", "-o", "json", input=json.dumps(manifest)))
            uid = pod["metadata"]["uid"]
            report.update({"pod_uid": uid, "pod_name": name, "status": "RUNNING"})
            deadline = time.monotonic() + 690
            bound = False
            while time.monotonic() < deadline:
                pod = self.observe_pod(name, deadline, report)
                validate_pod(pod, manifest, uid)
                report["pod_phase"] = pod["status"]["phase"]
                report["waiting_reasons"] = [c.get("state", {}).get("waiting", {}).get("reason")
                    for c in pod["status"].get("containerStatuses", []) if c.get("state", {}).get("waiting")]
                if pod["status"]["phase"] == "Running" and not bound and any(
                        c.get("containerID") and c.get("state", {}).get("running") for c in pod["status"].get("containerStatuses", []) if c["name"] == "fixture"):
                    report.update(self.authorize(pod, binding_dir))
                    bound = True
                if pod["status"]["phase"] in {"Succeeded", "Failed"}:
                    guest = load(data / "report.json")
                    report["guest"] = guest
                    if bound:
                        require(guest.get("target") == report["operator_receipt"]["target"], "guest target differs from operator-assigned generation")
                        require(guest.get("binding_receipt_sha256") == report["receipt_sha256"], "guest receipt differs from operator bytes")
                        require(guest.get("platform_binding") == report["platform_binding"], "Guest platform binding differs from operator configuration")
                    require(guest.get("checks", {}).get("guest_kernel", {}).get("boot_id") != Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "guest unexpectedly shares the node boot ID")
                    if guest["status"] == "BLOCKED":
                        raise Blocked(guest.get("error", "Guest prerequisite missing"))
                    require(bound, "guest exited before live CRI runtimeHandler validation")
                    if guest["status"] != "PASS" or pod["status"]["phase"] != "Succeeded":
                        raise RuntimeError("Guest acceptance failed; inspect retained guest report")
                    report["status"] = "PASS"
                    return guest
                time.sleep(1)
            raise TimeoutError("bounded Pod acceptance exceeded 690s")
        except Blocked as error:
            report["status"], report["error"] = "BLOCKED", redact(str(error))
            raise
        except Exception as error:
            report["status"], report["error"] = "FAIL", redact(str(error))
            raise
        finally:
            # Evidence is a retained, uniquely owned host directory, never emptyDir.
            with defer_sigterm():
                try:
                    if uid is None:
                        uid = self.recover_created_uid(manifest, report)
                    try:
                        token_path = data / "daemon-token"
                        secrets = (token_path.read_text().strip(),) if token_path.exists() else ()
                        logs = self.kubectl("-n", self.args.namespace, "logs", name, "-c", "fixture",
                                            "--tail=200", "--limit-bytes=65536", timeout=20, secrets=secrets)
                        (data / "pod.log").write_text(redact(logs, secrets))
                        report["pod_log_sha256"] = digest(data / "pod.log")
                    except Exception as error:
                        report["pod_log_error"] = redact(str(error))
                    self.delete_owned(name, uid, owner)
                    report["pod_deleted"] = True
                except Exception as error:
                    report["cleanup_error"] = redact(str(error))
                    raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("preflight", "run"))
    for key in ("binary", "data-dir", "output", "lock"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--verifier", type=Path, help="optional Linux amd64 agentprov-verify, pinned in lock.verifier")
    parser.add_argument("--workspace-case", choices=("contract", "harness"), nargs="?", const="contract",
                        help="optional remote-authoritative MCP/Sensor case in the rebuilt second Guest")
    for key in ("context", "namespace", "node", "cri-endpoint"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--crictl", default="crictl")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-privileged-guest", action="store_true")
    parser.add_argument("--mount-guest-tracefs", action="store_true",
                        help="explicitly mount tracefs inside each owned Guest fixture before publishing its binding")
    parser.add_argument("--stage-guest-binaries", action="store_true",
                        help="copy hash-pinned executables into a private 384 MiB Guest tmpfs for this fixture")
    args = parser.parse_args()
    os.umask(0o077)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": "agentprovenance.kata_acceptance/v1", "status": "BLOCKED", "dry_run": args.dry_run,
              "r03_status": "PENDING", "q01_status": "PENDING",
              "matrix": {k: {"status": "PENDING", "description": v} for k, v in MATRIX.items()}, "stages": [],
              "profile": {"execution_entry": "Pod fixture / existing Guest handoff daemon", "capture_layer": "guest_kernel",
                          "workspace_mode": "command-private workdir; remote-authoritative pending",
                          "browser_attribution": "not exercised", "export_mode": "original signed handoff",
                          "runtimeadapter": "handoff backend.guest with operator binding receipt and signed platform_binding"}}
    exit_code = 2
    terminated = False
    def terminate(signum, frame):
        nonlocal terminated
        if not terminated:
            terminated = True
            raise InterruptedError("acceptance runner received SIGTERM")
    previous_sigterm = signal.signal(signal.SIGTERM, terminate)
    try:
        require(re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", args.namespace), "invalid namespace")
        args.binary = args.binary.resolve(strict=True)
        args.data_dir = args.data_dir.resolve()
        require(args.output != args.data_dir and not args.output.is_relative_to(args.data_dir) and not args.data_dir.is_relative_to(args.output), "data/output must be separate new directories")
        require(not args.data_dir.exists(), "data directory already exists; choose a fresh path")
        lock = load(args.lock)
        report["source"] = {"head": command(["git", "-C", REPO, "rev-parse", "HEAD"]).strip(),
                            "dirty": bool(command(["git", "-C", REPO, "status", "--porcelain", "--untracked-files=normal"]).strip())}
        report["binary_sha256"] = digest(args.binary)
        report["lock_sha256"] = digest(args.lock)
        report["fixture_sha256"] = {str(p.relative_to(REPO)): digest(p) for p in sorted(HERE.glob("*.py"))}
        report["fixture_sha256"].update({p: digest(REPO / p) for p in FIXTURES})
        if args.workspace_case:
            report["fixture_sha256"].update({p: digest(REPO / p) for p in WORKSPACE_INPUTS})
            report["profile"].update(workspace_mode="remote-authoritative", workspace_case=args.workspace_case,
                                     workspace_stage=2, workspace_harness="requested" if args.workspace_case == "harness" else "PENDING")
        report["pipeline_reference_sha256"] = {p: digest(REPO / p) for p in REFERENCED_PIPELINE}
        report["lock_issues"] = lock_issues(lock)
        report["lock_issues"] += option_issues(args.workspace_case, lock, args.verifier)
        save(args.output / "lock.json", lock)
        name = "ap-kata-" + uuid.uuid4().hex[:12]
        save(args.output / "pod-plan.json", pod_manifest(args, lock, name, args.data_dir / "assets", args.data_dir / "boot-1",
                                                       workspace_case=args.workspace_case))
        save(args.output / "runtimeclass-reference.json", {"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
             "metadata": {"name": "kata-qemu-runtime-rs"}, "handler": "kata-qemu-runtime-rs"})
        require(not report["lock_issues"], "incomplete lock: " + ", ".join(report["lock_issues"]))
        require(report["binary_sha256"] == lock["sensor"]["sha256"], "agentprov/embedded sensor hash mismatch")
        if args.verifier:
            args.verifier = args.verifier.resolve(strict=True)
            report["verifier_sha256"] = digest(args.verifier)
            require(report["verifier_sha256"] == lock.get("verifier", {}).get("sha256"), "agentprov-verify hash missing or mismatched")
            require(bool(lock["verifier"].get("version")) and re.fullmatch(r"[a-f0-9]{40}", lock["verifier"].get("source_sha") or ""),
                    "agentprov-verify version/source_sha must be pinned")
        if args.dry_run:
            report["status"] = "PENDING"
            exit_code = 0
            return exit_code
        node = Node(args, lock, report["source"])
        report["preflight"] = node.preflight()
        report["preflight"]["status"] = "PASS"
        if args.phase == "preflight":
            report["status"] = "PENDING"
            return 0
        require(args.allow_privileged_guest, "run requires --allow-privileged-guest after reviewing the Pod plan")
        args.data_dir.mkdir(parents=True, exist_ok=False)
        assets = args.data_dir / "assets"
        assets.mkdir()
        for file in (HERE / "common.py", HERE / "binding.py", HERE / "reader.py", HERE / "workspace_case.py", HERE / "staging.py", HERE / "guest.py", *(REPO / p for p in FIXTURES)):
            shutil.copyfile(file, assets / file.name)
            require(digest(assets / file.name) == report["fixture_sha256"][str(file.relative_to(REPO))], "fixture changed during preflight")
        if args.workspace_case:
            for relative in WORKSPACE_INPUTS:
                destination = assets / (Path(relative).name if relative.startswith("scripts/") else relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPO / relative, destination)
                require(digest(destination) == report["fixture_sha256"][relative], "workspace fixture changed during preflight")
        shutil.copyfile(args.binary, assets / "agentprov")
        require(digest(assets / "agentprov") == lock["sensor"]["sha256"], "binary changed during preflight")
        (assets / "agentprov").chmod(0o500)
        if args.verifier:
            shutil.copyfile(args.verifier, assets / "agentprov-verify")
            require(digest(assets / "agentprov-verify") == lock["verifier"]["sha256"], "verifier changed during preflight")
            (assets / "agentprov-verify").chmod(0o500)
        save(assets / "lock.json", lock)
        previous = None
        for index in (1, 2):
            data = args.data_dir / f"boot-{index}"
            data.mkdir()
            binding_dir = args.data_dir / f"binding-{index}"
            binding_dir.mkdir(mode=0o700)
            stage = {"index": index, "evidence_directory": str(data)}
            report["stages"].append(stage)
            manifest = pod_manifest(args, lock, name, assets, data, previous, binding_dir,
                                    workspace_case=args.workspace_case if index == 2 else None)
            save(args.output / f"pod-{index}.json", manifest)
            guest = node.stage(manifest, data, stage, binding_dir)
            previous = guest["target"]
            required_checks = ("guest_kernel", "single_delivery", "concurrent_isolation", "recovery", "offline_delivery", "runtimeadapter_binding")
            for key in required_checks:
                require(guest["checks"][key]["status"] == "PASS", "missing real Guest check: " + key)
            if args.verifier:
                require(guest["checks"]["derived_verifier"]["status"] == "PASS", "standalone reader verifier did not pass")
        first, second = report["stages"]
        require(first["pod_uid"] != second["pod_uid"] and set(first["container_ids"]).isdisjoint(second["container_ids"]), "Pod rebuild reused native identity")
        require(first["guest"]["checks"]["guest_kernel"]["boot_id"] != second["guest"]["checks"]["guest_kernel"]["boot_id"], "Pod rebuild reused guest boot")
        require(first["guest"]["target"]["generation"] != second["guest"]["target"]["generation"], "Pod rebuild reused executor generation")
        require(second["guest"]["checks"]["stale_target"]["status"] == "PASS", "stale generation was not rejected")
        for key in required_checks:
            report["matrix"][key]["status"] = "PASS"
        if args.verifier:
            report["matrix"]["derived_verifier"]["status"] = "PASS"
        report["matrix"]["pod_rebuild"]["status"] = "PASS"
        if args.workspace_case:
            workspace = second["guest"]["checks"].get("workspace_case", {})
            require(workspace.get("status") == "PASS" and workspace.get("target") == second["guest"]["target"],
                    "optional workspace case failed or used another Guest generation")
            report["matrix"]["workspace_case"].update(status=workspace["matrix_status"], mode=args.workspace_case,
                                                        contract="PASS", harness=workspace["harness"])
        report["r03_status"], report["status"], exit_code = "PASS", "PENDING", 0
        report["pending_release_checks"] = [key for key, value in report["matrix"].items() if value["status"] == "PENDING"]
    except InterruptedError as error:
        report["status"], report["error"], report["interrupted_signal"], exit_code = "FAIL", redact(str(error)), "SIGTERM", 143
    except (Blocked, FileNotFoundError, PermissionError) as error:
        report["error"] = redact(str(error))
    except Exception as error:
        report["status"], report["error"], exit_code = "FAIL", redact(str(error)), 1
    finally:
        try:
            save(args.output / "report.json", report)
            print(json.dumps({"status": report["status"], "report": str(args.output / "report.json")}))
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
