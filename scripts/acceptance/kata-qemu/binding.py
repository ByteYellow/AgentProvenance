"""Operator receipt checks for the real handoff backend.guest configuration."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from common import require


SCHEMA = "agentprovenance.kata_binding_receipt/v1"
GUEST_FIELDS = ("runtime_class", "runtime_handler", "pod_uid", "container_id", "guest_boot_id")


def trusted_read(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "binding path must be clean and absolute")
    for entry in (path, *path.parents):
        info = entry.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode),
                "binding files and ancestors must be root-owned, non-writable and non-symlink")
        require(stat.S_ISREG(info.st_mode) if entry == path else stat.S_ISDIR(info.st_mode), "invalid binding path type")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022, "untrusted binding descriptor")
        raw = stream.read(65537)
    require(len(raw) <= 65536, "binding document exceeds 64 KiB")
    return raw


def configuration(target, identity, *, apparmor_state=True):
    return {
        "target": target,
        "backend": {"mode": "guest", "guest": {key: identity[key] for key in GUEST_FIELDS}},
        "caller": {"principal_id": "fixture-router", "producer_id": "fixture-caller", "namespace": "fixture"},
        "concurrency": 2,
        # Fixed resource profile for the 2 GiB nested Guest. Map allocation is
        # part of startup; readiness and zero-loss/drain checks remain required.
        "capture": {"mode": "native", "placement": "guest_kernel", "auto_tls": False, "no_policy": True,
                    "ring_buffer_mib": 4, "startup_timeout_seconds": 120,
                    "apparmor_state": apparmor_state, "seccomp_state": True},
        "delivery": {"receiver_id": "fixture-receiver", "sign_key_file": "/binding/executor.key",
                     "receiver_public_key_file": "/binding/receiver.pub"},
    }


def validate_receipt(receipt, config_raw, observed, lock):
    require(receipt.get("schema_version") == SCHEMA, "unsupported binding receipt schema")
    require(receipt.get("authority") == "operator_kubernetes_cri", "binding requires operator API/CRI authority")
    require(hashlib.sha256(config_raw).hexdigest() == receipt.get("configuration_sha256"), "operator execution config digest mismatch")
    config = json.loads(config_raw)
    require(config.get("target") == receipt.get("target"), "operator target generation or identity mismatch")
    target = config["target"]
    require(set(target) == {"producer_id", "instance_id", "generation"} and
            all(isinstance(v, str) and v.strip() == v and 0 < len(v) <= 512 for v in target.values()), "incomplete operator Target")
    identity = receipt.get("identity", {})
    require(all(isinstance(identity.get(key), str) and identity[key] for key in GUEST_FIELDS), "incomplete Guest binding")
    require(config.get("backend") == {"mode": "guest", "guest": {key: identity[key] for key in GUEST_FIELDS}},
            "execution backend.guest differs from operator receipt")
    require(config.get("capture", {}).get("mode") == "native" and config["capture"].get("placement") == "guest_kernel",
            "bound Guest requires native guest_kernel capture")
    require(config["capture"].get("apparmor_state", True) is lock.get("capture", {}).get("apparmor_state", True) and
            config["capture"].get("seccomp_state", True) is True,
            "bound Guest state sampling differs from the pinned capture profile")
    for key in ("runtime_class", "runtime_handler"):
        require(identity[key] == lock[key], "binding " + key + " differs from runtime lock")
    require(re.fullmatch(r"[a-f0-9]{64}", identity["container_id"]), "binding requires the raw CRI container ID")
    for key in ("pod_uid", "guest_boot_id"):
        require(identity[key] == observed.get(key), "observed " + key + " differs from operator binding")
    require(observed.get("lock_sha256") == receipt.get("lock_sha256"), "binding lock digest mismatch")
    require(observed.get("binary_sha256") == receipt.get("binary_sha256"), "binding executable digest mismatch")
    return config


def expected_platform(config):
    return {"target": config["target"], "mode": "guest", **config["backend"]["guest"]}


def validate_checkpoint(checkpoint, config):
    platform = expected_platform(config)
    if checkpoint.get("target") != config["target"] or checkpoint.get("platform_binding") != platform:
        raise RuntimeError("checkpoint platform binding differs from operator-authorized Guest/Target")
    runtime = checkpoint.get("runtime_report", {})
    if runtime.get("execution", {}).get("binding") != platform or runtime.get("capture") is not None:
        raise RuntimeError("Guest runtime projection lost its binding or replaced native capture")


def rejection_checks(receipt, raw, observed, lock):
    from common import Blocked
    checks = []
    for field in ("pod_uid", "guest_boot_id"):
        changed = dict(observed, **{field: "mismatch-" + observed[field]})
        try:
            validate_receipt(receipt, raw, changed, lock)
        except Blocked:
            checks.append("observed_" + field + "_rejected")
        else:
            raise RuntimeError("binding accepted mismatched " + field)
    for field in ("instance_id", "generation"):
        changed = json.loads(raw)
        changed["target"][field] += "-mismatch"
        changed_raw = json.dumps(changed).encode()
        same_receipt = dict(receipt, configuration_sha256=hashlib.sha256(changed_raw).hexdigest())
        try:
            validate_receipt(same_receipt, changed_raw, observed, lock)
        except Blocked:
            checks.append("target_" + field + "_rejected")
        else:
            raise RuntimeError("binding accepted mismatched target " + field)
    return checks
