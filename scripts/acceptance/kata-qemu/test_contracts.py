"""Local contracts only. No Kubernetes, KVM, Sensor or hardware PASS is simulated."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import common
import binding
import guest
import run


def pinned():
    lock = common.load(run.HERE / "versions.lock.json")
    for item in lock["artifacts"].values():
        item["version"] = "4.2.0-measured"
        item["sha256"] = "a" * 64
    lock["artifacts"]["kata"]["source_sha"] = "f" * 40
    lock["artifacts"]["guest_kernel"].update(release="6.18.56-test", btf_sha256="b" * 64)
    lock["sensor"].update(version="1.0-test", source_sha="c" * 40, sha256="d" * 64)
    lock["kubernetes"].update(server_version="v1.36.1", kubelet_version="v1.36.1")
    lock["containerd"]["version"] = "2.3.0"
    lock["workload_image"] = "example.invalid/fixture@sha256:" + "e" * 64
    return lock


def cri(lock):
    return {"config": {"containerd": {"runtimes": {lock["runtime_handler"]: {
        "runtimeType": lock["runtime_type"], "runtimePath": lock["artifacts"]["kata"]["path"],
        "options": {"ConfigPath": lock["artifacts"]["kata_config"]["path"]},
        "privileged_without_host_devices": True}}}}}


class LockTests(unittest.TestCase):
    def test_shipped_lock_requires_real_inventory(self):
        missing = run.lock_issues(common.load(run.HERE / "versions.lock.json"))
        self.assertIn("kata.sha256", missing)
        self.assertIn("guest_kernel.btf_sha256", missing)
        self.assertIn("sensor.source_sha", missing)
        self.assertIn("workload_image", missing)

    def test_complete_contract(self):
        self.assertEqual(run.lock_issues(pinned()), [])

    def test_measured_versions_do_not_require_candidate_reinstall(self):
        lock = pinned()
        for name, version in (("kata", "3.28.0"), ("qemu", "9.2.0"), ("guest_kernel", "6.12.76")):
            lock["artifacts"][name]["version"] = version
        self.assertEqual(run.lock_issues(lock), [])

    def test_unpinned_values_rejected(self):
        for name in run.ARTIFACTS:
            lock = pinned()
            lock["artifacts"][name]["sha256"] = None
            self.assertIn(name + ".sha256", run.lock_issues(lock))
        lock = pinned()
        lock["workload_image"] = "ubuntu:latest"
        self.assertIn("workload_image", run.lock_issues(lock))

    def test_go_runtime_cannot_enter_profile(self):
        lock = pinned()
        lock["runtime_handler"] = "kata-qemu"
        self.assertIn("runtime_handler", run.lock_issues(lock))


class RuntimeTests(unittest.TestCase):
    def test_crictl_version_uses_real_text_contract(self):
        result = run.cri_version("Version:  0.1.0\nRuntimeName:  containerd\nRuntimeVersion:  2.3.0\nRuntimeApiVersion:  v1\n")
        self.assertEqual(result["RuntimeVersion"], "2.3.0")
        with self.assertRaises(common.Blocked):
            run.cri_version("Usage: crictl version")
        with self.assertRaises(common.Blocked):
            run.cri_version("RuntimeName: containerd\nRuntimeName: other")

    def test_trusted_cri_handler(self):
        lock = pinned()
        result = run.validate_handler(lock, {"handler": lock["runtime_handler"]}, cri(lock))
        self.assertEqual(result["runtime_type"], lock["runtime_type"])

    def test_labels_do_not_authorize_handler(self):
        lock = pinned()
        with self.assertRaises(common.Blocked):
            run.validate_handler(lock, {"handler": "runc", "metadata": {"labels": {"runtime": "kata"}}}, cri(lock))

    def test_live_runtime_path_and_configuration_must_match(self):
        lock = pinned()
        for key, value in (("runtimeType", "io.containerd.runc.v2"), ("runtimePath", "/bin/runc"),
                           ("options", {"ConfigPath": "/other.toml"}), ("privileged_without_host_devices", False)):
            info = cri(lock)
            info["config"]["containerd"]["runtimes"][lock["runtime_handler"]][key] = value
            with self.assertRaises(common.Blocked):
                run.validate_handler(lock, {"handler": lock["runtime_handler"]}, info)

    def test_manifest_has_no_host_namespace_or_policy_override(self):
        args = argparse.Namespace(namespace="fixture", node="node-1")
        manifest = run.pod_manifest(args, pinned(), "ap-test", Path("/private/assets"), Path("/private/data"))
        spec = manifest["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["runtimeClassName"], "kata-qemu-runtime-rs")
        self.assertEqual(spec["activeDeadlineSeconds"], 720)
        self.assertEqual(spec["containers"][0]["imagePullPolicy"], "Never")
        self.assertNotIn("hostPID", spec)
        self.assertNotIn("hostNetwork", spec)
        self.assertNotIn("annotations", manifest["metadata"])
        self.assertEqual([v["hostPath"]["path"] for v in spec["volumes"]],
                         ["/private/assets", "/private/binding-1", "/private/data"])
        control = next(v for v in spec["containers"][0]["volumeMounts"] if v["name"] == "binding")
        self.assertTrue(control["readOnly"])
        self.assertEqual(control["mountPath"], "/binding")

    def test_mutated_pod_cannot_change_binding_mount(self):
        args = argparse.Namespace(namespace="fixture", node="node-1")
        plan = run.pod_manifest(args, pinned(), "ap-test", Path("/private/assets"), Path("/private/data"))
        pod = copy.deepcopy(plan)
        pod["metadata"]["uid"] = "owned"
        run.validate_pod(pod, plan, "owned")
        pod["spec"]["containers"][0]["volumeMounts"][1]["readOnly"] = False
        with self.assertRaises(common.Blocked):
            run.validate_pod(pod, plan, "owned")
        pod = copy.deepcopy(plan)
        pod["metadata"]["uid"] = "replaced"
        with self.assertRaises(common.Blocked):
            run.validate_pod(pod, plan, "owned")

    def test_mutated_pod_cannot_supply_target_as_label(self):
        args = argparse.Namespace(namespace="fixture", node="node-1")
        plan = run.pod_manifest(args, pinned(), "ap-test", Path("/private/assets"), Path("/private/data"))
        pod = copy.deepcopy(plan)
        pod["metadata"].update(uid="owned", labels={"generation": "trusted"})
        pod["spec"]["runtimeClassName"] = "runc"
        with self.assertRaises(common.Blocked):
            run.validate_pod(pod, plan, "owned")

    def test_pod_annotations_cannot_override_pinned_kernel(self):
        args = argparse.Namespace(namespace="fixture", node="node-1")
        plan = run.pod_manifest(args, pinned(), "ap-test", Path("/private/assets"), Path("/private/data"))
        pod = copy.deepcopy(plan)
        pod["metadata"].update(uid="owned", annotations={"io.katacontainers.config.hypervisor.kernel": "/different/kernel"})
        with self.assertRaises(common.Blocked):
            run.validate_pod(pod, plan, "owned")

    def test_cleanup_rejects_replaced_uid(self):
        args = argparse.Namespace(kubectl="kubectl", context="test", crictl="crictl", cri_endpoint="unix:///run/test.sock", namespace="fixture")
        node = run.Node(args, pinned())
        with patch.object(node, "kubectl", return_value=json.dumps({"metadata": {"uid": "replacement"}})) as kube:
            with self.assertRaises(common.Blocked):
                node.delete_owned("ap-test", "original")
            self.assertEqual(kube.call_count, 1)

    def test_cleanup_has_atomic_uid_precondition(self):
        args = argparse.Namespace(kubectl="kubectl", context="test", crictl="crictl", cri_endpoint="unix:///run/test.sock", namespace="fixture")
        node = run.Node(args, pinned())
        current = {"metadata": {"uid": "owned", "labels": {"agentprov.io/acceptance": "ap-test"}}}
        with patch.object(node, "kubectl", side_effect=[json.dumps(current), "", ""]) as kube:
            node.delete_owned("ap-test", "owned")
            deletion = kube.call_args_list[1]
            self.assertEqual(json.loads(deletion.kwargs["input"])["preconditions"], {"uid": "owned"})
            self.assertIn("--raw", deletion.args)


class OperatorBindingContracts(unittest.TestCase):
    def authorize(self, temporary, mismatch=None):
        root = Path(temporary)
        (root / "assets").mkdir()
        (root / "binding").mkdir()
        common.save(root / "assets/lock.json", pinned())
        (root / "agentprov").write_bytes(b"contract-only fixture binary")
        args = argparse.Namespace(kubectl="kubectl", context="test", crictl="crictl", cri_endpoint="unix:///run/test.sock",
                                  namespace="fixture", node="node-1", binary=root / "agentprov", data_dir=root)
        node = run.Node(args, pinned(), {"head": "c" * 40, "dirty": True})
        node.observed = {"node_uid": "node-uid", "node_info": {"bootID": "node-boot"}, "runtimeclass_uid": "rc-1"}
        pod = {"metadata": {"name": "ap-test", "uid": "pod-1", "labels": {"generation": "untrusted-label"}},
               "spec": {"nodeName": "node-1"},
               "status": {"containerStatuses": [{"name": "fixture", "containerID": "containerd://" + "a" * 64}]}}
        keygens = []
        def cli(argv, **kwargs):
            if argv[0] == args.binary:
                keygens.append(argv)
                Path(argv[argv.index("--pub") + 1]).write_bytes(b"fixture public key")
                Path(argv[argv.index("--priv") + 1]).write_bytes(b"fixture private key")
                return ""
            operation = argv[len(node.cri)]
            if operation == "pods":
                return json.dumps({"items": [{"metadata": {"uid": "pod-1"}, "id": "sandbox-1", "state": "SANDBOX_READY"}]})
            if operation == "inspectp":
                return json.dumps({"status": {"metadata": {"uid": "wrong" if mismatch == "sandbox-pod" else "pod-1"},
                                              "runtimeHandler": "kata-qemu-runtime-rs"}})
            if operation == "inspect":
                return json.dumps({"status": {"id": "a" * 64}, "info": {"sandboxID": "wrong" if mismatch == "container" else "sandbox-1"}})
            if operation == "info":
                return json.dumps(cri(pinned()))
            raise AssertionError(argv)
        def kube(*argv, **kwargs):
            if "exec" in argv:
                return "a4e66e5f-d280-4d9d-ae8f-7c88d710efb6\n"
            if "pod" in argv:
                changed = copy.deepcopy(pod)
                if mismatch == "pod-replaced":
                    changed["metadata"]["uid"] = "wrong"
                return json.dumps(changed)
            if "runtimeclass" in argv:
                return json.dumps({"metadata": {"uid": "wrong" if mismatch == "class-replaced" else "rc-1"},
                                   "handler": "kata-qemu-runtime-rs"})
            raise AssertionError(argv)
        with patch.object(run, "command", side_effect=cli), patch.object(node, "kubectl", side_effect=kube):
            if mismatch:
                with self.assertRaises(common.Blocked):
                    node.authorize(pod, root / "binding")
                self.assertFalse(keygens)
                self.assertFalse((root / "binding/receipt.json").exists())
            else:
                result = node.authorize(pod, root / "binding")
                receipt = common.load(root / "binding/receipt.json")
                self.assertEqual(receipt, result["operator_receipt"])
                self.assertEqual(receipt["identity"]["pod_uid"], "pod-1")
                self.assertEqual(receipt["identity"]["container_id"], "a" * 64)
                self.assertNotIn(receipt["target"]["generation"], {"pod-1", "untrusted-label"})
                self.assertRegex(receipt["target"]["generation"], r"^g-[a-f0-9]{32}$")
                self.assertEqual(len(keygens), 2)
                self.assertTrue(all(p.stat().st_mode & 0o777 == 0o400 for p in (root / "binding").iterdir()))

    def test_operator_joins_native_identity_before_publishing(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.authorize(temporary)

    def test_mismatched_native_identity_cannot_publish(self):
        for field in ("sandbox-pod", "container", "pod-replaced", "class-replaced"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                self.authorize(temporary, field)


class BindingContracts(unittest.TestCase):
    def setUp(self):
        self.lock = pinned()
        self.identity = {"runtime_class": self.lock["runtime_class"], "runtime_handler": self.lock["runtime_handler"],
                         "pod_uid": "pod-1", "container_id": "a" * 64, "guest_boot_id": "boot-1"}
        self.target = {"producer_id": "fixture", "instance_id": "pod-1", "generation": "operator-generation-1"}
        self.config = binding.configuration(self.target, self.identity)
        self.raw = json.dumps(self.config).encode()
        self.observed = dict(self.identity, lock_sha256="b" * 64, binary_sha256="c" * 64)
        self.receipt = {"schema_version": binding.SCHEMA, "authority": "operator_kubernetes_cri",
                        "configuration_sha256": hashlib.sha256(self.raw).hexdigest(), "identity": self.identity,
                        "target": self.target, "lock_sha256": "b" * 64, "binary_sha256": "c" * 64}

    def test_actual_guest_config_and_independent_target_generation(self):
        result = binding.validate_receipt(self.receipt, self.raw, self.observed, self.lock)
        self.assertEqual(result["backend"], {"mode": "guest", "guest": self.identity})
        self.assertNotEqual(result["target"]["generation"], result["backend"]["guest"]["pod_uid"])

    def test_pod_boot_and_target_rejection_contract(self):
        self.assertEqual(binding.rejection_checks(self.receipt, self.raw, self.observed, self.lock),
                         ["observed_pod_uid_rejected", "observed_guest_boot_id_rejected",
                          "target_instance_id_rejected", "target_generation_rejected"])

    def test_labels_do_not_authorize_receipt(self):
        self.receipt["authority"] = "pod_labels"
        with self.assertRaises(common.Blocked):
            binding.validate_receipt(self.receipt, self.raw, self.observed, self.lock)

    def test_changed_receipt_native_fields_rejected(self):
        for key in binding.GUEST_FIELDS:
            receipt = copy.deepcopy(self.receipt)
            receipt["identity"][key] += "-different"
            with self.subTest(field=key), self.assertRaises(common.Blocked):
                binding.validate_receipt(receipt, self.raw, self.observed, self.lock)

    def test_changed_binary_or_lock_rejected(self):
        for field in ("binary_sha256", "lock_sha256"):
            with self.subTest(field=field), self.assertRaises(common.Blocked):
                binding.validate_receipt(self.receipt, self.raw, dict(self.observed, **{field: "d" * 64}), self.lock)

    def test_checkpoint_both_projections_match(self):
        platform = binding.expected_platform(self.config)
        checkpoint = {"target": self.target, "platform_binding": platform,
                      "runtime_report": {"execution": {"binding": copy.deepcopy(platform)}}}
        binding.validate_checkpoint(checkpoint, self.config)
        checkpoint["runtime_report"]["execution"]["binding"]["target"]["generation"] = "wrong"
        with self.assertRaises(RuntimeError):
            binding.validate_checkpoint(checkpoint, self.config)
        checkpoint["runtime_report"]["execution"]["binding"] = platform
        checkpoint["platform_binding"] = dict(platform, pod_uid="wrong")
        with self.assertRaises(RuntimeError):
            binding.validate_checkpoint(checkpoint, self.config)

    def test_trusted_path_rejects_symlink_and_writable_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            document = Path(temporary) / "receipt.json"
            document.write_bytes(self.raw)
            document.chmod(0o666)
            with self.assertRaises(common.Blocked):
                binding.trusted_read(document)
            link = Path(temporary) / "link.json"
            link.symlink_to(document)
            with self.assertRaises(common.Blocked):
                binding.trusted_read(link)


class GuestContracts(unittest.TestCase):
    def test_delivery_prelude_is_explicit_and_leaves_source_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = guest.Guest.__new__(guest.Guest)
            value.root, value.env, value.token, value.report = Path(temporary), {}, "fixture-token", {}
            with patch.object(guest, "command", return_value="{}") as execute:
                value.fixture("accept_execution_delivery.py", ["--url", "http://127.0.0.1:1"], 30)
            args = execute.call_args.args[0]
            self.assertEqual(args[1], "-c")
            compile(args[2], "<delivery-wrapper>", "exec")
            self.assertEqual(value.report["delivery_task_prelude"], "import time; time.sleep(2)\n")

    def test_logical_capture_is_rejected(self):
        report = {"attempt": {"state": {"capture": "sealed"}}, "checkpoint": {"scope": {"scope_kind": "logical", "cgroup_id": "12"}}}
        with self.assertRaises(RuntimeError):
            guest.validate_capture(report)

    def test_incomplete_capture_is_not_pass(self):
        report = {"attempt": {"state": {"capture": "incomplete"}}, "checkpoint": {}}
        with self.assertRaises(RuntimeError):
            guest.validate_capture(report)

    def test_recovery_preserves_unknown(self):
        report = {"attempt": {"state": {"execution": "unknown", "capture": "incomplete"}},
                  "checkpoint": {"stdout": {"state": "unknown"}, "stderr": {"state": "unknown"}}}
        replay = {"attempt": {"id": "attempt"}, "reused": True}
        guest.validate_recovery(report, replay, "attempt")
        for axis, value in (("execution", "succeeded"), ("capture", "sealed")):
            changed = copy.deepcopy(report)
            changed["attempt"]["state"][axis] = value
            with self.assertRaises(RuntimeError):
                guest.validate_recovery(changed, replay, "attempt")
        with self.assertRaises(RuntimeError):
            guest.validate_recovery(report, {"attempt": {"id": "new"}, "reused": False}, "attempt")


class SafetyTests(unittest.TestCase):
    def test_bilingual_document_links(self):
        for relative in ("docs/validation/kata-qemu.md", "docs/zh-CN/validation/kata-qemu.md"):
            document = run.REPO / relative
            for link in re.findall(r"\]\(([^)]+)\)", document.read_text()):
                if not link.startswith("https://"):
                    self.assertTrue((document.parent / link).resolve().exists(), (relative, link))

    def test_redaction(self):
        raw = 'Authorization: Bearer abc.def\nhttps://user:pass@host/path?token=credential\npassword=secret\nknown-token'
        result = common.redact(raw, ("known-token",))
        for value in ("abc.def", "user:pass", "credential", "=secret", "known-token"):
            self.assertNotIn(value, result)

    def test_inventory_excludes_keys_and_tokens(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("executor.key", "daemon-token", "bundle.json", "executor.pub"):
                (root / name).write_text("fixture")
            self.assertEqual(set(common.artifact_inventory(root)), {"bundle.json", "executor.pub"})

    def test_owned_process_deadline(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            common.command([sys.executable, "-c", "import time; time.sleep(20)"], timeout=0.05)

    def test_dry_run_never_contacts_cluster(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "agentprov"
            binary.write_bytes(b"contract-only; not an executable")
            out = root / "report"
            argv = [sys.executable, str(run.HERE / "run.py"), "run", "--dry-run", "--binary", str(binary),
                    "--data-dir", str(root / "data"), "--output", str(out), "--lock", str(run.HERE / "versions.lock.json"),
                    "--context", "unused", "--namespace", "fixture", "--node", "unused", "--cri-endpoint", "unix:///unused",
                    "--kubectl", "/must-not-execute-kubectl", "--crictl", "/must-not-execute-crictl"]
            result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = common.load(out / "report.json")
            self.assertEqual(report["status"], "BLOCKED")
            self.assertTrue(all(v["status"] == "PENDING" for v in report["matrix"].values()))
            self.assertFalse((root / "data").exists())
            self.assertIn("scripts/accept_execution_handoff.py", report["fixture_sha256"])

    def test_complete_dry_run_still_leaves_hardware_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "agentprov"
            binary.write_bytes(b"not executable")
            lock = pinned()
            lock["sensor"]["sha256"] = common.digest(binary)
            common.save(root / "lock.json", lock)
            argv = ["run.py", "preflight", "--dry-run", "--binary", str(binary), "--data-dir", str(root / "data"),
                    "--output", str(root / "report"), "--lock", str(root / "lock.json"), "--context", "unused",
                    "--namespace", "fixture", "--node", "unused", "--cri-endpoint", "unix:///unused"]
            with patch.object(sys, "argv", argv), patch.object(run.Node, "preflight", side_effect=AssertionError("must not probe")):
                self.assertEqual(run.main(), 0)
            self.assertEqual(common.load(root / "report/report.json")["status"], "PENDING")


if __name__ == "__main__":
    unittest.main()
