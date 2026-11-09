import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from accept_kvm_guest import export_signed_replay, validate_guest_cpu, validate_guest_platform


class GuestPlatformTest(unittest.TestCase):
    def test_qemu_whpx_keeps_microsoft_cpuid(self):
        validate_guest_platform("microsoft", "QEMU")
        validate_guest_platform("kvm", "")
        validate_guest_platform("qemu", "QEMU")

    def test_microsoft_without_qemu_dmi_is_not_the_lab_guest(self):
        for vendor in ("", "Microsoft Corporation", "Dell Inc."):
            with self.assertRaises(SystemExit):
                validate_guest_platform("microsoft", vendor)


class GuestCPUTest(unittest.TestCase):
    def test_cet_without_xsave_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "cold boot with -cpu max"):
            validate_guest_cpu("x86_64", "flags\t: fpu sse2 user_shstk\n")

    def test_cet_without_supervisor_state_save_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "xsaves is missing"):
            validate_guest_cpu("x86_64", "flags : fpu xsave user_shstk\n")

    def test_every_cpu_is_checked(self):
        with self.assertRaisesRegex(SystemExit, "CPU 1"):
            validate_guest_cpu("x86_64", "flags : xsave xsaves user_shstk\n"
                              "flags : fpu user_shstk\n")

    def test_consistent_cet_is_recorded(self):
        result = validate_guest_cpu("x86_64", "flags : fpu xsave xsaves user_shstk\n")
        self.assertEqual(result["x86_cet_check"], "passed")
        self.assertIn("user_shstk", result["common_flags"])

    def test_guest_without_cet_remains_supported(self):
        self.assertEqual(validate_guest_cpu("x86_64", "flags : fpu sse2\n")
                         ["x86_cet_check"], "passed")

    def test_missing_x86_flags_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "cannot inspect"):
            validate_guest_cpu("x86_64", "processor : 0\n")

    def test_arm_is_not_subject_to_x86_check(self):
        self.assertEqual(validate_guest_cpu("aarch64", "Features : fp asimd\n")
                         ["x86_cet_check"], "not_applicable")


class SignedReplayTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("AGENTPROV_TEST_BINARY"), "set AGENTPROV_TEST_BINARY to run the CLI roundtrip")
    def test_signed_bundle_handoff(self):
        binary = str(Path(os.environ["AGENTPROV_TEST_BINARY"]).resolve())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            base = [binary, "--data-dir", str(root / "capture")]
            run = "run-signed-handoff"
            subprocess.run(base + ["record", "--run", run, "--workdir", str(workspace),
                "--", "true"], check=True, stdout=subprocess.DEVNULL)
            bundle, attestation, public_key, replay, imported = export_signed_replay(
                base, run, root / "report.json", directory)
            self.assertEqual(imported["run_id"], run)
            self.assertTrue(imported["attestation_verified"])
            self.assertEqual(imported["attestation_status"], "verified")
            self.assertTrue(attestation.is_file())
            self.assertTrue(public_key.is_file())
            result = json.loads(subprocess.check_output(replay + ["graph", "verify", "--run", run,
                "--json"], text=True))
            self.assertEqual(result["error_count"], 0)
            bundle.write_bytes(bundle.read_bytes() + b"\n")
            tampered = subprocess.run(replay + ["forensics", "import", str(bundle),
                "--pub-key", str(public_key), "--json"], capture_output=True, text=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("attestation verify failed", tampered.stderr)


if __name__ == "__main__":
    unittest.main()
