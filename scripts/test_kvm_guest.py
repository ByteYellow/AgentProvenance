import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from accept_kvm_guest import export_signed_replay


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
