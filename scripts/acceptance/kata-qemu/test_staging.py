"""Byte integrity/ownership contracts; no mount or hardware result is simulated."""
import argparse
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import Blocked
import run
import staging
from test_contracts import pinned


class StagingTests(unittest.TestCase):
    def test_copy_checks_actual_bytes_before_enabling_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "source", Path(tmp) / "target"
            source.write_bytes(b"pinned executable")
            with patch.object(staging, "trusted_source"):
                with self.assertRaises(Blocked):
                    staging.copy_pinned(source, target, "0" * 64)
                self.assertFalse(target.exists())
                sha = hashlib.sha256(source.read_bytes()).hexdigest()
                result = staging.copy_pinned(source, target, sha)
                self.assertEqual(target.read_bytes(), source.read_bytes())
                self.assertEqual(target.stat().st_mode & 0o777, 0o500)
                self.assertEqual(result["sha256"], sha)

    def test_existing_destination_and_source_symlink_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target, link = (Path(tmp) / name for name in ("source", "target", "link"))
            source.write_bytes(b"source")
            target.write_bytes(b"previous")
            link.symlink_to(source)
            with patch.object(staging, "trusted_source"):
                with self.assertRaises(FileExistsError):
                    staging.copy_pinned(source, target, "0" * 64)
                self.assertEqual(target.read_bytes(), b"previous")
                with self.assertRaises(OSError):
                    staging.copy_pinned(link, Path(tmp) / "new", "0" * 64)
            with self.assertRaises(Blocked):
                staging.trusted_source(link)

    def test_manifest_requires_explicit_option_and_keeps_deadlines(self):
        args = argparse.Namespace(namespace="fixture", node="node-1")
        def manifest():
            return run.pod_manifest(args, pinned(), "ap-test", Path("/private/assets"), Path("/private/data"))
        self.assertNotIn("--stage-guest-binaries", manifest()["spec"]["containers"][0]["command"])
        args.stage_guest_binaries = True
        actual = manifest()
        self.assertIn("--stage-guest-binaries", actual["spec"]["containers"][0]["command"])
        self.assertEqual(actual["spec"]["activeDeadlineSeconds"], 720)


if __name__ == "__main__":
    unittest.main()
