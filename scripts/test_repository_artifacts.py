from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).with_name("check_repository_artifacts.py").resolve()
LIMIT = 10 * 1024 * 1024


class ArtifactPolicyTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "test")
        self.git("config", "user.email", "test@example.invalid")
        (self.root / "output").mkdir()
        (self.root / "output/go.mod").write_text("module example.invalid/output\n")
        self.git("add", "output/go.mod")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def check(self, *args):
        return subprocess.run([sys.executable, str(CHECK), *args], cwd=self.root,
                              capture_output=True, text=True)

    def test_ignored_output_and_staged_output(self):
        # Exercise the actual ignore policy, not a copy in the fixture.
        (self.root / ".gitignore").write_bytes((CHECK.parents[1] / ".gitignore").read_bytes())
        path = "output/preview/main.go"
        (self.root / "output/preview").mkdir()
        (self.root / path).write_text("package main\n")
        self.git("add", "-A")
        self.assertNotIn(path, self.git("ls-files"))
        self.assertEqual(self.check().returncode, 0)
        self.git("add", "-f", "--", path)
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(path, result.stderr)

    def test_intermediate_commit_cannot_hide_large_blob(self):
        path = "capture with spaces.zip"
        with (self.root / path).open("wb") as out:
            out.truncate(LIMIT + 1)
        self.git("add", "--", path)
        self.git("commit", "-qm", "add capture")
        self.git("rm", "-q", "--", path)
        self.git("commit", "-qm", "remove capture")
        self.assertEqual(self.check().returncode, 0)
        result = self.check("--since", self.base)
        self.assertEqual(result.returncode, 1)
        self.assertIn(path, result.stderr)

    def test_size_boundary_and_changed_legacy_path(self):
        path = self.root / "docs/benchmarks/v1.0-candidate/replays/task-investigation.zip"
        path.parent.mkdir(parents=True)
        with path.open("wb") as out:
            out.truncate(LIMIT)
        self.git("add", "-A")
        self.assertEqual(self.check().returncode, 0)
        with path.open("ab") as out:
            out.write(b"!")
        self.git("add", "-A")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(path.name, result.stderr)

    def test_missing_output_module_boundary(self):
        self.git("rm", "-q", "output/go.mod")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("output/go.mod", result.stderr)

    @unittest.skipUnless(shutil.which("go"), "Go is required for package discovery")
    def test_wildcard_go_packages_exclude_generated_source(self):
        (self.root / "go.mod").write_text("module example.invalid/project\n\ngo 1.23.0\n")
        (self.root / "app.go").write_text("package app\n")
        (self.root / "output/go.mod").write_bytes((CHECK.parents[1] / "output/go.mod").read_bytes())
        (self.root / "output/preview").mkdir()
        (self.root / "output/preview/main.go").write_text("package main\nfunc main() {}\n")
        packages = subprocess.check_output(["go", "list", "./..."], cwd=self.root, text=True)
        self.assertEqual(packages.splitlines(), ["example.invalid/project"])

    def test_shallow_range_is_not_reported_as_clean(self):
        with tempfile.TemporaryDirectory() as clone:
            self.git("clone", "-q", "--depth=1", self.root.as_uri(), clone)
            result = subprocess.run([sys.executable, str(CHECK), "--since", "HEAD"],
                                    cwd=clone, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("full commit history", result.stderr)


if __name__ == "__main__":
    unittest.main()
