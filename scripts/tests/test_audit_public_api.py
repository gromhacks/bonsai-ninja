"""Contract checks for the lightweight crate-root declaration snapshot."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "audit-public-api.sh"


@unittest.skipUnless(shutil.which("bash"), "requires Bash")
class PublicApiAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="bonsai-api-audit-")
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        self.lib = self.root / "crates" / "example" / "src" / "lib.rs"
        self.lib.parent.mkdir(parents=True)
        self.lib.write_text("pub struct Evidence;   // public root\nfn private() {}\n")
        (self.root / ".snapshots").mkdir()
        self.snapshot = self.root / ".snapshots" / "public-api.snapshot"

    def run_audit(self, *args):
        return subprocess.run(
            ["bash", str(self.root / "scripts" / SCRIPT.name), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_generated_snapshot_round_trips(self):
        generated = self.run_audit()
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertIn("pub struct Evidence;\n", generated.stdout)
        self.assertNotIn("fn private", generated.stdout)
        self.snapshot.write_text(generated.stdout)
        checked = self.run_audit("--check")
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_missing_snapshot_fails_closed(self):
        checked = self.run_audit("--check")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("no snapshot", checked.stdout)

    def test_changed_root_declaration_reports_its_diff(self):
        self.snapshot.write_text(self.run_audit().stdout)
        self.lib.write_text("pub struct RevisedEvidence;\n")
        checked = self.run_audit("--check")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("-pub struct Evidence;", checked.stdout)
        self.assertIn("+pub struct RevisedEvidence;", checked.stdout)


if __name__ == "__main__":
    unittest.main()
