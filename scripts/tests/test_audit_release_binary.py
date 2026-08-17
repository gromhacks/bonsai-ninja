from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / "scripts" / "audit-release-binary.py"


class AuditReleaseBinaryTests(unittest.TestCase):
    def run_audit(self, payload: bytes) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bonsai-ninja"
            binary.write_bytes(payload)
            return subprocess.run(
                [sys.executable, str(AUDIT), str(binary)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                env=os.environ,
            )

    def test_accepts_binary_without_builder_paths(self) -> None:
        result = self.run_audit(b"compiler-backed release artifact")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("build paths: remapped", result.stdout)

    def test_rejects_binary_with_checkout_path(self) -> None:
        result = self.run_audit(b"prefix\0" + str(ROOT).encode() + b"\0suffix")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unremapped build path", result.stderr)


if __name__ == "__main__":
    unittest.main()
