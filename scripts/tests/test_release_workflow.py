#!/usr/bin/env python3
"""Regression tests for cross-platform release artifact assembly."""

from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"
)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_windows_checksum_is_portable_to_unix_verifiers(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            '"$hash  $artifact.zip`n"',
            workflow,
            "Windows checksum output must end with an explicit Unix newline",
        )
        self.assertIn(
            "[System.Text.UTF8Encoding]::new($false)",
            workflow,
            "Windows checksum output must not contain a UTF-8 BOM",
        )
        self.assertNotIn(
            'Out-File -Encoding ascii "$artifact.zip.sha256"',
            workflow,
            "Out-File emits CRLF on Windows and breaks sha256sum -c on Linux",
        )


if __name__ == "__main__":
    unittest.main()
