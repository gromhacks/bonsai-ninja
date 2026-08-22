#!/usr/bin/env python3
"""Regression tests for cross-platform release artifact assembly."""

from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"
)
PACK_AUDIT_WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "pack-audit.yml"
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

    def test_pack_audit_installs_pinned_rust_before_cargo(self) -> None:
        workflow = PACK_AUDIT_WORKFLOW.read_text(encoding="utf-8")
        toolchain = "dtolnay/rust-toolchain@"
        cargo_build = "cargo build --release --locked -p bonsai-ninja"

        self.assertIn(toolchain, workflow)
        self.assertIn('toolchain: "1.88"', workflow)
        self.assertIn(
            'RUSTUP_TOOLCHAIN: "1.88"',
            workflow,
            "pack-audit must use the action-installed toolchain directly",
        )
        self.assertLess(
            workflow.index(toolchain),
            workflow.index(cargo_build),
            "pack-audit must install Rust before invoking Cargo",
        )

    def test_elasticsearch_cold_structural_slo_uses_measured_runner_class(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            'BONSAI_ES_COLD_STRUCTURAL_INDEX_MAX_SECS: "300"',
            workflow,
            "the tag workflow must retain the measured public-runner calibration",
        )
        self.assertIn(
            "255.94s on the public ubuntu-22.04 runner",
            workflow,
            "runner calibration must remain tied to a completed exact measurement",
        )


if __name__ == "__main__":
    unittest.main()
