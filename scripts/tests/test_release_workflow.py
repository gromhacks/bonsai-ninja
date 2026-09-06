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
AUDIT_LOOP = Path(__file__).resolve().parents[2] / "scripts" / "audit-loop.sh"


class ReleaseWorkflowTests(unittest.TestCase):
    def test_audit_correctness_tests_preserve_the_release_artifact(self) -> None:
        script = AUDIT_LOOP.read_text(encoding="utf-8")

        self.assertNotIn("cargo test --release", script)
        for package, target in (
            ("bonsai-ninja-taint", "language_matrix"),
            ("bonsai-ninja", "taint_engine_e2e"),
        ):
            self.assertIn(
                f"env -u NO_PROGRESS cargo test -q --locked -p {package} --test {target}",
                script,
            )
        self.assertNotIn("saved_release_binary", script)

    def test_audit_loop_bootstraps_a_remapped_release_binary(self) -> None:
        script = AUDIT_LOOP.read_text(encoding="utf-8")

        self.assertIn(
            'bash scripts/build-release.sh',
            script,
            "audit-loop must bootstrap the path-remapped distributable builder",
        )
        self.assertNotIn(
            'cargo build --release -q',
            script,
            "audit-loop must not create an unreproducible fallback binary",
        )

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
        self.assertIn(
            'BONSAI_ES_SINK_ANALYSIS_MAX_SECS: "300"',
            workflow,
            "the tag workflow must budget the measured sink-centric scale gate",
        )
        self.assertIn(
            'BONSAI_ES_SECURITY_INVENTORY_COLD_MAX_SECS: "180"',
            workflow,
            "the tag workflow must budget the measured cold inventory gate",
        )

    def test_elasticsearch_semantic_slo_uses_completed_runner_measurement(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            'BONSAI_ES_COLD_SEMANTIC_INDEX_MAX_SECS: "1200"',
            workflow,
            "the tag workflow must retain public-runner semantic headroom",
        )
        self.assertIn(
            "999.71s",
            workflow,
            "semantic runner calibration must remain tied to completed exact work",
        )
        self.assertIn(
            "strict 600s product/reference",
            workflow,
            "host calibration must not replace the product/reference SLO",
        )

    def test_elasticsearch_scale_tests_run_serially_in_release_ci(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "--test elasticsearch_large_repo -- --nocapture --test-threads=1",
            workflow,
            "large-repository SLOs must not compete with sibling scale cases",
        )


if __name__ == "__main__":
    unittest.main()
