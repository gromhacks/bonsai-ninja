#!/usr/bin/env python3
"""Regression tests for strict security-pattern YAML loading."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "pack_audit.py"
SPEC = importlib.util.spec_from_file_location("pack_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
pack_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pack_audit)


class RulepackYamlLoaderTests(unittest.TestCase):
    def load_text(self, text: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.yml"
            path.write_text(text, encoding="utf-8")
            return pack_audit.load_yaml(path)

    def test_accepts_unique_mapping_keys(self) -> None:
        rows = self.load_text("- id: example\n  enabled: true\n")
        self.assertEqual(rows, [{"id": "example", "enabled": True}])

    def test_rejects_duplicate_mapping_keys(self) -> None:
        rows = self.load_text(
            "- id: example\n  enabled: true\n  enabled: false\n"
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("duplicate key 'enabled'", rows[0]["_parse_error"])


if __name__ == "__main__":
    unittest.main()
