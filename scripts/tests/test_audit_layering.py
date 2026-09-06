#!/usr/bin/env python3
"""Regression checks for the architecture gate; no builds or network needed."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "audit_layering", Path(__file__).resolve().parents[1] / "audit-layering.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class LayeringTests(unittest.TestCase):
    def metadata(self, dependencies, name="bonsai-ninja-common"):
        return {
            "workspace_members": ["member"],
            "packages": [{"id": "member", "name": name, "dependencies": dependencies}],
        }

    def test_alias_does_not_hide_an_upward_edge(self):
        dependency = {"name": "bonsai-ninja-security", "rename": "innocent_alias", "kind": None}
        self.assertEqual(len(audit.violations(self.metadata([dependency]))), 1)

    def test_build_and_target_specific_edges_are_checked(self):
        for kind in [None, "build"]:
            dependency = {"name": "bonsai-ninja-sdk", "kind": kind, "target": "cfg(windows)", "optional": True}
            with self.subTest(kind=kind):
                self.assertEqual(len(audit.violations(self.metadata([dependency]))), 1)

    def test_development_external_and_downward_edges_are_allowed(self):
        dependencies = [
            {"name": "bonsai-ninja-sdk", "kind": "dev"},
            {"name": "serde", "kind": None},
            {"name": "bonsai-ninja-hash", "kind": "build"},
        ]
        self.assertEqual(audit.violations(self.metadata(dependencies)), [])

    def test_new_workspace_members_require_classification(self):
        self.assertIn("UNCLASSIFIED CRATE", audit.violations(self.metadata([], "new-crate"))[0])


if __name__ == "__main__":
    unittest.main()
