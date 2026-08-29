from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "validate-language-gauntlets.py"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("validate_language_gauntlets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ValidateLanguageGauntletsTests(unittest.TestCase):
    def test_fixture_taint_query_requires_concrete_sources_without_production_filtering(
        self,
    ) -> None:
        module = load_validator_module()
        args = module.derive_taint_args(Path("fixture"), Path("rules"))
        self.assertNotIn("--profile", args)
        self.assertNotIn("--inferred-sources", args)
        self.assertIn("--all", args)
        self.assertIn("--no-cache", args)


if __name__ == "__main__":
    unittest.main()
