from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "validate-mega-cli.py"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("validate_mega_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ValidateMegaCliTests(unittest.TestCase):
    def test_fixture_taint_query_disables_production_profile_filtering(self) -> None:
        module = load_validator_module()
        args = module.derive_taint_args(Path("fixture"), Path("rules"))
        profile = args.index("--profile")
        self.assertEqual(args[profile + 1], "all")
        self.assertIn("--inferred-sources", args)
        self.assertIn("--all", args)


if __name__ == "__main__":
    unittest.main()
