from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest.mock import patch
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
    def test_artifact_ids_use_canonical_envelopes_including_call_edges(self) -> None:
        module = load_validator_module()
        validator = module.Validator(REPO, Path("binary"), Path("rules"))
        documents = [
            {"decl_hits": [{"flows": [{"flow_id": "F:01"}], "groups": [{"group_id": "G:02"}]}]},
            {"rows": [{"edge_id": "E:03"}]},
            {"rows": [{"node_id": "N:04"}]},
            {"candidates": [{"candidate_id": "R:05"}]},
            {"records": [{"taint_id": "T:06"}]},
        ]
        with patch.object(validator, "check", side_effect=documents):
            ids = validator.derive_artifact_ids("python", Path("fixture"), {}, "entry", "target")
        self.assertEqual(ids, ("F:01", "G:02", "E:03", "N:04", "R:05", "T:06"))

    def test_concrete_gauntlet_pins_known_coverage_without_hiding_other_gaps(self) -> None:
        module = load_validator_module()
        for language in ["python", "go", "objc", "swift"]:
            reasons = module.EXPECTED_ANALYSIS_INCOMPLETE_REASONS.get(language, [])
            for complete, reported, accepted in [
                (not reasons, reasons, True),
                (False, [*reasons, "parser-error:unexpected"], False),
                (bool(reasons), reasons, False),
            ]:
                with self.subTest(language=language, complete=complete, reasons=reported):
                    validator = module.Validator(REPO, Path("binary"), Path("rules"))
                    document = {
                        "rows": [{"analysis_complete": True, "source": {}}],
                        "analysis_complete": complete,
                        "analysis_incomplete_reasons": reported,
                    }
                    with patch.object(validator, "check", return_value=document):
                        rows = validator.derive_taint_rows(language, Path("fixture"))
                    self.assertEqual(rows is not None, accepted)
                    self.assertEqual(not validator.failures, accepted)

    def test_pagination_contract_accepts_command_specific_units(self) -> None:
        module = load_validator_module()
        for unit in ["row", "rows", "finding", "findings", "call sites", "writes"]:
            with self.subTest(unit=unit):
                self.assertIsNotNone(
                    module.PAGE_FOOTER_RE.search(f"page 1 of 2 (1 {unit})\n")
                )
        for malformed in ["page one of 2 (1 row)", "page 1 of 2 (rows)"]:
            self.assertIsNone(module.PAGE_FOOTER_RE.search(malformed))

    def test_fixture_taint_query_uses_default_production_with_concrete_sources(
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
