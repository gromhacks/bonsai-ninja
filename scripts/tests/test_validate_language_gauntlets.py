from __future__ import annotations

import copy
import importlib.util
import io
import subprocess
import sys
import unittest
from types import SimpleNamespace
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
    def test_source_values_that_resemble_flags_use_explicit_value_syntax(self) -> None:
        module = load_validator_module()
        self.assertEqual(module.filter_value_args("--contains", "-- a Lua comment"),
                         ("--contains=-- a Lua comment",))
        self.assertEqual(module.filter_value_args("--contains", "--not-contains"),
                         ("--contains=--not-contains",))
        self.assertEqual(module.filter_value_args("--contains", "ordinary"),
                         ("--contains", "ordinary"))

    def test_corridor_reopen_requires_the_exact_originating_corridor(self) -> None:
        module = load_validator_module()
        document = {"corridor": {
            "from": "entry", "to": "sink", "nodes": [{"name": "entry"}],
            "edges": [{"edge_id": "E:01"}], "stack": {"flow_id": "F:02"},
        }}
        for field in (None, "from", "to", "nodes", "edges", "stack"):
            with self.subTest(field=field):
                validator = module.Validator(REPO, Path("binary"), Path("rules"))
                reopened = copy.deepcopy(document)
                if field is not None:
                    reopened["corridor"].pop(field)
                with patch.object(validator, "check", return_value=reopened) as check:
                    validator.validate_corridor_reopen("python", Path("fixture"), document)
                self.assertEqual(not validator.failures, field is None)
                self.assertEqual(validator.counts, [("python/endpoint-roundtrip", 1)])
                self.assertEqual(check.call_args.args[2][:4], ["show", Path("fixture"), "--id", "F:02"])

    def test_missing_corridor_stack_is_not_silent_positive_coverage(self) -> None:
        module = load_validator_module()
        for document in (None, {}, {"corridor": {"stack": {}}}):
            validator = module.Validator(REPO, Path("binary"), Path("rules"))
            with patch.object(validator, "check") as check:
                validator.validate_corridor_reopen("python", Path("fixture"), document)
            check.assert_not_called()
            self.assertTrue(validator.failures)
            self.assertEqual(validator.counts, [])

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


def browse_document(rows, *, number=1, pages=1, total=None):
    complete = number == 1 and pages == 1
    return {
        "analysis_complete": True,
        "analysis_incomplete_reasons": [],
        "result_complete": complete,
        "result_incomplete_reasons": [] if complete else ["remaining pages"],
        "rows": rows,
        "page": {
            "number": number,
            "total_pages": pages,
            "shown_rows": len(rows),
            "total_rows": len(rows) if total is None else total,
            "cursor": f"P:{number}",
            "next_cursor": f"P:{number + 1}" if number < pages else None,
            "is_last": number == pages,
        },
    }


class BrowseFilterOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_validator_module()
        self.validator = self.module.Validator(REPO, Path("never-execute"), Path("rules"))
        self.context = SimpleNamespace(entry="entry", target="target", first_file="src/a.py")
        self.rows = [
            {"file": "src/a.py", "line": 1, "name": "alpha", "code": "keep source fact"},
            {"file": "src/a.py", "line": 2, "name": "beta"},
            {"file": "other/b.py", "line": 3, "name": "gamma"},
        ]

    def coverage(self, command="defs"):
        result = self.module.FilterCoverage(baseline_rows=len(self.rows))
        self.validator.filter_coverage[("python", command)] = result
        return result

    def test_uppercase_filename_and_repeated_and_use_independent_leaves(self):
        self.assertEqual(self.module.filter_rows(self.rows, ("A.PY",)), self.rows[:2])
        self.assertEqual(self.module.filter_rows(self.rows, ("A.PY", "ALPHA")), self.rows[:1])
        self.assertEqual(self.module.filter_rows(self.rows, ("A.PY", "gamma")), [])
        self.assertEqual(self.module.filter_rows(self.rows, ("A.PY", "impossible", "A.PY")), [])

    def test_exclusions_are_or_and_can_combine_with_contains(self):
        self.assertEqual(
            self.module.filter_rows(self.rows, exclusions=("ALPHA", "GAMMA")), self.rows[1:2]
        )
        self.assertEqual(
            self.module.filter_rows(self.rows, ("A.PY",), ("BETA", "absent")), self.rows[:1]
        )

    def test_filter_does_not_match_keys_numbers_or_join_unrelated_leaves(self):
        rows = [{"secret_key": "abc", "nested": ["def", {"n": 123}], "bool": True}]
        for needle in ("secret_key", "nested", "123", "true", "abcdef", "abc def"):
            with self.subTest(needle=needle):
                self.assertEqual(self.module.filter_rows(rows, (needle,)), [])
        self.assertEqual(self.module.filter_rows(rows, ("abc", "def")), rows)

    def test_regex_oracle_is_case_insensitive_only_when_requested(self):
        self.assertEqual(self.module.filter_rows(self.rows, (r"(?i)A\.PY",), regex=True), self.rows[:2])
        self.assertEqual(self.module.filter_rows(self.rows, (r"A\.PY",), regex=True), [])
        with self.assertRaises(self.module.re.error):
            self.module.filter_rows([], ("[",), regex=True)

    def test_row_facts_ignore_only_presentation_and_preserve_duplicate_counts(self):
        decorated = [{**row, "presentation": {"flow": "page-dependent"}} for row in self.rows]
        self.module.assert_row_facts_equal(decorated, list(reversed(self.rows)))
        altered = copy.deepcopy(self.rows)
        altered[0]["code"] = "changed source fact"
        with self.assertRaises(AssertionError):
            self.module.assert_row_facts_equal(altered, self.rows)
        with self.assertRaises(AssertionError):
            self.module.assert_row_facts_equal([self.rows[0], self.rows[0]], self.rows[:2])
        with self.assertRaisesRegex(AssertionError, "order"):
            self.module.assert_row_facts_equal(list(reversed(self.rows)), self.rows, ordered=True)

    def test_file_subset_uses_exact_relative_identity_not_basename(self):
        rows = [{"file": "src/a.py"}, {"file": "other/a.py"}, {"file": "/fixtures/src/a.py"}]
        self.assertEqual(self.module.file_subset(rows, Path("/fixtures"), "src/a.py"), [rows[0], rows[2]])
        with self.assertRaises(AssertionError):
            self.module.relative_row_file({"file": "../a.py"}, Path("/fixtures"))

    def test_probes_choose_nonempty_discriminating_subset(self):
        relative, filename, operand = self.module.filter_probe_values(self.rows, Path("/fixtures"), "fallback")
        self.assertEqual((relative, filename), ("src/a.py", "A.PY"))
        selected = self.module.filter_rows(self.rows, (filename, operand))
        self.assertEqual(len(selected), 1)
        self.assertEqual(self.module.filter_probe_values([], Path("/fixtures"), "src/a.py")[0], "src/a.py")

    def test_all_twenty_languages_and_twelve_browse_surfaces_have_negatives(self):
        self.assertEqual(len(self.module.LANGS), 20)
        self.assertEqual(set(self.module.BROWSE_COMMANDS), {
            "defs", "entrypoints", "calls", "imports", "vars", "args", "operations",
            "classes", "refs", "search", "strings", "comments",
        })
        self.assertEqual(sum(map(len, self.module.PRIMARY_NEGATIVE_FILTERS.values())), 50)
        for command in self.module.BROWSE_COMMANDS:
            cases = self.module.primary_negative_cases(command, [])
            self.assertEqual(len(cases), len(set(flag for flag, _ in cases)))
            self.assertIn("--file", dict(cases))

    def test_numeric_negatives_are_above_every_baseline_row(self):
        self.assertEqual(dict(self.module.primary_negative_cases("args", [{"position": 19}]))["--position"], "20")
        self.assertEqual(dict(self.module.primary_negative_cases("classes", [{"method_count": 99}]))["--min-methods"], "100")
        self.assertEqual(dict(self.module.primary_negative_cases("strings", [{"text": '"é"', "content_len": 1}]))["--min-len"], "2")

    def test_min_len_threshold_uses_content_len_without_measuring_raw_text(self):
        rows = [
            {"text": '"é"', "content_len": 1},
            {"text": "delimiter and prefix spelling " * 20, "content_len": 3},
            {"text": '""', "content_len": 0},
        ]
        for command in ("strings", "comments"):
            with self.subTest(command=command):
                self.assertEqual(dict(self.module.primary_negative_cases(command, rows))["--min-len"], "4")
                self.assertEqual(dict(self.module.primary_negative_cases(command, []))["--min-len"], "1")

    def test_min_len_unknown_or_invalid_content_len_cannot_fall_back_to_raw_text(self):
        for command in ("strings", "comments"):
            for row in (
                {"text": "a long raw spelling"},
                *({"text": "a long raw spelling", "content_len": value} for value in (None, -1, True, "3", 3.0)),
            ):
                with self.subTest(command=command, row=row), self.assertRaisesRegex(AssertionError, "content_len"):
                    self.module.primary_negative_cases(command, [row])

    def test_unknown_content_len_records_validator_failure_instead_of_crashing(self):
        rows = [{"file": "src/a.py", "line": 1, "text": '"text"', "content_len": None}]
        with patch.object(self.module, "BROWSE_COMMANDS", ("strings",)), \
             patch.object(self.validator, "check", return_value=browse_document(rows)) as check:
            self.validator.validate_filters("python", Path("/fixtures"), self.context)
        self.assertEqual(check.call_count, 1)
        self.assertEqual(len(self.validator.failures), 1)
        self.assertIn("content_len", self.validator.failures[0].message)
        self.assertEqual(self.validator.counts, [("python/filters", 1)])

    def test_derived_selectors_are_replaced_not_duplicated_and_flags_cross_levels(self):
        for command, flag, selector in (("refs", "--symbol", "target"), ("search", "--query", "entry")):
            args = self.module.browse_filter_args(command, Path("fixture"), self.context)
            self.assertEqual(args[args.index(flag) + 1], selector)
            negative = self.module.browse_filter_args(command, Path("fixture"), self.context, primary=(flag, "absent"))
            self.assertEqual(negative.count(flag), 1)
            self.assertEqual(negative[negative.index(flag) + 1], "absent")
        args = self.module.browse_filter_args(
            "defs", Path("fixture"), self.context, before=("--contains", "a"),
            middle=("--contains", "b"), after=("--contains", "c"),
        )
        self.assertEqual(args[:8], ["--contains", "a", "defs", "--contains", "b", Path("fixture"), "--contains", "c"])
        self.assertIn("--all", args)

    def test_canonical_envelope_rejects_missing_facts_and_incomplete_baselines(self):
        base = browse_document(self.rows)
        for mutate in (
            lambda doc: doc.pop("rows"),
            lambda doc: doc.update(rows=None),
            lambda doc: doc.update(analysis_complete=False),
            lambda doc: doc.update(analysis_incomplete_reasons=["parser gap"]),
            lambda doc: doc["page"].update(shown_rows=0),
            lambda doc: doc["page"].update(total_rows=999),
            lambda doc: doc["page"].update(next_cursor="P:2"),
            lambda doc: doc.update(result_complete=False),
        ):
            document = copy.deepcopy(base)
            mutate(document)
            with self.subTest(document=document), self.assertRaises(AssertionError):
                self.module.checked_browse_document(document, all_rows=True)
        self.assertEqual(self.module.checked_browse_document(browse_document([]), all_rows=True)[0], [])

    def test_nonfinal_page_requires_next_cursor_and_row_progress(self):
        for document in (
            browse_document([], number=1, pages=2, total=2),
            {**browse_document(self.rows[:1], number=1, pages=2, total=2),
             "page": {**browse_document([], number=1, pages=2)["page"], "shown_rows": 1, "total_rows": 2, "next_cursor": None}},
        ):
            with self.assertRaises(AssertionError):
                self.module.checked_browse_document(document, all_rows=False)

    def test_ignored_filter_records_a_failure_even_when_row_count_is_unchanged(self):
        self.coverage()
        document = browse_document(self.rows[1:2])
        with patch.object(self.validator, "check", return_value=document):
            result = self.validator.check_filter_rows("python", "defs", "selector", ["defs"], self.rows[:1])
        self.assertIsNone(result)
        self.assertEqual(len(self.validator.failures), 1)
        self.assertIn("row facts differ", self.validator.failures[0].message)

    def test_pagination_follows_every_cursor_and_ignores_page_presentation(self):
        coverage = self.coverage()
        docs = [browse_document([{**row, "presentation": {"page": n}}], number=n, pages=3, total=3)
                for n, row in enumerate(self.rows, 1)]
        with patch.object(self.validator, "check", side_effect=docs) as check:
            self.validator.validate_filtered_pages("python", "defs", ["defs", "--contains", "py"], self.rows)
        self.assertEqual([call.args[2][-1] for call in check.call_args_list], ["1", "P:2", "P:3"])
        self.assertEqual(coverage.pagination_pages, 3)
        self.assertFalse(self.validator.failures)

    def test_pagination_detects_duplicate_omitted_and_out_of_order_facts(self):
        for emitted in ([self.rows[0], self.rows[0], self.rows[2]], list(reversed(self.rows)), self.rows[:2]):
            self.validator.failures.clear()
            self.coverage()
            docs = [browse_document([row], number=n, pages=len(emitted), total=3) for n, row in enumerate(emitted, 1)]
            with patch.object(self.validator, "check", side_effect=docs):
                self.validator.validate_filtered_pages("python", "defs", ["defs"], self.rows)
            self.assertTrue(self.validator.failures, emitted)

    def test_pagination_repeated_cursor_fails_without_looping(self):
        self.coverage()
        first = browse_document(self.rows[:1], number=1, pages=3, total=3)
        second = browse_document(self.rows[1:2], number=2, pages=3, total=3)
        second["page"]["cursor"] = "P:1"
        with patch.object(self.validator, "check", side_effect=[first, second]) as check:
            self.validator.validate_filtered_pages("python", "defs", ["defs"], self.rows)
        self.assertEqual(check.call_count, 2)
        self.assertIn("cursor", self.validator.failures[0].message)

    def test_text_count_reads_command_heading_not_source_or_footer(self):
        for command, unit in (("defs", "definitions"), ("entrypoints", "entry points"), ("calls", "call sites"), ("vars", "writes")):
            self.assertEqual(self.module.text_row_count(f"{command} — 1,234 {unit}\nsource\n", command), 1234)
        for output in ("", "unrelated\ndefs — 3 definitions\n", "total 3 definitions\n"):
            with self.assertRaises(AssertionError):
                self.module.text_row_count(output, "defs")

    def test_watchdog_is_300_seconds_and_timeout_is_always_failure(self):
        with patch.object(self.module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
            self.validator.run(["--help"])
        self.assertEqual(run.call_args.kwargs["timeout"], 300)
        with patch.object(self.validator, "run", side_effect=subprocess.TimeoutExpired("binary", 300, output=b"partial", stderr=b"details")):
            result = self.validator.check("python", "timeout", ["defs"], ok=(0, 124))
        self.assertIsNone(result)
        self.assertIn("300s", self.validator.failures[0].message)
        self.assertEqual(self.validator.failures[0].stdout, "partial")

    def test_invalid_regex_must_fail_for_regex_reason_not_unrelated_cli_error(self):
        for code, stderr, accepted in (
            (2, "Error: regex parse error: unclosed character class", True),
            (0, "regex parse error", False),
            (2, "unexpected argument --contains", False),
        ):
            self.validator.failures.clear()
            with patch.object(self.validator, "run", return_value=subprocess.CompletedProcess([], code, "", stderr)):
                self.validator.check("python", "regex", [], ok=(1, 2), error_pattern="regex parse error")
            self.assertEqual(not self.validator.failures, accepted)

    def test_filters_only_dispatch_skips_legacy_and_realworld_work(self):
        with patch.object(self.module, "find_bin", return_value=Path("never-execute")), \
             patch.object(self.module, "Validator") as validator_type, \
             patch.object(sys, "argv", ["validator", "--filters-only", "--lang", "python"]):
            validator_type.return_value.report.return_value = 0
            self.assertEqual(self.module.main(), 0)
        validator_type.return_value.validate_lang.assert_called_once_with("python", filters_only=True)
        validator_type.return_value.validate_realworld_redis_footers.assert_not_called()

    def test_default_dispatch_keeps_twenty_languages_and_existing_work(self):
        with patch.object(self.module, "find_bin", return_value=Path("never-execute")), \
             patch.object(self.module, "Validator") as validator_type, \
             patch.object(sys, "argv", ["validator"]):
            validator_type.return_value.report.return_value = 0
            self.module.main()
        self.assertEqual(validator_type.return_value.validate_lang.call_count, 20)
        self.assertTrue(all(call.kwargs == {"filters_only": False} for call in validator_type.return_value.validate_lang.call_args_list))
        validator_type.return_value.validate_realworld_redis_footers.assert_called_once()

    def test_filters_only_reuses_context_without_deriving_artifact_ids(self):
        with patch.object(self.validator, "derive_taint_rows", return_value=[{}]), \
             patch.object(self.validator, "derive_validation", return_value=self.context) as derive, \
             patch.object(self.validator, "validate_filters") as sweep, \
             patch.object(self.validator, "check") as legacy:
            self.validator.validate_lang("python", filters_only=True)
        ws = REPO / "examples" / "python" / "language_gauntlet"
        derive.assert_called_once_with("python", ws, [{}], artifact_ids=False)
        sweep.assert_called_once_with("python", ws, self.context)
        legacy.assert_not_called()

    def test_empty_strings_still_exercise_filters_and_invalid_regex(self):
        def check(lang, label, args, **kwargs):
            if "invalid contains regex" in label:
                self.assertEqual(kwargs["ok"], (1, 2))
                self.assertIn("error_pattern", kwargs)
                return ""
            if "text" in args:
                return "strings — 0 string literals\n"
            return browse_document([])

        with patch.object(self.module, "BROWSE_COMMANDS", ("strings",)), \
             patch.object(self.validator, "check", side_effect=check) as checked:
            self.validator.validate_filters("python", Path("/fixtures"), self.context)
        coverage = self.validator.filter_coverage[("python", "strings")]
        self.assertEqual(coverage.baseline_rows, 0)
        self.assertEqual(coverage.positive_cases, 0)
        self.assertEqual(coverage.primary_negatives, 4)
        self.assertEqual(coverage.pagination_pages, 1)
        self.assertTrue(any("invalid contains regex" in call.args[1] for call in checked.call_args_list))
        self.assertFalse(self.validator.failures)

    def test_failed_baseline_is_not_reported_as_valid_empty_coverage(self):
        with patch.object(self.module, "BROWSE_COMMANDS", ("defs",)), \
             patch.object(self.validator, "check", return_value={"rows": []}):
            self.validator.validate_filters("python", Path("/fixtures"), self.context)
        coverage = self.validator.filter_coverage[("python", "defs")]
        self.assertIsNone(coverage.baseline_rows)
        self.assertEqual(coverage.commands, 1)
        self.assertTrue(self.validator.failures)
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(self.validator.report(), 1)
        self.assertIn("FAILED BASELINE", out.getvalue())

    def test_complete_sweep_tracks_empty_categories_and_all_primary_negatives(self):
        rows = [*self.rows[:2], {"file": "src/a.py", "line": 4, "name": "delta"}, self.rows[2]]
        invocations = []

        def check(lang, label, args, **kwargs):
            args = list(map(str, args))
            invocations.append((label, args))
            command = next(arg for arg in args if arg in self.module.BROWSE_COMMANDS)
            selected = [] if command == "imports" else rows
            if command in ("strings", "comments"):
                selected = [{**row, "text": "a", "content_len": 1} for row in selected]
            if "invalid contains regex" in label:
                return ""
            if "primary negative" in label:
                selected = []
            elif "--file" in args:
                wanted = args[args.index("--file") + 1]
                if wanted.startswith("/fixtures/"):
                    wanted = wanted.removeprefix("/fixtures/")
                selected = [row for row in selected if row["file"] == wanted]
            contains = tuple(args[n + 1] for n, arg in enumerate(args) if arg == "--contains")
            exclusions = tuple(args[n + 1] for n, arg in enumerate(args) if arg == "--not-contains")
            selected = self.module.filter_rows(selected, contains, exclusions, regex="--regex" in args)
            if args[args.index("--format") + 1] == "text":
                return f"{command} — {len(selected)} rows\n"
            if "--all" in args:
                return browse_document(selected)
            limit = int(args[args.index("--limit") + 1])
            page = int(args[args.index("--page") + 1].removeprefix("P:"))
            pages = max(1, (len(selected) + limit - 1) // limit)
            return browse_document(selected[(page - 1) * limit:page * limit], number=page, pages=pages, total=len(selected))

        with patch.object(self.validator, "check", side_effect=check):
            self.validator.validate_filters("python", Path("/fixtures"), self.context)
        self.assertFalse(self.validator.failures, [failure.message for failure in self.validator.failures])
        self.assertEqual(len(self.validator.filter_coverage), 12)
        self.assertEqual(sum(coverage.primary_negatives for coverage in self.validator.filter_coverage.values()), 50)
        self.assertEqual(self.validator.counts, [("python/filters", len(invocations))])
        empty = self.validator.filter_coverage[("python", "imports")]
        self.assertEqual(empty.baseline_rows, 0)
        self.assertEqual(empty.positive_cases, 0)
        self.assertEqual(empty.primary_negatives, 3)
        self.assertEqual(empty.pagination_pages, 1)
        for command in ("strings", "comments"):
            self.assertTrue(any(f"filters/{command}/invalid contains regex" in label for label, _ in invocations))
        self.assertEqual(sum("--no-cache" in args for _, args in invocations), 2)
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            self.validator.report()
        self.assertIn("python/imports: rows=EMPTY", out.getvalue())


if __name__ == "__main__":
    unittest.main()
