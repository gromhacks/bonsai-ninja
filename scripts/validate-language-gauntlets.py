#!/usr/bin/env python3
"""Release-binary command and representative switch validation.

The maintained matrix runs every command family across every language; focused
CLI integration tests cover additional flags and invalid combinations. A baseline-
derived filter sweep also checks all twelve browse commands in all twenty languages;
--filters-only runs that sweep without the ordinary command matrix or Redis sweep.
This is not an exhaustive Cartesian product of options. Every subprocess has a
300-second watchdog; a timeout fails validation. Destructive cache commands run only against temporary
copies of the fixture workspaces. By default the script also runs the Redis
realworld header/footer stress sweep; pass --skip-realworld for a faster
language-fixture-only pass.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LANGS = [
    "c",
    "cpp",
    "csharp",
    "dart",
    "elixir",
    "erlang",
    "go",
    "java",
    "javascript",
    "kotlin",
    "lua",
    "objc",
    "perl",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "swift",
    "typescript",
]

EXPECTED_FINDINGS = {
    # Concrete rule-backed source-to-sink counts under
    # the default production `taint-analysis --all`. Inferred entry-point sources are
    # tested separately and must never be required for this acceptance gate.
    "c": 1,
    "cpp": 1,
    "csharp": 1,
    "dart": 1,
    "elixir": 1,
    "erlang": 1,
    "go": 1,
    "java": 1,
    "javascript": 1,
    "kotlin": 1,
    # Lua previously reported two extra SQLi findings from generic
    # Executor.execute calls. LuaSQL sinks now require LuaSQL package
    # evidence, leaving the one real os.execute command-injection flow.
    "lua": 1,
    "objc": 1,
    # One real CGI-param-to-system flow; the second sink is the clean twin.
    "perl": 1,
    # Production emits the critical shell flow; the medium reflected-output
    # row remains covered by the separate explicit all-code profile.
    "php": 1,
    "python": 1,
    # Equivalent receiver-derived evidence is grouped into the one distinct
    # Rails-params -> Kernel.system vulnerability.
    "ruby": 1,
    "rust": 1,
    "scala": 1,
    "swift": 1,
    "typescript": 1,
}

MatrixEntry = tuple[str, list[Any], tuple[int, ...], bool, bool]
COMMAND_TIMEOUT_SECONDS = 300
FILTER_MISS = "__BONSAI_FILTER_IMPOSSIBLE_7c9f25e6__"

# Each selector is tested independently. Boolean selectors such as --wildcard
# are not impossible predicates; numeric bounds are derived from actual rows.
PRIMARY_NEGATIVE_FILTERS = {
    "defs": ("--name", "--kind", "--file", "--has-callee", "--has-decorator", "--has-param"),
    "entrypoints": ("--name", "--kind", "--file"),
    "calls": ("--callee", "--caller", "--call-kind", "--file"),
    "imports": ("--module", "--alias", "--file"),
    "vars": ("--name", "--in-fn", "--source", "--file"),
    "args": ("--callee", "--in-fn", "--value", "--position", "--keyword", "--file"),
    "operations": ("--kind", "--name", "--in-fn", "--file"),
    "classes": ("--name", "--kind", "--has-method", "--min-methods", "--file"),
    "refs": ("--symbol", "--kind", "--in-fn", "--file"),
    "search": ("--query", "--kind", "--file"),
    "strings": ("--category", "--in-fn", "--min-len", "--file"),
    "comments": ("--kind", "--in-fn", "--min-len", "--file"),
}
BROWSE_COMMANDS = tuple(PRIMARY_NEGATIVE_FILTERS)

# Match the compiler CLI gate in tests/support/analysis_coverage.rs. These
# manifests intentionally report missing dependency coverage; the concrete
# source-to-sink proof remains complete. Pin exact gaps, never waive arbitrary
# incompleteness or accept a falsely complete envelope.
EXPECTED_ANALYSIS_INCOMPLETE_REASONS = {
    "go": ["dependency-manifest:unsupported:go:go.mod:files=1"],
    "objc": ["dependency-manifest:unsupported:objc:Podfile:files=1"],
    "swift": ["dependency-manifest:unsupported:swift:Package.swift:files=1"],
}

CONTEXT_FOOTER_RE = re.compile(r"context\s+~?([0-9,]+) / ([0-9,]+) tokens \((\d+)%\)")
PAGE_FOOTER_RE = re.compile(
    r"^page\s+\d+\s+of\s+[0-9,]+\s+\([0-9,]+\s+[^)\n]+\)", re.MULTILINE
)
TOTAL_FOOTER_RE = re.compile(r"^total\s+[0-9,]+\s+\S+", re.MULTILINE)


class Failure:
    def __init__(
        self,
        lang: str,
        label: str,
        args: list[str],
        message: str,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.lang = lang
        self.label = label
        self.args = args
        self.message = message
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class DerivedValidation:
    entry: str
    target: str
    source_rule: str
    sink_rule: str
    source_file: str
    sink_file: str
    call_filter_query: str
    call_filter_file: str
    call_filter_fn: str
    first_file: str
    flow_id: str | None
    group_id: str | None
    edge_id: str | None
    node_id: str | None
    candidate_id: str | None
    taint_id: str | None


@dataclass
class FilterCoverage:
    baseline_rows: int | None = None
    commands: int = 0
    positive_cases: int = 0
    strict_subset_cases: int = 0
    primary_negatives: int = 0
    pagination_pages: int = 0


def row_facts(row: dict[str, Any]) -> dict[str, Any]:
    """Ignore page-dependent decoration, never source facts such as code/context."""
    return {key: value for key, value in row.items() if key != "presentation"}


def row_fact_keys(rows: list[dict[str, Any]]) -> list[str]:
    return [json.dumps(row_facts(row), sort_keys=True, ensure_ascii=False) for row in rows]


def assert_row_facts_equal(
    actual: list[dict[str, Any]], expected: list[dict[str, Any]], *, ordered: bool = False
) -> None:
    actual_keys, expected_keys = row_fact_keys(actual), row_fact_keys(expected)
    if Counter(actual_keys) != Counter(expected_keys):
        missing = list((Counter(expected_keys) - Counter(actual_keys)).elements())
        extra = list((Counter(actual_keys) - Counter(expected_keys)).elements())
        raise AssertionError(
            f"row facts differ: expected={len(expected)} actual={len(actual)}; "
            f"missing={missing[:2]} unexpected={extra[:2]}"
        )
    if ordered and actual_keys != expected_keys:
        raise AssertionError("pagination changed the filtered --all row order")


def string_leaves(value: Any):
    """The output-filter contract searches string values, not JSON keys/numbers."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_leaves(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_leaves(child)


def filter_rows(
    rows: list[dict[str, Any]],
    contains: tuple[str, ...] = (),
    exclusions: tuple[str, ...] = (),
    *,
    regex: bool = False,
) -> list[dict[str, Any]]:
    patterns = [re.compile(needle) for needle in contains if needle] if regex else []
    selected = []
    for row in rows:
        parts = list(string_leaves(row_facts(row)))
        lower_parts = [part.lower() for part in parts]
        if any(needle.lower() in part for needle in exclusions if needle for part in lower_parts):
            continue
        if regex:
            matches = all(any(pattern.search(part) for part in parts) for pattern in patterns)
        else:
            matches = all(
                any(needle.lower() in part for part in lower_parts)
                for needle in contains if needle
            )
        if matches:
            selected.append(row)
    return selected


def relative_row_file(row: dict[str, Any], ws: Path) -> str:
    file = row.get("file")
    if not isinstance(file, str) or not file:
        raise AssertionError(f"browse row lacks a source file: {row}")
    path = Path(file)
    if path.is_absolute():
        path = path.relative_to(ws.resolve())
    if ".." in path.parts:
        raise AssertionError(f"browse file escapes workspace: {file}")
    return path.as_posix()


def file_subset(rows: list[dict[str, Any]], ws: Path, relative: str) -> list[dict[str, Any]]:
    return [row for row in rows if relative_row_file(row, ws) == relative]


def filter_probe_values(rows: list[dict[str, Any]], ws: Path, fallback: str) -> tuple[str, str, str]:
    """Choose a populated file and the most selective nonempty AND operand."""
    if not rows:
        return fallback, Path(fallback).name.upper(), FILTER_MISS
    files = Counter(relative_row_file(row, ws) for row in rows)
    relative = max(files, key=files.get)
    filename = Path(relative).name.upper()
    selected = filter_rows(rows, (filename,))
    candidates = {
        row[field]
        for row in selected
        for field in ("name", "callee", "symbol", "module", "text", "in_function", "kind", "category")
        if isinstance(row.get(field), str) and row[field]
    }
    # Bounded by fixture row fields, not by source-token heuristics. Favor a
    # proper subset so a broken OR or ignored second operand cannot pass.
    second = min(
        candidates,
        key=lambda value: (len(filter_rows(selected, (value,))), len(value), value),
        default=filename,
    )
    return relative, filename, second


def filter_value_args(flag: str, value: str) -> tuple[str, ...]:
    """Use explicit value syntax when source text resembles an option."""
    return (f"{flag}={value}",) if value.startswith("-") else (flag, value)


def browse_filter_args(
    command: str, ws: Path, context: DerivedValidation,
    *, primary: tuple[str, str] | None = None,
    before: tuple[str, ...] = (), middle: tuple[str, ...] = (), after: tuple[str, ...] = (),
    all_rows: bool = True, format: str = "json",
) -> list[Any]:
    selectors = {"refs": ("--symbol", context.target), "search": ("--query", context.entry)}
    selector = selectors.get(command)
    args: list[Any] = [*before, command, *middle, ws]
    if selector and (primary is None or primary[0] != selector[0]):
        args.extend(selector)
    if primary:
        args.extend(primary)
    args.extend(after)
    args.extend(["--format", format, "--no-color", "--no-progress"])
    if all_rows:
        args.append("--all")
    return args


def primary_negative_cases(command: str, rows: list[dict[str, Any]]) -> list[tuple[str, str]]:
    numeric_fields = {"--position": "position", "--min-methods": "method_count"}
    cases = []
    for flag in PRIMARY_NEGATIVE_FILTERS[command]:
        value = FILTER_MISS
        if flag in numeric_fields:
            value = str(max((row.get(numeric_fields[flag], 0) for row in rows), default=0) + 1)
        elif flag == "--min-len":
            # Bundled adapters supply exact lexical body counts. A missing
            # count cannot justify a positive threshold or a raw-text fallback.
            lengths = []
            for row in rows:
                length = row.get("content_len")
                if type(length) is not int or length < 0:
                    raise AssertionError(
                        f"{command} --min-len oracle requires known nonnegative content_len; "
                        f"got {length!r} at {row.get('file')}:{row.get('line')}"
                    )
                lengths.append(length)
            value = str(max(lengths, default=0) + 1)
        cases.append((flag, value))
    return cases


def checked_browse_document(document: Any, *, all_rows: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(document, dict):
        raise AssertionError("expected a canonical browse JSON envelope")
    rows, page = document.get("rows"), document.get("page")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise AssertionError("expected rows[] of objects; absent/null rows are not an empty result")
    if document.get("analysis_complete") is not True or document.get("analysis_incomplete_reasons") != []:
        raise AssertionError(f"browse analysis incomplete: {document.get('analysis_incomplete_reasons')}")
    if not isinstance(page, dict):
        raise AssertionError("missing pagination metadata")
    for key in ("number", "total_pages", "shown_rows", "total_rows"):
        if type(page.get(key)) is not int or page[key] < (1 if key in ("number", "total_pages") else 0):
            raise AssertionError(f"invalid page.{key}: {page.get(key)}")
    if page["shown_rows"] != len(rows) or len(rows) > page["total_rows"]:
        raise AssertionError("page row counts disagree with rows[]")
    last = page["number"] == page["total_pages"]
    if page["number"] > page["total_pages"] or page.get("is_last") is not last:
        raise AssertionError("inconsistent last-page metadata")
    for field in ("cursor", "next_cursor"):
        cursor = page.get(field)
        if field == "next_cursor" and last:
            if cursor is not None:
                raise AssertionError("last page still has a next cursor")
        elif not isinstance(cursor, str) or not cursor.startswith("P:") or len(cursor) <= 2:
            raise AssertionError(f"missing/invalid page.{field}")
    if not last and not rows:
        raise AssertionError("non-final page made no row progress")
    complete = page["number"] == 1 and last
    if document.get("result_complete") is not complete:
        raise AssertionError("result_complete disagrees with page coverage")
    reasons = document.get("result_incomplete_reasons")
    if not isinstance(reasons, list) or (complete and reasons) or (not complete and not reasons):
        raise AssertionError("result incomplete reasons disagree with page coverage")
    if all_rows and (not complete or page["total_rows"] != len(rows)):
        raise AssertionError("--all did not return the complete result")
    return rows, page


def text_row_count(stdout: str, command: str) -> int:
    # --all suppresses the pagination footer, so use the command heading.
    # Read only the first nonempty line: a source snippet may contain a fake
    # heading or count. --no-color is mandatory on sweep invocations.
    first = next((line.strip() for line in stdout.splitlines() if line.strip()), "")
    match = re.fullmatch(rf"{re.escape(command)}\s+—\s+([0-9,]+)\s+\S.*", first)
    if not match:
        raise AssertionError(f"missing canonical {command} count heading: {first!r}")
    return int(match.group(1).replace(",", ""))


def is_inferred_finding(row: dict[str, Any]) -> bool:
    return (child_mapping(row, "source").get("rule_id") or "").startswith(
        "entry-point."
    )


def is_module_synthetic(name: object) -> bool:
    return isinstance(name, str) and name.startswith("__module__")


def good_primary_finding(row: dict[str, Any]) -> bool:
    if is_inferred_finding(row):
        return False
    chain = row.get("chain_display") or []
    head = (
        chain[0]
        if isinstance(chain, list) and chain
        else (child_mapping(row, "source").get("enclosing_fn") or "")
    )
    sink_enclosing = child_mapping(row, "sink").get("enclosing_fn") or ""
    return not is_module_synthetic(head) and not is_module_synthetic(sink_enclosing)


def select_primary_finding(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return next(
        (row for row in rows if good_primary_finding(row)),
        next(
            (row for row in rows if not is_inferred_finding(row)),
            rows[0],
        ),
    )


def function_names_from_export(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    names = [
        function.get("name")
        for function in value.get("taint_graph", {}).get("functions", []) or []
        if isinstance(function, dict) and isinstance(function.get("name"), str)
    ]
    names.extend(
        function.get("name")
        for function in value.get("functions", []) or []
        if isinstance(function, dict) and isinstance(function.get("name"), str)
    )
    names.extend(
        function.get("function")
        for function in value.get("flow_graph", []) or []
        if isinstance(function, dict) and isinstance(function.get("function"), str)
    )
    return names


def preferred_function(names: list[str], candidates: set[str]) -> str | None:
    return next((name for name in names if name in candidates), None)


def finding_symbols(first: dict[str, Any]) -> tuple[str | None, str | None]:
    chain = [name for name in first.get("chain_display") or [] if isinstance(name, str)]
    source_enclosing = child_mapping(first, "source").get("enclosing_fn")
    entry = chain[0] if chain else source_enclosing
    if not isinstance(entry, str):
        entry = None

    sink_enclosing = child_mapping(first, "sink").get("enclosing_fn")
    if is_module_synthetic(sink_enclosing) and chain:
        target = next(
            (name for name in reversed(chain) if not is_module_synthetic(name)),
            None,
        )
    else:
        target = sink_enclosing or (chain[-1] if chain else entry)
    return entry, target if isinstance(target, str) else None


def finding_call_filter(
    first: dict[str, Any],
    target: str,
    sink_text: str,
    sink_file: str,
) -> tuple[str, str, str]:
    taint_path = first.get("taint_path")
    if not isinstance(taint_path, list):
        return sink_text, sink_file, target
    for step in reversed(taint_path):
        if not isinstance(step, dict):
            continue
        callee = step.get("callee")
        caller = step.get("caller")
        call_file = step.get("file")
        if callee == target and isinstance(caller, str) and isinstance(call_file, str):
            return callee, Path(call_file).as_posix(), caller
    return sink_text, sink_file, target


def first_collection_field(value: Any, collection: str, field: str) -> Any:
    if not isinstance(value, dict):
        return None
    rows = value.get(collection)
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return None
    return rows[0].get(field)


def child_mapping(value: dict[str, Any], field: str) -> dict[str, Any]:
    child = value.get(field)
    return child if isinstance(child, dict) else {}


def path_or_default(value: Any, default: str) -> str:
    """Keep an exact workspace-relative path for CLI selector checks.

    Basenames are intentionally insufficient: idiomatic projects commonly
    contain repeated names such as Rust's `mod.rs`, Java's `Main.java`, or
    framework `index.ts` files. The public CLI must reject those ambiguous
    selectors, so the validator must exercise its success path with the exact
    compiler-reported identity instead of relying on suffix luck.
    """

    return Path(value).as_posix() if isinstance(value, str) and value else default


def append_optional_entry(
    matrix: list[MatrixEntry],
    identifier: str | None,
    label: str,
    args: list[Any],
    *,
    ok: tuple[int, ...] = (0,),
    nonempty: bool = False,
    json_out: bool = False,
) -> None:
    if identifier:
        matrix.append((label, args, ok, nonempty, json_out))


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def find_bin(root: Path, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    for candidate in [
        root / "target" / "release" / "bonsai-ninja",
        root / "target" / "debug" / "bonsai-ninja",
    ]:
        if candidate.exists():
            return candidate
    raise SystemExit("missing bonsai-ninja binary; run `cargo build --release`")


def json_load(stdout: str) -> Any:
    return json.loads(stdout or "null")


def first_node_id(value: Any) -> str | None:
    if isinstance(value, dict):
        node_id = value.get("node_id")
        if isinstance(node_id, str):
            return node_id
        for child in value.values():
            found = first_node_id(child)
            if found:
                return found
    if isinstance(value, list):
        for child in value:
            found = first_node_id(child)
            if found:
                return found
    return None


def collect_flow_ids(value: Any) -> tuple[list[str], list[str]]:
    flows: list[str] = []
    groups: list[str] = []
    if not isinstance(value, dict):
        return flows, groups
    for section in ("decl_hits", "hits"):
        for hit in value.get(section, []) or []:
            for flow in hit.get("flows", []) or []:
                flow_id = flow.get("flow_id")
                if isinstance(flow_id, str):
                    flows.append(flow_id)
            for group in hit.get("groups", []) or []:
                group_id = group.get("group_id")
                if isinstance(group_id, str):
                    groups.append(group_id)
    return flows, groups


def derive_taint_args(ws: Path, rules_dir: Path) -> list[Any]:
    """Build the plain production-profile concrete fixture query."""

    return [
        "security",
        ws,
        "taint-analysis",
        "--rules-dir",
        rules_dir,
        "--format",
        "json",
        "--all",
        "--no-cache",
    ]


def export_files(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return [
        file.get("path", "")
        for file in value.get("files", []) or []
        if isinstance(file, dict)
    ]


class Validator:
    def __init__(self, root: Path, binary: Path, rules_dir: Path) -> None:
        self.root = root
        self.binary = binary
        self.rules_dir = rules_dir
        self.failures: list[Failure] = []
        self.counts: list[tuple[str, int]] = []
        self.filter_coverage: dict[tuple[str, str], FilterCoverage] = {}

    def run(self, args: list[Any]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.binary), *[str(arg) for arg in args]],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    def check(
        self,
        lang: str,
        label: str,
        args: list[Any],
        *,
        ok: tuple[int, ...] = (0,),
        nonempty: bool = False,
        json_out: bool = False,
        error_pattern: str | None = None,
    ) -> Any:
        str_args = [str(arg) for arg in args]
        try:
            proc = self.run(str_args)
        except subprocess.TimeoutExpired as exc:
            def partial_text(value: Any) -> str:
                return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")

            self.failures.append(Failure(
                lang, label, str_args, f"command watchdog expired after {COMMAND_TIMEOUT_SECONDS}s",
                partial_text(exc.stdout)[:900], partial_text(exc.stderr)[:900],
            ))
            return None
        except OSError as exc:
            self.failures.append(Failure(lang, label, str_args, f"cannot execute command: {exc}"))
            return None
        if proc.returncode not in ok:
            self.failures.append(
                Failure(
                    lang,
                    label,
                    str_args,
                    f"exit {proc.returncode}",
                    proc.stdout[:900],
                    proc.stderr[:900],
                )
            )
            return None
        if nonempty and not (proc.stdout + proc.stderr).strip():
            self.failures.append(Failure(lang, label, str_args, "empty output"))
        if error_pattern and not re.search(error_pattern, proc.stdout + proc.stderr):
            self.failures.append(Failure(
                lang, label, str_args, "command did not report the expected regex rejection",
                proc.stdout[:900], proc.stderr[:900],
            ))
        if not json_out:
            self.validate_text_footer(lang, label, str_args, proc.stdout)
        if json_out:
            try:
                return json_load(proc.stdout)
            except Exception as exc:  # noqa: BLE001 - report parser context.
                self.failures.append(
                    Failure(
                        lang,
                        label,
                        str_args,
                        f"json parse {exc}",
                        proc.stdout[:900],
                        proc.stderr[:900],
                    )
                )
                return None
        return proc.stdout

    def filter_check(self, lang: str, command: str, label: str, args: list[Any], **kwargs: Any) -> Any:
        self.filter_coverage[(lang, command)].commands += 1
        return self.check(lang, f"filters/{command}/{label}", args, **kwargs)

    def filter_failure(self, lang: str, command: str, label: str, args: list[Any], message: str) -> None:
        self.failures.append(Failure(lang, f"filters/{command}/{label}", list(map(str, args)), message))

    def check_filter_rows(
        self, lang: str, command: str, label: str, args: list[Any],
        expected: list[dict[str, Any]] | None = None, *, all_rows: bool = True,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
        document = self.filter_check(lang, command, label, args, json_out=True)
        if document is None:
            return None
        try:
            rows, page = checked_browse_document(document, all_rows=all_rows)
            if expected is not None:
                coverage = self.filter_coverage[(lang, command)]
                coverage.positive_cases += bool(expected)
                coverage.strict_subset_cases += 0 < len(expected) < (coverage.baseline_rows or 0)
                assert_row_facts_equal(rows, expected)
            return rows, page
        except (AssertionError, ValueError) as exc:
            self.filter_failure(lang, command, label, args, str(exc))
            return None

    def validate_filtered_pages(
        self, lang: str, command: str, args: list[Any], expected: list[dict[str, Any]],
    ) -> None:
        """Follow every cursor; compare the complete ordered stream to --all."""
        collected: list[dict[str, Any]] = []
        seen: set[str] = set()
        cursor = "1"
        number = 1
        total_pages = None
        while True:
            page_args = [*args, "--page", cursor]
            result = self.check_filter_rows(
                lang, command, f"pagination/{number}", page_args, all_rows=False,
            )
            if result is None:
                return
            rows, page = result
            coverage = self.filter_coverage[(lang, command)]
            coverage.pagination_pages += 1
            try:
                if page["total_rows"] != len(expected) or page["number"] != number:
                    raise AssertionError("filtered pagination total/number disagrees with --all")
                if total_pages is not None and total_pages != page["total_pages"]:
                    raise AssertionError("total_pages changed while following cursors")
                total_pages = page["total_pages"]
                if page["cursor"] in seen or (cursor != "1" and page["cursor"] != cursor):
                    raise AssertionError("pagination repeated or resolved the wrong cursor")
                seen.add(page["cursor"])
                collected.extend(rows)
                if len(collected) > len(expected):
                    raise AssertionError("pagination emitted more rows than filtered --all")
                if page["is_last"]:
                    assert_row_facts_equal(collected, expected, ordered=True)
                    return
                if len(collected) >= len(expected):
                    raise AssertionError("pagination has a next cursor after exhausting the expected rows")
                cursor = page["next_cursor"]
                number += 1
            except AssertionError as exc:
                self.filter_failure(lang, command, "pagination", page_args, str(exc))
                return

    def validate_filters(self, lang: str, ws: Path, context: DerivedValidation) -> None:
        for command in BROWSE_COMMANDS:
            coverage = FilterCoverage()
            self.filter_coverage[(lang, command)] = coverage
            args = browse_filter_args(command, ws, context)
            result = self.check_filter_rows(lang, command, "baseline --all", args)
            if result is None:
                continue
            baseline, _ = result
            coverage.baseline_rows = len(baseline)
            try:
                if filter_rows(baseline, (FILTER_MISS,)):
                    raise AssertionError("impossible-filter sentinel occurs in baseline facts")
                relative, filename, operand = filter_probe_values(baseline, ws, context.first_file)
                negative_cases = primary_negative_cases(command, baseline)
            except (AssertionError, ValueError) as exc:
                self.filter_failure(lang, command, "baseline probes", args, str(exc))
                continue

            # Global options appear before the command, between command/root,
            # and after its selectors. Distinct AND operands span string leaves.
            positive = filter_rows(baseline, (filename,))
            positive_args = browse_filter_args(command, ws, context, before=("--contains", filename))
            positive_result = self.check_filter_rows(
                lang, command, "uppercase filename", positive_args, positive,
            )
            self.check_filter_rows(
                lang, command, "repeated AND positive",
                browse_filter_args(
                    command, ws, context, before=("--contains", filename),
                    after=filter_value_args("--contains", operand),
                ),
                filter_rows(baseline, (filename, operand)),
            )
            # A missing middle operand catches first-wins, last-wins, and OR
            # implementations of a repeated global option in the same case.
            self.check_filter_rows(
                lang, command, "impossible AND across levels",
                browse_filter_args(
                    command, ws, context, before=("--contains", filename),
                    middle=("--contains", FILTER_MISS), after=("--contains", filename),
                ), [],
            )
            other_filename = next(
                (Path(relative_row_file(row, ws)).name.upper() for row in baseline
                 if Path(relative_row_file(row, ws)).name.upper() != filename), FILTER_MISS,
            )
            self.check_filter_rows(
                lang, command, "exclusions OR across levels",
                browse_filter_args(
                    command, ws, context, before=("--not-contains", FILTER_MISS),
                    middle=("--not-contains", filename), after=("--not-contains", other_filename),
                ),
                filter_rows(baseline, exclusions=(FILTER_MISS, filename, other_filename)),
            )

            for flag, value in negative_cases:
                coverage.primary_negatives += 1
                self.check_filter_rows(
                    lang, command, f"primary negative {flag}",
                    browse_filter_args(command, ws, context, primary=(flag, value)), [],
                )

            # Empty categories are valid in the maintained fixtures, but are
            # recorded as empty, never credited as positive selector coverage.
            if baseline:
                expected_file = file_subset(baseline, ws, relative)
                for label, file in (("relative", relative), ("absolute", str((ws / relative).resolve()))):
                    self.check_filter_rows(
                        lang, command, f"positive file {label}",
                        browse_filter_args(command, ws, context, primary=("--file", file)), expected_file,
                    )

            text_args = browse_filter_args(
                command, ws, context, before=("--contains", filename), format="text",
            )
            stdout = self.filter_check(lang, command, "JSON/text filtered count", text_args)
            if stdout is not None:
                try:
                    if text_row_count(stdout, command) != len(positive):
                        raise AssertionError(f"text count disagrees with JSON: expected {len(positive)}")
                except AssertionError as exc:
                    self.filter_failure(lang, command, "JSON/text filtered count", text_args, str(exc))

            # Use a generous finite context and roughly three pages. --all or
            # --context uncapped would disable pagination even with --limit.
            page_args = browse_filter_args(
                command, ws, context, before=("--contains", filename), all_rows=False,
                after=("--limit", str(max(1, (len(positive) + 2) // 3)), "--context", "1m"),
            )
            # Preserve the actual --all order after its independent fact check.
            self.validate_filtered_pages(
                lang, command, page_args, positive_result[0] if positive_result else positive,
            )
            if command in ("defs", "calls"):
                self.check_filter_rows(
                    lang, command, "warm/no-cache sample", [*positive_args, "--no-cache"], positive,
                )
            if command in ("strings", "comments"):
                pattern = "(?i)" + re.escape(filename)
                self.check_filter_rows(
                    lang, command, "contains regex (?i)",
                    browse_filter_args(
                        command, ws, context, before=("--contains", pattern), after=("--regex",),
                    ), filter_rows(baseline, (pattern,), regex=True),
                )
                self.filter_check(
                    lang, command, "invalid contains regex rejected",
                    browse_filter_args(
                        command, ws, context, before=("--contains", "["), after=("--regex",),
                    ), ok=(1, 2), nonempty=True,
                    error_pattern=r"(?i)(invalid regex|regex (parse|syntax) error|unclosed character class)",
                )

        self.counts.append((f"{lang}/filters", sum(
            self.filter_coverage[(lang, command)].commands for command in BROWSE_COMMANDS
        )))

    def validate_text_footer(
        self, lang: str, label: str, args: list[str], stdout: str
    ) -> None:
        lines = [line for line in stdout.splitlines() if line.strip()]
        if not lines:
            return
        if lines[0].startswith(("page ", "context ", "next ")):
            self.failures.append(
                Failure(
                    lang,
                    label,
                    args,
                    f"footer appeared before command output: {lines[0]}",
                )
            )
        match = CONTEXT_FOOTER_RE.search(stdout)
        if match:
            used = int(match.group(1).replace(",", ""))
            budget = int(match.group(2).replace(",", ""))
            if used > budget and "single row cost exceeded --context" not in stdout:
                self.failures.append(
                    Failure(
                        lang,
                        label,
                        args,
                        f"context footer exceeded budget without oversized-row warning: {used}>{budget}",
                        stdout[-900:],
                    )
                )
        page_lines = [line for line in lines if PAGE_FOOTER_RE.match(line)]
        if page_lines and "next     " not in stdout and "end of results" not in stdout:
            self.failures.append(
                Failure(
                    lang,
                    label,
                    args,
                    "page footer missing next cursor or end-of-results marker",
                    stdout[-900:],
                )
            )
        if page_lines and not TOTAL_FOOTER_RE.search(stdout):
            self.failures.append(
                Failure(
                    lang,
                    label,
                    args,
                    "page footer missing total count line",
                    stdout[-900:],
                )
            )

    def validate_global(self) -> None:
        self.check("global", "help", ["--help"], nonempty=True)
        self.check("global", "version", ["--version"], nonempty=True)
        self.check("global", "short version", ["-V"], nonempty=True)
        self.check(
            "global", "theme help", ["--theme", "dracula", "--help"], nonempty=True
        )

    def derive_taint_rows(self, lang: str, ws: Path) -> list[dict[str, Any]] | None:
        expected_findings = EXPECTED_FINDINGS.get(lang, 1)
        taint = self.check(
            lang,
            "derive taint",
            derive_taint_args(ws, self.rules_dir),
            json_out=True,
        )
        raw_rows = taint.get("rows", []) if isinstance(taint, dict) else taint
        expected_reasons = EXPECTED_ANALYSIS_INCOMPLETE_REASONS.get(lang, [])
        if (
            not isinstance(taint, dict)
            or taint.get("analysis_complete") is not (not expected_reasons)
            or taint.get("analysis_incomplete_reasons") != expected_reasons
        ):
            self.failures.append(
                Failure(
                    lang,
                    "derive taint",
                    ["security", str(ws), "taint-analysis", "--no-cache"],
                    f"expected exact analysis coverage: {expected_reasons or 'complete'}",
                )
            )
            return None
        if (
            not isinstance(raw_rows, list)
            or len(raw_rows) != expected_findings
            or not all(isinstance(row, dict) for row in raw_rows)
        ):
            got = len(raw_rows) if isinstance(raw_rows, list) else "?"
            self.failures.append(
                Failure(
                    lang,
                    "derive taint",
                    ["security", str(ws), "taint-analysis", "--no-cache"],
                    f"expected {expected_findings} findings, got {got}",
                )
            )
            return None

        rows: list[dict[str, Any]] = raw_rows
        if lang == "python" and any(
            child_mapping(row, "source").get("rule_id")
            == "entry-point.decorator_handler.param_0"
            and child_mapping(row, "source").get("enclosing_fn") == "run_pipeline"
            for row in rows
        ):
            self.failures.append(
                Failure(
                    lang,
                    "derive taint",
                    ["security", str(ws), "taint-analysis", "--no-cache"],
                    "undecorated run_pipeline inherited handle_request decorators",
                )
            )
            return None
        return rows

    def derive_artifact_ids(
        self,
        lang: str,
        ws: Path,
        first: dict[str, Any],
        entry: str,
        target: str,
    ) -> tuple[str | None, str | None, str | None, str | None, str | None, str | None]:
        inspect = self.check(
            lang,
            "inspect derive",
            [
                "inspect-graph",
                ws,
                "--query",
                target,
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        flow_ids, group_ids = collect_flow_ids(inspect)
        flow_id = flow_ids[0] if flow_ids else first.get("representative_flow_id")
        group_id = group_ids[0] if group_ids else first.get("group_id")

        edges = self.check(
            lang,
            "edges derive",
            ["dump-edges", ws, "--format", "json", "--all"],
            json_out=True,
        )
        edge_id = first_collection_field(edges, "rows", "edge_id")

        ast = self.check(
            lang,
            "ast derive",
            ["dump-ast", ws, "--function", entry, "--format", "json", "--all"],
            json_out=True,
        )
        node_id = first_node_id(ast)

        resolve = self.check(
            lang,
            "resolve derive",
            ["dump-resolve", ws, target, "--format", "json"],
            ok=(0, 2),
            json_out=True,
        )
        candidate_id = first_collection_field(resolve, "candidates", "candidate_id")

        dump_taint = self.check(
            lang,
            "dump-taint derive",
            ["dump-taint", ws, "--source", entry, "--format", "json"],
            json_out=True,
        )
        taint_id = first_collection_field(dump_taint, "records", "taint_id")
        return flow_id, group_id, edge_id, node_id, candidate_id, taint_id

    def derive_validation(
        self, lang: str, ws: Path, rows: list[dict[str, Any]], *, artifact_ids: bool = True
    ) -> DerivedValidation | None:
        first = select_primary_finding(rows)
        entry, target = finding_symbols(first)
        source = child_mapping(first, "source")
        sink = child_mapping(first, "sink")

        export = self.check(lang, "export derive", ["export", ws], json_out=True)
        files = export_files(export)
        source_file = path_or_default(source.get("file"), "app")
        first_file = Path(files[0]).as_posix() if files else source_file
        if not entry or not target:
            names = function_names_from_export(export)
            entry = entry or preferred_function(
                names, {"handle_request", "handleRequest", "handle", "Handle", "main"}
            )
            target = target or preferred_function(
                names,
                {
                    "execute",
                    "Execute",
                    "executeCmd",
                    "run",
                    "Run",
                    "persist",
                    "Persist",
                },
            )
            target = target or entry
        if not entry or not target:
            self.failures.append(
                Failure(lang, "derive symbols", [str(ws)], "missing entry/target")
            )
            return None

        sink_text = sink.get("text")
        sink_text = sink_text if isinstance(sink_text, str) and sink_text else target
        sink_file = path_or_default(sink.get("file"), first_file)
        call_filter_query, call_filter_file, call_filter_fn = finding_call_filter(
            first, target, sink_text, sink_file
        )
        ids = self.derive_artifact_ids(lang, ws, first, entry, target) if artifact_ids else (None,) * 6
        return DerivedValidation(
            entry=entry,
            target=target,
            source_rule=source.get("rule_id") or ".",
            sink_rule=sink.get("rule_id") or ".",
            source_file=source_file,
            sink_file=sink_file,
            call_filter_query=call_filter_query,
            call_filter_file=call_filter_file,
            call_filter_fn=call_filter_fn,
            first_file=first_file,
            flow_id=ids[0],
            group_id=ids[1],
            edge_id=ids[2],
            node_id=ids[3],
            candidate_id=ids[4],
            taint_id=ids[5],
        )

    def validate_lang(self, lang: str, *, filters_only: bool = False) -> None:
        ws = self.root / "examples" / lang / "language_gauntlet"
        if not ws.exists():
            self.failures.append(
                Failure(lang, "workspace", [str(ws)], "missing language_gauntlet")
            )
            return

        rows = self.derive_taint_rows(lang, ws)
        if rows is None:
            return
        context = self.derive_validation(lang, ws, rows, artifact_ids=not filters_only)
        if context is None:
            return

        self.validate_filters(lang, ws, context)
        if filters_only:
            return

        entry = context.entry
        target = context.target
        source_rule = context.source_rule
        sink_rule = context.sink_rule
        source_file = context.source_file
        sink_file = context.sink_file
        call_filter_query = context.call_filter_query
        call_filter_file = context.call_filter_file
        call_filter_fn = context.call_filter_fn
        first_file = context.first_file
        flow_id = context.flow_id
        group_id = context.group_id
        edge_id = context.edge_id
        node_id = context.node_id
        candidate_id = context.candidate_id
        taint_id = context.taint_id

        matrix: list[MatrixEntry] = []

        def add(
            label: str,
            args: list[Any],
            *,
            ok: tuple[int, ...] = (0,),
            nonempty: bool = False,
            json_out: bool = False,
        ) -> None:
            matrix.append((label, args, ok, nonempty, json_out))

        # Reopen each applicable ID family through the public router, not only
        # through its owning command's selector. Resolver and propagation IDs
        # retain the exact query/source context that produced them.
        for label, identifier, extra in [
            ("F", flow_id, []),
            ("G", group_id, []),
            ("E", edge_id, []),
            ("N", node_id, []),
            ("R", candidate_id, ["--query", target]),
            ("T", taint_id, ["--taint-source", entry]),
            ("S", select_primary_finding(rows).get("finding_id"), []),
        ]:
            append_optional_entry(
                matrix,
                identifier,
                f"show {label} id",
                ["show", ws, "--id", identifier, *extra, "--format", "json", "--all"],
                json_out=True,
            )

        add(
            "global --no-color",
            ["--no-color", "defs", ws, "--limit", "1"],
            nonempty=True,
        )
        add(
            "global --no-cache",
            [
                "--no-cache",
                "inspect-graph",
                ws,
                "--query",
                target,
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "global --no-progress",
            [
                "--no-progress",
                "security",
                ws,
                "taint-analysis",
                "--rules-dir",
                self.rules_dir,
                "--format",
                "json",
                "--all",
            ],
            json_out=True,
        )
        add(
            "global --theme",
            ["--theme", "retro-amber", "calls", ws, "--limit", "1"],
            nonempty=True,
        )
        add("index", ["index", ws], nonempty=True)
        add("export", ["export", ws], json_out=True)
        add(
            "export --full-propagations",
            ["export", ws, "--full-propagations"],
            json_out=True,
        )
        add(
            "inspect-graph declaration",
            [
                "inspect-graph",
                ws,
                "--query",
                entry,
                "--kind",
                "decl",
                "--compact",
                "--format",
                "json",
                "--all",
            ],
            json_out=True,
        )
        add(
            "inspect-graph compressed corridor",
            [
                "inspect-graph",
                ws,
                "--from",
                entry,
                "--to",
                target,
                "--format",
                "json",
                "--all",
            ],
            json_out=True,
        )
        add(
            "inspect-graph positional json",
            ["inspect-graph", ws, entry, "--format", "json"],
            json_out=True,
        )
        add(
            "inspect-graph --query",
            ["inspect-graph", ws, "--query", entry, "--format", "json"],
            json_out=True,
        )
        add(
            "inspect-graph --from --to",
            [
                "inspect-graph",
                ws,
                "--from",
                entry,
                "--to",
                target,
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "inspect-graph --context",
            ["inspect-graph", ws, entry, "--context", "4k"],
            nonempty=True,
        )
        add(
            "inspect-graph --page",
            ["inspect-graph", ws, entry, "--page", "1"],
            nonempty=True,
        )
        add(
            "inspect-graph --all",
            ["inspect-graph", ws, entry, "--all"],
            nonempty=True,
        )
        add(
            "inspect-graph text",
            ["inspect-graph", ws, entry, "--format", "text"],
            nonempty=True,
        )
        add("diagnostics", ["diagnostics", ws])
        add("dump-hir positional", ["dump-hir", ws, entry], nonempty=True)
        add("dump-hir --symbol", ["dump-hir", ws, "--symbol", entry], nonempty=True)
        add("dump-cfg positional", ["dump-cfg", ws, entry], nonempty=True)
        add("dump-cfg --symbol", ["dump-cfg", ws, "--symbol", entry], nonempty=True)
        add(
            "dump-callgraph json",
            ["dump-callgraph", ws, "--format", "json", "--all"],
            json_out=True,
        )
        add(
            "dump-callgraph switches",
            [
                "dump-callgraph",
                ws,
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        add(
            "dump-edges json",
            ["dump-edges", ws, "--format", "json", "--all"],
            json_out=True,
        )
        add(
            "dump-edges switches",
            [
                "dump-edges",
                ws,
                "--from",
                entry,
                "--to",
                target,
                "--compact",
                "--limit",
                "10",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        append_optional_entry(
            matrix,
            edge_id,
            "dump-edges --edge",
            ["dump-edges", ws, "--edge", edge_id, "--format", "json"],
            json_out=True,
        )
        add(
            "dump-ast positional",
            ["dump-ast", ws, entry, "--format", "json", "--all"],
            json_out=True,
        )
        add(
            "dump-ast file switches",
            [
                "dump-ast",
                ws,
                "--file",
                first_file,
                "--compact",
                "--max-depth",
                "3",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        add(
            "dump-ast --function",
            ["dump-ast", ws, "--function", entry, "--format", "json"],
            json_out=True,
        )
        append_optional_entry(
            matrix,
            node_id,
            "dump-ast --node",
            ["dump-ast", ws, "--node", node_id, "--format", "json"],
            json_out=True,
        )
        add(
            "dump-resolve positional",
            ["dump-resolve", ws, target, "--format", "json"],
            ok=(0, 2),
            json_out=True,
        )
        add(
            "dump-resolve switches",
            [
                "dump-resolve",
                ws,
                "--name",
                target,
                "--in-file",
                sink_file,
                "--compact",
                "--format",
                "text",
            ],
            ok=(0, 2),
            nonempty=True,
        )
        append_optional_entry(
            matrix,
            candidate_id,
            "dump-resolve --candidate",
            [
                "dump-resolve",
                ws,
                target,
                "--candidate",
                candidate_id,
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "dump-taint basic",
            ["dump-taint", ws, "--source", entry, "--format", "json"],
            json_out=True,
        )
        add(
            "dump-taint switches",
            [
                "dump-taint",
                ws,
                "--source",
                entry,
                "--seed",
                "cmd",
                "--sink",
                target,
                "--compact",
                "--all",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        append_optional_entry(
            matrix,
            taint_id,
            "dump-taint --taint",
            [
                "dump-taint",
                ws,
                "--source",
                entry,
                "--taint",
                taint_id,
                "--format",
                "json",
            ],
            json_out=True,
        )

        add(
            "defs all switches",
            [
                "defs",
                ws,
                "--kind",
                "function",
                "--file",
                first_file,
                "--name",
                entry[:4],
                "--has-callee",
                target,
                "--has-decorator",
                "decorator",
                "--has-param",
                "cmd",
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "calls all switches",
            [
                "calls",
                ws,
                "--callee",
                target[:4],
                "--file",
                sink_file,
                "--caller",
                entry,
                "--call-kind",
                "function",
                "--regex",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--summaries",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "imports all switches",
            [
                "imports",
                ws,
                "--file",
                first_file,
                "--module",
                ".",
                "--alias",
                "x",
                "--wildcard",
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "vars all switches",
            [
                "vars",
                ws,
                "--name",
                "cmd",
                "--file",
                first_file,
                "--in-fn",
                entry,
                "--source",
                "cmd",
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "strings all switches",
            [
                "strings",
                ws,
                "--category",
                "generic",
                "--contains",
                "cmd",
                "--file",
                first_file,
                "--in-fn",
                entry,
                "--min-len",
                "1",
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "comments all switches",
            [
                "comments",
                ws,
                "--kind",
                "generic",
                "--contains",
                "SOURCE|SINK|NEGATIVE",
                "--file",
                first_file,
                "--in-fn",
                entry,
                "--min-len",
                "1",
                "--regex",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "args all switches",
            [
                "args",
                ws,
                "--callee",
                target[:4],
                "--file",
                sink_file,
                "--in-fn",
                target,
                "--value",
                "cmd",
                "--position",
                "0",
                "--keyword",
                "cmd",
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "classes all switches",
            [
                "classes",
                ws,
                "--name",
                "Envelope",
                "--file",
                first_file,
                "--kind",
                "class",
                "--has-method",
                target,
                "--min-methods",
                "0",
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "refs all switches",
            [
                "refs",
                ws,
                "--symbol",
                target,
                "--kind",
                "call",
                "--file",
                sink_file,
                "--in-fn",
                target,
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "search all switches",
            [
                "search",
                ws,
                "--query",
                entry,
                "--kind",
                "function",
                "--file",
                first_file,
                "--regex",
                "--limit",
                "5",
                "--summaries",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "tree all switches",
            [
                "tree",
                ws,
                "--max-depth",
                "3",
                "--file",
                first_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "10",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "read-file all switches",
            [
                "read-file",
                ws,
                first_file,
                "--lines",
                "1:50",
                "--from",
                entry,
                "--to",
                target,
                "--max-inlined-bodies",
                "2",
                "--compact",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
                "--rules-dir",
                self.rules_dir,
            ],
            json_out=True,
        )

        add(
            "inspect-graph positional",
            ["inspect-graph", ws, target, "--format", "json", "--all"],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "inspect-graph decl-kind switches",
            [
                "inspect-graph",
                ws,
                "--query",
                entry,
                "--regex",
                "--from",
                entry,
                "--from-kind",
                "decl",
                "--to",
                entry,
                "--to-kind",
                "decl",
                "--all",
                "--compact",
                "--view",
                "auto",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "json",
            ],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "inspect-graph call filters",
            [
                "inspect-graph",
                ws,
                "--query",
                call_filter_query,
                "--kind",
                "call",
                "--file",
                call_filter_file,
                "--in-fn",
                call_filter_fn,
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "inspect-graph grouped",
            [
                "inspect-graph",
                ws,
                "--query",
                target,
                "--view",
                "grouped",
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        append_optional_entry(
            matrix,
            flow_id,
            "inspect-graph --flow",
            [
                "inspect-graph",
                ws,
                "--query",
                target,
                "--flow",
                flow_id,
                "--format",
                "json",
            ],
            ok=(0, 1),
            json_out=True,
        )
        append_optional_entry(
            matrix,
            group_id,
            "inspect-graph --group",
            [
                "inspect-graph",
                ws,
                "--query",
                target,
                "--view",
                "grouped",
                "--group",
                group_id,
                "--format",
                "json",
            ],
            ok=(0, 1),
            json_out=True,
        )

        # `--rules-dir` is per-subcommand — it must follow each
        # security subcommand name (sources/sinks/...), not the
        # parent `security` verb.
        sec = ["security", ws]
        rd = ["--rules-dir", self.rules_dir]
        add(
            "security sources switches",
            [
                *sec,
                "sources",
                *rd,
                "--rule",
                source_rule,
                "--rule-regex",
                ".*",
                "--trust",
                "local",
                "--category",
                "inferred",
                "--tag",
                "entry-point",
                "--file",
                source_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security sinks switches",
            [
                *sec,
                "sinks",
                *rd,
                "--rule",
                sink_rule,
                "--rule-regex",
                ".*",
                "--severity",
                "critical",
                "--tag",
                "command-injection",
                "--file",
                sink_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security sanitizers switches",
            [
                *sec,
                "sanitizers",
                *rd,
                "--rule",
                "none",
                "--rule-regex",
                ".*",
                "--tag",
                "shell-escape",
                "--file",
                first_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security deps switches",
            [
                *sec,
                "deps",
                *rd,
                "--framework",
                "none",
                "--severity",
                "critical",
                "--file",
                first_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security taint switches",
            [
                *sec,
                "taint-analysis",
                *rd,
                "--source",
                ".*",
                "--trust",
                "local",
                "--category",
                "inferred",
                "--sink",
                ".*",
                "--severity",
                "critical",
                "--tag",
                "command-injection",
                "--file",
                sink_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--inferred-sources",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security source-analysis switches",
            [
                *sec,
                "source-analysis",
                *rd,
                "--source",
                ".*",
                "--trust",
                "local",
                "--tag",
                "entry-point",
                "--category",
                "inferred",
                "--file",
                source_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--inferred-sources",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security pack switches",
            [
                *sec,
                "pack",
                *rd,
                "--lang",
                lang,
                "--category",
                "cmdi",
                "--kind",
                "sink",
                "--severity",
                "critical",
                "--audit",
                "--tree",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--limit",
                "10",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add("cache stats", ["cache", "stats", ws], nonempty=True)

        with tempfile.TemporaryDirectory(prefix=f"cli_matrix_{lang}_") as temp_dir:
            temp_ws = Path(temp_dir) / "language_gauntlet"
            shutil.copytree(ws, temp_ws)
            add(
                "cache clear --dataflow-only",
                ["cache", "clear", temp_ws, "--dataflow-only"],
            )
            add("cache rebuild", ["cache", "rebuild", temp_ws])
            add("cache clear", ["cache", "clear", temp_ws])
            for label, args, ok, nonempty, json_out in matrix:
                result = self.check(
                    lang, label, args, ok=ok, nonempty=nonempty, json_out=json_out
                )
                if label == "inspect-graph compressed corridor":
                    self.validate_corridor_reopen(lang, ws, result)
                if label.startswith("show "):
                    identifier = str(args[args.index("--id") + 1])
                    if identifier not in json.dumps(result):
                        self.failures.append(
                            Failure(lang, label, list(map(str, args)), f"reopened result lost {identifier}")
                        )

        self.counts.append((lang, len(matrix)))

    def validate_corridor_reopen(self, lang: str, ws: Path, document: Any) -> None:
        corridor = child_mapping(document, "corridor") if isinstance(document, dict) else {}
        identifier = child_mapping(corridor, "stack").get("flow_id")
        if not isinstance(identifier, str) or not identifier.startswith("F:"):
            self.failures.append(Failure(
                lang, "corridor flow id", ["inspect-graph", str(ws)],
                "concrete source-to-sink fixture did not emit an addressable corridor stack",
            ))
            return
        arguments = ["show", ws, "--id", identifier, "--compact", "--format", "json", "--all"]
        reopened = self.check(lang, "show endpoint corridor", arguments, json_out=True)
        self.counts.append((f"{lang}/endpoint-roundtrip", 1))
        selected = child_mapping(reopened, "corridor") if isinstance(reopened, dict) else {}
        if (child_mapping(selected, "stack").get("flow_id") != identifier
                or any(selected.get(field) != corridor.get(field)
                       for field in ("from", "to", "nodes", "edges"))):
            self.failures.append(Failure(
                lang, "show endpoint corridor", list(map(str, arguments)),
                "show lost the originating endpoints, exact corridor, or requested flow id",
            ))

    def validate_realworld_redis_footers(self) -> None:
        ws = self.root / "examples" / "realworld" / "redis"
        if not ws.exists():
            return
        checks: list[tuple[str, list[Any]]] = [
            ("defs", ["defs", ws]),
            ("calls", ["calls", ws]),
            ("imports", ["imports", ws]),
            ("vars", ["vars", ws]),
            ("strings", ["strings", ws]),
            ("comments", ["comments", ws]),
            ("args", ["args", ws]),
            ("classes", ["classes", ws]),
            ("refs", ["refs", ws, "server"]),
            ("search", ["search", ws, "--query", "strcpy"]),
            ("tree", ["tree", ws]),
            ("read-file", ["read-file", ws, "src/server.c"]),
            ("dump-callgraph", ["dump-callgraph", ws]),
            ("dump-edges", ["dump-edges", ws]),
            ("dump-ast", ["dump-ast", ws, "--file", "src/server.c"]),
            ("inspect-graph", ["inspect-graph", ws, "--query", "strcpy"]),
            ("inspect-graph query", ["inspect-graph", ws, "--query", "main"]),
            ("security sources", ["security", ws, "sources"]),
            ("security sinks", ["security", ws, "sinks"]),
            ("security sanitizers", ["security", ws, "sanitizers"]),
            ("security deps", ["security", ws, "deps"]),
            ("security taint-analysis", ["security", ws, "taint-analysis"]),
            ("security source-analysis", ["security", ws, "source-analysis"]),
            ("security pack", ["security", ws, "pack"]),
        ]
        for label, args in checks:
            if "--context" in [str(arg) for arg in args]:
                cmd = [*args, "--no-color", "--no-progress"]
            else:
                cmd = [*args, "--context", "32k", "--no-color", "--no-progress"]
            self.check("realworld/redis", label, cmd, nonempty=True)
        self.counts.append(("realworld/redis footers", len(checks)))

    def report(self) -> int:
        print("COMMAND COUNTS")
        for lang, count in self.counts:
            print(f"{lang}: {count}")
        if self.filter_coverage:
            print("\nFILTER FACT COVERAGE (empty baselines are not positive coverage)")
            for (lang, command), coverage in self.filter_coverage.items():
                rows = coverage.baseline_rows
                status = "FAILED BASELINE" if rows is None else ("EMPTY" if rows == 0 else str(rows))
                print(
                    f"{lang}/{command}: rows={status} commands={coverage.commands} "
                    f"positive={coverage.positive_cases} strict-subsets={coverage.strict_subset_cases} "
                    f"primary-negatives={coverage.primary_negatives} cursor-pages={coverage.pagination_pages}"
                )
        if not self.failures:
            print("\nALL COMMAND/SWITCH VALIDATION PASSED")
            return 0
        print("\nFAILURES")
        for failure in self.failures[:200]:
            print(f"[{failure.lang}] {failure.label}: {failure.message}")
            print(f"  args={failure.args}")
            if failure.stdout:
                print("  stdout:", failure.stdout.replace("\n", " ")[:900])
            if failure.stderr:
                print("  stderr:", failure.stderr.replace("\n", " ")[:900])
        print(f"total failures: {len(self.failures)}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", help="Path to bonsai-ninja binary")
    parser.add_argument(
        "--lang",
        action="append",
        choices=LANGS,
        help="Restrict to one language; repeatable",
    )
    parser.add_argument(
        "--skip-realworld",
        action="store_true",
        help="Skip the Redis realworld header/footer stress sweep",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--realworld-only",
        action="store_true",
        help="Run only the Redis realworld header/footer stress sweep",
    )
    mode.add_argument(
        "--filters-only",
        action="store_true",
        help="Run only the 20-language browse filter sweep (retains existing selector derivation)",
    )
    args = parser.parse_args()

    root = repo_root()
    validator = Validator(root, find_bin(root, args.bin), root / "security-patterns")
    if not args.realworld_only:
        validator.validate_global()
        for lang in args.lang or LANGS:
            validator.validate_lang(lang, filters_only=args.filters_only)
    if args.realworld_only or (not args.filters_only and not args.skip_realworld):
        validator.validate_realworld_redis_footers()
    return validator.report()


if __name__ == "__main__":
    raise SystemExit(main())
