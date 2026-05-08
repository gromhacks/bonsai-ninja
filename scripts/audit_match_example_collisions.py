#!/usr/bin/env python3
"""Audit rule match_examples against the shipped matcher.

The script batches every `match_examples` snippet by language + rule kind,
runs the normal `bonsai-ninja security <inventory>` command against those
snippets, and reports:

* owner misses: the rule that owns an example did not match it;
* expected text misses: the owner matched, but not the declared text;
* collisions: another enabled rule matched the same example file.

Collision rows are merge candidates. They mean two rules can recognize the
same adapter fact in at least one fixture, so the rules should be merged,
split by a more precise match shape, or otherwise de-duplicated.

Rules using `arg_tainted` are excluded from BOTH collision and owner-
miss accounting. The inventory command is the pre-taint
sink/source/sanitizer pass and intentionally ignores tainted-argument
predicates, so an `arg_tainted` rule's example will never report a
match in this audit even when the example syntactically nails the
rule's shape. The taint-aware validator and `rulepack_conformance`
tests are the right place to verify those examples; flagging them as
owner-misses here would be a false positive.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


KIND_COMMAND = {
    "sources": "sources",
    "sinks": "sinks",
    "sanitizers": "sanitizers",
}

DEFAULT_EXT = {
    "c": "c",
    "cpp": "cpp",
    "csharp": "cs",
    "dart": "dart",
    "elixir": "ex",
    "erlang": "erl",
    "go": "go",
    "java": "java",
    "javascript": "js",
    "kotlin": "kt",
    "lua": "lua",
    "objc": "m",
    "perl": "pl",
    "php": "php",
    "python": "py",
    "ruby": "rb",
    "rust": "rs",
    "scala": "scala",
    "solidity": "sol",
    "swift": "swift",
    "typescript": "ts",
}


@dataclass(frozen=True)
class ExampleCase:
    key: str
    rule_id: str
    language: str
    kind: str
    source_path: str
    example_name: str
    rel_path: str
    expected_text: tuple[str, ...]
    expect_no_match: bool
    enabled: bool


@dataclass(frozen=True)
class Finding:
    case_key: str
    owner_rule: str
    owner_kind: str
    matched_rule: str
    command_kind: str
    text: str
    line: int | None
    file: str


def load_yaml_rules(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text()) or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def rule_uses_arg_tainted(rule: dict[str, Any]) -> bool:
    constraints = rule.get("constraints") or []
    if not isinstance(constraints, list):
        return False
    return any(isinstance(item, dict) and "arg_tainted" in item for item in constraints)


def arg_tainted_rule_ids(rules_root: Path) -> set[str]:
    ids: set[str] = set()
    for path in sorted((rules_root / "langs").rglob("*.yml")):
        for rule in load_yaml_rules(path):
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_uses_arg_tainted(rule):
                ids.add(rule_id)
    return ids


def safe_rel_path(raw: str | None, language: str) -> Path:
    fallback = f"example.{DEFAULT_EXT.get(language, 'txt')}"
    candidate = Path(raw or fallback)
    if candidate.is_absolute():
        candidate = Path(*candidate.parts[1:])
    parts = [p for p in candidate.parts if p not in ("", ".", "..")]
    if not parts:
        parts = [fallback]
    return Path(*parts)


def iter_cases(
    rules_root: Path,
    langs: set[str] | None,
    kinds: set[str] | None,
    include_disabled: bool,
) -> Iterable[tuple[ExampleCase, str]]:
    langs_dir = rules_root / "langs"
    seq = 0
    for path in sorted(langs_dir.rglob("*.yml")):
        rel = path.relative_to(rules_root)
        parts = rel.parts
        if len(parts) < 4:
            continue
        _, path_lang, kind, *_ = parts
        if kind not in KIND_COMMAND:
            continue
        if langs and path_lang not in langs:
            continue
        if kinds and kind not in kinds:
            continue
        for rule in load_yaml_rules(path):
            rule_id = str(rule.get("id") or "")
            language = str(rule.get("language") or path_lang)
            enabled = rule.get("enabled") is True
            if not rule_id or (not enabled and not include_disabled):
                continue
            examples = rule.get("match_examples") or []
            if not isinstance(examples, list):
                continue
            for idx, example in enumerate(examples):
                if not isinstance(example, dict):
                    continue
                code = example.get("code")
                if not isinstance(code, str):
                    continue
                seq += 1
                example_path = safe_rel_path(example.get("path"), language)
                case_dir = Path(f"case_{seq:05d}")
                rel_path = case_dir / example_path
                expected = example.get("expect_match_text") or []
                if not isinstance(expected, list):
                    expected = []
                expect_no_match = example.get("expect_no_match") is True
                name = example.get("name") or f"example {idx + 1}"
                yield (
                    ExampleCase(
                        key=case_dir.as_posix(),
                        rule_id=rule_id,
                        language=language,
                        kind=kind,
                        source_path=str(rel),
                        example_name=str(name),
                        rel_path=rel_path.as_posix(),
                        expected_text=tuple(str(x) for x in expected),
                        expect_no_match=expect_no_match,
                        enabled=enabled,
                    ),
                    code,
                )


def resolve_binary(value: str | None) -> str:
    if value:
        return value
    release = Path("target/release/bonsai-ninja")
    if release.exists():
        return str(release)
    debug = Path("target/debug/bonsai-ninja")
    if debug.exists():
        return str(debug)
    found = shutil.which("bonsai-ninja")
    if found:
        return found
    return str(release)


def run_inventory(
    binary: str,
    workspace: Path,
    rules_root: Path,
    command_kind: str,
) -> list[dict[str, Any]]:
    cmd = [
        binary,
        "security",
        str(workspace),
        KIND_COMMAND[command_kind],
        "--rules-dir",
        str(rules_root),
        "--format",
        "json",
        "--all",
        "--no-color",
        "--no-progress",
        "--context",
        "64k",
    ]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(cmd)} failed with exit {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    payload = json.loads(proc.stdout or "{}")
    rows = payload.get("rows") or []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def write_group_workspace(root: Path, group: list[tuple[ExampleCase, str]]) -> dict[Path, ExampleCase]:
    file_to_case: dict[Path, ExampleCase] = {}
    for case, code in group:
        path = root / case.rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
        file_to_case[path.resolve()] = case
    return file_to_case


def print_section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run match_examples through bonsai-ninja and report rule collisions."
    )
    parser.add_argument("rules_dir", nargs="?", default="security-patterns")
    parser.add_argument("--bin", dest="binary", help="Path to bonsai-ninja binary.")
    parser.add_argument("--lang", action="append", help="Limit to a language. Repeatable.")
    parser.add_argument(
        "--kind",
        action="append",
        choices=sorted(KIND_COMMAND),
        help="Limit to sources, sinks, or sanitizers. Repeatable.",
    )
    parser.add_argument("--include-disabled", action="store_true")
    parser.add_argument(
        "--cross-kind",
        action="store_true",
        help="Also run the other inventory families against each example.",
    )
    parser.add_argument("--limit", type=int, help="Limit number of examples after filters.")
    parser.add_argument("--json-out", type=Path, help="Write full machine-readable report.")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for stdout (default: text).",
    )
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument(
        "--allow-collisions",
        action="store_true",
        help="Report collisions but exit 0 when collisions are the only issue.",
    )
    parser.add_argument(
        "--no-fail-on-owner-miss",
        dest="fail_on_owner_miss",
        action="store_false",
        help="Report owner/example drift but exit 0 when that is the only issue.",
    )
    parser.set_defaults(fail_on_owner_miss=True)
    args = parser.parse_args()

    rules_root = Path(args.rules_dir).resolve()
    binary = resolve_binary(args.binary)
    langs = set(args.lang) if args.lang else None
    kinds = set(args.kind) if args.kind else None
    arg_tainted_rules = arg_tainted_rule_ids(rules_root)

    cases_with_code = list(iter_cases(rules_root, langs, kinds, args.include_disabled))
    if args.limit is not None:
        cases_with_code = cases_with_code[: args.limit]
    cases = [case for case, _ in cases_with_code]

    grouped: dict[tuple[str, str], list[tuple[ExampleCase, str]]] = defaultdict(list)
    for case, code in cases_with_code:
        grouped[(case.language, case.kind)].append((case, code))

    all_findings: list[Finding] = []
    owner_misses: list[dict[str, Any]] = []
    expected_text_misses: list[dict[str, Any]] = []
    command_errors: list[str] = []
    temp_paths: list[Path] = []

    for (language, owner_kind), group in sorted(grouped.items()):
        tmp = Path(tempfile.mkdtemp(prefix=f"bonsai-match-examples-{language}-{owner_kind}-")).resolve()
        temp_paths.append(tmp)
        file_to_case = write_group_workspace(tmp, group)
        command_kinds = sorted(KIND_COMMAND) if args.cross_kind else [owner_kind]
        rows_by_case: dict[str, list[Finding]] = defaultdict(list)

        for command_kind in command_kinds:
            try:
                rows = run_inventory(binary, tmp, rules_root, command_kind)
            except Exception as exc:  # noqa: BLE001 - report and continue other groups.
                command_errors.append(f"{language}/{owner_kind}/{command_kind}: {exc}")
                continue
            for row in rows:
                file_raw = row.get("file")
                if not isinstance(file_raw, str):
                    continue
                case = file_to_case.get(Path(file_raw).resolve())
                if case is None:
                    continue
                if case.expect_no_match:
                    continue
                finding = Finding(
                    case_key=case.key,
                    owner_rule=case.rule_id,
                    owner_kind=case.kind,
                    matched_rule=str(row.get("rule_id") or ""),
                    command_kind=command_kind,
                    text=str(row.get("text") or ""),
                    line=row.get("line") if isinstance(row.get("line"), int) else None,
                    file=str(Path(file_raw).resolve().relative_to(tmp)),
                )
                all_findings.append(finding)
                rows_by_case[case.key].append(finding)

        for case, _ in group:
            if case.expect_no_match:
                continue
            # Rules with `arg_tainted` constraints can't match in
            # isolated examples — they need a taint source-to-sink
            # chain to fire. The example is the rule's correct
            # syntactic shape, so flagging it as an owner-miss only
            # because the static analyser found no taint flow would
            # be a false positive in this audit's accounting. Same
            # treatment as collision filtering below.
            if case.rule_id in arg_tainted_rules:
                continue
            hits = rows_by_case.get(case.key, [])
            owner_hits = [hit for hit in hits if hit.matched_rule == case.rule_id]
            if not owner_hits:
                owner_misses.append(asdict(case))
                continue
            for expected in case.expected_text:
                if not any(hit.text == expected for hit in owner_hits):
                    expected_text_misses.append(
                        {
                            **asdict(case),
                            "expected": expected,
                            "got": sorted({hit.text for hit in owner_hits}),
                        }
                    )

    collisions = [
        hit
        for hit in all_findings
        if hit.matched_rule and hit.matched_rule != hit.owner_rule
        and hit.owner_rule not in arg_tainted_rules
        and hit.matched_rule not in arg_tainted_rules
    ]
    collision_pairs = Counter((hit.owner_rule, hit.matched_rule, hit.command_kind) for hit in collisions)
    merge_candidates = [
        {
            "owner_rule": owner,
            "matched_rule": matched,
            "command_kind": command_kind,
            "count": count,
        }
        for (owner, matched, command_kind), count in collision_pairs.most_common()
    ]
    report_payload = {
        "rules_dir": str(rules_root),
        "binary": binary,
        "examples": [asdict(case) for case in cases],
        "owner_misses": owner_misses,
        "expected_text_misses": expected_text_misses,
        "collisions": [asdict(hit) for hit in collisions],
        "collision_pairs": merge_candidates,
        "merge_candidates": merge_candidates,
        "command_errors": command_errors,
        "summary": {
            "examples": len(cases),
            "groups": len(grouped),
            "owner_misses": len(owner_misses),
            "expected_text_misses": len(expected_text_misses),
            "collision_hits": len(collisions),
            "collision_pairs": len(collision_pairs),
            "command_errors": len(command_errors),
        },
    }

    if args.format == "json":
        print(json.dumps(report_payload, indent=2, sort_keys=True))
    else:
        print(f"rules_dir: {rules_root}")
        print(f"binary: {binary}")
        print(f"examples: {len(cases)}")
        print(f"groups: {len(grouped)}")
        print(f"owner misses: {len(owner_misses)}")
        print(f"expected text misses: {len(expected_text_misses)}")
        print(f"collision hits: {len(collisions)}")
        print(f"collision pairs: {len(collision_pairs)}")

    if args.format == "text" and command_errors:
        print_section("Command Errors")
        for error in command_errors[:50]:
            print(error)
        if len(command_errors) > 50:
            print(f"... {len(command_errors) - 50} more")

    if args.format == "text" and owner_misses:
        print_section("Owner Misses")
        for miss in owner_misses[:100]:
            print(
                f"{miss['rule_id']} [{miss['language']}/{miss['kind']}] "
                f"{miss['example_name']} ({miss['source_path']})"
            )
        if len(owner_misses) > 100:
            print(f"... {len(owner_misses) - 100} more")

    if args.format == "text" and expected_text_misses:
        print_section("Expected Text Misses")
        for miss in expected_text_misses[:100]:
            print(
                f"{miss['rule_id']} [{miss['language']}/{miss['kind']}] "
                f"{miss['example_name']}: expected {miss['expected']!r}, got {miss['got']}"
            )
        if len(expected_text_misses) > 100:
            print(f"... {len(expected_text_misses) - 100} more")

    if args.format == "text" and collision_pairs:
        print_section("Collision Pairs")
        for (owner, matched, command_kind), count in collision_pairs.most_common(100):
            print(f"{count:4} {owner}  <->  {matched}  ({command_kind})")
        if len(collision_pairs) > 100:
            print(f"... {len(collision_pairs) - 100} more")

        print_section("Collision Examples")
        for hit in collisions[:100]:
            print(
                f"{hit.owner_rule} example {hit.case_key} also matched "
                f"{hit.matched_rule} ({hit.command_kind}) text={hit.text!r} file={hit.file}"
            )
        if len(collisions) > 100:
            print(f"... {len(collisions) - 100} more")

    if args.json_out:
        args.json_out.write_text(json.dumps(report_payload, indent=2, sort_keys=True) + "\n")

    if args.keep_temp:
        print_section("Temporary Workspaces")
        for path in temp_paths:
            print(path)
    else:
        for path in temp_paths:
            shutil.rmtree(path, ignore_errors=True)

    if command_errors:
        return 2
    if args.fail_on_owner_miss and (owner_misses or expected_text_misses):
        return 1
    if collisions and not args.allow_collisions:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
