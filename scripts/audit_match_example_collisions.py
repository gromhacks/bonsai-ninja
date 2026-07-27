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

Rules using a taint-dependent constraint (`arg_tainted`,
`any_arg_tainted`, `receiver_tainted`, or the compiler-backed receiver
origin/callback proof) are excluded from BOTH collision and owner-miss
accounting. The inventory command is the pre-taint
sink/source/sanitizer pass and intentionally ignores those predicates,
so its match text can differ from the final attributed taint finding.
The taint-replay validator and `rulepack_conformance` tests are the right
place to verify those examples; treating inventory output as the final
taint result would be a false positive.

Rules tagged `passthrough-transform` are also excluded when they overlap a
non-passthrough sanitizer/source/sink example. Those rules encode taint
propagation semantics for otherwise safe transformations, not separate
security boundaries. A function can legitimately be both a category-specific
sanitizer and a taint-preserving transform for other categories.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
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


@dataclass
class AuditRun:
    findings: list[Finding] = field(default_factory=list)
    owner_misses: list[dict[str, Any]] = field(default_factory=list)
    expected_text_misses: list[dict[str, Any]] = field(default_factory=list)
    command_errors: list[str] = field(default_factory=list)
    temp_paths: list[Path] = field(default_factory=list)


def load_yaml_rules(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text()) or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


TAINT_CONSTRAINTS = frozenset(
    {
        "arg_tainted",
        "any_arg_tainted",
        "receiver_tainted",
        "receiver_origin_callback_param_reaches_call",
    }
)


def rule_uses_taint_constraint(rule: dict[str, Any]) -> bool:
    constraints = rule.get("constraints") or []
    if not isinstance(constraints, list):
        return False
    return any(
        isinstance(item, dict) and not TAINT_CONSTRAINTS.isdisjoint(item)
        for item in constraints
    )


def taint_dependent_rule_ids(rules_root: Path) -> set[str]:
    ids: set[str] = set()
    for path in sorted((rules_root / "langs").rglob("*.yml")):
        for rule in load_yaml_rules(path):
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_uses_taint_constraint(rule):
                ids.add(rule_id)
    return ids


def rule_tags(rules_root: Path) -> dict[str, str]:
    tags: dict[str, str] = {}
    for path in sorted((rules_root / "langs").rglob("*.yml")):
        for rule in load_yaml_rules(path):
            rule_id = rule.get("id")
            tag = rule.get("tag")
            if isinstance(rule_id, str) and isinstance(tag, str):
                tags[rule_id] = tag
    return tags


def is_passthrough_sidecar_overlap(hit: Finding, tags: dict[str, str]) -> bool:
    owner_tag = tags.get(hit.owner_rule)
    matched_tag = tags.get(hit.matched_rule)
    return (owner_tag == "passthrough-transform") ^ (
        matched_tag == "passthrough-transform"
    )


def is_same_family_layered_overlap(
    hit: Finding,
    tags: dict[str, str],
    expected_by_case: dict[str, frozenset[str]],
) -> bool:
    """A same-tag sibling rule that matched a DIFFERENT construct than the
    example demonstrates is a legitimate layered overlap, not a rule
    ambiguity. The canonical case: the GraphQL `args` param source
    (`graphql_resolver_args`, matches the `args` param) co-occurs in the
    examples of `graphql_args_field` (`args.input` read) and
    `graphql_info_context_args` (`info.context.args` read). All three are
    `graphql-input`; the param and the field-reads seed DIFFERENT nodes
    (the combiner dedups any shared finding), so flagging them as
    colliding is a false positive — the example just happens to contain
    the param the field is read from. We only suppress when (a) both
    rules share a tag and (b) the colliding match text is NOT one of the
    owner example's demonstrated `expect_match_text` (i.e. a different
    construct). Same-construct same-tag overlaps (a real two-rules-one-
    node ambiguity) and all cross-tag overlaps stay flagged."""
    owner_tag = tags.get(hit.owner_rule)
    matched_tag = tags.get(hit.matched_rule)
    if owner_tag is None or owner_tag != matched_tag:
        return False
    owner_expected = expected_by_case.get(hit.case_key, frozenset())
    return hit.text not in owner_expected


def safe_rel_path(raw: str | None, language: str) -> Path:
    fallback = f"example.{DEFAULT_EXT.get(language, 'txt')}"
    candidate = Path(raw or fallback)
    if candidate.is_absolute():
        candidate = Path(*candidate.parts[1:])
    parts = [p for p in candidate.parts if p not in ("", ".", "..")]
    if not parts:
        parts = [fallback]
    return Path(*parts)


def rule_file_scope(
    path: Path,
    rules_root: Path,
    langs: set[str] | None,
    kinds: set[str] | None,
) -> tuple[Path, str, str] | None:
    rel = path.relative_to(rules_root)
    parts = rel.parts
    if len(parts) < 4:
        return None
    _, path_lang, kind, *_ = parts
    if kind not in KIND_COMMAND:
        return None
    if langs and path_lang not in langs:
        return None
    if kinds and kind not in kinds:
        return None
    return rel, path_lang, kind


def example_case(
    *,
    sequence: int,
    rule: dict[str, Any],
    example: object,
    example_index: int,
    rel: Path,
    path_lang: str,
    kind: str,
    include_disabled: bool,
) -> tuple[ExampleCase, str] | None:
    rule_id = str(rule.get("id") or "")
    language = str(rule.get("language") or path_lang)
    enabled = rule.get("enabled") is True
    if not rule_id or (not enabled and not include_disabled):
        return None
    if not isinstance(example, dict):
        return None
    code = example.get("code")
    if not isinstance(code, str):
        return None

    case_dir = Path(f"case_{sequence:05d}")
    rel_path = case_dir / safe_rel_path(example.get("path"), language)
    expected = example.get("expect_match_text") or []
    if not isinstance(expected, list):
        expected = []
    return (
        ExampleCase(
            key=case_dir.as_posix(),
            rule_id=rule_id,
            language=language,
            kind=kind,
            source_path=str(rel),
            example_name=str(example.get("name") or f"example {example_index + 1}"),
            rel_path=rel_path.as_posix(),
            expected_text=tuple(str(value) for value in expected),
            expect_no_match=example.get("expect_no_match") is True,
            enabled=enabled,
        ),
        code,
    )


def iter_cases(
    rules_root: Path,
    langs: set[str] | None,
    kinds: set[str] | None,
    include_disabled: bool,
) -> Iterable[tuple[ExampleCase, str]]:
    langs_dir = rules_root / "langs"
    seq = 0
    for path in sorted(langs_dir.rglob("*.yml")):
        scope = rule_file_scope(path, rules_root, langs, kinds)
        if scope is None:
            continue
        rel, path_lang, kind = scope
        for rule in load_yaml_rules(path):
            examples = rule.get("match_examples") or []
            if not isinstance(examples, list):
                continue
            for index, example in enumerate(examples):
                candidate = example_case(
                    sequence=seq + 1,
                    rule=rule,
                    example=example,
                    example_index=index,
                    rel=rel,
                    path_lang=path_lang,
                    kind=kind,
                    include_disabled=include_disabled,
                )
                if candidate is None:
                    continue
                seq += 1
                yield candidate


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


def write_group_workspace(
    root: Path, group: list[tuple[ExampleCase, str]]
) -> dict[Path, ExampleCase]:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run match_examples through bonsai-ninja and report rule collisions."
    )
    parser.add_argument("rules_dir", nargs="?", default="security-patterns")
    parser.add_argument("--bin", dest="binary", help="Path to bonsai-ninja binary.")
    parser.add_argument(
        "--lang", action="append", help="Limit to a language. Repeatable."
    )
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
    parser.add_argument(
        "--limit", type=int, help="Limit number of examples after filters."
    )
    parser.add_argument(
        "--json-out", type=Path, help="Write full machine-readable report."
    )
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
    return parser.parse_args()


def group_cases(
    cases_with_code: list[tuple[ExampleCase, str]],
) -> dict[tuple[str, str], list[tuple[ExampleCase, str]]]:
    grouped: dict[tuple[str, str], list[tuple[ExampleCase, str]]] = defaultdict(list)
    for case, code in cases_with_code:
        grouped[(case.language, case.kind)].append((case, code))
    return grouped


def collect_inventory_rows(
    rows: list[dict[str, Any]],
    command_kind: str,
    file_to_case: dict[Path, ExampleCase],
    workspace: Path,
    rows_by_case: dict[str, list[Finding]],
    run: AuditRun,
) -> None:
    for row in rows:
        file_raw = row.get("file")
        if not isinstance(file_raw, str):
            continue
        case = file_to_case.get(Path(file_raw).resolve())
        if case is None or case.expect_no_match:
            continue
        finding = Finding(
            case_key=case.key,
            owner_rule=case.rule_id,
            owner_kind=case.kind,
            matched_rule=str(row.get("rule_id") or ""),
            command_kind=command_kind,
            text=str(row.get("text") or ""),
            line=row.get("line") if isinstance(row.get("line"), int) else None,
            file=str(Path(file_raw).resolve().relative_to(workspace)),
        )
        run.findings.append(finding)
        rows_by_case[case.key].append(finding)


def collect_owner_expectations(
    group: list[tuple[ExampleCase, str]],
    rows_by_case: dict[str, list[Finding]],
    taint_dependent_rules: set[str],
    run: AuditRun,
) -> None:
    for case, _ in group:
        if case.expect_no_match or case.rule_id in taint_dependent_rules:
            continue
        owner_hits = [
            hit
            for hit in rows_by_case.get(case.key, [])
            if hit.matched_rule == case.rule_id
        ]
        if not owner_hits:
            run.owner_misses.append(asdict(case))
            continue
        for expected in case.expected_text:
            if any(hit.text == expected for hit in owner_hits):
                continue
            run.expected_text_misses.append(
                {
                    **asdict(case),
                    "expected": expected,
                    "got": sorted({hit.text for hit in owner_hits}),
                }
            )


def audit_group(
    *,
    binary: str,
    rules_root: Path,
    language: str,
    owner_kind: str,
    group: list[tuple[ExampleCase, str]],
    cross_kind: bool,
    taint_dependent_rules: set[str],
    run: AuditRun,
) -> None:
    workspace = Path(
        tempfile.mkdtemp(prefix=f"bonsai-match-examples-{language}-{owner_kind}-")
    ).resolve()
    run.temp_paths.append(workspace)
    file_to_case = write_group_workspace(workspace, group)
    command_kinds = sorted(KIND_COMMAND) if cross_kind else [owner_kind]
    rows_by_case: dict[str, list[Finding]] = defaultdict(list)
    for command_kind in command_kinds:
        try:
            rows = run_inventory(binary, workspace, rules_root, command_kind)
        except Exception as exc:  # noqa: BLE001 - audit remaining groups.
            run.command_errors.append(f"{language}/{owner_kind}/{command_kind}: {exc}")
            continue
        collect_inventory_rows(
            rows,
            command_kind,
            file_to_case,
            workspace,
            rows_by_case,
            run,
        )
    collect_owner_expectations(group, rows_by_case, taint_dependent_rules, run)


def run_audit(
    *,
    binary: str,
    rules_root: Path,
    grouped: dict[tuple[str, str], list[tuple[ExampleCase, str]]],
    cross_kind: bool,
    taint_dependent_rules: set[str],
) -> AuditRun:
    run = AuditRun()
    for (language, owner_kind), group in sorted(grouped.items()):
        audit_group(
            binary=binary,
            rules_root=rules_root,
            language=language,
            owner_kind=owner_kind,
            group=group,
            cross_kind=cross_kind,
            taint_dependent_rules=taint_dependent_rules,
            run=run,
        )
    return run


def collision_findings(
    findings: list[Finding],
    taint_dependent_rules: set[str],
    tags_by_rule: dict[str, str],
    expected_by_case: dict[str, frozenset[str]],
) -> list[Finding]:
    return [
        hit
        for hit in findings
        if hit.matched_rule
        and hit.matched_rule != hit.owner_rule
        and hit.owner_rule not in taint_dependent_rules
        and hit.matched_rule not in taint_dependent_rules
        and not is_passthrough_sidecar_overlap(hit, tags_by_rule)
        and not is_same_family_layered_overlap(hit, tags_by_rule, expected_by_case)
    ]


def build_report(
    *,
    rules_root: Path,
    binary: str,
    cases: list[ExampleCase],
    grouped: dict[tuple[str, str], list[tuple[ExampleCase, str]]],
    run: AuditRun,
    collisions: list[Finding],
) -> tuple[dict[str, Any], Counter]:
    collision_pairs = Counter(
        (hit.owner_rule, hit.matched_rule, hit.command_kind) for hit in collisions
    )
    merge_candidates = [
        {
            "owner_rule": owner,
            "matched_rule": matched,
            "command_kind": command_kind,
            "count": count,
        }
        for (owner, matched, command_kind), count in collision_pairs.most_common()
    ]
    payload = {
        "rules_dir": str(rules_root),
        "binary": binary,
        "examples": [asdict(case) for case in cases],
        "owner_misses": run.owner_misses,
        "expected_text_misses": run.expected_text_misses,
        "collisions": [asdict(hit) for hit in collisions],
        "collision_pairs": merge_candidates,
        "merge_candidates": merge_candidates,
        "command_errors": run.command_errors,
        "summary": {
            "examples": len(cases),
            "groups": len(grouped),
            "owner_misses": len(run.owner_misses),
            "expected_text_misses": len(run.expected_text_misses),
            "collision_hits": len(collisions),
            "collision_pairs": len(collision_pairs),
            "command_errors": len(run.command_errors),
        },
    }
    return payload, collision_pairs


def print_command_errors(errors: list[str]) -> None:
    if not errors:
        return
    print_section("Command Errors")
    for error in errors[:50]:
        print(error)
    if len(errors) > 50:
        print(f"... {len(errors) - 50} more")


def print_owner_misses(misses: list[dict[str, Any]]) -> None:
    if not misses:
        return
    print_section("Owner Misses")
    for miss in misses[:100]:
        print(
            f"{miss['rule_id']} [{miss['language']}/{miss['kind']}] "
            f"{miss['example_name']} ({miss['source_path']})"
        )
    if len(misses) > 100:
        print(f"... {len(misses) - 100} more")


def print_expected_text_misses(misses: list[dict[str, Any]]) -> None:
    if not misses:
        return
    print_section("Expected Text Misses")
    for miss in misses[:100]:
        print(
            f"{miss['rule_id']} [{miss['language']}/{miss['kind']}] "
            f"{miss['example_name']}: expected {miss['expected']!r}, "
            f"got {miss['got']}"
        )
    if len(misses) > 100:
        print(f"... {len(misses) - 100} more")


def print_collision_details(
    collision_pairs: Counter, collisions: list[Finding]
) -> None:
    if not collision_pairs:
        return
    print_section("Collision Pairs")
    for (owner, matched, command_kind), count in collision_pairs.most_common(100):
        print(f"{count:4} {owner}  <->  {matched}  ({command_kind})")
    if len(collision_pairs) > 100:
        print(f"... {len(collision_pairs) - 100} more")

    print_section("Collision Examples")
    for hit in collisions[:100]:
        print(
            f"{hit.owner_rule} example {hit.case_key} also matched "
            f"{hit.matched_rule} ({hit.command_kind}) text={hit.text!r} "
            f"file={hit.file}"
        )
    if len(collisions) > 100:
        print(f"... {len(collisions) - 100} more")


def render_text_report(
    *,
    rules_root: Path,
    binary: str,
    cases: list[ExampleCase],
    grouped: dict[tuple[str, str], list[tuple[ExampleCase, str]]],
    run: AuditRun,
    collisions: list[Finding],
    collision_pairs: Counter,
) -> None:
    print(f"rules_dir: {rules_root}")
    print(f"binary: {binary}")
    print(f"examples: {len(cases)}")
    print(f"groups: {len(grouped)}")
    print(f"owner misses: {len(run.owner_misses)}")
    print(f"expected text misses: {len(run.expected_text_misses)}")
    print(f"collision hits: {len(collisions)}")
    print(f"collision pairs: {len(collision_pairs)}")
    print_command_errors(run.command_errors)
    print_owner_misses(run.owner_misses)
    print_expected_text_misses(run.expected_text_misses)
    print_collision_details(collision_pairs, collisions)


def finish_temp_paths(paths: list[Path], keep: bool) -> None:
    if keep:
        print_section("Temporary Workspaces")
        for path in paths:
            print(path)
        return
    for path in paths:
        shutil.rmtree(path, ignore_errors=True)


def audit_exit_code(
    *,
    run: AuditRun,
    collisions: list[Finding],
    fail_on_owner_miss: bool,
    allow_collisions: bool,
) -> int:
    if run.command_errors:
        return 2
    if fail_on_owner_miss and (run.owner_misses or run.expected_text_misses):
        return 1
    if collisions and not allow_collisions:
        return 1
    return 0


def main() -> int:
    args = parse_args()

    rules_root = Path(args.rules_dir).resolve()
    binary = resolve_binary(args.binary)
    langs = set(args.lang) if args.lang else None
    kinds = set(args.kind) if args.kind else None
    taint_dependent_rules = taint_dependent_rule_ids(rules_root)
    tags_by_rule = rule_tags(rules_root)

    cases_with_code = list(iter_cases(rules_root, langs, kinds, args.include_disabled))
    if args.limit is not None:
        cases_with_code = cases_with_code[: args.limit]
    cases = [case for case, _ in cases_with_code]
    grouped = group_cases(cases_with_code)
    run = run_audit(
        binary=binary,
        rules_root=rules_root,
        grouped=grouped,
        cross_kind=args.cross_kind,
        taint_dependent_rules=taint_dependent_rules,
    )

    expected_by_case: dict[str, frozenset[str]] = {
        case.key: frozenset(case.expected_text) for case in cases
    }
    collisions = collision_findings(
        run.findings,
        taint_dependent_rules,
        tags_by_rule,
        expected_by_case,
    )
    report_payload, collision_pairs = build_report(
        rules_root=rules_root,
        binary=binary,
        cases=cases,
        grouped=grouped,
        run=run,
        collisions=collisions,
    )

    if args.format == "json":
        print(json.dumps(report_payload, indent=2, sort_keys=True))
    else:
        render_text_report(
            rules_root=rules_root,
            binary=binary,
            cases=cases,
            grouped=grouped,
            run=run,
            collisions=collisions,
            collision_pairs=collision_pairs,
        )

    if args.json_out:
        args.json_out.write_text(
            json.dumps(report_payload, indent=2, sort_keys=True) + "\n"
        )

    finish_temp_paths(run.temp_paths, args.keep_temp)
    return audit_exit_code(
        run=run,
        collisions=collisions,
        fail_on_owner_miss=args.fail_on_owner_miss,
        allow_collisions=args.allow_collisions,
    )


if __name__ == "__main__":
    raise SystemExit(main())
