#!/usr/bin/env python3
"""Score every rule for FP risk and emit the worst offenders.

FP risk signals (highest first):

  1. Bare verb name (`callee.name`) with no `packages:` / `imports:` /
     `frameworks:` constraint and no typed matcher constraint.
     Example: `name: query` with nothing else fires on every method
     called `query` in the workspace.

  2. Generic receiver-attribute pair (`callee.attribute: [db, query]`,
     `[client, query]`, `[user, save]`) without a package or typed matcher
     constraint.
     ORM facades and helper objects routinely use these names.

  3. Missing argument-boundary constraint on a sink whose first arg is
     supposed to be the dangerous value. For bundled sinks, `arg_tainted`
     is the preferred narrowing; source-text shape constraints are mainly
     for source, sanitizer, or custom inventory rules.

  4. Sink rule with no `severity:` or with `enabled: true` but no scoping
     of any kind.

Usage:
    python3 scripts/fp_audit.py [--lang LANG] [--top N]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "security-patterns" / "langs"

# Verbs that are common method names across many libraries / ORMs /
# helpers. A bare `name:` or `attribute: [_, <verb>]` rule on these
# is FP-prone unless there are package / arg constraints.
GENERIC_VERBS = {
    "query",
    "execute",
    "exec",
    "run",
    "send",
    "post",
    "get",
    "put",
    "delete",
    "patch",
    "fetch",
    "call",
    "invoke",
    "spawn",
    "render",
    "compile",
    "parse",
    "load",
    "open",
    "read",
    "write",
    "save",
    "update",
    "create",
    "find",
    "search",
    "process",
    "handle",
    "do",
    "perform",
    "submit",
    "dispatch",
    "emit",
    "trigger",
    "redirect",
    "forward",
    "include",
    "require",
}

# Receiver names that are heavily aliased and not unique to a driver.
GENERIC_RECEIVERS = {
    "db",
    "client",
    "connection",
    "conn",
    "user",
    "model",
    "data",
    "self",
    "this",
    "obj",
    "instance",
    "session",
    "service",
    "manager",
    "controller",
    "handler",
}

# Sink categories where a specific argument is usually the dangerous value.
# If a rule in one of these categories does not have an argument-boundary
# constraint such as arg_tainted, arg_count, or format_arg_index, it is
# FP-prone.
SHAPE_EXPECTED = {
    "sqli",
    "cmdi",
    "ssrf",
    "path",
    "template",
    "ldap",
    "ssti",
    "redos",
    "open_redirect",
    "xss",
    "header_injection",
}


def has_constraint_kind(rule: dict, kinds: tuple[str, ...]) -> bool:
    constraints = rule.get("constraints") or []
    if not isinstance(constraints, list):
        return False
    for c in constraints:
        if not isinstance(c, dict):
            continue
        if any(k in c for k in kinds):
            return True
    return False


def generic_name_risk(
    name: object, has_package: bool, has_typed_constraint: bool
) -> tuple[int, list[str]]:
    if not isinstance(name, str) or name.lower() not in GENERIC_VERBS:
        return 0, []
    if not has_package and not has_typed_constraint:
        return 5, [f"bare generic verb name `{name}` with no scoping"]
    return 0, []


def generic_receiver_risk(
    attribute: object, has_package: bool, has_typed_constraint: bool
) -> tuple[int, list[str]]:
    if (
        not isinstance(attribute, list)
        or len(attribute) != 2
        or not all(isinstance(value, str) for value in attribute)
    ):
        return 0, []
    receiver, method = attribute
    if receiver.lower() not in GENERIC_RECEIVERS or has_package or has_typed_constraint:
        return 0, []
    return 3, [
        f"generic receiver `{receiver}.{method}` with no argument-boundary constraint"
    ]


def expected_shape_risk(
    family: str,
    name: object,
    attribute: object,
    has_arg_constraint: bool,
) -> tuple[int, list[str]]:
    if family not in SHAPE_EXPECTED or has_arg_constraint:
        return 0, []
    if isinstance(name, str) and name.lower() in GENERIC_VERBS:
        return 2, [f"{family} family expects argument-boundary constraint"]
    if (
        isinstance(attribute, list)
        and len(attribute) == 2
        and isinstance(attribute[1], str)
        and attribute[1].lower() in GENERIC_VERBS
    ):
        return 1, [
            f"{family} family + generic method `{attribute[1]}` "
            "no argument-boundary constraint"
        ]
    return 0, []


def score_rule(rule: dict, family: str, _kind: str) -> tuple[int, list[str]]:
    """Return (fp_risk_score, reasons[]). Higher = more FP-prone."""
    reasons: list[str] = []
    score = 0

    if rule.get("enabled") is False:
        return 0, ["disabled"]

    has_pkg = bool(
        rule.get("packages")
        or rule.get("imports")
        or rule.get("frameworks")
        or rule.get("namespace")
    )
    has_arg_constraint = has_constraint_kind(
        rule,
        (
            "arg_matches_regex",
            "arg_not_matches_regex",
            "arg_equals",
            "any_arg_matches_regex",
            "arg_count",
            "arg_tainted",
            "max_args",
            "min_args",
            "format_arg_index",
            "top_level",
            "receiver_name_in",
        ),
    )
    constraints = rule.get("constraints") or []
    has_typed_constraint = bool(
        isinstance(constraints, list)
        and any(
            isinstance(constraint, dict) and constraint for constraint in constraints
        )
    )

    match = rule.get("match") or {}
    callee = match.get("callee") if isinstance(match, dict) else None
    if not isinstance(callee, dict):
        return 0, ["no callee"]

    name = callee.get("name")
    attr = callee.get("attribute")
    for component_score, component_reasons in (
        generic_name_risk(name, has_pkg, has_typed_constraint),
        generic_receiver_risk(attr, has_pkg, has_typed_constraint),
        expected_shape_risk(family, name, attr, has_arg_constraint),
    ):
        score += component_score
        reasons.extend(component_reasons)

    return score, reasons


def selected_rule_files(selected_language: str | None):
    for lang_dir in sorted(PACK.iterdir()):
        if not lang_dir.is_dir():
            continue
        if selected_language and lang_dir.name != selected_language:
            continue
        for cat_dir in (
            lang_dir / "sinks",
            lang_dir / "sanitizers",
            lang_dir / "sources",
        ):
            if not cat_dir.exists():
                continue
            for f in sorted(cat_dir.glob("*.yml")):
                yield f, cat_dir.name


def load_rule_file(path: Path) -> list[dict]:
    try:
        rules = yaml.safe_load(path.read_text()) or []
    except yaml.YAMLError as exc:
        print(f"PARSE ERR {path}: {exc}", file=sys.stderr)
        return []
    if not isinstance(rules, list):
        return []
    return [rule for rule in rules if isinstance(rule, dict) and "id" in rule]


def collect_findings(
    selected_language: str | None,
) -> list[tuple[int, str, str, str, list[str]]]:
    findings: list[tuple[int, str, str, str, list[str]]] = []
    for path, kind in selected_rule_files(selected_language):
        for rule in load_rule_file(path):
            rule_id = rule["id"]
            family = rule_id.split(".")[1] if "." in rule_id else "?"
            score, reasons = score_rule(rule, family, kind)
            if score > 0:
                findings.append(
                    (score, rule_id, kind, str(path.relative_to(REPO)), reasons)
                )
    findings.sort(key=lambda finding: -finding[0])
    return findings


def risk_totals(
    findings: list[tuple[int, str, str, str, list[str]]],
) -> tuple[Counter[str], Counter[str]]:
    by_lang: Counter[str] = Counter()
    by_family: Counter[str] = Counter()
    for score, rule_id, _kind, _path, _reasons in findings:
        by_lang[rule_id.split(".")[0]] += score
        by_family[rule_id.split(".")[1] if "." in rule_id else "?"] += score
    return by_lang, by_family


def render_findings(
    findings: list[tuple[int, str, str, str, list[str]]], top: int
) -> None:
    print(f"Total scored rules: {len(findings)}")
    if not findings:
        print("No heuristic FP-risk candidates.")
        return

    by_lang, by_family = risk_totals(findings)
    print(f"Top {top} FP-prone rules:")
    for score, rule_id, kind, path, reasons in findings[:top]:
        print(f"  [{score:>2}] {rule_id}  ({kind})")
        for reason in reasons:
            print(f"          - {reason}")
        print(f"          @ {path}")
    print()
    print("By language (sum of FP risk):")
    for language, score in by_lang.most_common():
        print(f"  {language:<12} {score}")
    print()
    print("By family (sum of FP risk):")
    for family, score in by_family.most_common():
        print(f"  {family:<20} {score}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    render_findings(collect_findings(args.lang), args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
