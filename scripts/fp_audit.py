#!/usr/bin/env python3
"""Score every rule for FP risk and emit the worst offenders.

FP risk signals (highest first):

  1. Bare verb name (`callee.name`) with no `packages:` / `imports:` /
     `frameworks:` constraint AND no argument-boundary constraint.
     Example: `name: query` with nothing else fires on every method
     called `query` in the workspace.

  2. Generic receiver-attribute pair (`callee.attribute: [db, query]`,
     `[client, query]`, `[user, save]`) without an argument-boundary
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
    "query", "execute", "exec", "run", "send", "post", "get", "put",
    "delete", "patch", "fetch", "call", "invoke", "spawn",
    "render", "compile", "parse", "load", "open", "read", "write",
    "save", "update", "create", "find", "search", "process", "handle",
    "do", "perform", "submit", "dispatch", "emit", "trigger",
    "redirect", "forward", "include", "require",
}

# Receiver names that are heavily aliased and not unique to a driver.
GENERIC_RECEIVERS = {
    "db", "client", "connection", "conn", "user", "model", "data",
    "self", "this", "obj", "instance",
    "session", "service", "manager", "controller", "handler",
}

# Sink categories where a specific argument is usually the dangerous value.
# If a rule in one of these categories does not have an argument-boundary
# constraint such as arg_tainted, arg_count, or format_arg_index, it is
# FP-prone.
SHAPE_EXPECTED = {
    "sqli", "cmdi", "ssrf", "path", "template", "ldap", "ssti", "redos",
    "open_redirect", "xss", "header_injection",
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


def score_rule(rule: dict, family: str, kind: str) -> tuple[int, list[str]]:
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

    match = rule.get("match") or {}
    callee = match.get("callee") if isinstance(match, dict) else None
    if not isinstance(callee, dict):
        return 0, ["no callee"]

    # Bare-verb-name rules.
    name = callee.get("name")
    if isinstance(name, str) and name.lower() in GENERIC_VERBS:
        if not has_pkg and not has_arg_constraint:
            score += 5
            reasons.append(f"bare generic verb name `{name}` with no scoping")
        elif not has_arg_constraint:
            score += 2
            reasons.append(f"bare generic verb name `{name}` (has package, no arg)")

    # Attribute-chain with a generic receiver name.
    attr = callee.get("attribute")
    if isinstance(attr, list) and len(attr) == 2:
        recv, method = attr
        if (
            isinstance(recv, str)
            and isinstance(method, str)
            and recv.lower() in GENERIC_RECEIVERS
        ):
            if not has_arg_constraint:
                score += 3
            reasons.append(f"generic receiver `{recv}.{method}` with no argument-boundary constraint")

    # Shape-expected family without an arg constraint.
    if family in SHAPE_EXPECTED and not has_arg_constraint:
        # Lower the noise: only flag if the callee shape is a generic verb.
        if isinstance(name, str) and name.lower() in GENERIC_VERBS:
            score += 2
            reasons.append(f"{family} family expects argument-boundary constraint")
        elif isinstance(attr, list) and len(attr) == 2 and attr[1].lower() in GENERIC_VERBS:
            score += 1
            reasons.append(f"{family} family + generic method `{attr[1]}` no argument-boundary constraint")

    return score, reasons


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()

    findings: list[tuple[int, str, str, str, list[str]]] = []
    for lang_dir in sorted(PACK.iterdir()):
        if not lang_dir.is_dir():
            continue
        if args.lang and lang_dir.name != args.lang:
            continue
        for cat_dir in (lang_dir / "sinks", lang_dir / "sanitizers", lang_dir / "sources"):
            if not cat_dir.exists():
                continue
            for f in sorted(cat_dir.glob("*.yml")):
                try:
                    rules = yaml.safe_load(f.read_text()) or []
                except yaml.YAMLError as exc:
                    print(f"PARSE ERR {f}: {exc}", file=sys.stderr)
                    continue
                if not isinstance(rules, list):
                    continue
                for r in rules:
                    if not isinstance(r, dict) or "id" not in r:
                        continue
                    rid = r["id"]
                    family = rid.split(".")[1] if "." in rid else "?"
                    kind = cat_dir.name
                    score, reasons = score_rule(r, family, kind)
                    if score > 0:
                        findings.append((score, rid, kind, str(f.relative_to(REPO)), reasons))

    findings.sort(key=lambda x: -x[0])

    by_lang: Counter[str] = Counter()
    by_family: Counter[str] = Counter()
    for s, rid, _kind, _f, _r in findings:
        by_lang[rid.split(".")[0]] += s
        by_family[rid.split(".")[1] if "." in rid else "?"] += s

    print(f"Total scored rules: {len(findings)}")
    print(f"Top {args.top} FP-prone rules:")
    for s, rid, kind, fpath, reasons in findings[: args.top]:
        print(f"  [{s:>2}] {rid}  ({kind})")
        for r in reasons:
            print(f"          - {r}")
        print(f"          @ {fpath}")
    print()
    print("By language (sum of FP risk):")
    for lang, n in by_lang.most_common():
        print(f"  {lang:<12} {n}")
    print()
    print("By family (sum of FP risk):")
    for fam, n in by_family.most_common():
        print(f"  {fam:<20} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
