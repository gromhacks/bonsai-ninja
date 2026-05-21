#!/usr/bin/env python3
"""Audit sanitizer YAML rules for tag-credit-table alignment.

Walks `security-patterns/langs/<lang>/sanitizers/*.yml`, extracts every
rule's `tag:` value, and reports rules whose tag is not recognised by
the engine's credit table at
`crates/security/src/sanitizer_credit.rs`.

A sanitizer with an unrecognised tag still loads and still appears in
`sanitizers_seen` for review, but it cannot credit any sink — so the
finding stays unsanitized. That's almost always a typo or a forgotten
table entry.

The canonical list below mirrors the engine's `MAPPING` plus the
"same-tag-credits-same-tag" implicit set (any sink tag the engine
matches against is automatically a valid sanitizer tag for itself).
Updating the engine table requires updating this list and vice-versa
— if they diverge, the audit reports the gap.

Usage:
  python3 scripts/sanitizer_credit_audit.py
  python3 scripts/sanitizer_credit_audit.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "security-patterns" / "langs"

# Cross-tag credit map. Source of truth for the same vocabulary lives
# at crates/security/src/sanitizer_credit.rs::MAPPING. Keep in sync.
CROSS_TAG_CREDITS: dict[str, list[str]] = {
    "open-redirect-sanitize": ["open-redirect"],
    "url-encode": ["open-redirect"],
    "url-build": ["ssrf", "open-redirect"],
    "same-origin-path": ["open-redirect", "header-injection"],
    "nosql-sanitize": ["nosql-injection"],
    "nosql-parameter": ["nosql-injection"],
    "signed-token-verify": ["code-injection", "insecure-deserialization"],
    "signature-verify": ["code-injection", "insecure-deserialization", "untrusted-token"],
    "signature-sanitizer": ["signature-replay", "untrusted-token"],
    "html-encode": ["xss"],
    "html-sanitize": ["xss"],
    "js-encode": ["xss"],
    "css-encode": ["xss"],
    "xss-sanitize": ["xss"],
    "path-sanitize": ["path-traversal"],
    "zip-slip-guard": ["path-traversal"],
    "regex-validate": [
        "path-traversal",
        "open-redirect",
        "sql-injection",
        "xpath-injection",
    ],
    "allowlist-validate": [
        "path-traversal",
        "open-redirect",
        "sql-injection",
        "ssrf",
        "xpath-injection",
    ],
    "char-allowlist": [
        "path-traversal",
        "open-redirect",
        "sql-injection",
        "command-injection",
        "header-injection",
        "xpath-injection",
    ],
    "csrf-protect": ["csrf"],
    "ssrf-sanitize": ["ssrf"],
    "ldap-escape": ["ldap-injection"],
    "shell-escape": ["command-injection"],
    "sql-escape": ["sql-injection"],
    "sql-parameter": ["sql-injection"],
    "sql-parameterize": ["sql-injection"],
    "db-bind-parameter": ["sql-injection"],
    "header-sanitize": ["header-injection"],
    "xxe-sanitizer": ["xxe"],
    "xpath-parameter": ["xpath-injection"],
    "auth-sanitizer": ["weak-auth", "access-control"],
    "password-verify": ["weak-auth"],
    "deser-secure": ["insecure-deserialization"],
    "jwt-verify": ["jwt", "untrusted-token", "signature-replay"],
    "constant-time": ["timing-attack"],
    "constant-time-compare": ["timing-attack"],
    "bounds-check": ["memory-safety"],
    "crypto-bounds": ["memory-safety", "weak-crypto"],
    "crypto-mode": ["weak-crypto"],
    "kdf": ["weak-crypto"],
    "numeric-coerce": ["integer-overflow"],
    "regex-escape": ["redos"],
    "controlled-exposure": ["information-exposure"],
    "lock-acquire": ["race"],
    "cookie-secure": ["cookie-misconfig"],
    "rate-limit": ["rate-limit-missing"],
    # Passthrough: recognized but credits nothing (T104 — engine
    # treats these as identity edges instead of clears).
    "passthrough-decode": [],
    "passthrough-encode": [],
    "passthrough-transform": [],
    # Recognized but intentionally non-crediting.
    "validation": [],
    "schema-validate": [],
    "base64-encode": [],
    "hash": [],
    "url-decode": [],
    "non-sanitizer": [],
}

# Sink-side tag vocabulary (same-tag credits its own family). Pulled
# from the rulepack so it stays in sync without manual maintenance.
def collect_sink_tags() -> set[str]:
    out: set[str] = set()
    for f in PACK.glob("*/sinks/*.yml"):
        try:
            data = yaml.safe_load(f.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(data, list):
            continue
        for r in data:
            if not isinstance(r, dict):
                continue
            t = r.get("tag")
            if isinstance(t, str):
                out.add(t)
            elif isinstance(t, list):
                out.update(str(x) for x in t)
    return out


def collect_sanitizer_rules() -> list[tuple[str, Path]]:
    """Return [(rule_dict, file_path)] for every sanitizer YAML rule."""
    out: list[tuple[dict, Path]] = []
    for f in sorted(PACK.glob("*/sanitizers/*.yml")):
        try:
            data = yaml.safe_load(f.read_text())
        except yaml.YAMLError as exc:
            print(f"warn: parse error in {f.relative_to(REPO)}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, list):
            continue
        for r in data:
            if isinstance(r, dict):
                out.append((r, f))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    sink_tags = collect_sink_tags()
    valid_san_tags = set(sink_tags) | set(CROSS_TAG_CREDITS.keys())

    rules = collect_sanitizer_rules()
    unknown: list[dict] = []
    by_tag: dict[str, int] = defaultdict(int)
    no_tag: list[dict] = []

    for rule, file in rules:
        tag = rule.get("tag")
        if tag is None:
            no_tag.append({
                "rule_id": rule.get("id"),
                "file": str(file.relative_to(REPO)),
            })
            continue
        tags = [tag] if isinstance(tag, str) else [str(t) for t in tag]
        for t in tags:
            by_tag[t] += 1
            if t not in valid_san_tags:
                unknown.append({
                    "rule_id": rule.get("id"),
                    "tag": t,
                    "file": str(file.relative_to(REPO)),
                })

    report = {
        "rule_count": len(rules),
        "no_tag_count": len(no_tag),
        "unknown_tag_count": len(unknown),
        "tag_distribution": dict(sorted(by_tag.items(), key=lambda x: -x[1])),
        "no_tag": no_tag,
        "unknown_tag": unknown,
        "credit_table_size": len(CROSS_TAG_CREDITS),
        "sink_tag_count": len(sink_tags),
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if unknown or no_tag else 0

    print(f"sanitizer rules examined: {len(rules)}")
    print(f"sink tag vocabulary: {len(sink_tags)} unique values")
    print(f"cross-tag credits: {len(CROSS_TAG_CREDITS)} entries")
    print(f"valid sanitizer tags (cross + same-tag): {len(valid_san_tags)}")
    print()

    if no_tag:
        print(f"WARN: {len(no_tag)} sanitizer rule(s) without a tag — they cannot credit any sink:")
        for r in no_tag[:10]:
            print(f"  - {r['rule_id']}  ({r['file']})")
        if len(no_tag) > 10:
            print(f"  ... +{len(no_tag) - 10} more")
        print()

    if unknown:
        print(f"WARN: {len(unknown)} sanitizer rule(s) with unrecognised tag — they cannot credit any sink:")
        for r in unknown[:20]:
            print(f"  - {r['rule_id']}  tag={r['tag']!r}  ({r['file']})")
        if len(unknown) > 20:
            print(f"  ... +{len(unknown) - 20} more")
        print()
        print("Either:")
        print("  1. Fix the typo in the rule's `tag:` field, or")
        print("  2. Add the tag to crates/security/src/sanitizer_credit.rs::MAPPING")
        print("     (and mirror in scripts/sanitizer_credit_audit.py CROSS_TAG_CREDITS).")
        return 1

    print("OK: every sanitizer rule has a tag and the tag is recognised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
