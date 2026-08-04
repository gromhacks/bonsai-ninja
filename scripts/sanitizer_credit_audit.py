#!/usr/bin/env python3
"""Audit sanitizer YAML rules against rulepack-owned credit metadata.

Walks `security-patterns/langs/<lang>/sanitizers/*.yml`, extracts every
rule's `tag:` value, and reports rules whose tag is not recognized by
`security-patterns/metadata.yml` or the sink-tag vocabulary.

A sanitizer with an unrecognised tag still loads and still appears in
`sanitizers_seen` for review, but it cannot credit any sink — so the
finding stays unsanitized. That's almost always a typo or a forgotten
table entry.

The runtime and this audit read the same metadata. There is no mirrored
taxonomy in Python or Rust.

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


def load_cross_tag_credits() -> dict[str, list[str]]:
    metadata_path = REPO / "security-patterns" / "metadata.yml"
    data = yaml.safe_load(metadata_path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{metadata_path.relative_to(REPO)} must contain a mapping")
    credits = data.get("sanitizer_credits")
    if not isinstance(credits, dict):
        raise ValueError("metadata.yml must define sanitizer_credits")
    out: dict[str, list[str]] = {}
    for tag, sinks in credits.items():
        if not isinstance(tag, str) or not isinstance(sinks, list):
            raise ValueError("sanitizer_credits entries must map strings to lists")
        if not all(isinstance(sink, str) for sink in sinks):
            raise ValueError(f"sanitizer_credits.{tag} contains a non-string sink tag")
        out[tag] = sinks
    return out


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


def build_report() -> dict:
    cross_tag_credits = load_cross_tag_credits()
    sink_tags = collect_sink_tags()
    valid_san_tags = set(sink_tags) | set(cross_tag_credits)
    rules = collect_sanitizer_rules()
    unknown: list[dict] = []
    by_tag: dict[str, int] = defaultdict(int)
    no_tag: list[dict] = []

    for rule, file in rules:
        tag = rule.get("tag")
        if tag is None:
            no_tag.append(
                {
                    "rule_id": rule.get("id"),
                    "file": str(file.relative_to(REPO)),
                }
            )
            continue
        tags = [tag] if isinstance(tag, str) else [str(t) for t in tag]
        for t in tags:
            by_tag[t] += 1
            if t not in valid_san_tags:
                unknown.append(
                    {
                        "rule_id": rule.get("id"),
                        "tag": t,
                        "file": str(file.relative_to(REPO)),
                    }
                )

    return {
        "rule_count": len(rules),
        "no_tag_count": len(no_tag),
        "unknown_tag_count": len(unknown),
        "tag_distribution": dict(sorted(by_tag.items(), key=lambda x: -x[1])),
        "no_tag": no_tag,
        "unknown_tag": unknown,
        "credit_table_size": len(cross_tag_credits),
        "sink_tag_count": len(sink_tags),
        "valid_sanitizer_tag_count": len(valid_san_tags),
    }


def print_no_tag_warning(no_tag: list[dict]) -> None:
    if not no_tag:
        return
    print(
        f"WARN: {len(no_tag)} sanitizer rule(s) without a tag — "
        "they cannot credit any sink:"
    )
    for rule in no_tag[:10]:
        print(f"  - {rule['rule_id']}  ({rule['file']})")
    if len(no_tag) > 10:
        print(f"  ... +{len(no_tag) - 10} more")
    print()


def print_unknown_tag_warning(unknown: list[dict]) -> None:
    if not unknown:
        return
    print(
        f"WARN: {len(unknown)} sanitizer rule(s) with unrecognised tag — "
        "they cannot credit any sink:"
    )
    for rule in unknown[:20]:
        print(f"  - {rule['rule_id']}  tag={rule['tag']!r}  ({rule['file']})")
    if len(unknown) > 20:
        print(f"  ... +{len(unknown) - 20} more")
    print()
    print("Either:")
    print("  1. Fix the typo in the rule's `tag:` field, or")
    print("  2. Add the tag to security-patterns/metadata.yml sanitizer_credits.")


def render_text(report: dict) -> None:
    print(f"sanitizer rules examined: {report['rule_count']}")
    print(f"sink tag vocabulary: {report['sink_tag_count']} unique values")
    print(f"cross-tag credits: {report['credit_table_size']} entries")
    print(
        "valid sanitizer tags (cross + same-tag): "
        f"{report['valid_sanitizer_tag_count']}"
    )
    print()
    print_no_tag_warning(report["no_tag"])
    print_unknown_tag_warning(report["unknown_tag"])
    if not report["no_tag"] and not report["unknown_tag"]:
        print("OK: every sanitizer rule has a tag and the tag is recognised.")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()
    report = build_report()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        render_text(report)
    return 1 if report["unknown_tag"] or report["no_tag"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
