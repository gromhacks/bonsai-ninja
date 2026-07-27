#!/usr/bin/env python3
"""Report enabled rulepack rules that still lack match_examples."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


def load_rules(path: Path) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text()) or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "rules_dir",
        nargs="?",
        default="security-patterns",
        help="Rulepack root, default: security-patterns",
    )
    parser.add_argument(
        "--by-file",
        action="store_true",
        help="Also print per-file missing counts.",
    )
    args = parser.parse_args()

    root = Path(args.rules_dir)
    langs_dir = root / "langs"
    missing_by_lang_kind: Counter[tuple[str, str]] = Counter()
    enabled_by_lang_kind: Counter[tuple[str, str]] = Counter()
    missing_by_file: Counter[Path] = Counter()
    total_enabled = 0
    total_missing = 0

    for path in sorted(langs_dir.rglob("*.yml")):
        rel = path.relative_to(root)
        parts = rel.parts
        if len(parts) < 4:
            continue
        _, lang, kind, *_ = parts
        for rule in load_rules(path):
            if rule.get("enabled") is not True:
                continue
            total_enabled += 1
            enabled_by_lang_kind[(lang, kind)] += 1
            if rule.get("match_examples"):
                continue
            total_missing += 1
            missing_by_lang_kind[(lang, kind)] += 1
            missing_by_file[rel] += 1

    print(f"enabled rules: {total_enabled}")
    print(f"missing match_examples: {total_missing}")
    print()
    for (lang, kind), missing in missing_by_lang_kind.most_common():
        enabled = enabled_by_lang_kind[(lang, kind)]
        print(f"{lang:12} {kind:10} missing {missing:4} / enabled {enabled:4}")

    if args.by_file:
        print()
        for path, missing in missing_by_file.most_common():
            print(f"{missing:4} {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
