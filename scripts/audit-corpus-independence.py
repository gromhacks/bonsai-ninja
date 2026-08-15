#!/usr/bin/env python3
"""Reject benchmark/corpus identities from production logic and rule data."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATTERNS = {
    "construct-fixture": re.compile(r"\bmega_flow\b", re.IGNORECASE),
    "benchmark-case": re.compile(r"\bCB2-", re.IGNORECASE),
    "benchmark-snapshot": re.compile(r"\brepo_(?:vulnerable|fixed)\b", re.IGNORECASE),
}
HOST_PATH_PATTERNS = {
    "developer-home": re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+/"),
    "windows-developer-home": re.compile(
        r"[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]", re.IGNORECASE
    ),
}


def production_rust_lines(path: Path) -> list[tuple[int, str]]:
    """Drop cfg(test) items while retaining every production line."""
    output: list[tuple[int, str]] = []
    skipping = False
    pending_test_cfg = False
    depth = 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if skipping:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and ("}" in line or line.rstrip().endswith(";")):
                skipping = False
                depth = 0
            continue
        if re.match(r"\s*#\[cfg\(test\)\]", line):
            pending_test_cfg = True
            continue
        if pending_test_cfg and re.match(r"\s*#\[", line):
            continue
        if pending_test_cfg:
            pending_test_cfg = False
            depth = line.count("{") - line.count("}")
            if depth > 0 or not line.rstrip().endswith(";"):
                skipping = True
            continue
        output.append((number, line))
    return output


def main() -> int:
    violations: list[tuple[str, Path, int, str]] = []
    rust_files = sorted((ROOT / "crates").glob("*/src/**/*.rs"))
    for path in rust_files:
        if path.name == "tests.rs" or path.name.endswith(("_test.rs", "_tests.rs")):
            continue
        for number, line in production_rust_lines(path):
            for label, pattern in {**CORPUS_PATTERNS, **HOST_PATH_PATTERNS}.items():
                if pattern.search(line):
                    violations.append(
                        (label, path.relative_to(ROOT), number, line.strip())
                    )

    rule_files = sorted((ROOT / "security-patterns" / "langs").glob("**/*.yml"))
    rule_files += sorted((ROOT / "security-patterns" / "langs").glob("**/*.yaml"))
    for path in rule_files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for label, pattern in {**CORPUS_PATTERNS, **HOST_PATH_PATTERNS}.items():
                if pattern.search(line):
                    violations.append(
                        (label, path.relative_to(ROOT), number, line.strip())
                    )

    if violations:
        print("corpus-independence violations:", file=sys.stderr)
        for label, path, number, line in violations:
            print(f"{label}\t{path}:{number}\t{line}", file=sys.stderr)
        return 1
    print(
        f"corpus-independence: 0 violations ({len(rust_files)} Rust files, {len(rule_files)} rule files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
