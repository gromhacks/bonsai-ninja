#!/usr/bin/env python3
"""Reject large exact clones in shared production Rust code."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WINDOW = 20
ADAPTER_CRATES = {"adapters", "conformance", "testkit"}


def is_adapter(path: Path) -> bool:
    crate = path.relative_to(ROOT / "crates").parts[0]
    return crate.startswith("lang_") or crate in ADAPTER_CRATES


def production_lines(path: Path) -> list[tuple[int, str]]:
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
        stripped = line.strip()
        if stripped and not stripped.startswith("//"):
            output.append((number, stripped))
    return output


def main() -> int:
    files = [
        path
        for path in sorted((ROOT / "crates").glob("*/src/**/*.rs"))
        if path.name != "tests.rs" and not path.name.endswith(("_test.rs", "_tests.rs"))
    ]
    sequences = {path: production_lines(path) for path in files}
    windows: dict[tuple[str, ...], list[tuple[Path, int]]] = defaultdict(list)
    for path, lines in sequences.items():
        values = [line for _, line in lines]
        for offset in range(len(values) - WINDOW + 1):
            windows[tuple(values[offset : offset + WINDOW])].append((path, offset))

    violations: set[tuple[Path, int, Path, int, int]] = set()
    for matches in windows.values():
        for left_index, (left_path, left_offset) in enumerate(matches):
            for right_path, right_offset in matches[left_index + 1 :]:
                if left_path == right_path or (
                    is_adapter(left_path) and is_adapter(right_path)
                ):
                    continue
                left = [line for _, line in sequences[left_path]]
                right = [line for _, line in sequences[right_path]]
                if (
                    left_offset
                    and right_offset
                    and left[left_offset - 1] == right[right_offset - 1]
                ):
                    continue
                length = WINDOW
                while (
                    left_offset + length < len(left)
                    and right_offset + length < len(right)
                    and left[left_offset + length] == right[right_offset + length]
                ):
                    length += 1
                violations.add(
                    (
                        left_path.relative_to(ROOT),
                        sequences[left_path][left_offset][0],
                        right_path.relative_to(ROOT),
                        sequences[right_path][right_offset][0],
                        length,
                    )
                )

    if violations:
        print(
            f"exact production clones of at least {WINDOW} logical lines:",
            file=sys.stderr,
        )
        for left, left_line, right, right_line, length in sorted(violations):
            print(
                f"{length}\t{left}:{left_line}\t{right}:{right_line}", file=sys.stderr
            )
        return 1
    print(f"rust-duplication: 0 shared production clones >= {WINDOW} logical lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
