#!/usr/bin/env python3
"""Reject release binaries that disclose build-machine source paths."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def path_spellings(value: str) -> set[bytes]:
    value = value.strip()
    if not value:
        return set()
    spellings = {value, value.replace("\\", "/"), value.replace("/", "\\")}
    return {spelling.encode() for spelling in spellings if len(spelling) >= 6}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: audit-release-binary.py <binary>", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1])
    payload = binary.read_bytes()
    root = Path(__file__).resolve().parent.parent
    candidates = {
        str(root),
        os.environ.get("HOME", ""),
        os.environ.get("USERPROFILE", ""),
        os.environ.get("GITHUB_WORKSPACE", ""),
    }
    for candidate in candidates:
        if any(spelling in payload for spelling in path_spellings(candidate)):
            print(
                f"release binary contains an unremapped build path ({candidate!r})",
                file=sys.stderr,
            )
            return 1
    print("release binary build paths: remapped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
