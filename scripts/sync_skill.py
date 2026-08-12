#!/usr/bin/env python3
"""Sync or verify the canonical bonsai-ninja agent skill copies."""

from __future__ import annotations

import argparse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CANONICAL = REPO / ".agents" / "skills" / "bonsai-ninja" / "SKILL.md"
SKILL_COPIES = [
    REPO / "SKILLS.md",
    REPO / ".claude" / "skills" / "bonsai-ninja" / "SKILL.md",
    REPO / ".cline" / "skills" / "bonsai-ninja" / "SKILL.md",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when a copy differs instead of rewriting it",
    )
    args = parser.parse_args()

    skill = CANONICAL.read_text()
    stale: list[Path] = []
    for path in SKILL_COPIES:
        if args.check:
            if not path.is_file() or path.read_text() != skill:
                stale.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(skill)
        print(f"wrote {path}")

    if stale:
        for path in stale:
            print(f"stale skill copy: {path.relative_to(REPO)}")
        print("run: python3 scripts/sync_skill.py")
        return 1
    if args.check:
        print(f"agent skill copies are current ({len(SKILL_COPIES)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
