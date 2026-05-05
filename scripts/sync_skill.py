#!/usr/bin/env python3
"""Sync bonsai-ninja agent guidance across supported tool folders."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CANONICAL = REPO / ".agents" / "skills" / "bonsai-ninja" / "SKILL.md"
SKILL_COPIES = [
    REPO / ".claude" / "skills" / "bonsai-ninja" / "SKILL.md",
    REPO / ".cline" / "skills" / "bonsai-ninja" / "SKILL.md",
]
PLAIN_COPIES = [REPO / "AGENTS.md", REPO / "SKILLS.md"]


def strip_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    end = text.find("\n---\n", 3)
    if end == -1:
        return text
    return text[end + 5 :].lstrip("\n")


def main() -> int:
    skill = CANONICAL.read_text()
    for path in SKILL_COPIES:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(skill)
        print(f"wrote {path}")

    plain = strip_frontmatter(skill)
    for path in PLAIN_COPIES:
        path.write_text(plain)
        print(f"wrote {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
