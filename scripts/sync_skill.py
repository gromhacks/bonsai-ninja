#!/usr/bin/env python3
"""Sync the root SKILLS.md from the canonical .agents skill.

The tool-specific SKILL.md files are stubs that reference the canonical
.agents file directly, so they pick up changes automatically.
The root SKILLS.md is a human-readable mirror of the canonical body
(minus the Agent Skills YAML frontmatter) and needs to be regenerated
when the canonical changes.

Usage:
    python3 scripts/sync_skill.py
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CANONICAL = REPO / ".agents" / "skills" / "bonsai-ninja" / "SKILL.md"
TARGET = REPO / "SKILLS.md"

HEADER = """# SKILLS.md

This is the human-readable project guide. The canonical
Agent Skills-compatible version lives at
[.agents/skills/bonsai-ninja/SKILL.md](.agents/skills/bonsai-ninja/SKILL.md).
Compatibility shims live at
[.claude/skills/bonsai-ninja/SKILL.md](.claude/skills/bonsai-ninja/SKILL.md)
and [.cline/skills/bonsai-ninja/SKILL.md](.cline/skills/bonsai-ninja/SKILL.md).
Tools that do not support skills should start from [AGENTS.md](AGENTS.md).

This guide is for agents using `bonsai-ninja` as a repository
understanding, debugging, code review, and security review tool.
The body below mirrors the canonical SKILL.md byte-for-byte (minus
the Agent Skills YAML frontmatter); update only the canonical and
re-run `python3 scripts/sync_skill.py` to refresh this file.

"""


def main() -> int:
    s = CANONICAL.read_text()
    if s.startswith("---"):
        end = s.find("\n---\n", 3)
        if end != -1:
            s = s[end + 5 :].lstrip("\n")
    lines = s.splitlines()
    first_section = next(
        (i for i, l in enumerate(lines) if l.startswith("## ")), None
    )
    if first_section is None:
        print("ERROR: no '## ' section found in canonical SKILL.md")
        return 2
    body = "\n".join(lines[first_section:])
    out = HEADER + body
    if not out.endswith("\n"):
        out += "\n"
    TARGET.write_text(out)
    print(f"wrote {TARGET} ({len(out.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
