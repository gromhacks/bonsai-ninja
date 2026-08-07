#!/usr/bin/env python3
"""Reject broken documentation links, navigation drift, and retired CLI flags."""

from __future__ import annotations

import json
import re
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
ARCHIVES = {"goal.md", "goal-benchmark-2026-05-15.md"}
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*$")
LANGUAGE_COUNT_RES = (
    re.compile(r"\b(\d+)-language\b", re.IGNORECASE),
    re.compile(r"\b(\d+) languages\b", re.IGNORECASE),
    re.compile(r"\b(\d+) supported languages\b", re.IGNORECASE),
    re.compile(r"\b(\d+) parser(?:/navigation)? adapters\b", re.IGNORECASE),
    re.compile(r"\ball (\d+) adapters\b", re.IGNORECASE),
)


def documentation_files() -> list[Path]:
    files = [REPO / "README.md", REPO / "AGENTS.md", REPO / "SKILLS.md"]
    roots = (DOCS, REPO / ".agents", REPO / ".claude", REPO / ".cline", REPO / "crates")
    for root in roots:
        for suffix in ("*.md", "*.mdx"):
            files.extend(root.rglob(suffix))
    return sorted({path for path in files if path.is_file() and "target" not in path.parts})


def active_docs() -> list[Path]:
    return sorted(
        path
        for path in DOCS.rglob("*")
        if path.suffix in {".md", ".mdx"} and path.name not in ARCHIVES
    )


def resolve_link(source: Path, raw: str) -> tuple[Path | None, str]:
    raw = raw.strip()
    if raw.startswith("<") and raw.endswith(">"):
        raw = raw[1:-1]
    if not raw or raw.startswith(("http://", "https://", "mailto:", "app://")):
        return None, ""

    target, _, fragment = raw.partition("#")
    target = target.split("?", 1)[0]
    if not target:
        return source, fragment
    if " " in target and not target.startswith("/"):
        target = target.split()[0]

    path = REPO / target.lstrip("/") if target.startswith("/") else source.parent / target
    candidates = [path]
    if not path.suffix:
        candidates.extend(
            (Path(f"{path}.md"), Path(f"{path}.mdx"), path / "index.md", path / "index.mdx")
        )
    resolved = next(
        (candidate.resolve() for candidate in candidates if candidate.exists()),
        path.resolve(),
    )
    return resolved, fragment


def heading_slug(heading: str) -> str:
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"[`*_~]", "", heading)
    heading = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return re.sub(r"[\s-]+", "-", heading).strip("-")


def anchors(path: Path) -> set[str]:
    return {
        heading_slug(match.group(1))
        for line in path.read_text(errors="replace").splitlines()
        if (match := HEADING_RE.match(line))
    }


def check_links(files: list[Path]) -> list[str]:
    failures: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    for source in files:
        text = source.read_text(errors="replace")
        for match in LINK_RE.finditer(text):
            raw = match.group(1)
            target, fragment = resolve_link(source, raw)
            if target is None:
                continue
            line = text.count("\n", 0, match.start()) + 1
            location = f"{source.relative_to(REPO)}:{line}"
            if not target.exists():
                failures.append(f"{location}: missing link target `{raw}`")
                continue
            if fragment and target.suffix in {".md", ".mdx"}:
                available = anchor_cache.setdefault(target, anchors(target))
                if fragment not in available:
                    failures.append(
                        f"{location}: missing heading `#{fragment}` in {target.relative_to(REPO)}"
                    )
    return failures


def check_navigation() -> list[str]:
    config = json.loads((REPO / "docs.json").read_text())
    pages = [
        page for group in config["navigation"]["groups"] for page in group["pages"]
    ]
    failures: list[str] = []
    if len(pages) != len(set(pages)):
        failures.append("docs.json contains duplicate navigation pages")

    for page in pages:
        if not any(Path(f"{REPO / page}{suffix}").is_file() for suffix in (".md", ".mdx")):
            failures.append(f"docs.json references missing page `{page}`")

    active = {str(path.relative_to(REPO).with_suffix("")) for path in active_docs()}
    missing_from_nav = active - set(pages)
    stale_nav = set(pages) - active
    failures.extend(
        f"active documentation page is absent from docs.json: `{page}`"
        for page in sorted(missing_from_nav)
    )
    failures.extend(
        f"docs.json page is not active documentation: `{page}`"
        for page in sorted(stale_nav)
    )
    return failures


def check_retired_surface() -> list[str]:
    failures: list[str] = []
    for path in active_docs() + [REPO / "README.md", REPO / "AGENTS.md", REPO / "SKILLS.md"]:
        for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            if "--no-flows" in line:
                failures.append(
                    f"{path.relative_to(REPO)}:{line_number}: retired `--no-flows`; "
                    "flow columns are opt-in with `--flows`"
                )
    return failures


def check_language_counts() -> list[str]:
    registry_source = (REPO / "crates" / "adapters" / "src" / "lib.rs").read_text()
    adapter_count = len(re.findall(r"Arc::new\(bonsai_lang_[a-z_]+::", registry_source))
    if adapter_count == 0:
        return ["could not derive the supported-language count from crates/adapters/src/lib.rs"]

    failures: list[str] = []
    current_files = active_docs() + [REPO / "README.md", REPO / "AGENTS.md", REPO / "SKILLS.md"]
    for path in current_files:
        for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            for pattern in LANGUAGE_COUNT_RES:
                for match in pattern.finditer(line):
                    documented = int(match.group(1))
                    if documented != adapter_count:
                        failures.append(
                            f"{path.relative_to(REPO)}:{line_number}: documents {documented} "
                            f"languages/adapters, registry has {adapter_count}"
                        )
    return failures


def main() -> int:
    files = documentation_files()
    failures = (
        check_links(files)
        + check_navigation()
        + check_retired_surface()
        + check_language_counts()
    )
    if failures:
        for failure in failures:
            print(f"documentation audit: {failure}")
        return 1
    print(
        f"documentation audit: {len(files)} files and "
        f"{len(active_docs())} active pages are consistent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
