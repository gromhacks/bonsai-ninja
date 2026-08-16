#!/usr/bin/env python3
"""Reject documentation structure, ownership, link, and surface drift."""

from __future__ import annotations

import itertools
import json
import re
import tomllib
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
SCRIPTS = REPO / "scripts"
ROOT_DOCUMENTS = (
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "AGENTS.md",
    "SKILLS.md",
)
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
    files = [REPO / name for name in ROOT_DOCUMENTS]
    roots = (
        DOCS,
        REPO / ".github",
        REPO / ".agents",
        REPO / ".claude",
        REPO / ".cline",
        REPO / "crates",
        REPO / "schemas",
        SCRIPTS,
    )
    for root in roots:
        for suffix in ("*.md", "*.mdx"):
            files.extend(root.rglob(suffix))
    return sorted(
        {path for path in files if path.is_file() and "target" not in path.parts}
    )


def public_documentation_files() -> list[Path]:
    files = [REPO / name for name in ROOT_DOCUMENTS]
    files.extend(active_docs())
    files.extend((REPO / ".github").rglob("*.md"))
    return sorted({path for path in files if path.is_file()})


def active_docs() -> list[Path]:
    return sorted(path for path in DOCS.rglob("*") if path.suffix in {".md", ".mdx"})


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

    path = (
        REPO / target.lstrip("/") if target.startswith("/") else source.parent / target
    )
    candidates = [path]
    if not path.suffix:
        candidates.extend(
            (
                Path(f"{path}.md"),
                Path(f"{path}.mdx"),
                path / "index.md",
                path / "index.mdx",
            )
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
        if not any(
            Path(f"{REPO / page}{suffix}").is_file() for suffix in (".md", ".mdx")
        ):
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
    retired_tokens = {
        "--no-flows": "flow columns are opt-in with `--flows`",
        "--findings": "security analysis is an explicit `security` command",
        "goal-benchmark-2026-05-15.md": "historical engineering logs are not product documentation",
        "docs/goal.md": "historical engineering logs are not product documentation",
    }
    for path in documentation_files():
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            for token, replacement in retired_tokens.items():
                if token in line:
                    failures.append(
                        f"{path.relative_to(REPO)}:{line_number}: retired `{token}`; {replacement}"
                    )
    return failures


def check_publication_hygiene() -> list[str]:
    """Reject local-only or corpus-specific residue from public documentation."""

    failures: list[str] = []
    retired = {
        "cvebench": "public product documentation must not depend on a private evaluation corpus",
        "cve bench": "public product documentation must not depend on a private evaluation corpus",
        "cb2-": "public product documentation must not expose corpus case identifiers",
        "/users/": "replace developer-specific absolute paths with portable examples",
        "/private/tmp": "replace host-specific temporary paths with portable examples",
    }
    for path in documentation_files():
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            lowered = line.lower()
            for token, replacement in retired.items():
                if token in lowered:
                    failures.append(
                        f"{path.relative_to(REPO)}:{line_number}: publication residue "
                        f"`{token}`; {replacement}"
                    )
    return failures


def check_github_community_files() -> list[str]:
    required = (
        REPO / ".github" / "ISSUE_TEMPLATE" / "bug-report.yml",
        REPO / ".github" / "ISSUE_TEMPLATE" / "analysis-quality.yml",
        REPO / ".github" / "ISSUE_TEMPLATE" / "feature-request.yml",
        REPO / ".github" / "ISSUE_TEMPLATE" / "config.yml",
        REPO / ".github" / "PULL_REQUEST_TEMPLATE.md",
        REPO / "CODE_OF_CONDUCT.md",
    )
    return [
        f"missing GitHub community file `{path.relative_to(REPO)}`"
        for path in required
        if not path.is_file()
    ]


def check_maturity_disclaimer() -> list[str]:
    readme = (REPO / "README.md").read_text(errors="replace")
    required = (
        "**Project maturity:**",
        "ambitious early-stage project",
        "it is not perfect",
        "feedback",
        "help from the community",
    )
    return [
        f"README.md project-maturity disclaimer is missing `{phrase}`"
        for phrase in required
        if phrase not in readme
    ]


def check_command_examples() -> list[str]:
    """Reject known-invalid public command shapes.

    Security always takes a workspace before its nested action. Keeping this
    small grammar check in the docs-only job catches copy/paste drift without
    requiring a release binary in that job.
    """

    failures: list[str] = []
    invalid_security_pack = re.compile(r"\bbonsai-ninja\s+security\s+pack\b")
    invalid_index = re.compile(r"\bbonsai-ninja\s+index\s+--")
    for path in public_documentation_files():
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            if invalid_security_pack.search(line):
                failures.append(
                    f"{path.relative_to(REPO)}:{line_number}: `security` requires "
                    "`<workspace>` before `pack`"
                )
            if invalid_index.search(line):
                failures.append(
                    f"{path.relative_to(REPO)}:{line_number}: `index` requires "
                    "`<workspace>` before its options"
                )
    return failures


def check_product_contract_language() -> list[str]:
    """Keep documentation aligned with the compiler/rule ownership boundary."""

    failures: list[str] = []
    retired_phrases = {
        "compiler-owned source/sink/sanitizer": (
            "adapters own syntax and rule data owns sources, sinks, and sanitizers"
        ),
        "## taint\n": "use the full `security taint-analysis` command heading",
        "## source-analysis\n": "use the full `security source-analysis` command heading",
        "Out of scope (Phase 10-12)": "document current analysis boundaries, not old phase labels",
        "statically proven behavior": (
            "say compiler-evidenced behavior and retain the documented static-model boundary"
        ),
        "`Exact` — proven correct": (
            "scope Exact to admitted static facts rather than all runtime behavior"
        ),
    }
    checked = public_documentation_files()
    for path in checked:
        text = path.read_text(errors="replace")
        for phrase, replacement in retired_phrases.items():
            if phrase in text:
                line_number = text[: text.index(phrase)].count("\n") + 1
                failures.append(
                    f"{path.relative_to(REPO)}:{line_number}: stale documentation phrase "
                    f"`{phrase.strip()}`; {replacement}"
                )

    cli_reference = (DOCS / "cli-reference.mdx").read_text(errors="replace")
    for flag, owner in (("--framework", "security deps"), ("--lang", "security pack")):
        if flag not in cli_reference:
            failures.append(
                f"docs/cli-reference.mdx does not document `{owner} {flag}`"
            )
    return failures


def check_mdx_frontmatter() -> list[str]:
    failures: list[str] = []
    for path in active_docs():
        if path.suffix != ".mdx":
            continue
        text = path.read_text(errors="replace")
        if not text.startswith("---\n"):
            failures.append(f"{path.relative_to(REPO)}: missing MDX frontmatter")
            continue
        end = text.find("\n---\n", 4)
        if end < 0:
            failures.append(f"{path.relative_to(REPO)}: unclosed MDX frontmatter")
            continue
        frontmatter = text[4:end]
        for key in ("title:", "description:"):
            if not any(line.startswith(key) for line in frontmatter.splitlines()):
                failures.append(
                    f"{path.relative_to(REPO)}: frontmatter is missing `{key[:-1]}`"
                )
    return failures


def check_markdown_structure(files: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in files:
        relative = path.relative_to(REPO)
        headings: dict[str, int] = {}
        fence: tuple[str, int] | None = None
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            heading = HEADING_RE.match(line)
            if heading:
                slug = heading_slug(heading.group(1))
                if slug in headings:
                    failures.append(
                        f"{relative}:{line_number}: duplicate heading anchor `#{slug}`; "
                        f"first declared at line {headings[slug]}"
                    )
                else:
                    headings[slug] = line_number

            marker = re.match(r"^\s*(```+|~~~+)", line)
            if marker:
                kind = marker.group(1)[0]
                if fence is None:
                    fence = (kind, line_number)
                elif fence[0] == kind:
                    fence = None

        if fence is not None:
            failures.append(f"{relative}:{fence[1]}: unclosed Markdown code fence")
    return failures


def check_duplicate_prose() -> list[str]:
    """Reject long prose copied between public pages.

    Commands and generated snippets may be repeated intentionally, so fenced
    blocks are excluded. A 24-word window is long enough to identify copied
    explanation while allowing short terminology and contract phrases to
    recur where a page needs local context.
    """

    window_size = 24
    owners: dict[tuple[str, ...], set[Path]] = {}
    reader_files = active_docs() + [
        REPO / "README.md",
        REPO / "CONTRIBUTING.md",
        REPO / "CODE_OF_CONDUCT.md",
        REPO / "SECURITY.md",
    ]
    for path in reader_files:
        text = path.read_text(errors="replace")
        text = re.sub(r"```.*?```|~~~.*?~~~", " ", text, flags=re.DOTALL)
        if text.startswith("---\n"):
            text = re.sub(r"\A---\n.*?\n---\n", " ", text, flags=re.DOTALL)
        text = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", text)
        words = re.findall(r"[a-z0-9]+", text.lower())
        for index in range(len(words) - window_size + 1):
            window = tuple(words[index : index + window_size])
            owners.setdefault(window, set()).add(path)

    duplicate_pairs: dict[tuple[Path, Path], tuple[str, ...]] = {}
    for window, paths in owners.items():
        if len(paths) < 2:
            continue
        for left, right in itertools.combinations(sorted(paths), 2):
            duplicate_pairs.setdefault((left, right), window)

    return [
        f"{left.relative_to(REPO)} and {right.relative_to(REPO)} repeat a "
        f"{window_size}-word prose block: `{' '.join(window)}`"
        for (left, right), window in sorted(duplicate_pairs.items())
    ]


def check_measurement_ownership() -> list[str]:
    failures: list[str] = []
    date_re = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
    for path in active_docs() + [REPO / "README.md"]:
        if path.name == "RELEASE_READINESS.md":
            continue
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            if date_re.search(line) or re.search(r"\bABI-v\d+\b", line):
                failures.append(
                    f"{path.relative_to(REPO)}:{line_number}: dated release evidence belongs in "
                    "docs/RELEASE_READINESS.md"
                )
    return failures


def check_language_counts() -> list[str]:
    registry_source = (REPO / "crates" / "adapters" / "src" / "lib.rs").read_text()
    adapter_count = len(re.findall(r"Arc::new\(bonsai_lang_[a-z_]+::", registry_source))
    if adapter_count == 0:
        return [
            "could not derive the supported-language count from crates/adapters/src/lib.rs"
        ]

    failures: list[str] = []
    current_files = public_documentation_files()
    for path in current_files:
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            for pattern in LANGUAGE_COUNT_RES:
                for match in pattern.finditer(line):
                    documented = int(match.group(1))
                    if documented != adapter_count:
                        failures.append(
                            f"{path.relative_to(REPO)}:{line_number}: documents {documented} "
                            f"languages/adapters, registry has {adapter_count}"
                        )
    return failures


def check_workspace_counts() -> list[str]:
    workspace_manifest = tomllib.loads((REPO / "Cargo.toml").read_text())
    crate_count = len(workspace_manifest["workspace"]["members"])
    failures: list[str] = []
    patterns = (
        re.compile(r"\b(\d+)-crate Rust workspace\b", re.IGNORECASE),
        re.compile(r"\b(\d+) workspace crates\b", re.IGNORECASE),
    )
    for path in public_documentation_files():
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            for pattern in patterns:
                for match in pattern.finditer(line):
                    documented = int(match.group(1))
                    if documented != crate_count:
                        failures.append(
                            f"{path.relative_to(REPO)}:{line_number}: documents {documented} "
                            f"workspace crates, repository has {crate_count} crate manifests"
                        )
    return failures


def check_dependency_counts() -> list[str]:
    lock_text = (REPO / "Cargo.lock").read_text(errors="replace")
    package_count = len(re.findall(r"^\[\[package\]\]$", lock_text, re.MULTILINE))
    if package_count == 0:
        return ["could not derive the locked package count from Cargo.lock"]

    failures: list[str] = []
    pattern = re.compile(r"\b(\d[\d,]*) packages\b", re.IGNORECASE)
    for path in public_documentation_files():
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            for match in pattern.finditer(line):
                documented = int(match.group(1).replace(",", ""))
                if documented != package_count:
                    failures.append(
                        f"{path.relative_to(REPO)}:{line_number}: documents {documented} "
                        f"locked packages, Cargo.lock has {package_count}"
                    )
    return failures


def check_selected_dependency_inventory() -> list[str]:
    """Reject stale crate names in the selected third-party license table."""

    lock_text = (REPO / "Cargo.lock").read_text(errors="replace")
    locked_names = set(re.findall(r'^name = "([^"]+)"$', lock_text, re.MULTILINE))
    document = (DOCS / "contributing" / "third-party-licenses.mdx").read_text(
        errors="replace"
    )
    start = document.index("## Per-crate licenses (selected)")
    end = document.index("## Reproducing the audit", start)
    failures = []
    for line_number, line in enumerate(document[:end].splitlines(), start=1):
        if line_number <= document[:start].count("\n") + 1 or not line.startswith("|"):
            continue
        crate_cell = line.split("|", 2)[1].strip()
        if crate_cell in {"Crate", "---"}:
            continue
        crate_cell = re.sub(r"\s*\([^)]*\)\s*$", "", crate_cell)
        for crate in (part.strip().strip("`") for part in crate_cell.split(" / ")):
            if crate and crate not in locked_names:
                failures.append(
                    "docs/contributing/third-party-licenses.mdx documents "
                    f"unlocked crate `{crate}`"
                )
    return failures


def check_rule_counts() -> list[str]:
    rule_count = 0
    disabled_count = 0
    for path in sorted((REPO / "security-patterns").rglob("*.yml")):
        text = path.read_text(errors="replace")
        rule_count += len(re.findall(r"^\s*-\s+id:\s*\S+", text, re.MULTILINE))
        disabled_count += len(
            re.findall(r"^\s+enabled:\s*false\s*(?:#.*)?$", text, re.MULTILINE)
        )
    if rule_count == 0:
        return ["could not derive bundled rule counts from security-patterns"]

    enabled_count = rule_count - disabled_count
    readiness = (DOCS / "RELEASE_READINESS.md").read_text(errors="replace")
    expected = (
        f"{rule_count:,} bundled rules, of which {enabled_count:,} are enabled",
        f"| Rules | {rule_count:,} |",
        f"| Enabled rules | {enabled_count:,} |",
        f"| Disabled rules | {disabled_count:,} |",
    )
    return [
        f"docs/RELEASE_READINESS.md is missing current rulepack count `{fragment}`"
        for fragment in expected
        if fragment not in readiness
    ]


def check_rule_documentation_vocabulary() -> list[str]:
    """Keep author-facing rule vocabulary synchronized with the compiler enum."""

    source = (REPO / "crates" / "security" / "src" / "rule.rs").read_text()
    start = source.index("pub fn name(&self) -> &'static str")
    end = source.index("pub fn is_discriminating", start)
    names = set(re.findall(r'"([a-z][a-z0-9_]+)"', source[start:end]))
    guide = (DOCS / "pattern-guide.mdx").read_text(errors="replace")
    failures = [
        f"docs/pattern-guide.mdx does not document rule constraint `{name}`"
        for name in sorted(names)
        if name not in guide
    ]

    disabled_impl = source.index("impl DisabledReasonCode")
    disabled_names = source.index("pub fn as_str", disabled_impl)
    disabled_names_end = source.index("pub fn waits_on_reenable_work", disabled_names)
    allowed_codes = set(
        re.findall(r'"([a-z][a-z-]+)"', source[disabled_names:disabled_names_end])
    )
    security_spec = (DOCS / "security-spec.mdx").read_text(errors="replace")
    for code in sorted(allowed_codes):
        if code not in security_spec:
            failures.append(
                f"docs/security-spec.mdx does not document disabled reason code `{code}`"
            )
    concrete_code = re.compile(r"^\s+code:\s*([a-z][a-z-]*)\s*(?:#.*)?$")
    for path in documentation_files():
        for line_number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            match = concrete_code.match(line)
            if match and match.group(1) not in allowed_codes:
                failures.append(
                    f"{path.relative_to(REPO)}:{line_number}: invalid disabled rule "
                    f"reason code `{match.group(1)}`"
                )
    return failures


def _rust_enum_variants(source: str, enum_name: str) -> set[str]:
    """Extract top-level variants from one public Rust enum."""

    marker = f"pub enum {enum_name}"
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth and end < len(source):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    body = source[opening + 1 : end - 1]
    return set(
        re.findall(r"^    ([A-Z][A-Za-z0-9_]*)\s*(?:\{|\(|,)", body, re.MULTILINE)
    )


def check_flow_event_documentation_vocabulary() -> list[str]:
    """Keep the normative FlowEvent vocabulary synchronized with lang_api."""

    source = (REPO / "crates" / "lang_api" / "src" / "types.rs").read_text()
    specification = (DOCS / "contributing" / "flow-event-spec.mdx").read_text(
        errors="replace"
    )
    failures = []
    for enum_name in ("FlowEvent", "CallKind", "AssignValueKind", "LoopKind"):
        for variant in sorted(_rust_enum_variants(source, enum_name)):
            if not re.search(rf"\b{re.escape(variant)}\b", specification):
                failures.append(
                    "docs/contributing/flow-event-spec.mdx does not document "
                    f"`{enum_name}::{variant}`"
                )
    return failures


def check_script_inventory() -> list[str]:
    """Require an explicit owner-facing description for every developer script."""

    readme = SCRIPTS / "README.md"
    if not readme.is_file():
        return ["scripts/README.md is missing"]
    expected = {
        path.name
        for path in SCRIPTS.iterdir()
        if path.is_file() and path.name != readme.name
    }
    listed_rows = re.findall(
        r"^- `([^`]+)` — ", readme.read_text(errors="replace"), re.MULTILINE
    )
    listed = set(listed_rows)
    failures = [
        f"scripts/README.md does not document `{name}`"
        for name in sorted(expected - listed)
    ]
    failures.extend(
        f"scripts/README.md lists missing script or data file `{name}`"
        for name in sorted(listed - expected)
    )
    failures.extend(
        f"scripts/README.md lists `{name}` more than once"
        for name in sorted(
            {name for name in listed_rows if listed_rows.count(name) > 1}
        )
    )
    return failures


def main() -> int:
    files = documentation_files()
    failures = (
        check_links(files)
        + check_navigation()
        + check_retired_surface()
        + check_publication_hygiene()
        + check_github_community_files()
        + check_maturity_disclaimer()
        + check_command_examples()
        + check_product_contract_language()
        + check_mdx_frontmatter()
        + check_markdown_structure(files)
        + check_duplicate_prose()
        + check_measurement_ownership()
        + check_language_counts()
        + check_workspace_counts()
        + check_dependency_counts()
        + check_selected_dependency_inventory()
        + check_rule_counts()
        + check_rule_documentation_vocabulary()
        + check_flow_event_documentation_vocabulary()
        + check_script_inventory()
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
