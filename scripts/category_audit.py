#!/usr/bin/env python3
"""Per-(lang, category, variant) coverage audit.

Reads `docs/pattern-variants.mdx` for the canonical taxonomy, walks
`security-patterns/langs/<lang>/{sources,sinks,sanitizers}/*.yml`, and
classifies every rule into one of the variant cells. Emits the matrix
to `build/category_coverage.md` and `build/category_coverage.json`.

Cell statuses:

  x        at least one enabled rule maps to this variant
  partial  rule exists but has parse / shape errors, or is disabled
  -        no rule found
  n/a      lang lacks the primitive (declared in `pattern_variants_na.yml`
           if present; otherwise inferred from the per-category n/a list
           in this file)

Modes:

  default                emit `build/category_coverage.{md,json}`
  --diff <git-base>      list cells that changed status since <git-base>
  --suggest <lang> <cat> print YAML stub rules for missing variants

Usage:
  python3 scripts/category_audit.py
  python3 scripts/category_audit.py --diff origin/main
  python3 scripts/category_audit.py --suggest python sqli
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "security-patterns" / "langs"
TAXONOMY = REPO / "docs" / "pattern-variants.mdx"
NA_OVERRIDE = REPO / "scripts" / "pattern_variants_na.yml"
BUILD = REPO / "build"

# Rule `tag:` values that map onto each canonical category. A rule is
# placed in a category if its tag is in the category's tag set OR its
# rule id second segment matches one of the id-family aliases. Both
# axes are used because not every old rule has a tag yet.
CATEGORY_TAGS: dict[str, set[str]] = {
    "path-traversal": {
        "path-traversal",
        "zip-slip",
        "lfi",
        "path-sanitize",
        "regex-validate",
        "allowlist-validate",
        "char-allowlist",
    },
    "command-injection": {"command-injection", "shell-escape", "char-allowlist"},
    "sqli": {
        "sql-injection",
        "sqli",
        "cql-injection",
        "cypher-injection",
        "sql-parameter",
        "sql-parameterize",
        "sql-escape",
        "db-bind-parameter",
        "regex-validate",
        "allowlist-validate",
        "char-allowlist",
    },
    "ssrf": {"ssrf", "ssrf-sanitize", "url-build", "allowlist-validate"},
    "xss": {"xss"},
    "deserialization": {"insecure-deserialization"},
    "xxe": {"xxe"},
    "ldap-injection": {"ldap-injection"},
    "crypto": {"weak-crypto", "hash-collision", "timing-attack"},
    "tls": {"weak-tls"},
    "open-redirect": {
        "open-redirect",
        "open-redirect-sanitize",
        "same-origin-path",
        "url-encode",
        "regex-validate",
        "allowlist-validate",
        "char-allowlist",
    },
    "ssti": {"ssti"},
    "jwt": {"jwt", "untrusted-token"},
    "nosql-injection": {"nosql-injection"},
    "code-injection": {"code-injection", "jndi-injection"},
    "header-injection": {
        "header-injection",
        "host-header",
        "smtp-injection",
        "header-sanitize",
        "same-origin-path",
        "char-allowlist",
    },
    "regex-dos": {"redos", "atom-exhaustion", "ets-match-dos"},
    "prototype-pollution": {"prototype-pollution"},
    "request-smuggling": {"request-smuggling"},
    "mass-assignment": {"mass-assignment"},
    "cors-misconfig": {"cors"},
    "auth-bypass": {"weak-auth", "access-control"},
    "cookie-misconfig": {"cookie-misconfig"},
    "oauth-misconfig": {"oauth"},
    "csrf": {"csrf", "csrf-protect"},
    "rate-limit-missing": {"rate-limit", "rate-limit-missing"},
    "log-injection": {"log-injection"},
    "weak-rng": {"weak-randomness"},
    "info-disclosure": {"information-disclosure", "env-leak"},
    "graphql": {"graphql", "graphql-injection"},
    "llm": {"web-llm"},
}

# Rule-id second segment aliases per category (covers older rules that
# pre-date the unified tag vocabulary).
CATEGORY_ID_FAMILIES: dict[str, set[str]] = {
    # `passthrough` rules (URL decode etc.) count as path-traversal
    # because the canonical motivator for passthrough-as-identity-edge
    # is the urldecode-amplifier variant (Bludit CVE-2019-16113).
    "path-traversal": {"path", "lfi", "passthrough"},
    "command-injection": {"cmdi"},
    "sqli": {"sqli"},
    "ssrf": {"ssrf"},
    "xss": {"xss"},
    "deserialization": {"deserialization", "deser"},
    "xxe": {"xxe"},
    "ldap-injection": {"ldap"},
    "crypto": {"crypto"},
    "tls": {"tls"},
    "open-redirect": {"open_redirect", "oredr"},
    "ssti": {"template", "ssti", "tmpl"},
    "jwt": {"jwt"},
    "nosql-injection": {"nosql"},
    "code-injection": {"eval", "code"},
    "header-injection": {"header_injection", "header", "hdr", "smtp_inject"},
    "regex-dos": {"regex_dos", "redos"},
    "prototype-pollution": {"proto_pollution", "prototype"},
    "request-smuggling": {"smuggle", "request_smuggle"},
    "mass-assignment": {"mass_assign", "mass_assignment"},
    "cors-misconfig": {"cors"},
    "auth-bypass": {"auth", "authz", "access"},
    "cookie-misconfig": {"cookie"},
    "oauth-misconfig": {"oauth"},
    "csrf": {"csrf"},
    "rate-limit-missing": {"rate_limit", "ratelimit"},
    "log-injection": {"log_injection", "logging"},
    "weak-rng": {"rng", "random", "randomness"},
    "info-disclosure": {"info_disclosure", "info", "downstream"},
    "graphql": {"graphql"},
    "llm": {"llm"},
}

# Common boilerplate words that don't help variant matching.
STOP_TOKENS = {
    "the",
    "a",
    "an",
    "of",
    "for",
    "with",
    "and",
    "or",
    "to",
    "in",
    "on",
    "at",
    "as",
    "by",
    "is",
    "be",
    "from",
    "into",
    "via",
}

HEADING_CATEGORY_ALIASES = {
    "command-injection": "command-injection",
    "sql-injection": "sqli",
    "sqli": "sqli",
    "path-traversal": "path-traversal",
    "eval": "code-injection",
    "code-injection": "code-injection",
    "deserialisation": "deserialization",
    "deserialization": "deserialization",
    "header-injection": "header-injection",
    "html-escape": "xss",
    "xss": "xss",
    "parameterised-query": "sqli",
    "parameterized-query": "sqli",
    "token-verification": "jwt",
    "jwt": "jwt",
}


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "shape"


def variant_from_heading(category: str, name: str, desc: str = "") -> dict:
    cat_tokens = {t for t in re.split(r"[-_/]", category) if t}
    name_tokens = {
        t
        for t in re.split(r"[-_/]", name)
        if t and t not in STOP_TOKENS and t not in cat_tokens
    }
    desc_tokens = {
        w
        for w in re.findall(r"[a-z][a-z0-9_]+", desc.lower())
        if len(w) > 3 and w not in STOP_TOKENS and w not in cat_tokens
    }
    return {
        "name": name,
        "tokens": name_tokens | desc_tokens,
        "name_tokens": name_tokens,
        "shape": desc,
    }


def expanded_description_tokens(desc: str, category_tokens: set[str]) -> set[str]:
    tokens: set[str] = set()
    for word in re.findall(r"[a-z][a-z0-9_]+", desc.lower()):
        if len(word) <= 3 or word in STOP_TOKENS or word in category_tokens:
            continue
        tokens.add(word)
        tokens.update(
            part
            for part in word.split("_")
            if len(part) > 3 and part not in STOP_TOKENS and part not in category_tokens
        )
    return tokens


def taxonomy_from_bullets(text: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    category: str | None = None
    h3_re = re.compile(r"^### (.+?)\s*$")
    bullet_re = re.compile(r"^- \*\*([a-z0-9][a-z0-9-]*)\*\* — (.*)$")
    for raw in text.splitlines():
        heading = h3_re.match(raw)
        if heading:
            category = heading.group(1).split(" / ")[0].strip()
            out.setdefault(category, [])
            continue
        if category is None:
            continue
        bullet = bullet_re.match(raw)
        if not bullet:
            continue
        name, desc = bullet.groups()
        category_tokens = {t for t in re.split(r"[-_/]", category) if t}
        name_tokens = {
            t
            for t in re.split(r"[-_/]", name)
            if t and t not in STOP_TOKENS and t not in category_tokens
        }
        out[category].append(
            {
                "name": name,
                "tokens": name_tokens
                | expanded_description_tokens(desc, category_tokens),
                "name_tokens": name_tokens,
                "shape": desc,
            }
        )
    return out


def taxonomy_from_headings(text: str) -> dict[str, list[dict]]:
    section: str | None = None
    h2_re = re.compile(r"^## (.+?)\s*$")
    shape_re = re.compile(r"^### (.+?)\s*$")
    fallback: dict[str, list[dict]] = defaultdict(list)
    for raw in text.splitlines():
        m = h2_re.match(raw)
        if m:
            section = m.group(1).strip().lower()
            continue
        m = shape_re.match(raw)
        if not m or section not in {"sinks", "sanitizers"}:
            continue
        heading = m.group(1).strip()
        parts = re.split(r"\s+[—-]\s+", heading, maxsplit=1)
        category_label = parts[0]
        variant_label = parts[1] if len(parts) == 2 else parts[0]
        category_key = HEADING_CATEGORY_ALIASES.get(slugify(category_label))
        if not category_key:
            continue
        variant_name = slugify(variant_label)
        fallback[category_key].append(
            variant_from_heading(category_key, variant_name, heading)
        )
        if "deserial" in heading.lower() and category_key != "deserialization":
            fallback["deserialization"].append(
                variant_from_heading("deserialization", "deserialization", heading)
            )
    return dict(fallback)


def load_taxonomy() -> dict[str, list[dict]]:
    """Return {category-name: [{name, tokens, raw_line}]} from pattern-variants.mdx."""
    if not TAXONOMY.exists():
        sys.exit(f"missing taxonomy: {TAXONOMY}")
    text = TAXONOMY.read_text()
    taxonomy = taxonomy_from_bullets(text)
    if any(taxonomy.values()):
        return taxonomy
    taxonomy = taxonomy_from_headings(text)
    if not taxonomy:
        sys.exit(f"no taxonomy variants found in {TAXONOMY}")
    return taxonomy


def load_na_overrides() -> dict[tuple[str, str], list[str]]:
    """Optional sidecar: {(lang, category): [variant, ...]} that are n/a."""
    if not NA_OVERRIDE.exists():
        return {}
    data = yaml.safe_load(NA_OVERRIDE.read_text()) or {}
    out: dict[tuple[str, str], list[str]] = {}
    for lang, cats in data.items():
        for cat, variants in (cats or {}).items():
            out[(lang, cat)] = list(variants or [])
    return out


def load_rules(lang: str) -> list[dict]:
    """Flatten every rule for a language across sources/sinks/sanitizers."""
    rules: list[dict] = []
    for sub in ("sources", "sinks", "sanitizers"):
        d = PACK / lang / sub
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yml")):
            try:
                data = yaml.safe_load(f.read_text())
            except yaml.YAMLError as exc:
                rules.append(
                    {
                        "id": f"<parse-error>:{f.name}",
                        "_parse_error": str(exc),
                        "_kind": sub,
                        "_file": f.name,
                    }
                )
                continue
            if not isinstance(data, list):
                continue
            for r in data:
                if not isinstance(r, dict):
                    continue
                r["_kind"] = sub
                r["_file"] = f.name
                rules.append(r)
    return rules


def rule_categories(rule: dict) -> set[str]:
    """A rule may span more than one category (e.g. tag list)."""
    cats: set[str] = set()
    tags: list[str] = []
    t = rule.get("tag")
    if isinstance(t, str):
        tags = [t]
    elif isinstance(t, list):
        tags = [str(x) for x in t]
    for cat, tagset in CATEGORY_TAGS.items():
        if any(tag in tagset for tag in tags):
            cats.add(cat)
    rid = (rule.get("id") or "").split(".")
    if len(rid) >= 2:
        family = rid[1]
        for cat, families in CATEGORY_ID_FAMILIES.items():
            if family in families:
                cats.add(cat)
    return cats


def variant_for_rule(rule: dict, variants: list[dict]) -> str | None:
    """Pick the variant whose tokens overlap most with the rule id / file / tag."""
    rid = (rule.get("id") or "").lower()
    file = (rule.get("_file") or "").lower()
    tag = rule.get("tag")
    tag_str = (tag if isinstance(tag, str) else " ".join(tag)) if tag else ""
    desc = (rule.get("description") or "").lower()
    haystack = " ".join(
        [
            rid.replace(".", " ").replace("_", " "),
            file.replace(".yml", "").replace("_", " "),
            tag_str.lower(),
            desc,
        ]
    )
    haystack_tokens = set(re.findall(r"[a-z][a-z0-9]+", haystack))
    # Score = (name-overlap, total-overlap). Higher is better; name
    # overlap dominates so an alg-confusion rule isn't pulled toward
    # alg-none just because both share the `alg` token.
    best: tuple[int, int, str | None] = (0, 0, None)
    for v in variants:
        name_hits = len(v.get("name_tokens", set()) & haystack_tokens)
        total_hits = len(v["tokens"] & haystack_tokens)
        score = (name_hits, total_hits)
        if score > (best[0], best[1]):
            best = (name_hits, total_hits, v["name"])
    if best[1] == 0:
        return None
    return best[2]


def classify_category_rules(
    rules: list[dict], category: str, variants: list[dict]
) -> tuple[dict[str, list[dict]], dict[str, list[dict]], list[dict]]:
    enabled: dict[str, list[dict]] = defaultdict(list)
    disabled: dict[str, list[dict]] = defaultdict(list)
    unmatched = []
    for rule in rules:
        if category not in rule_categories(rule):
            continue
        variant = variant_for_rule(rule, variants)
        if variant is None:
            unmatched.append(rule)
        elif rule.get("enabled") is False:
            disabled[variant].append(rule)
        else:
            enabled[variant].append(rule)
    return enabled, disabled, unmatched


def coverage_status(
    variant: str,
    not_applicable: set[str],
    enabled: dict[str, list[dict]],
    disabled: dict[str, list[dict]],
) -> str:
    if variant in not_applicable:
        return "n/a"
    if variant in enabled:
        return "x"
    if variant in disabled:
        return "partial"
    return "-"


def add_category_cells(
    matrix: dict,
    *,
    lang: str,
    category: str,
    variants: list[dict],
    rules: list[dict],
    not_applicable: set[str],
) -> None:
    enabled, disabled, unmatched = classify_category_rules(rules, category, variants)
    for variant in variants:
        name = variant["name"]
        matrix["cells"][f"{lang}|{category}|{name}"] = {
            "lang": lang,
            "category": category,
            "variant": name,
            "status": coverage_status(name, not_applicable, enabled, disabled),
            "rule_count": len(enabled.get(name, [])),
            "disabled_count": len(disabled.get(name, [])),
        }
    if unmatched:
        matrix["cells"][f"{lang}|{category}|<unmatched>"] = {
            "lang": lang,
            "category": category,
            "variant": "<unmatched>",
            "status": "info",
            "rule_count": len(unmatched),
            "ids": [rule.get("id") for rule in unmatched[:10]],
        }


def build_matrix() -> dict:
    taxonomy = load_taxonomy()
    na_overrides = load_na_overrides()
    langs = sorted(path.name for path in PACK.iterdir() if path.is_dir())
    matrix: dict = {
        "langs": langs,
        "categories": list(taxonomy),
        "cells": {},
    }
    for lang in langs:
        rules = load_rules(lang)
        for category, variants in taxonomy.items():
            add_category_cells(
                matrix,
                lang=lang,
                category=category,
                variants=variants,
                rules=rules,
                not_applicable=set(na_overrides.get((lang, category), [])),
            )
    return matrix


def category_tables(matrix: dict) -> list[str]:
    by_cat: dict[str, dict[str, dict[str, str]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for cell in matrix["cells"].values():
        if cell["variant"] == "<unmatched>":
            continue
        by_cat[cell["category"]][cell["variant"]][cell["lang"]] = cell["status"]
    lines = []
    for category in matrix["categories"]:
        lines.append(f"## {category}")
        lines.append("")
        header = ["variant"] + matrix["langs"]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("| " + " | ".join("---" for _ in header) + " |")
        for variant in sorted(by_cat[category]):
            row = [variant] + [
                by_cat[category][variant].get(lang, "-") for lang in matrix["langs"]
            ]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
    return lines


def aggregate_lines(matrix: dict) -> list[str]:
    counts = defaultdict(int)
    for cell in matrix["cells"].values():
        if cell["variant"] != "<unmatched>":
            counts[cell["status"]] += 1
    total = sum(counts.values())
    lines = ["## Aggregate", ""]
    for status in ("x", "partial", "-", "n/a"):
        count = counts.get(status, 0)
        percent = (100.0 * count / total) if total else 0
        lines.append(f"- `{status}`: {count} ({percent:.1f}%)")
    lines.append("")
    return lines


def unmatched_rule_lines(matrix: dict) -> list[str]:
    lines = [
        "## Unmatched rules (review hints)",
        "",
        "Rules whose tag/id placed them in a category but whose "
        "name/file did not overlap any variant token. Either the "
        "variant name is too narrow (update pattern-variants.mdx) or "
        "the rule id is wrong (rename in the rulepack).",
        "",
    ]
    for cell in matrix["cells"].values():
        if cell["variant"] != "<unmatched>" or cell["rule_count"] == 0:
            continue
        ids = cell.get("ids", [])
        lines.append(
            f"- {cell['lang']} / {cell['category']}: "
            f"{cell['rule_count']} rules; sample: {', '.join(ids)}"
        )
    lines.append("")
    return lines


def render_markdown(matrix: dict) -> str:
    lines = [
        "# Category coverage matrix",
        "",
        "Generated by `scripts/category_audit.py`. Cells:",
        "",
        "- `x` rule(s) present and enabled",
        "- `partial` rule(s) present but disabled",
        "- `-` no rule found",
        "- `n/a` language lacks the primitive",
        "",
    ]
    lines.extend(category_tables(matrix))
    lines.extend(aggregate_lines(matrix))
    lines.extend(unmatched_rule_lines(matrix))
    return "\n".join(lines)


def emit_default() -> int:
    matrix = build_matrix()
    BUILD.mkdir(parents=True, exist_ok=True)
    md_path = BUILD / "category_coverage.md"
    json_path = BUILD / "category_coverage.json"
    md_path.write_text(render_markdown(matrix))
    json_path.write_text(json.dumps(matrix, indent=2, sort_keys=True))
    print(f"wrote {md_path.relative_to(REPO)}")
    print(f"wrote {json_path.relative_to(REPO)}")
    counts = defaultdict(int)
    for cell in matrix["cells"].values():
        if cell["variant"] == "<unmatched>":
            continue
        counts[cell["status"]] += 1
    total = sum(counts.values())
    print(
        f"cells: {total} | x={counts['x']} partial={counts['partial']} -={counts['-']} n/a={counts['n/a']}"
    )
    return 0


def matrix_status(matrix: dict) -> dict[str, str]:
    return {
        key: cell["status"]
        for key, cell in matrix["cells"].items()
        if cell["variant"] != "<unmatched>"
    }


def baseline_status(base: str) -> dict[str, str] | None:
    tmp = REPO / "build" / f".diff-base.{base.replace('/', '_')}"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "git",
                "--git-dir",
                str(REPO / ".git"),
                "worktree",
                "add",
                "--detach",
                str(tmp),
                base,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"git worktree add failed: {exc.stderr}", file=sys.stderr)
        return None

    try:
        prev_proc = subprocess.run(
            [sys.executable, str(tmp / "scripts" / "category_audit.py")],
            cwd=str(tmp),
            capture_output=True,
            text=True,
        )
        if prev_proc.returncode != 0:
            print(
                "baseline run failed; treating all current cells as new",
                file=sys.stderr,
            )
            return {}
        prev_path = tmp / "build" / "category_coverage.json"
        return matrix_status(json.loads(prev_path.read_text()))
    finally:
        subprocess.run(
            [
                "git",
                "--git-dir",
                str(REPO / ".git"),
                "worktree",
                "remove",
                "--force",
                str(tmp),
            ],
            capture_output=True,
            text=True,
        )


def compare_statuses(
    current: dict[str, str], previous: dict[str, str]
) -> tuple[list[tuple], list[tuple], list[tuple]]:
    rank = {"x": 3, "partial": 2, "n/a": 1, "-": 0}
    regressions = []
    improvements = []
    new_cells = []
    for key, status in current.items():
        if key not in previous:
            if status != "-":
                new_cells.append((key, status))
            continue
        before = previous[key]
        if rank.get(status, 0) < rank.get(before, 0):
            regressions.append((key, before, status))
        elif rank.get(status, 0) > rank.get(before, 0):
            improvements.append((key, before, status))
    return regressions, improvements, new_cells


def print_status_changes(
    regressions: list[tuple],
    improvements: list[tuple],
    new_cells: list[tuple],
) -> None:
    sections = (
        ("REGRESSIONS:", regressions),
        ("IMPROVEMENTS:", improvements),
        ("NEW CELLS:", new_cells),
    )
    for title, rows in sections:
        if not rows:
            continue
        print(title)
        for row in rows:
            if len(row) == 3:
                key, before, after = row
                print(f"  {key}: {before} -> {after}")
            else:
                key, status = row
                print(f"  {key}: {status}")


def diff_against(base: str) -> int:
    """Compare the current matrix to the matrix produced from `base`'s tree."""
    previous = baseline_status(base)
    if previous is None:
        return 2
    regressions, improvements, new_cells = compare_statuses(
        matrix_status(build_matrix()), previous
    )
    print_status_changes(regressions, improvements, new_cells)
    return 1 if regressions else 0


def suggest_yaml(lang: str, category: str) -> int:
    taxonomy = load_taxonomy()
    if category not in taxonomy:
        print(f"unknown category: {category}", file=sys.stderr)
        print(f"known: {', '.join(sorted(taxonomy))}", file=sys.stderr)
        return 2
    matrix = build_matrix()
    cells = [
        c
        for c in matrix["cells"].values()
        if c["lang"] == lang
        and c["category"] == category
        and c["status"] in {"-", "partial"}
        and c["variant"] != "<unmatched>"
    ]
    if not cells:
        print(f"# {lang} / {category}: no missing variants")
        return 0
    stubs: list[dict] = []
    for cell in cells:
        variant = cell["variant"]
        rule_id = (
            f"{lang}.{category.replace('-', '_')}.TODO_{variant.replace('-', '_')}"
        )
        tag = next(iter(CATEGORY_TAGS.get(category, [category])))
        stubs.append(
            {
                "id": rule_id,
                "enabled": False,  # default off until reviewer enables
                "tag": tag,
                "severity": "high",
                "match": {
                    "kind": "call",
                    "callee": {"name": "TODO_callee_here"},
                },
                "description": f"TODO: {category} / {variant} sink for {lang}. See docs/pattern-variants.mdx.",
            }
        )
    print(yaml.safe_dump(stubs, sort_keys=False, default_flow_style=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--diff",
        metavar="GIT_BASE",
        help="compare matrix to <GIT_BASE>; nonzero exit on regression",
    )
    ap.add_argument(
        "--suggest",
        nargs=2,
        metavar=("LANG", "CATEGORY"),
        help="print YAML stubs for missing variants in (lang, category)",
    )
    args = ap.parse_args()
    if args.diff:
        return diff_against(args.diff)
    if args.suggest:
        return suggest_yaml(*args.suggest)
    return emit_default()


if __name__ == "__main__":
    raise SystemExit(main())
