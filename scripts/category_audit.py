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
    "jwt": {"jwt", "untrusted-token", "signature-replay"},
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
    "info-disclosure": {"information-disclosure", "information-exposure", "env-leak"},
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
    "the", "a", "an", "of", "for", "with", "and", "or", "to", "in",
    "on", "at", "as", "by", "is", "be", "from", "into", "via",
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
        t for t in re.split(r"[-_/]", name)
        if t and t not in STOP_TOKENS and t not in cat_tokens
    }
    desc_tokens = {
        w for w in re.findall(r"[a-z][a-z0-9_]+", desc.lower())
        if len(w) > 3 and w not in STOP_TOKENS and w not in cat_tokens
    }
    return {
        "name": name,
        "tokens": name_tokens | desc_tokens,
        "name_tokens": name_tokens,
        "shape": desc,
    }


def load_taxonomy() -> dict[str, list[dict]]:
    """Return {category-name: [{name, tokens, raw_line}]} from pattern-variants.mdx."""
    if not TAXONOMY.exists():
        sys.exit(f"missing taxonomy: {TAXONOMY}")
    text = TAXONOMY.read_text()
    out: dict[str, list[dict]] = {}
    cur: str | None = None
    h3_re = re.compile(r"^### (.+?)\s*$")
    bullet_re = re.compile(r"^- \*\*([a-z0-9][a-z0-9-]*)\*\* — (.*)$")
    for raw in text.splitlines():
        m = h3_re.match(raw)
        if m:
            # Normalize "ssti / template-injection" -> "ssti", "code-injection / eval" -> "code-injection".
            cur = m.group(1).split(" / ")[0].strip()
            out.setdefault(cur, [])
            continue
        if cur is None:
            continue
        m = bullet_re.match(raw)
        if not m:
            continue
        name = m.group(1)
        desc = m.group(2)
        # Tokens are tracked in two buckets: name-tokens (the variant's
        # short name) carry more semantic weight than desc-tokens
        # (synonyms scraped from the prose). When two variants tie on
        # total overlap, the one with higher name-overlap wins — that
        # avoids `alg-confusion` losing to `alg-none` just because
        # both share the `alg` token.
        # Strip category-name tokens — every rule in the category will
        # have these (e.g. every `*.xxe.*` rule has "xxe"), so they
        # carry zero discriminating power and just bias the matcher.
        cat_tokens = {t for t in re.split(r"[-_/]", cur) if t}
        name_tokens = {
            t for t in re.split(r"[-_/]", name)
            if t and t not in STOP_TOKENS and t not in cat_tokens
        }
        desc_tokens: set[str] = set()
        for w in re.findall(r"[a-z][a-z0-9_]+", desc.lower()):
            if len(w) > 3 and w not in STOP_TOKENS and w not in cat_tokens:
                desc_tokens.add(w)
                for sub in w.split("_"):
                    if len(sub) > 3 and sub not in STOP_TOKENS and sub not in cat_tokens:
                        desc_tokens.add(sub)
        tokens = name_tokens | desc_tokens
        out[cur].append({
            "name": name,
            "tokens": tokens,
            "name_tokens": name_tokens,
            "shape": desc,
        })
    if any(out.values()):
        return out

    # Current MDX docs present rule shapes as `### Category — variant`
    # examples rather than the older bullet taxonomy. Keep this audit
    # useful by deriving a compact taxonomy from those headings.
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
    if not fallback:
        sys.exit(f"no taxonomy variants found in {TAXONOMY}")
    return dict(fallback)


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
                rules.append({
                    "id": f"<parse-error>:{f.name}",
                    "_parse_error": str(exc),
                    "_kind": sub,
                    "_file": f.name,
                })
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
    haystack = " ".join([rid.replace(".", " ").replace("_", " "),
                         file.replace(".yml", "").replace("_", " "),
                         tag_str.lower(), desc])
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


def build_matrix() -> dict:
    taxonomy = load_taxonomy()
    na_overrides = load_na_overrides()
    langs = sorted([p.name for p in PACK.iterdir() if p.is_dir()])
    matrix: dict = {
        "langs": langs,
        "categories": list(taxonomy.keys()),
        "cells": {},
    }
    for lang in langs:
        rules = load_rules(lang)
        for cat, variants in taxonomy.items():
            classified = defaultdict(list)
            classified_disabled = defaultdict(list)
            uncat: list[dict] = []
            for r in rules:
                if cat not in rule_categories(r):
                    continue
                v = variant_for_rule(r, variants)
                if v is None:
                    uncat.append(r)
                    continue
                if r.get("enabled") is False:
                    classified_disabled[v].append(r)
                else:
                    classified[v].append(r)
            na_list = set(na_overrides.get((lang, cat), []))
            for v in variants:
                vname = v["name"]
                cell_id = f"{lang}|{cat}|{vname}"
                if vname in na_list:
                    status = "n/a"
                elif vname in classified:
                    status = "x"
                elif vname in classified_disabled:
                    status = "partial"
                else:
                    status = "-"
                matrix["cells"][cell_id] = {
                    "lang": lang,
                    "category": cat,
                    "variant": vname,
                    "status": status,
                    "rule_count": len(classified.get(vname, [])),
                    "disabled_count": len(classified_disabled.get(vname, [])),
                }
            # Stash uncategorized rules for visibility (per-cat).
            unmatched_id = f"{lang}|{cat}|<unmatched>"
            if uncat:
                matrix["cells"][unmatched_id] = {
                    "lang": lang,
                    "category": cat,
                    "variant": "<unmatched>",
                    "status": "info",
                    "rule_count": len(uncat),
                    "ids": [r.get("id") for r in uncat[:10]],
                }
    return matrix


def render_markdown(matrix: dict) -> str:
    lines: list[str] = []
    lines.append("# Category coverage matrix")
    lines.append("")
    lines.append("Generated by `scripts/category_audit.py`. Cells:")
    lines.append("")
    lines.append("- `x` rule(s) present and enabled")
    lines.append("- `partial` rule(s) present but disabled")
    lines.append("- `-` no rule found")
    lines.append("- `n/a` language lacks the primitive")
    lines.append("")
    by_cat: dict[str, dict[str, dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
    for cell in matrix["cells"].values():
        if cell["variant"] == "<unmatched>":
            continue
        by_cat[cell["category"]][cell["variant"]][cell["lang"]] = cell["status"]
    for cat in matrix["categories"]:
        lines.append(f"## {cat}")
        lines.append("")
        header = ["variant"] + matrix["langs"]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("| " + " | ".join("---" for _ in header) + " |")
        variants = sorted(by_cat[cat].keys())
        for v in variants:
            row = [v] + [by_cat[cat][v].get(lang, "-") for lang in matrix["langs"]]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    lines.append("## Aggregate")
    lines.append("")
    counts = defaultdict(int)
    for cell in matrix["cells"].values():
        if cell["variant"] == "<unmatched>":
            continue
        counts[cell["status"]] += 1
    total = sum(counts.values())
    for status in ("x", "partial", "-", "n/a"):
        n = counts.get(status, 0)
        pct = (100.0 * n / total) if total else 0
        lines.append(f"- `{status}`: {n} ({pct:.1f}%)")
    lines.append("")

    lines.append("## Unmatched rules (review hints)")
    lines.append("")
    lines.append("Rules whose tag/id placed them in a category but whose "
                 "name/file did not overlap any variant token. Either the "
                 "variant name is too narrow (update pattern-variants.mdx) or "
                 "the rule id is wrong (rename in the rulepack).")
    lines.append("")
    for cell in matrix["cells"].values():
        if cell["variant"] != "<unmatched>":
            continue
        if cell["rule_count"] == 0:
            continue
        ids = cell.get("ids", [])
        lines.append(f"- {cell['lang']} / {cell['category']}: {cell['rule_count']} rules; sample: {', '.join(ids)}")
    lines.append("")
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
    print(f"cells: {total} | x={counts['x']} partial={counts['partial']} -={counts['-']} n/a={counts['n/a']}")
    return 0


def diff_against(base: str) -> int:
    """Compare the current matrix to the matrix produced from `base`'s tree.

    We only need to compare cell statuses. We rebuild the matrix in
    a worktree-free fashion by `git show`-ing the relevant files.
    """
    cur = build_matrix()
    cur_status = {k: v["status"] for k, v in cur["cells"].items() if v["variant"] != "<unmatched>"}

    # Build prior matrix by checking out the base tree to a temp dir.
    tmp = REPO / "build" / f".diff-base.{base.replace('/', '_')}"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "--git-dir", str(REPO / ".git"), "worktree", "add",
             "--detach", str(tmp), base],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"git worktree add failed: {exc.stderr}", file=sys.stderr)
        return 2

    try:
        prev_proc = subprocess.run(
            [sys.executable, str(tmp / "scripts" / "category_audit.py")],
            cwd=str(tmp), capture_output=True, text=True,
        )
        if prev_proc.returncode != 0:
            print("baseline run failed; treating all current cells as new",
                  file=sys.stderr)
            prev = {}
        else:
            prev_path = tmp / "build" / "category_coverage.json"
            prev_data = json.loads(prev_path.read_text())
            prev = {k: v["status"] for k, v in prev_data["cells"].items()
                    if v["variant"] != "<unmatched>"}
    finally:
        subprocess.run(
            ["git", "--git-dir", str(REPO / ".git"), "worktree", "remove",
             "--force", str(tmp)],
            capture_output=True, text=True,
        )

    rank = {"x": 3, "partial": 2, "n/a": 1, "-": 0}
    regressions = []
    improvements = []
    new_cells = []
    for k, status in cur_status.items():
        if k not in prev:
            if status != "-":
                new_cells.append((k, status))
            continue
        if rank.get(status, 0) < rank.get(prev[k], 0):
            regressions.append((k, prev[k], status))
        elif rank.get(status, 0) > rank.get(prev[k], 0):
            improvements.append((k, prev[k], status))

    if regressions:
        print("REGRESSIONS:")
        for k, before, after in regressions:
            print(f"  {k}: {before} -> {after}")
    if improvements:
        print("IMPROVEMENTS:")
        for k, before, after in improvements:
            print(f"  {k}: {before} -> {after}")
    if new_cells:
        print("NEW CELLS:")
        for k, status in new_cells:
            print(f"  {k}: {status}")
    return 1 if regressions else 0


def suggest_yaml(lang: str, category: str) -> int:
    taxonomy = load_taxonomy()
    if category not in taxonomy:
        print(f"unknown category: {category}", file=sys.stderr)
        print(f"known: {', '.join(sorted(taxonomy))}", file=sys.stderr)
        return 2
    matrix = build_matrix()
    cells = [c for c in matrix["cells"].values()
             if c["lang"] == lang
             and c["category"] == category
             and c["status"] in {"-", "partial"}
             and c["variant"] != "<unmatched>"]
    if not cells:
        print(f"# {lang} / {category}: no missing variants")
        return 0
    stubs: list[dict] = []
    for cell in cells:
        variant = cell["variant"]
        rule_id = f"{lang}.{category.replace('-', '_')}.TODO_{variant.replace('-', '_')}"
        tag = next(iter(CATEGORY_TAGS.get(category, [category])))
        stubs.append({
            "id": rule_id,
            "enabled": False,  # default off until reviewer enables
            "tag": tag,
            "severity": "high",
            "match": {
                "kind": "call",
                "callee": {"name": "TODO_callee_here"},
            },
            "description": f"TODO: {category} / {variant} sink for {lang}. See docs/pattern-variants.mdx.",
        })
    print(yaml.safe_dump(stubs, sort_keys=False, default_flow_style=False))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--diff", metavar="GIT_BASE",
                    help="compare matrix to <GIT_BASE>; nonzero exit on regression")
    ap.add_argument("--suggest", nargs=2, metavar=("LANG", "CATEGORY"),
                    help="print YAML stubs for missing variants in (lang, category)")
    args = ap.parse_args()
    if args.diff:
        return diff_against(args.diff)
    if args.suggest:
        return suggest_yaml(*args.suggest)
    return emit_default()


if __name__ == "__main__":
    raise SystemExit(main())
