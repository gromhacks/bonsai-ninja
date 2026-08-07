#!/usr/bin/env python3
"""Audit the bonsai-ninja security-patterns rulepack.

Walks `security-patterns/langs/<lang>/{sources,sinks,sanitizers}/*.yml`,
loads every rule, and emits a per-(lang, category) report covering:

  - rule counts, enabled/disabled split
  - rule-id family coverage vs the canonical 17 sink families
  - match-shape distribution (call/new/read/write/...)
  - matcher-precision distribution (attribute-chain / regex / bare name / ...)
  - rules that look fragile (bare verb names, missing package/import scoping)
  - missing canonical families per lang
  - per-tag and per-severity rollups
  - duplicate ids, duplicate enabled match shapes, and cross-family API
    collisions (`--duplicates`)

Usage:
    python3 scripts/pack_audit.py [--lang LANG] [--category CAT] [--json]
    python3 scripts/pack_audit.py --duplicates [--json] [--fail-on-family-file-mismatch]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "security-patterns" / "langs"

CATEGORIES = ("sources", "sinks", "sanitizers")

# Canonical sink families tracked by `security pack --audit`. Each entry is the
# canonical name plus any in-pack aliases used in rule ids.
CANONICAL_SINK_FAMILIES: dict[str, tuple[str, ...]] = {
    "cmdi": ("cmdi",),
    "sqli": ("sqli",),
    "nosql": ("nosql",),
    "path": ("path",),
    "ssrf": ("ssrf",),
    "xss": ("xss",),
    "eval": ("eval",),
    "deserialization": ("deserialization", "deser"),
    "xxe": ("xxe",),
    "ldap": ("ldap",),
    "jwt": ("jwt",),
    "crypto": ("crypto",),
    "tls": ("tls",),
    "template": ("template", "ssti", "tmpl"),
    "open_redirect": ("open_redirect", "oredr"),
    "file_upload": ("file_upload", "upload", "upld"),
    "header_injection": ("header_injection", "header", "hdr"),
}

FAMILY_NOT_APPLICABLE = {("c", "deserialization")}

FAMILY_FILE_ALIASES: dict[str, tuple[str, ...]] = {
    "cache_poisoning": ("cache",),
    "cors_csrf": ("cors",),
    "deserialization": ("deser",),
    "downstream": ("sink",),
    "file_upload": (
        "upload",
        "upld",
        "upload_file_copy_client_filename",
        "upload_file_copy_to_client_filename",
        "upload_file_write_client_filename",
        "upload_gcdwebserver_uploaded_file_path",
        "upload_io_open_client_filename",
    ),
    "header_injection": ("header",),
    "host_header": ("hostheader",),
    "jwt": (
        "jwt_jose_decode_unverified",
        "jwt_jwt_decode_no_verify",
    ),
    "log_injection": ("log",),
    "mass_assignment": ("mass_assign",),
    "nosql": ("nosql_mongoc_aggregate",),
    "open_redirect": ("oredr",),
    "prototype_pollution": ("proto", "proto_pollution"),
    "queue": ("celery",),
    "request_smuggling": ("smuggle",),
    "race": ("toctou",),
    "regex_dos": ("redos",),
    "info_disclosure": ("info", "info_disclosure"),
    "smtp_inject": ("smtpinj",),
    "template": (
        "ssti",
        "template_bbmustache_compile",
        "template_mustache_render",
    ),
}

# Rules whose match shape uses a single `name:` (not `attribute:` or `regex:`)
# are considered "bare-name" risks unless they have a package/import constraint.
BARE_NAME_VERBS = {
    "open",
    "load",
    "exec",
    "execute",
    "query",
    "write",
    "read",
    "copy",
    "create",
    "parse",
    "send",
    "run",
    "eval",
    "fetch",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "call",
    "invoke",
    "spawn",
}

# Bare-name rules that have been manually reviewed and are intentionally
# package-less. These are language builtins, POSIX/PHP stdlib globals, or
# lifecycle-state uses where the precise guard is the taint/state constraint,
# not an import/package signal.
REVIEWED_BARE_NAME_RULES = {
    "c.path.open",
    "cpp.path.open",
    "erlang.memory.gen_server_stop",
    "perl.cmdi.exec",
    "perl.eval.builtin_eval",
    "php.path.copy",
    "php.path.copy_dest",
    "python.eval.builtin_exec",
    "ruby.cmdi.kernel_exec",
    "ruby.eval.builtin_eval",
    "ruby.memory.io_close",
    "ruby.memory.file_close",
}


def load_yaml(path: Path) -> list[dict]:
    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return [{"_parse_error": str(exc), "_path": str(path)}]
    if data is None:
        return []
    if not isinstance(data, list):
        return [{"_shape_error": "top-level not a list", "_path": str(path)}]
    return data


def iter_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(PACK.glob("*/*/*.yml")):
        rel = path.relative_to(REPO)
        parts = path.relative_to(PACK).parts
        if len(parts) < 3:
            continue
        lang, category, file_name = parts[0], parts[1], parts[-1]
        for idx, rule in enumerate(load_yaml(path)):
            if rule.get("_parse_error") or rule.get("_shape_error"):
                rule["_path"] = str(rel)
                rules.append(rule)
                continue
            rule = dict(rule)
            rule["_lang"] = lang
            rule["_category"] = category
            rule["_family_file"] = Path(file_name).stem
            rule["_path"] = str(rel)
            rule["_index"] = idx
            rules.append(rule)
    return rules


def rule_family_from_id(rule: dict) -> str:
    rid = str(rule.get("id") or "")
    parts = rid.split(".")
    return parts[1] if len(parts) >= 2 else "<missing>"


def canonical_family_from_id(rule_id: str) -> str:
    parts = str(rule_id or "").split(".")
    family = parts[1] if len(parts) >= 2 else "<missing>"
    for canonical, aliases in CANONICAL_SINK_FAMILIES.items():
        if family == canonical or family in aliases:
            return canonical
    for canonical, aliases in FAMILY_FILE_ALIASES.items():
        if family == canonical or family in aliases:
            return canonical
    return family


def rule_coverage_families(rule: dict) -> set[str]:
    ids = [str(rule.get("id") or "")]
    aliases = rule.get("aliases") or []
    if isinstance(aliases, list):
        ids.extend(str(alias) for alias in aliases)
    return {canonical_family_from_id(rule_id) for rule_id in ids if rule_id}


def normalise_for_signature(value):
    if isinstance(value, dict):
        return {
            str(k): normalise_for_signature(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
            if not str(k).startswith("_")
        }
    if isinstance(value, list):
        return [normalise_for_signature(v) for v in value]
    return value


def signature_json(value) -> str:
    return json.dumps(
        normalise_for_signature(value), sort_keys=True, separators=(",", ":")
    )


def match_signature(rule: dict) -> str:
    return signature_json(
        {
            "match": rule.get("match"),
            "constraints": rule.get("constraints"),
        }
    )


def api_signature(rule: dict) -> str:
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    target = {}
    for key in ("callee", "target", "name"):
        if key in match:
            target[key] = match.get(key)
    return signature_json(
        {
            "kind": match.get("kind"),
            "target": target,
            "packages": rule.get("packages"),
            "imports": rule.get("imports"),
            "frameworks": rule.get("frameworks"),
            "namespace": rule.get("namespace"),
            "constraints": rule.get("constraints"),
        }
    )


def location(rule: dict) -> dict:
    return {
        "id": rule.get("id"),
        "path": rule.get("_path"),
        "language": rule.get("_lang") or rule.get("language"),
        "category": rule.get("_category"),
        "family": rule_family_from_id(rule),
        "enabled": rule.get("enabled", True),
    }


def duplicate_ids_for(rules: list[dict]) -> list[dict]:
    by_id: dict[str, list[dict]] = defaultdict(list)
    for rule in rules:
        rid = rule.get("id")
        if rid:
            by_id[str(rid)].append(rule)
    return [
        {"id": rid, "rules": [location(rule) for rule in group]}
        for rid, group in sorted(by_id.items())
        if len(group) > 1
    ]


def duplicate_match_shapes(enabled: list[dict]) -> list[dict]:
    by_shape: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for rule in enabled:
        key = (
            str(rule.get("_lang") or rule.get("language") or "<unknown>"),
            str(rule.get("_category") or "<unknown>"),
            rule_family_from_id(rule),
            match_signature(rule),
        )
        by_shape[key].append(rule)
    return [
        {
            "language": lang,
            "category": category,
            "family": family,
            "match_signature": sig,
            "rules": [location(rule) for rule in group],
        }
        for (lang, category, family, sig), group in sorted(by_shape.items())
        if len(group) > 1
    ]


def cross_family_collisions(enabled: list[dict]) -> list[dict]:
    by_api: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for rule in enabled:
        sig = api_signature(rule)
        if sig == "{}":
            continue
        key = (
            str(rule.get("_lang") or rule.get("language") or "<unknown>"),
            str(rule.get("_category") or "<unknown>"),
            sig,
        )
        by_api[key].append(rule)
    collisions = []
    for (lang, category, sig), group in sorted(by_api.items()):
        families = sorted({rule_family_from_id(rule) for rule in group})
        if len(families) <= 1:
            continue
        collisions.append(
            {
                "language": lang,
                "category": category,
                "api_signature": sig,
                "families": families,
                "rules": [location(rule) for rule in group],
            }
        )
    return collisions


def family_file_mismatches_for(rules: list[dict]) -> list[dict]:
    mismatches = []
    for rule in rules:
        if rule.get("_category") != "sinks":
            continue
        id_family = rule_family_from_id(rule)
        file_family = str(rule.get("_family_file"))
        allowed = {file_family, *FAMILY_FILE_ALIASES.get(file_family, ())}
        if id_family in allowed or id_family == "<missing>":
            continue
        mismatches.append(
            {
                "id": rule.get("id"),
                "path": rule.get("_path"),
                "id_family": id_family,
                "file_family": file_family,
                "language": rule.get("_lang") or rule.get("language"),
                "category": rule.get("_category"),
                "enabled": rule.get("enabled", True),
            }
        )
    return mismatches


def duplicate_audit() -> dict:
    rules = [
        rule
        for rule in iter_rules()
        if not rule.get("_parse_error") and not rule.get("_shape_error")
    ]
    enabled = [rule for rule in rules if rule.get("enabled", True)]

    return {
        "duplicate_ids": duplicate_ids_for(rules),
        "duplicate_enabled_match_shapes": duplicate_match_shapes(enabled),
        "cross_family_api_collisions": cross_family_collisions(enabled),
        "family_file_mismatches": family_file_mismatches_for(rules),
    }


def render_duplicate_text(report: dict) -> str:
    out = ["Duplicate / collision audit"]
    sections = [
        ("Duplicate IDs", "duplicate_ids"),
        ("Duplicate enabled match shapes", "duplicate_enabled_match_shapes"),
        ("Cross-family API collisions", "cross_family_api_collisions"),
        ("Family file mismatches", "family_file_mismatches"),
    ]
    for title, key in sections:
        rows = report[key]
        out.append("")
        out.append(f"{title}: {len(rows)}")
        for row in rows[:50]:
            if key == "duplicate_ids":
                out.append(f"  - {row['id']}")
            elif key == "duplicate_enabled_match_shapes":
                out.append(
                    f"  - {row['language']}/{row['category']}/{row['family']}: "
                    f"{len(row['rules'])} rules share one enabled match shape"
                )
            elif key == "cross_family_api_collisions":
                out.append(
                    f"  - {row['language']}/{row['category']}: families="
                    f"{','.join(row['families'])}"
                )
            else:
                out.append(
                    f"  - {row['id']} in {row['path']} "
                    f"(id family={row['id_family']}, file={row['file_family']})"
                )
            for rule in row.get("rules", [])[:6]:
                out.append(f"      {rule['id']} ({rule['path']})")
            if len(row.get("rules", [])) > 6:
                out.append(f"      ... +{len(row['rules']) - 6} more")
        if len(rows) > 50:
            out.append(f"  ... +{len(rows) - 50} more")
    return "\n".join(out)


def classify_match_shape(rule: dict) -> str:
    m = rule.get("match") or {}
    if not isinstance(m, dict):
        return "<no-match>"
    return str(m.get("kind", "<no-kind>"))


def classify_precision(rule: dict) -> str:
    m = rule.get("match") or {}
    if not isinstance(m, dict):
        return "<no-match>"
    target_keys = ("callee", "target", "name")
    for key in target_keys:
        spec = m.get(key)
        if not isinstance(spec, dict):
            continue
        if "attribute" in spec:
            return "attribute-chain"
        if "regex" in spec:
            return "regex"
        if "name" in spec:
            name = spec["name"]
            if isinstance(name, list):
                return "name-list"
            return "bare-name"
    return "other"


def is_fragile(rule: dict) -> tuple[bool, str | None]:
    """Identify rules that risk over-matching: bare verb name, no package scope."""
    if rule.get("_parse_error") or rule.get("_shape_error"):
        return False, None
    if rule.get("enabled") is False:
        return False, None
    m = rule.get("match") or {}
    if not isinstance(m, dict):
        return False, None
    bare = None
    for key in ("callee", "target", "name"):
        spec = m.get(key) if isinstance(m.get(key), dict) else None
        if spec and "name" in spec and "attribute" not in spec and "regex" not in spec:
            n = spec["name"]
            if isinstance(n, str) and n.lower() in BARE_NAME_VERBS:
                bare = n
                break
    if bare is None:
        return False, None
    if str(rule.get("id") or "") in REVIEWED_BARE_NAME_RULES:
        return False, None
    has_scope = any(
        rule.get(k) for k in ("packages", "imports", "frameworks", "namespace")
    )
    if has_scope:
        return False, None
    return True, f"bare-name '{bare}' without packages/imports/frameworks scope"


def load_category_rules(base: Path) -> tuple[list[Path], list[dict], list[dict]]:
    files = sorted(base.glob("*.yml")) if base.exists() else []
    rules = []
    parse_errors = []
    for path in files:
        for rule in load_yaml(path):
            if rule.get("_parse_error") or rule.get("_shape_error"):
                parse_errors.append(rule)
                continue
            rule["_file"] = path.name
            rules.append(rule)
    return files, rules, parse_errors


def tag_counts(rules: list[dict]) -> Counter[str]:
    tags: Counter[str] = Counter()
    for rule in rules:
        tag = rule.get("tag")
        if isinstance(tag, str):
            tags[tag] += 1
        elif isinstance(tag, list):
            tags.update(str(value) for value in tag)
    return tags


def fragile_rules(rules: list[dict]) -> list[dict]:
    fragile = []
    for rule in rules:
        bad, why = is_fragile(rule)
        if bad:
            fragile.append(
                {
                    "id": rule.get("id"),
                    "file": rule.get("_file"),
                    "issue": why,
                }
            )
    return fragile


def missing_canonical_families(
    lang: str, category: str, families: Counter[str]
) -> list[str]:
    if category != "sinks":
        return []
    return [
        canonical
        for canonical in CANONICAL_SINK_FAMILIES
        if (lang, canonical) not in FAMILY_NOT_APPLICABLE and canonical not in families
    ]


def summarize_lang_category(lang: str, cat: str) -> dict:
    base = PACK / lang / cat
    files, rules, parse_errors = load_category_rules(base)
    enabled = [rule for rule in rules if rule.get("enabled", True)]
    disabled = [rule for rule in rules if rule.get("enabled") is False]
    families: Counter[str] = Counter()
    for rule in enabled:
        for family in rule_coverage_families(rule):
            families[family] += 1

    return {
        "lang": lang,
        "category": cat,
        "files": [f.name for f in files],
        "rule_total": len(rules),
        "rule_enabled": len(enabled),
        "rule_disabled": len(disabled),
        "parse_errors": parse_errors,
        "families": dict(families),
        "match_shapes": dict(Counter(classify_match_shape(rule) for rule in enabled)),
        "match_precision": dict(Counter(classify_precision(rule) for rule in enabled)),
        "severities": dict(
            Counter((rule.get("severity") or "<none>") for rule in enabled)
        ),
        "tags": dict(tag_counts(enabled).most_common()),
        "fragile": fragile_rules(enabled),
        "missing_canonical_families": missing_canonical_families(lang, cat, families),
    }


def category_text(report: dict) -> list[str]:
    out = [
        f"  [{report['category']}] files={len(report['files'])} "
        f"rules={report['rule_total']} enabled={report['rule_enabled']} "
        f"disabled={report['rule_disabled']}"
    ]
    if report["parse_errors"]:
        out.append(f"    PARSE ERRORS: {len(report['parse_errors'])}")
    if report["families"]:
        families = ", ".join(
            f"{name}={count}"
            for name, count in sorted(
                report["families"].items(), key=lambda item: -item[1]
            )
        )
        out.append(f"    families: {families}")
    if report["match_shapes"]:
        out.append(f"    shapes: {dict(report['match_shapes'])}")
    if report["match_precision"]:
        out.append(f"    precision: {dict(report['match_precision'])}")
    if report["missing_canonical_families"]:
        out.append(
            "    MISSING canonical families: "
            + ", ".join(report["missing_canonical_families"])
        )
    if report["fragile"]:
        out.append(f"    FRAGILE rules: {len(report['fragile'])}")
        for fragile in report["fragile"][:5]:
            out.append(
                f"      - {fragile['id']} ({fragile['file']}): {fragile['issue']}"
            )
        if len(report["fragile"]) > 5:
            out.append(f"      ... +{len(report['fragile']) - 5} more")
    return out


def render_text(report: list[dict]) -> str:
    by_lang: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in report:
        by_lang[row["lang"]][row["category"]] = row
    out = []
    for lang in sorted(by_lang):
        out.append("=" * 72)
        out.append(f"LANG: {lang}")
        out.append("=" * 72)
        for cat in CATEGORIES:
            category = by_lang[lang].get(cat)
            if category:
                out.extend(category_text(category))
        out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang")
    ap.add_argument("--category", choices=CATEGORIES)
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--duplicates",
        action="store_true",
        help="audit duplicate ids, duplicate enabled match shapes, and cross-family API collisions",
    )
    ap.add_argument(
        "--fail-on-family-file-mismatch",
        action="store_true",
        help="exit non-zero if any sink id family disagrees with sink file name",
    )
    ap.add_argument(
        "--allow-collisions",
        action="store_true",
        help="Report duplicate enabled match shapes and cross-family API collisions but exit 0.",
    )
    args = ap.parse_args()

    if args.duplicates:
        report = duplicate_audit()
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True, default=str))
        else:
            print(render_duplicate_text(report))
        if args.fail_on_family_file_mismatch and report["family_file_mismatches"]:
            print(
                "pack_audit found sink family/file-name mismatches",
                file=sys.stderr,
            )
            return 2
        if not args.allow_collisions and (
            report["duplicate_enabled_match_shapes"]
            or report["cross_family_api_collisions"]
        ):
            print(
                "pack_audit found duplicate enabled match shapes or cross-family API collisions",
                file=sys.stderr,
            )
            return 2
        return 0

    langs = sorted([p.name for p in PACK.iterdir() if p.is_dir()])
    if args.lang:
        if args.lang not in langs:
            print(f"unknown lang: {args.lang}", file=sys.stderr)
            return 2
        langs = [args.lang]
    cats = (args.category,) if args.category else CATEGORIES

    report = [summarize_lang_category(lang, cat) for lang in langs for cat in cats]

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
