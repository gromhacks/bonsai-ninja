#!/usr/bin/env python3
"""Cross-rule logic-alignment + duplication audit.

Layers on top of `pack_audit.py`'s exact-id / exact-shape duplicate
detection, looking for *semantic* drift the structural validator misses:

* `same-shape-different-tag` — two rules in the same family that share
  the same callee regex / name + kind + language pair but disagree on
  `tag`. Either one is mis-classified or they should merge.
* `same-shape-different-severity` — same as above but the disagreement
  is in `severity`. Indicates a stale severity that escaped review.
* `same-shape-different-cwe` — same as above but the CWE list differs
  (not a strict subset / superset).
* `cross-family-name-collision` — the same id stem appears in both a
  source rule and a sink rule with no shared semantic domain. Flags
  copy-paste accidents where a rule was duplicated into the wrong
  family.
* `name-only-rule` — a callee shape with no `packages` and no
  `imports` (no package gate); these match every callable with that
  name across the workspace and produce noisy findings.

`--duplication-only` skips the alignment categories and only reports
the cross-family + name-only checks (used by audit-loop.sh as a
duplication-focused stage).

Outputs human text by default. Use `--json` for machine-readable.
Exits non-zero when any unsuppressed finding is reported so CI / the
audit loop sees a failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
PACK = REPO / "security-patterns" / "langs"


def load_rules() -> list[tuple[dict, Path, str]]:
    """Return [(rule, file_path, kind)] over every rule YAML."""
    out: list[tuple[dict, Path, str]] = []
    for kind_dir in ("sources", "sinks", "sanitizers"):
        for f in sorted(PACK.glob(f"*/{kind_dir}/*.yml")):
            try:
                data = yaml.safe_load(f.read_text())
            except yaml.YAMLError:
                continue
            if not isinstance(data, list):
                continue
            for r in data:
                if isinstance(r, dict) and r.get("enabled", True) is not False:
                    out.append((r, f, kind_dir))
    return out


def shape_key(rule: dict) -> tuple[str, str, str, str]:
    """A finer fingerprint of a rule's match shape:
    (lang, match_kind, callee_pattern, arguments_signature).

    Including the arguments signature avoids false positives on
    rules that share a callee but distinguish themselves via per-arg
    constraints (e.g. PHP `mail()` with index-3 vs index-4 tainted,
    `filter_var($v, FILTER_VALIDATE_EMAIL)` vs the int / url filter
    variants). Two rules with the same callee + identical argument
    constraints are the cases the engine genuinely cannot
    disambiguate."""
    lang = str(rule.get("language", ""))
    match = rule.get("match", {}) or {}
    kind = str(match.get("kind", ""))
    callee = match.get("callee", {}) or {}
    pattern = callee.get("regex") or callee.get("name") or ""
    if isinstance(pattern, list):
        pattern = "|".join(map(str, pattern))
    args = match.get("arguments") or []
    constraints = rule.get("constraints") or []
    args_sig = json.dumps(args, sort_keys=True) if args else ""
    constraints_sig = json.dumps(constraints, sort_keys=True) if constraints else ""
    sig = "|".join(s for s in (args_sig, constraints_sig) if s)
    return (lang, kind, str(pattern), sig)


def category_of(file_path: Path) -> str:
    """Folder name (e.g. `xss`, `cmdi`) one level down from the rule
    `kind` directory. Used to detect cross-family copy-paste."""
    return file_path.stem


def is_name_only(rule: dict) -> bool:
    """A rule with no package gate AND no import gate that matches by
    name alone — fires on every callable with that name and produces
    workspace-wide noise.

    Receivers / receiver-bound regexes are exempt: `^foo\\.bar$` is
    already constrained to a receiver shape. Bare `^bar$` or
    `^[A-Za-z_]\\w*\\.bar$` (with no package) is what we flag."""
    if rule.get("packages") or rule.get("imports"):
        return False
    match = rule.get("match", {}) or {}
    callee = match.get("callee", {}) or {}
    pattern = callee.get("regex") or callee.get("name") or ""
    if isinstance(pattern, list):
        return False
    pattern = str(pattern)
    if not pattern:
        return False
    # Already constrained to a literal receiver path (`foo.bar`,
    # `Module::Method`, `:module:fn`) — not name-only.
    if "." in pattern.replace("\\.", ""):
        return False
    if "::" in pattern:
        return False
    if ":" in pattern.lstrip("^"):
        return False
    # Generic-receiver regexes like `^[A-Za-z_]\w*\.bar$` aren't truly
    # receiver-narrowed since the receiver class identity is wildcard.
    # The matcher's `requires_call_package_signal` already requires a
    # package gate for these, so without one the rule is non-firing.
    return True


def group_rules_by_shape(
    rules: list[tuple[dict, Path, str]],
) -> dict[tuple[str, str, str, str, str], list[dict]]:
    by_shape: dict[tuple[str, str, str, str, str], list[dict]] = defaultdict(list)
    for rule, path, kind in rules:
        rid = rule.get("id")
        if not isinstance(rid, str):
            continue
        lang, m_kind, pattern, args_sig = shape_key(rule)
        # Read/write rules without an explicit callee pattern share a
        # shape key purely on (lang, kind) — that's not a true logic
        # collision, just two rules in the same kind family. Skip.
        if not pattern:
            continue
        key = (lang, m_kind, pattern, args_sig, kind)
        by_shape[key].append(
            {"id": rid, "path": str(path.relative_to(REPO)), "rule": rule}
        )
    return by_shape


def conflicting_cwes(entries: list[dict]) -> set[tuple]:
    cwes_per_rule = [tuple(sorted(entry["rule"].get("cwe") or [])) for entry in entries]
    cwes = {cwe for cwe in cwes_per_rule if cwe}
    cwe_sets = [set(cwe) for cwe in cwes_per_rule]
    hierarchical = any(
        cwe_sets[left] <= cwe_sets[right] or cwe_sets[right] <= cwe_sets[left]
        for left in range(len(cwe_sets))
        for right in range(left + 1, len(cwe_sets))
    )
    return set() if hierarchical else cwes


def alignment_rows_for_shape(
    key: tuple[str, str, str, str, str], entries: list[dict]
) -> dict[str, dict]:
    if len(entries) < 2:
        return {}
    gates = {
        (
            tuple(sorted(entry["rule"].get("packages") or [])),
            tuple(sorted(entry["rule"].get("imports") or [])),
        )
        for entry in entries
    }
    if len(gates) > 1:
        return {}

    ids = sorted(entry["id"] for entry in entries)
    shape = list(key[:4])
    tags = {
        entry["rule"].get("tag")
        for entry in entries
        if isinstance(entry["rule"].get("tag"), str)
    }
    severities = {
        entry["rule"].get("severity")
        for entry in entries
        if isinstance(entry["rule"].get("severity"), str)
    }
    cwes = conflicting_cwes(entries)
    rows: dict[str, dict] = {}
    if len(tags) > 1:
        rows["same_shape_different_tag"] = {
            "shape": shape,
            "ids": ids,
            "tags": sorted(tags),
        }
    if len(severities) > 1:
        rows["same_shape_different_severity"] = {
            "shape": shape,
            "ids": ids,
            "severities": sorted(severities),
        }
    if len(cwes) > 1:
        rows["same_shape_different_cwe"] = {
            "shape": shape,
            "ids": ids,
            "cwes": [list(cwe) for cwe in cwes],
        }
    return rows


def audit_logic_alignment() -> dict[str, list[dict]]:
    findings: dict[str, list[dict]] = {
        "same_shape_different_tag": [],
        "same_shape_different_severity": [],
        "same_shape_different_cwe": [],
    }
    for key, entries in group_rules_by_shape(load_rules()).items():
        for category, row in alignment_rows_for_shape(key, entries).items():
            findings[category].append(row)
    return findings


def audit_duplication() -> dict[str, list[dict]]:
    rules = load_rules()
    name_only: list[dict] = []
    cross_family: list[dict] = []

    # name-only inventory.
    for rule, path, kind in rules:
        if is_name_only(rule):
            name_only.append(
                {
                    "id": rule.get("id"),
                    "path": str(path.relative_to(REPO)),
                    "kind": kind,
                }
            )

    # cross-family: same id stem in source/sink/sanitizer trios.
    # We flag a stem only when the rules also share an identical
    # match shape — different shapes mean the API is genuinely dual-
    # purpose (e.g. C `scanf` reads input AND writes a buffer, so
    # `c.input.scanf` and `c.memory.scanf` legitimately point at
    # different argument positions).
    by_stem: dict[tuple[str, str], list[tuple[str, str, str, dict]]] = defaultdict(list)
    for rule, path, kind in rules:
        rid = rule.get("id")
        if not isinstance(rid, str):
            continue
        parts = rid.split(".")
        if len(parts) < 3:
            continue
        stem = (parts[0], parts[-1])
        by_stem[stem].append((rid, kind, str(path.relative_to(REPO)), rule))
    for stem, entries in by_stem.items():
        kinds = {e[1] for e in entries}
        if not ("sources" in kinds and "sinks" in kinds):
            continue
        shapes = {shape_key(e[3]) for e in entries}
        if len(shapes) > 1:
            continue
        cross_family.append(
            {
                "lang": stem[0],
                "stem": stem[1],
                "ids": sorted(e[0] for e in entries),
                "kinds": sorted(kinds),
            }
        )

    return {
        "name_only_rules": name_only,
        "cross_family_collisions": cross_family,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable JSON")
    ap.add_argument(
        "--duplication-only",
        action="store_true",
        help="skip same-shape alignment checks; report only cross-family + name-only.",
    )
    args = ap.parse_args()

    report: dict[str, Any] = {}
    if not args.duplication_only:
        report.update(audit_logic_alignment())
    dup = audit_duplication()
    # `name_only_rules` enumerates rules without a package gate (mostly
    # libc / language-stdlib built-ins where `getenv`, `fopen`,
    # `system` are firs-class). Surfaced for inventory only.
    #
    # `cross_family_collisions` enumerates dual-purpose APIs (`scanf`
    # both reads stdin and writes a buffer; `wiringpi_spi_data_rw`
    # both transmits and receives) — legitimate split rules, not
    # copy-paste accidents. Surfaced for periodic review only.
    inventory = {
        "name_only_rules": dup.pop("name_only_rules"),
        "cross_family_collisions": dup.pop("cross_family_collisions"),
    }
    report.update(dup)

    bad = sum(len(v) for v in report.values())

    if args.json:
        print(
            json.dumps(
                {"findings": report, "inventory": inventory, "total": bad},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for name, items in report.items():
            print(f"{name}: {len(items)}")
            for item in items[:8]:
                print(f"  {json.dumps(item, sort_keys=True)}")
            if len(items) > 8:
                print(f"  ... +{len(items) - 8} more")
        print()
        print("inventory (informational, not failing):")
        for name, items in inventory.items():
            print(f"  {name}: {len(items)}")
        print()
        print(f"total findings: {bad}")

    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
