#!/usr/bin/env python3
"""Validate a complete security-patterns pack end-to-end.

The validator performs:

* `pack --validate` (schema + structural rule checks from bonsai-ninja),
* strict YAML-key and duplicate/collision audit via `pack_audit.py --duplicates`,
* match-example presence audit via `rule_example_coverage.py`,
* match-example collision audit via `audit_match_example_collisions.py`.

It is intentionally strict by default. Any non-zero findings are actionable
in the printed JSON report for rule-merge triage.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


@dataclass
class SectionResult:
    name: str
    ok: bool
    summary: str
    details: dict[str, Any]


def run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_json(cmd: list[str]) -> tuple[int, dict[str, Any], str]:
    code, stdout, stderr = run(cmd)
    if code < 0:
        return code, {"error": "command launch failed", "stderr": str(stderr)}, stderr
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        return (
            code,
            {"error": f"invalid json: {exc}", "stdout": stdout, "stderr": stderr},
            stderr,
        )
    return code, payload, stderr


def validate_pack_validate(rules_dir: str, binary: str) -> SectionResult:
    cmd = [
        binary,
        "security",
        rules_dir,
        "pack",
        "--validate",
        "--format",
        "json",
        "--rules-dir",
        rules_dir,
        "--no-progress",
        "--no-color",
    ]
    code, payload, stderr = run_json(cmd)
    # `info` issues are advisory diagnostics for rule authors (e.g.
    # type-method-needs-adapter-type-aliases when an adapter hasn't
    # yet populated Decl.type_aliases). They shouldn't fail
    # validation — the gate is errors + warnings.
    issues = payload.get("issues", []) or []
    blocking_issues = [i for i in issues if i.get("level") not in ("info",)]
    ok = code == 0 and bool(payload.get("valid")) is True and not blocking_issues
    total_issues = int(payload.get("errors", 0)) + int(payload.get("warnings", 0))
    detail: dict[str, Any] = {
        "command": " ".join(cmd),
        "exit_code": code,
        "issues": blocking_issues,
        "info_issues": [i for i in issues if i.get("level") == "info"],
        "errors": payload.get("errors", 0),
        "warnings": payload.get("warnings", 0),
        "rule_count": payload.get("rule_count", 0),
        "enabled_rule_count": payload.get("enabled_rule_count", 0),
        "stderr": stderr.strip(),
    }
    return SectionResult(
        name="pack-validate",
        ok=ok,
        summary=f"errors={total_issues}",
        details=detail,
    )


def validate_duplicates(
    strict_family_file: bool = True, fail_on_collision: bool = True
) -> SectionResult:
    cmd = [
        "python3",
        str(SCRIPT_DIR / "pack_audit.py"),
        "--duplicates",
        "--json",
    ]
    if strict_family_file:
        cmd.append("--fail-on-family-file-mismatch")
    code, payload, stderr = run_json(cmd)
    if code != 0 and not isinstance(payload, dict):
        payload = {}
    duplicate_ids = payload.get("duplicate_ids", [])
    duplicate_enabled_match_shapes = payload.get("duplicate_enabled_match_shapes", [])
    cross_family_api_collisions = payload.get("cross_family_api_collisions", [])
    family_file_mismatches = payload.get("family_file_mismatches", [])
    if not isinstance(duplicate_ids, list):
        duplicate_ids = []
    if not isinstance(duplicate_enabled_match_shapes, list):
        duplicate_enabled_match_shapes = []
    if not isinstance(cross_family_api_collisions, list):
        cross_family_api_collisions = []
    if not isinstance(family_file_mismatches, list):
        family_file_mismatches = []

    ok = code == 0 and not duplicate_ids and not family_file_mismatches
    if fail_on_collision and (
        duplicate_enabled_match_shapes or cross_family_api_collisions
    ):
        ok = False
    detail = {
        "command": " ".join(cmd),
        "exit_code": code,
        "rows": payload,
        "duplicate_enabled_match_shapes": duplicate_enabled_match_shapes,
        "cross_family_api_collisions": cross_family_api_collisions,
        "stderr": stderr.strip(),
    }
    return SectionResult(
        name="duplicates",
        ok=ok,
        summary=(
            f"ids={len(duplicate_ids)} "
            f"shapes={len(duplicate_enabled_match_shapes)} "
            f"cross-families={len(cross_family_api_collisions)} "
            f"family-mismatch={len(family_file_mismatches)}"
        ),
        details=detail,
    )


def parse_example_coverage(out: str) -> int:
    match = re.search(r"missing match_examples:\s+(\d+)", out)
    if not match:
        return -1
    return int(match.group(1))


def validate_examples(
    rules_dir: str, fail_on_missing_examples: bool = True
) -> SectionResult:
    cmd = ["python3", str(SCRIPT_DIR / "rule_example_coverage.py"), rules_dir]
    code, stdout, stderr = run(cmd)
    missing = parse_example_coverage(stdout)
    ok = code == 0 and (not fail_on_missing_examples or missing == 0)
    detail = {
        "command": " ".join(cmd),
        "exit_code": code,
        "missing": missing,
        "stdout_tail": (stdout.splitlines()[-20:] if stdout else []),
        "stderr": stderr.strip(),
    }
    return SectionResult(
        name="match-examples",
        ok=ok,
        summary=f"missing={missing}",
        details=detail,
    )


def validate_collision_examples(
    rules_dir: str,
    binary: str,
    fail_on_collision: bool,
    cross_kind: bool,
    require_binary: bool,
    json_out: Path | None = None,
) -> SectionResult:
    if not Path(binary).exists():
        if not require_binary:
            return SectionResult(
                name="match-example-collisions",
                ok=True,
                summary="skipped (bonsai-ninja binary missing)",
                details={
                    "command": (
                        f"python3 {SCRIPT_DIR / 'audit_match_example_collisions.py'} "
                        f"{rules_dir} --bin {binary} ..."
                    ),
                    "exit_code": 127,
                    "stderr": f"binary not found: {binary}",
                    "stdout_tail": [],
                    "total_examples": 0,
                    "collisions": [],
                    "collision_pairs": [],
                    "owner_misses": [],
                    "expected_text_misses": [],
                    "skipped": True,
                },
            )
        return SectionResult(
            name="match-example-collisions",
            ok=False,
            summary="missing bonsai-ninja binary",
            details={
                "command": (
                    f"python3 {SCRIPT_DIR / 'audit_match_example_collisions.py'} "
                    f"{rules_dir} --bin {binary}"
                ),
                "exit_code": 127,
                "stderr": f"binary not found: {binary}",
            },
        )

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as fp:
        temp_json = Path(fp.name)
    try:
        cmd = [
            "python3",
            str(SCRIPT_DIR / "audit_match_example_collisions.py"),
            rules_dir,
            "--bin",
            binary,
            "--format",
            "json",
            "--json-out",
            str(temp_json),
        ]
        if not fail_on_collision:
            cmd.append("--allow-collisions")
        if cross_kind:
            cmd.append("--cross-kind")
        code, stdout, stderr = run(cmd)
        report: dict[str, Any] = {}
        if temp_json.exists():
            try:
                report = json.loads(temp_json.read_text())
            except json.JSONDecodeError:
                report = {}
        collisions = report.get("collisions", [])
        collision_pairs = report.get("collision_pairs", [])
        merge_candidates = report.get("merge_candidates", collision_pairs)
        owner_misses = report.get("owner_misses", [])
        expected_text_misses = report.get("expected_text_misses", [])
        ok = (
            (code == 0 or (not fail_on_collision and code == 1))
            and (not fail_on_collision or len(collisions) == 0)
            and len(owner_misses) == 0
            and len(expected_text_misses) == 0
        )
        detail = {
            "command": " ".join(cmd),
            "exit_code": code,
            "stdout_tail": (stdout.splitlines()[-20:] if stdout else []),
            "stderr": stderr.strip(),
            "total_examples": len(report.get("examples", [])),
            "collisions": collisions,
            "collision_pairs": collision_pairs,
            "merge_candidates": merge_candidates,
            "owner_misses": owner_misses,
            "expected_text_misses": expected_text_misses,
        }
        return SectionResult(
            name="match-example-collisions",
            ok=ok,
            summary=(
                f"collisions={len(collisions)} "
                f"owner_miss={len(owner_misses)} "
                f"expected_miss={len(expected_text_misses)}"
            ),
            details=detail,
        )
    finally:
        temp_json.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "rules_dir",
        nargs="?",
        default="security-patterns",
        help="Rulepack root path (default: security-patterns)",
    )
    parser.add_argument(
        "--binary",
        default=str(REPO_ROOT / "target" / "release" / "bonsai-ninja"),
        help="Path to bonsai-ninja binary",
    )
    parser.add_argument(
        "--no-fail-on-missing-examples",
        dest="fail_on_missing_examples",
        action="store_false",
        help="Do not fail when rules miss match_examples.",
    )
    parser.set_defaults(fail_on_missing_examples=True)
    parser.add_argument(
        "--fail-on-collision",
        action="store_true",
        default=True,
        help="Fail when any collision is found between owners and other rules (default).",
    )
    parser.add_argument(
        "--allow-collisions",
        dest="fail_on_collision",
        action="store_false",
        help="Report collisions but do not fail the wrapper.",
    )
    parser.set_defaults(fail_on_collision=True)
    parser.add_argument(
        "--cross-kind",
        action="store_true",
        help="Audit match examples against all inventory families (typically for research; false by default).",
    )
    parser.add_argument(
        "--skip-collision-if-binary-missing",
        action="store_true",
        help="Treat missing bonsai-ninja binary as skip for match-example collision checks.",
    )
    parser.add_argument(
        "--allow-family-file-mismatch",
        action="store_true",
        help="Only report duplicate families; allow sink id family/file-name mismatches.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Write full validator JSON report.",
    )
    args = parser.parse_args()

    sections = [
        validate_pack_validate(args.rules_dir, args.binary),
        validate_duplicates(
            not args.allow_family_file_mismatch,
            fail_on_collision=args.fail_on_collision,
        ),
        validate_examples(
            args.rules_dir, fail_on_missing_examples=args.fail_on_missing_examples
        ),
        validate_collision_examples(
            args.rules_dir,
            args.binary,
            fail_on_collision=args.fail_on_collision,
            cross_kind=args.cross_kind,
            require_binary=not args.skip_collision_if_binary_missing,
        ),
    ]
    failed = [s for s in sections if not s.ok]

    print("pattern-pack-validator")
    for section in sections:
        state = "pass" if section.ok else "fail"
        print(f"{state:4} {section.name}: {section.summary}")
        if not section.ok:
            print(f"     cmd: {section.details.get('command')}")
            if "missing" in section.details:
                print(f"     missing: {section.details['missing']}")
            if section.details.get("issues"):
                print(f"     issues: {len(section.details['issues'])}")

    if args.json_out:
        collisions_section = next(
            (
                section
                for section in sections
                if section.name == "match-example-collisions"
            ),
            None,
        )
        merge_candidates = []
        if collisions_section:
            merge_candidates = (
                collisions_section.details.get("merge_candidates", []) or []
            )
        payload = {
            "rules_dir": args.rules_dir,
            "binary": args.binary,
            "sections": [section.__dict__ for section in sections],
            "failed": [section.name for section in failed],
            "merge_candidates": merge_candidates,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print(f"report written: {args.json_out}")

    if failed:
        print(f"validator failed: {len(failed)} section(s)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
