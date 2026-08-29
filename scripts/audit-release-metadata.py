#!/usr/bin/env python3
"""Reject incomplete or inconsistent public Cargo package metadata."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_ROOT_FILES = (
    "README.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "LICENSE",
)


def main() -> int:
    metadata = json.loads(
        subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--no-deps",
                "--format-version",
                "1",
            ],
            cwd=ROOT,
            text=True,
        )
    )

    violations: list[str] = []
    versions: set[str] = set()
    repositories: set[str] = set()
    for package in metadata["packages"]:
        name = package["name"]
        version = package.get("version")
        if (
            not isinstance(version, str)
            or re.fullmatch(
                r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
                version,
            )
            is None
        ):
            violations.append(f"{name}: invalid or missing semantic version")
        else:
            versions.add(version)

        for field in ("description", "license", "repository"):
            value = package.get(field)
            if not isinstance(value, str) or not value.strip():
                violations.append(f"{name}: missing {field}")
        repository = package.get("repository")
        if isinstance(repository, str) and repository:
            repositories.add(repository)

    if len(versions) != 1:
        violations.append(f"workspace package versions differ: {sorted(versions)}")
    if len(repositories) != 1:
        violations.append(
            f"workspace package repositories differ: {sorted(repositories)}"
        )

    for relative in REQUIRED_ROOT_FILES:
        if not (ROOT / relative).is_file():
            violations.append(f"missing public repository file: {relative}")

    rulepack_version_path = ROOT / "security-patterns" / "VERSION"
    if not rulepack_version_path.is_file():
        violations.append("missing embedded rulepack VERSION marker")
    elif len(versions) == 1:
        workspace_version = next(iter(versions))
        rulepack_version = rulepack_version_path.read_text().strip()
        if rulepack_version != workspace_version:
            violations.append(
                "embedded rulepack VERSION differs from workspace version: "
                f"{rulepack_version!r} != {workspace_version!r}"
            )

    if violations:
        for violation in violations:
            print(f"release metadata: {violation}")
        return 1

    print(
        "release metadata: "
        f"{len(metadata['packages'])} packages, version {next(iter(versions))}, "
        "complete public fields"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
