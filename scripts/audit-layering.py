#!/usr/bin/env python3
"""Check production dependency tiers using Cargo's canonical manifest parser."""

import json
from pathlib import Path
import subprocess
import sys


# Keep in sync with docs/contributing/architecture.mdx. Same-tier edges are
# allowed; Cargo itself rejects dependency cycles. Dev edges are not layering.
TIERS = [
    "hash rulepack",
    "common",
    "diagnostics vfs factstore",
    "lang-api",
    "lang-c lang-cpp lang-csharp lang-scala lang-rust lang-go lang-java "
    "lang-kotlin lang-swift lang-javascript lang-php lang-python lang-perl "
    "lang-ruby lang-dart lang-objc lang-lua lang-elixir lang-erlang cfg index parser",
    "abstract-interp lang-typescript resolve",
    "adapters callgraph trace",
    "idg",
    "db",
    "taint",
    "workspace",
    "inspect retrieval testkit",
    "browse conformance security",
    "sdk",
]
TIER_BY_PACKAGE = {
    f"bonsai-ninja-{name}": tier
    for tier, names in enumerate(TIERS)
    for name in names.split()
}
TIER_BY_PACKAGE["bonsai-ninja"] = len(TIERS)


def violations(metadata):
    """Return violations, resolving dependency identities independently of aliases."""
    members = set(metadata["workspace_members"])
    errors = []
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        name = package["name"]
        tier = TIER_BY_PACKAGE.get(name)
        if tier is None:
            errors.append(f"UNCLASSIFIED CRATE: '{name}' must be assigned an architecture tier")
            continue
        for dependency in package["dependencies"]:
            if dependency["kind"] == "dev":
                continue
            target = dependency["name"]
            target_tier = TIER_BY_PACKAGE.get(target)
            if target_tier is not None and target_tier > tier:
                errors.append(
                    f"LAYERING VIOLATION: {name} (tier {tier}) depends on "
                    f"{target} (tier {target_tier})"
                )
    return sorted(set(errors))


def main():
    root = Path(__file__).resolve().parent.parent
    # --no-deps still includes each workspace package's full dependency
    # declarations, including optional/renamed/build/target-specific edges.
    # No registry resolution, downloads, builds, or lockfile changes are needed.
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked", "--offline"],
        cwd=root, check=True, capture_output=True, text=True,
    )
    errors = violations(json.loads(result.stdout))
    if errors:
        print("\n".join(errors))
        print(f"\nTotal layering violations: {len(errors)}")
        return 1
    print("Layering DAG audit: OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stderr or str(error), file=sys.stderr)
        sys.exit(1)
