#!/usr/bin/env python3
"""Audit and publish the crates.io workspace in dependency order.

The default mode is read-only. Publication is deliberately opt-in and verifies
each package before its irreversible upload. A resumed run skips an existing
version only when the registry archive is byte-for-byte identical to the local
package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REGISTRY_API = "https://crates.io/api/v1/crates"
USER_AGENT = "bonsai-ninja-release contact@gromhacks.com"
PACKAGE_PREFIX = "bonsai-ninja"
EXPECTED_OWNER = "gromhacks"
REGISTRY_WAIT_SECONDS = 15 * 60


def run(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def metadata() -> dict[str, object]:
    completed = run(
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--locked",
        capture=True,
    )
    return json.loads(completed.stdout)


def publishable_packages(
    data: dict[str, object],
) -> tuple[dict[str, dict[str, object]], str]:
    packages = {
        package["name"]: package
        for package in data["packages"]  # type: ignore[index]
        if package.get("publish") == ["crates-io"]
    }
    versions = {package["version"] for package in packages.values()}
    if len(versions) != 1:
        raise ValueError(f"publishable workspace versions differ: {sorted(versions)}")
    version = versions.pop()

    errors: list[str] = []
    for name, package in sorted(packages.items()):
        if name != PACKAGE_PREFIX and not name.startswith(f"{PACKAGE_PREFIX}-"):
            errors.append(f"{name}: package is outside the {PACKAGE_PREFIX!r} namespace")
        if package.get("repository") != "https://github.com/gromhacks/bonsai-ninja":
            errors.append(f"{name}: unexpected repository metadata")
        for dependency in package["dependencies"]:  # type: ignore[index]
            if dependency.get("path") is None or dependency.get("kind") == "dev":
                continue
            dependency_name = dependency["name"]
            if dependency_name not in packages:
                errors.append(
                    f"{name}: production path dependency {dependency_name!r} is not publishable"
                )
            if dependency.get("req") != f"={version}":
                errors.append(
                    f"{name}: {dependency_name} requires {dependency.get('req')!r}, "
                    f"expected '={version}'"
                )

    cli = packages.get(PACKAGE_PREFIX)
    if cli is None:
        errors.append("missing publishable bonsai-ninja CLI package")
    elif not any(
        target.get("name") == "bonsai-ninja" and "bin" in target.get("kind", [])
        for target in cli["targets"]  # type: ignore[index]
    ):
        errors.append("bonsai-ninja package does not expose the bonsai-ninja binary")

    for internal in ("bonsai-ninja-conformance", "bonsai-ninja-testkit"):
        if internal in packages:
            errors.append(f"test-only package must not be published: {internal}")

    if errors:
        raise ValueError("\n".join(errors))
    return packages, str(version)


def publication_order(packages: dict[str, dict[str, object]]) -> list[str]:
    dependencies: dict[str, set[str]] = {}
    for name, package in packages.items():
        dependencies[name] = {
            dependency["name"]
            for dependency in package["dependencies"]  # type: ignore[index]
            if dependency.get("path") is not None
            and dependency.get("kind") != "dev"
            and dependency["name"] in packages
        }

    order: list[str] = []
    remaining = set(packages)
    while remaining:
        ready = sorted(name for name in remaining if not (dependencies[name] & remaining))
        if not ready:
            cycle = ", ".join(sorted(remaining))
            raise ValueError(f"production package dependency cycle: {cycle}")
        order.extend(ready)
        remaining.difference_update(ready)
    return order


def registry_json(path: str) -> dict[str, object] | None:
    request = urllib.request.Request(
        f"{REGISTRY_API}/{path}", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def audit_registry(packages: dict[str, dict[str, object]], version: str) -> None:
    errors: list[str] = []
    available = 0
    existing = 0
    for name in sorted(packages):
        crate = registry_json(name)
        if crate is None:
            available += 1
            continue
        existing += 1
        record = crate.get("crate", {})
        if record.get("repository") != "https://github.com/gromhacks/bonsai-ninja":
            errors.append(
                f"{name}: crates.io name belongs to {record.get('repository') or 'another project'}"
            )
            continue
        owners = registry_json(f"{name}/owners") or {}
        owner_logins = {
            owner.get("login")
            for owner in [*owners.get("users", []), *owners.get("teams", [])]
        }
        if EXPECTED_OWNER not in owner_logins:
            errors.append(
                f"{name}: expected crates.io owner {EXPECTED_OWNER!r}, "
                f"found {sorted(login for login in owner_logins if login)}"
            )
            continue
        if registry_json(f"{name}/{version}") is not None:
            print(f"registry: {name} {version} already exists")
    if errors:
        raise ValueError("\n".join(errors))
    print(f"registry names: {available} available, {existing} already owned by this project")


def registry_version_exists(name: str, version: str) -> bool:
    return registry_json(f"{name}/{version}") is not None


def wait_for_registry(name: str, version: str) -> None:
    deadline = time.monotonic() + REGISTRY_WAIT_SECONDS
    while time.monotonic() < deadline:
        if registry_version_exists(name, version):
            return
        time.sleep(10)
    raise TimeoutError(f"{name} {version} did not appear on crates.io within 15 minutes")


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def verify_existing_archive(name: str, version: str) -> None:
    run("cargo", "package", "-p", name, "--locked", "--no-verify")
    local = (ROOT / "target" / "package" / f"{name}-{version}.crate").read_bytes()
    remote = download(f"{REGISTRY_API}/{name}/{version}/download")
    if hashlib.sha256(local).digest() != hashlib.sha256(remote).digest():
        raise ValueError(f"{name} {version}: registry archive differs from local package")


def assert_clean_checkout() -> None:
    status = run("git", "status", "--porcelain", capture=True).stdout
    if status.strip():
        raise ValueError("crates.io publication requires a clean Git checkout")


def assert_registry_credentials() -> None:
    if os.environ.get("CARGO_REGISTRY_TOKEN", "").strip():
        return
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    if any((cargo_home / name).is_file() for name in ("credentials.toml", "credentials")):
        return
    raise ValueError(
        "crates.io publication requires CARGO_REGISTRY_TOKEN or `cargo login` credentials"
    )


def publish(order: list[str], version: str, *, resume: bool) -> None:
    assert_clean_checkout()
    assert_registry_credentials()
    for index, name in enumerate(order, start=1):
        print(f"[{index}/{len(order)}] {name} {version}", flush=True)
        if registry_version_exists(name, version):
            if not resume:
                raise ValueError(
                    f"{name} {version} already exists; rerun with --resume to verify and skip it"
                )
            verify_existing_archive(name, version)
            print("  existing registry archive is byte-identical; skipped", flush=True)
            continue
        run("cargo", "publish", "--dry-run", "-p", name, "--locked")
        run("cargo", "publish", "-p", name, "--locked")
        wait_for_registry(name, version)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-registry", action="store_true", help="also audit crates.io name ownership"
    )
    parser.add_argument(
        "--publish", action="store_true", help="perform irreversible crates.io uploads"
    )
    parser.add_argument(
        "--confirm-version",
        metavar="VERSION",
        help="required exact workspace version acknowledgement for --publish",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="verify and skip byte-identical versions from a partial prior run",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        packages, version = publishable_packages(metadata())
        order = publication_order(packages)
        print(f"crates.io: {len(order)} packages, version {version}")
        print("publication order:")
        for index, name in enumerate(order, start=1):
            print(f"  {index:02d}. {name}")
        if args.check_registry or args.publish:
            audit_registry(packages, version)
        if args.publish:
            if args.confirm_version != version:
                raise ValueError(
                    f"--publish requires --confirm-version {version} (got {args.confirm_version!r})"
                )
            publish(order, version, resume=args.resume)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"crates.io: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
