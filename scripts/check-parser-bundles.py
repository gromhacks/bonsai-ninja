#!/usr/bin/env python3
"""Validate the locked parser pack against bonsai-ninja's release matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "tree-sitter-language-pack"
RELEASE_PLATFORMS = {
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-gnu": "linux-aarch64",
    "x86_64-apple-darwin": "macos-x86_64",
    "aarch64-apple-darwin": "macos-arm64",
    "x86_64-pc-windows-msvc": "windows-x86_64",
    "aarch64-pc-windows-msvc": "windows-aarch64",
}
ADAPTER_GRAMMARS = {
    "c",
    "cpp",
    "csharp",
    "dart",
    "elixir",
    "erlang",
    "go",
    "java",
    "javascript",
    "kotlin",
    "lua",
    "objc",
    "perl",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "swift",
    "tsx",
    "typescript",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def locked_version(lock_path: Path) -> str:
    with lock_path.open("rb") as handle:
        lock = tomllib.load(handle)
    matches = [
        package
        for package in lock.get("package", [])
        if package.get("name") == PACKAGE
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected one locked {PACKAGE} package, found {len(matches)}"
        )
    version = matches[0].get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"locked {PACKAGE} has no version")
    return version


def load_manifest(version: str, path: Path | None) -> dict[str, Any]:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    url = (
        "https://github.com/xberg-io/tree-sitter-language-pack/"
        f"releases/download/v{version}/parsers.json"
    )
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "bonsai-ninja-release-gate"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return json.load(response)


def validate_manifest(manifest: dict[str, Any], version: str) -> None:
    errors: list[str] = []
    if manifest.get("version") != version:
        errors.append(
            f"manifest version {manifest.get('version')!r} != locked version {version!r}"
        )

    languages = manifest.get("languages")
    if not isinstance(languages, dict):
        errors.append("manifest languages must be an object")
    else:
        missing_grammars = sorted(ADAPTER_GRAMMARS.difference(languages))
        if missing_grammars:
            errors.append("missing adapter grammars: " + ", ".join(missing_grammars))

    platforms = manifest.get("platforms")
    if not isinstance(platforms, dict):
        errors.append("manifest platforms must be an object")
        platforms = {}

    for rust_target, platform in RELEASE_PLATFORMS.items():
        bundle = platforms.get(platform)
        if not isinstance(bundle, dict):
            errors.append(f"{rust_target}: missing parser bundle {platform!r}")
            continue
        url = bundle.get("url")
        digest = bundle.get("sha256")
        size = bundle.get("size")
        if not isinstance(url, str) or not url.startswith("https://"):
            errors.append(f"{rust_target}: bundle URL is not HTTPS")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            errors.append(f"{rust_target}: bundle SHA-256 is invalid")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            errors.append(f"{rust_target}: bundle size is invalid")

    if errors:
        raise ValueError("parser delivery validation failed:\n  - " + "\n  - ".join(errors))

    fingerprint = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    print(
        f"parser delivery valid: {PACKAGE} {version}; "
        f"{len(ADAPTER_GRAMMARS)} grammars; "
        f"{len(RELEASE_PLATFORMS)} platforms; manifest sha256={fingerprint}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="validate a local parsers.json instead of downloading the locked release",
    )
    args = parser.parse_args()
    try:
        version = locked_version(ROOT / "Cargo.lock")
        manifest = load_manifest(version, args.manifest)
        validate_manifest(manifest, version)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
