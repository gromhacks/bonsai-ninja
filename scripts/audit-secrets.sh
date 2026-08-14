#!/usr/bin/env bash
# Scan every reachable Git commit with one checksum-pinned Gitleaks release.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=8.29.1

if [[ -n "${GITLEAKS_BIN:-}" ]]; then
    scanner="$GITLEAKS_BIN"
    cleanup_dir=""
else
    case "$(uname -s):$(uname -m)" in
        Darwin:arm64)
            asset="gitleaks_${VERSION}_darwin_arm64.tar.gz"
            expected="69836c841d7e648fb30ff4846f8c3587855c5754ed02b8510caaf6008f65d177"
            ;;
        Darwin:x86_64)
            asset="gitleaks_${VERSION}_darwin_x64.tar.gz"
            expected="2cd739c684bf3f543f4f37774075c276e40a72bb16c4c5bb9dfd27bf4a4465a7"
            ;;
        Linux:aarch64 | Linux:arm64)
            asset="gitleaks_${VERSION}_linux_arm64.tar.gz"
            expected="691f826ce7c1c564c9c02d0f9025e8e70803e3816707a4be6224408a06a81eaa"
            ;;
        Linux:x86_64)
            asset="gitleaks_${VERSION}_linux_x64.tar.gz"
            expected="e4eb209d04e20339d77122a3bdf9cd41351255cfb27ebcb75e85325e04f88924"
            ;;
        *)
            echo "unsupported host for pinned Gitleaks binary; set GITLEAKS_BIN" >&2
            exit 2
            ;;
    esac

    cleanup_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonsai-gitleaks.XXXXXX")"
    trap 'rm -rf "$cleanup_dir"' EXIT
    archive="$cleanup_dir/$asset"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${asset}" \
        --output "$archive"
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        echo "Gitleaks archive checksum mismatch: expected $expected, got $actual" >&2
        exit 1
    fi
    tar -xzf "$archive" -C "$cleanup_dir" gitleaks
    scanner="$cleanup_dir/gitleaks"
fi

"$scanner" git --redact --no-banner --config "$ROOT_DIR/.gitleaks.toml" \
    --log-opts="--all --full-history" "$ROOT_DIR"
echo "full-history secret scan: OK"
