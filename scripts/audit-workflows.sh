#!/usr/bin/env bash
# Parse and statically validate every GitHub Actions workflow with actionlint.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=1.7.12

if [[ -n "${ACTIONLINT_BIN:-}" ]]; then
    scanner="$ACTIONLINT_BIN"
else
    case "$(uname -s):$(uname -m)" in
        Darwin:arm64)
            asset="actionlint_${VERSION}_darwin_arm64.tar.gz"
            expected="aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"
            ;;
        Darwin:x86_64)
            asset="actionlint_${VERSION}_darwin_amd64.tar.gz"
            expected="5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"
            ;;
        Linux:aarch64 | Linux:arm64)
            asset="actionlint_${VERSION}_linux_arm64.tar.gz"
            expected="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"
            ;;
        Linux:x86_64)
            asset="actionlint_${VERSION}_linux_amd64.tar.gz"
            expected="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
            ;;
        *)
            echo "unsupported host for pinned actionlint binary; set ACTIONLINT_BIN" >&2
            exit 2
            ;;
    esac

    cleanup_dir="$(mktemp -d "${TMPDIR:-/tmp}/bonsai-actionlint.XXXXXX")"
    trap 'rm -rf "$cleanup_dir"' EXIT
    archive="$cleanup_dir/$asset"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        "https://github.com/rhysd/actionlint/releases/download/v${VERSION}/${asset}" \
        --output "$archive"
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        echo "actionlint archive checksum mismatch: expected $expected, got $actual" >&2
        exit 1
    fi
    tar -xzf "$archive" -C "$cleanup_dir" actionlint
    scanner="$cleanup_dir/actionlint"
fi

cd "$ROOT_DIR"
"$scanner" -color=false
echo "GitHub Actions syntax audit: OK"
