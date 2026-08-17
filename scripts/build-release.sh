#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RELEASE_TARGET="${BONSAI_RELEASE_TARGET_DIR:-/tmp/bonsai-ninja-release-target}"

# Release archives must not disclose the builder's checkout or Cargo-home
# path through panic/debug metadata. CARGO_ENCODED_RUSTFLAGS keeps paths with
# spaces as one rustc argument and preserves any caller-supplied warning or
# target flags.
flags=()
if [[ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  IFS=$'\x1f' read -r -a flags <<<"${CARGO_ENCODED_RUSTFLAGS}"
elif [[ -n "${RUSTFLAGS:-}" ]]; then
  read -r -a flags <<<"${RUSTFLAGS}"
fi

add_remap() {
  local source="$1"
  local destination="$2"
  [[ -n "$source" ]] || return 0
  flags+=("--remap-path-prefix=${source}=${destination}")
}

add_remap "$ROOT" /workspace
add_remap "${HOME:-}" /cargo-home

# Git Bash exposes POSIX paths while rustc may record native Windows paths.
if command -v cygpath >/dev/null 2>&1; then
  add_remap "$(cygpath -w "$ROOT")" C:/workspace
  if [[ -n "${HOME:-}" ]]; then
    add_remap "$(cygpath -w "$HOME")" C:/cargo-home
  fi
fi

encoded=""
if ((${#flags[@]})); then
  printf -v encoded '%s\x1f' "${flags[@]}"
  encoded="${encoded%$'\x1f'}"
fi

unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="$encoded"

# A dependency-generated registry contains Cargo's OUT_DIR as a literal
# fallback for in-tree parser libraries. Build in a stable, non-personal
# target directory so that string cannot disclose the checkout or home path.
# The runtime uses the relocatable parser cache; the fallback is relevant only
# to an unrelocated build tree.
CARGO_TARGET_DIR="$RELEASE_TARGET" \
  cargo build --release --locked -p bonsai-ninja --bin bonsai-ninja "$@"

target_triple=""
expect_target=0
for argument in "$@"; do
  if ((expect_target)); then
    target_triple="$argument"
    expect_target=0
    continue
  fi
  case "$argument" in
    --target)
      expect_target=1
      ;;
    --target=*)
      target_triple="${argument#--target=}"
      ;;
  esac
done
if ((expect_target)); then
  echo "--target requires a target triple" >&2
  exit 2
fi

binary="bonsai-ninja"
if [[ "$target_triple" == *windows* ]]; then
  binary+=".exe"
fi

if [[ -n "$target_triple" ]]; then
  source_binary="$RELEASE_TARGET/$target_triple/release/$binary"
  destination="$ROOT/target/$target_triple/release/$binary"
else
  source_binary="$RELEASE_TARGET/release/$binary"
  destination="$ROOT/target/release/$binary"
fi

mkdir -p "$(dirname "$destination")"
cp "$source_binary" "$destination"
chmod +x "$destination" 2>/dev/null || true

# Count both compiler trees as one budget: the ordinary workspace output and
# the isolated release output that keeps build-host paths out of the binary.
"$ROOT/scripts/audit-build-artifacts.sh" "$ROOT/target" "$RELEASE_TARGET"
