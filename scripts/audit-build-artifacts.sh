#!/usr/bin/env bash
set -euo pipefail

# Bound local/CI Cargo output without deleting it. The default is deliberately
# above a clean full-workspace correctness build plus one production CLI build,
# but far below a target tree containing repeated ThinLTO test generations.
target_dir="${CARGO_TARGET_DIR:-target}"
max_gib="${BONSAI_MAX_TARGET_GIB:-32}"

if ! [[ "$max_gib" =~ ^[1-9][0-9]*$ ]]; then
  echo "BONSAI_MAX_TARGET_GIB must be a positive integer, got: $max_gib" >&2
  exit 2
fi

if [[ ! -d "$target_dir" ]]; then
  echo "build artifacts: 0 GiB / ${max_gib} GiB (no $target_dir directory)"
  exit 0
fi

size_kib="$(du -sk "$target_dir" | awk '{print $1}')"
max_kib="$((max_gib * 1024 * 1024))"
size_gib="$(awk -v kib="$size_kib" 'BEGIN { printf "%.2f", kib / 1024 / 1024 }')"

echo "build artifacts: ${size_gib} GiB / ${max_gib} GiB ($target_dir)"
if (( size_kib > max_kib )); then
  cat >&2 <<EOF
Cargo build artifacts exceed the ${max_gib} GiB release budget.
Run 'cargo clean' to remove generated artifacts, then use the compact
'cargo test --workspace' correctness gate. Do not run the full workspace with
'--release'; release optimization is reserved for the CLI and measured SLO
targets. Override only for an intentional reviewed build with
BONSAI_MAX_TARGET_GIB=<GiB>.
EOF
  exit 1
fi
