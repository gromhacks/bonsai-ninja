#!/usr/bin/env bash
set -euo pipefail

# Bound local/CI Cargo output without deleting it. The default is deliberately
# above a clean full-workspace correctness build plus one production CLI build,
# but far below target trees containing repeated ThinLTO test generations.
# Explicit arguments are summed so isolated, privacy-safe release output cannot
# evade the workspace-wide storage budget.
if (($#)); then
  target_dirs=("$@")
else
  target_dirs=("${CARGO_TARGET_DIR:-target}")
fi
max_gib="${BONSAI_MAX_TARGET_GIB:-32}"

if ! [[ "$max_gib" =~ ^[1-9][0-9]*$ ]]; then
  echo "BONSAI_MAX_TARGET_GIB must be a positive integer, got: $max_gib" >&2
  exit 2
fi

size_kib=0
existing_dirs=()
for target_dir in "${target_dirs[@]}"; do
  if [[ -d "$target_dir" ]]; then
    dir_kib="$(du -sk "$target_dir" | awk '{print $1}')"
    size_kib="$((size_kib + dir_kib))"
    existing_dirs+=("$target_dir")
  fi
done
max_kib="$((max_gib * 1024 * 1024))"
size_gib="$(awk -v kib="$size_kib" 'BEGIN { printf "%.2f", kib / 1024 / 1024 }')"

if ((${#existing_dirs[@]})); then
  joined="${existing_dirs[0]}"
  for ((index = 1; index < ${#existing_dirs[@]}; index++)); do
    joined+=" + ${existing_dirs[index]}"
  done
  echo "build artifacts: ${size_gib} GiB / ${max_gib} GiB ($joined)"
else
  echo "build artifacts: 0 GiB / ${max_gib} GiB (no target directories)"
fi
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
