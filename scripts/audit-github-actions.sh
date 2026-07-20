#!/usr/bin/env bash
# Reject mutable third-party GitHub Action references. A full commit SHA is
# the only immutable external-action reference supported by GitHub Actions.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

violations=0
while IFS= read -r workflow; do
    if ! rg -q '^permissions:' "$workflow"; then
        printf 'workflow lacks explicit top-level token permissions: %s\n' "$workflow" >&2
        violations=$((violations + 1))
    fi
done < <(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print)

while IFS= read -r occurrence; do
    action="$(sed -E 's/.*uses:[[:space:]]*([^[:space:]#]+).*/\1/' <<<"$occurrence")"
    case "$action" in
        ./* | docker://*)
            continue
            ;;
    esac
    ref="${action##*@}"
    if [[ "$action" != *@* || ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        printf 'mutable GitHub Action reference: %s\n' "$occurrence" >&2
        violations=$((violations + 1))
    fi
done < <(rg -n --no-heading 'uses:[[:space:]]*[^[:space:]#]+' .github/workflows --glob '*.yml' --glob '*.yaml')

while IFS=: read -r workflow line _; do
    following="$(sed -n "$((line + 1)),$((line + 7))p" "$workflow")"
    if ! rg -q 'persist-credentials:[[:space:]]*false' <<<"$following"; then
        printf 'checkout persists a repository credential: %s:%s\n' "$workflow" "$line" >&2
        violations=$((violations + 1))
    fi
done < <(rg -n --no-heading 'uses:[[:space:]]*actions/checkout@' .github/workflows --glob '*.yml' --glob '*.yaml')

while IFS= read -r occurrence; do
    if [[ "$occurrence" != *--require-hashes* ]]; then
        printf 'Python dependency install does not require hashes: %s\n' "$occurrence" >&2
        violations=$((violations + 1))
    fi
done < <(rg -n --no-heading 'pip[[:space:]]+install' .github/workflows --glob '*.yml' --glob '*.yaml' || true)

if (( violations > 0 )); then
    printf 'GitHub Actions pinning audit failed: %d mutable reference(s).\n' "$violations" >&2
    exit 1
fi

echo "GitHub Actions pinning audit: OK"
