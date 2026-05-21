#!/usr/bin/env bash
# Asserts the layering DAG documented in docs/contributing/architecture.mdx.
#
# Each tier may depend on prior tiers only. A new edge that crosses a
# tier boundary upward (e.g. `bonsai_taint` depending on `bonsai_browse`)
# is a layering violation. The script exits non-zero on any violation
# and prints the offending edges. Used in CI as a hard gate.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Tier definitions. Lower index = lower in DAG.
# A crate may depend on any crate in its own tier or a lower tier, but
# never on a crate in a higher tier.
declare -a TIER_0=(bonsai_common bonsai_hash)
declare -a TIER_1=(bonsai_diagnostics bonsai_vfs bonsai_parser bonsai_factstore)
declare -a TIER_2=(bonsai_lang_api)
declare -a TIER_3=(
    bonsai_lang_c bonsai_lang_cpp bonsai_lang_csharp bonsai_lang_scala
    bonsai_lang_rust bonsai_lang_go bonsai_lang_java bonsai_lang_kotlin
    bonsai_lang_swift bonsai_lang_javascript bonsai_lang_typescript
    bonsai_lang_php bonsai_lang_python bonsai_lang_perl bonsai_lang_ruby
    bonsai_lang_dart bonsai_lang_objc bonsai_lang_lua bonsai_lang_elixir
    bonsai_lang_erlang bonsai_lang_solidity
)
declare -a TIER_4=(bonsai_index bonsai_resolve bonsai_cfg bonsai_callgraph bonsai_abstract_interp bonsai_idg bonsai_db)
declare -a TIER_5=(bonsai_taint)
declare -a TIER_6=(bonsai_workspace)
declare -a TIER_7=(bonsai_inspect bonsai_browse bonsai_trace bonsai_security)
declare -a TIER_8=(bonsai_sdk)
declare -a TIER_9=(bonsai_adapters bonsai_cli bonsai_conformance bonsai_testkit)

tier_of() {
    local crate="$1"
    for t in 0 1 2 3 4 5 6 7 8 9; do
        local arr_name="TIER_$t[@]"
        for c in "${!arr_name}"; do
            if [[ "$c" == "$crate" ]]; then
                echo "$t"
                return 0
            fi
        done
    done
    echo "-1"
}

VIOLATIONS=0

for crate_dir in "$ROOT_DIR"/crates/*/; do
    crate_toml="${crate_dir}Cargo.toml"
    [[ -f "$crate_toml" ]] || continue

    crate_name="$(awk -F'"' '/^name[[:space:]]*=/ { print $2; exit }' "$crate_toml")"
    [[ -z "$crate_name" ]] && continue

    crate_tier="$(tier_of "$crate_name")"
    if [[ "$crate_tier" == "-1" ]]; then
        echo "WARN: crate '$crate_name' is not classified in audit-layering.sh"
        continue
    fi

    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        dep_tier="$(tier_of "$dep")"
        if [[ "$dep_tier" == "-1" ]]; then
            continue
        fi
        if (( dep_tier > crate_tier )); then
            echo "LAYERING VIOLATION: $crate_name (tier $crate_tier) depends on $dep (tier $dep_tier)"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    done < <(grep -E '^bonsai_[a-z_]+\s*=' "$crate_toml" | sed -E 's/^(bonsai_[a-z_]+)\s*=.*/\1/')
done

if (( VIOLATIONS > 0 )); then
    echo ""
    echo "Total layering violations: $VIOLATIONS"
    exit 1
fi

echo "Layering DAG audit: OK"
