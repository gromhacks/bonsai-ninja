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

# Tier definitions follow the production dependency DAG. Lower index = lower
# in the graph. A crate may depend on its own tier or a lower tier, but never
# a higher tier. Development-only dependencies are intentionally excluded.
declare -a TIER_0=(bonsai_factstore bonsai_hash)
declare -a TIER_1=(bonsai_common)
declare -a TIER_2=(bonsai_diagnostics bonsai_vfs)
declare -a TIER_3=(bonsai_lang_api)
declare -a TIER_4=(
    bonsai_lang_c bonsai_lang_cpp bonsai_lang_csharp bonsai_lang_scala
    bonsai_lang_rust bonsai_lang_go bonsai_lang_java bonsai_lang_kotlin
    bonsai_lang_swift bonsai_lang_javascript
    bonsai_lang_php bonsai_lang_python bonsai_lang_perl bonsai_lang_ruby
    bonsai_lang_dart bonsai_lang_objc bonsai_lang_lua bonsai_lang_elixir
    bonsai_lang_erlang bonsai_cfg bonsai_index bonsai_parser
)
declare -a TIER_5=(bonsai_abstract_interp bonsai_lang_typescript bonsai_resolve)
declare -a TIER_6=(bonsai_adapters bonsai_callgraph bonsai_trace)
declare -a TIER_7=(bonsai_idg)
declare -a TIER_8=(bonsai_db)
declare -a TIER_9=(bonsai_taint)
declare -a TIER_10=(bonsai_workspace)
declare -a TIER_11=(bonsai_inspect bonsai_retrieval bonsai_testkit)
declare -a TIER_12=(bonsai_browse bonsai_conformance bonsai_security)
declare -a TIER_13=(bonsai_sdk)
declare -a TIER_14=(bonsai_cli)

tier_of() {
    local crate="$1"
    for t in {0..14}; do
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
        echo "UNCLASSIFIED CRATE: '$crate_name' must be assigned an architecture tier"
        VIOLATIONS=$((VIOLATIONS + 1))
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
    done < <(awk '
        /^\[/ {
            production = ($0 == "[dependencies]" || $0 == "[build-dependencies]" ||
                $0 ~ /^\[target\..*\.dependencies\]$/ ||
                $0 ~ /^\[target\..*\.build-dependencies\]$/)
            next
        }
        production && /^bonsai_[a-z_]+[[:space:]]*=/ {
            name = $0
            sub(/[[:space:]]*=.*/, "", name)
            print name
        }
    ' "$crate_toml")
done

if (( VIOLATIONS > 0 )); then
    echo ""
    echo "Total layering violations: $VIOLATIONS"
    exit 1
fi

echo "Layering DAG audit: OK"
