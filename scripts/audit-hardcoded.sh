#!/usr/bin/env bash
# Sweeps every non-adapter, non-rulepack crate for hardcoded
# language-/library-/framework-/runtime-API names that should live
# in InterTaintConfig, LanguageCapabilities, or rulepack YAML.
#
# Output: /tmp/hardcoded-audit-<crate>.txt per crate. The script
# emits a summary count to stdout. It does NOT exit non-zero —
# triage is human-driven; this is a survey tool. Once Phase 3
# triage lands, the script can be tightened to fail on regressions.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-/tmp/hardcoded-audit}"
mkdir -p "$OUT_DIR"

# Crates that LEGITIMATELY know language/library/framework names:
# - lang_*  (per-language adapters)
# - adapters (registers all adapters)
# - security (rulepack-driven; loader/compile/pkg/validate know the schema)
# - cli, sdk (compose surfaces; expected to name commands)
# - testkit, conformance (test infra)
EXCLUDE_REGEX='^crates/(lang_|adapters|cli|sdk|testkit|conformance|security/src/(loader|compile|pkg|rule|finding|report|deps|sanitizer_credit)\.rs)'

# Suspect string-literal patterns. A hit is something a future
# contributor should explain or migrate.
declare -a SUSPECT_PATTERNS=(
    # Common library / API tokens (extend liberally)
    '"snprintf"'  '"strcpy"'  '"strncpy"'  '"strcat"'  '"sprintf"'  '"memset"'  '"memcpy"'
    '"system"'    '"exec"'    '"eval"'     '"open"'    '"read"'     '"write"'   '"fopen"'
    '"push"'      '"append"'  '"add"'      '"call"'    '"apply"'    '"bind"'
    # Sigils / language-specific punctuation as full string literals
    '"\$"'        '"@"'       '"%"'        '"&"'       '"::"'       '"->"'
    # Language identifiers
    '"python"'    '"rust"'    '"java"'     '"javascript"' '"typescript"' '"go"'
    '"ruby"'      '"perl"'    '"php"'      '"kotlin"'  '"swift"'    '"scala"'
    '"erlang"'    '"elixir"'  '"lua"'      '"dart"'    '"objc"'     '"solidity"'
    '"csharp"'    '"cpp"'
    # Framework / package-manager files
    '"package.json"'  '"Cargo.toml"' '"pom.xml"'   '"go.mod"'    '"Pipfile"'
    '"setup.py"'      '"build.gradle"' '"tsconfig.json"'  '"composer.json"'
    # Ignore-segment conventions
    '"node_modules"'  '"vendor"'  '"target"'   '"dist"'      '"build"'
    '"__pycache__"'   '"\.venv"'  '"\.git"'    '"\.bonsai"'
    # Test-path conventions
    '"_test"'   '"test_"'   '"_spec"'    '"\.test\."' '"__tests__"'
)

TOTAL=0
declare -a CRATE_NAMES=()
declare -a CRATE_HITS=()

for crate_dir in "$ROOT_DIR"/crates/*/src/; do
    crate_path="${crate_dir%/src/}"
    crate_name="$(basename "$crate_path")"
    rel="crates/$crate_name"

    if [[ "$rel" =~ $EXCLUDE_REGEX ]]; then
        continue
    fi

    out_file="$OUT_DIR/${crate_name}.txt"
    : > "$out_file"
    hit_count=0

    for pat in "${SUSPECT_PATTERNS[@]}"; do
        # rg --no-messages so missing files don't error out
        # -F so dollar/backslash patterns aren't interpreted as regex
        while IFS= read -r line; do
            # Skip test files (path or *_test{,s}.rs filename) and doc-comment-only hits.
            case "$line" in
                */tests/*|*/_tests.rs:*|*_test.rs:*|*_tests.rs:*) continue ;;
            esac
            # Skip lines that are pure doc comments (`/// ...`).
            content="${line#*:*:}"
            content_trimmed="${content#"${content%%[![:space:]]*}"}"
            case "$content_trimmed" in
                ///*) continue ;;
            esac
            echo "$line" >> "$out_file"
            hit_count=$((hit_count + 1))
        done < <(grep -rnF --include='*.rs' "$pat" "$crate_dir" 2>/dev/null || true)
    done

    if (( hit_count > 0 )); then
        CRATE_NAMES+=("$crate_name")
        CRATE_HITS+=("$hit_count")
        TOTAL=$((TOTAL + hit_count))
    else
        rm -f "$out_file"
    fi
done

echo "Hardcoded-value audit complete."
echo "Output directory: $OUT_DIR"
echo ""
if (( TOTAL == 0 )); then
    echo "No suspect literals found in surveyed crates."
    exit 0
fi

echo "Hits per crate (sorted):"
for i in "${!CRATE_NAMES[@]}"; do
    printf '  %-30s %5d\n' "${CRATE_NAMES[$i]}" "${CRATE_HITS[$i]}"
done | sort -k2 -n -r

echo ""
echo "Total suspect hits: $TOTAL"
echo ""
echo "Inspect per-crate detail in $OUT_DIR/<crate>.txt"
