#!/usr/bin/env bash
# Sweeps every non-adapter, non-rulepack crate for hardcoded
# language-/library-/framework-/runtime-API names that should live
# in InterTaintConfig, LanguageCapabilities, or rulepack YAML.
#
# Output: one detail report per crate plus a normalized, line-number-free
# signature set. `--check` compares that set with the committed baseline and
# fails on every unreviewed addition, removal, or replacement.
#
# Usage:
#   scripts/audit-hardcoded.sh [OUT_DIR]              # human-readable survey
#   scripts/audit-hardcoded.sh --check [OUT_DIR]      # enforce baseline
#   scripts/audit-hardcoded.sh --snapshot [OUT_DIR]   # print baseline payload

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="survey"
if [[ "${1:-}" == "--check" || "${1:-}" == "--snapshot" ]]; then
    MODE="${1#--}"
    shift
fi
OUT_DIR="${1:-/tmp/hardcoded-audit}"
mkdir -p "$OUT_DIR"
SIGNATURES="$OUT_DIR/.signatures.tsv"
SORTED_SIGNATURES="$OUT_DIR/.signatures.sorted.tsv"
COUNTS="$OUT_DIR/.counts.tsv"
: > "$SIGNATURES"
: > "$COUNTS"
SNAPSHOT_FILE="$ROOT_DIR/.snapshots/HARDCODED_KNOWLEDGE.snapshot"

# Crates that LEGITIMATELY know language/library/framework names:
# - lang_*  (per-language adapters)
# - adapters (registers all adapters)
# - security loader/compile/pkg/report/deps modules know the rule schema
# - cli, sdk (compose surfaces; expected to name commands)
# - testkit, conformance (test infra)
EXCLUDE_CRATE_REGEX='^crates/(lang_|adapters|cli|sdk|testkit|conformance)'
EXCLUDE_FILE_REGEX='/crates/security/src/(loader|compile|pkg|rule|finding|report|deps|sanitizer_credit)\.rs:'

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

    if [[ "$rel" =~ $EXCLUDE_CRATE_REGEX ]]; then
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
                */tests/*|*/tests.rs:*|*/_tests.rs:*|*_test.rs:*|*_tests.rs:*) continue ;;
            esac
            if [[ "$line" =~ $EXCLUDE_FILE_REGEX ]]; then
                continue
            fi
            # Skip lines that are pure doc comments (`/// ...`).
            content="${line#*:*:}"
            content_trimmed="${content#"${content%%[![:space:]]*}"}"
            case "$content_trimmed" in
                ///*) continue ;;
            esac
            echo "$line" >> "$out_file"
            relative="${line#"$ROOT_DIR/"}"
            source_path="${relative%%:*}"
            printf '%s\t%s\t%s\t%s\n' \
                "$crate_name" "$pat" "$source_path" "$content_trimmed" >> "$SIGNATURES"
            hit_count=$((hit_count + 1))
        done < <(rg -n -F --no-messages --glob '*.rs' "$pat" "$crate_dir" || true)
    done

    if (( hit_count > 0 )); then
        CRATE_NAMES+=("$crate_name")
        CRATE_HITS+=("$hit_count")
        printf '%s\t%d\n' "$crate_name" "$hit_count" >> "$COUNTS"
        TOTAL=$((TOTAL + hit_count))
    else
        rm -f "$out_file"
    fi
done

LC_ALL=C sort -u "$SIGNATURES" > "$SORTED_SIGNATURES"

emit_snapshot() {
    local digest
    digest="$(shasum -a 256 "$SORTED_SIGNATURES" | awk '{print $1}')"
    echo "# Normalized hardcoded-knowledge audit baseline (no source line numbers)."
    printf 'sha256\t%s\n' "$digest"
    printf 'total\t%d\n' "$TOTAL"
    LC_ALL=C sort "$COUNTS"
}

if [[ "$MODE" == "snapshot" ]]; then
    emit_snapshot
    exit 0
fi

if [[ "$MODE" == "check" ]]; then
    if [[ ! -f "$SNAPSHOT_FILE" ]]; then
        echo "ERROR: missing hardcoded-knowledge baseline: $SNAPSHOT_FILE" >&2
        echo "Generate it with: scripts/audit-hardcoded.sh --snapshot" >&2
        exit 1
    fi
    if ! diff -u "$SNAPSHOT_FILE" <(emit_snapshot) > "$OUT_DIR/baseline.diff"; then
        echo "DRIFT: hardcoded-knowledge signatures changed." >&2
        cat "$OUT_DIR/baseline.diff" >&2
        echo "Inspect per-crate details in $OUT_DIR and review every changed literal." >&2
        exit 1
    fi
    echo "Hardcoded-knowledge signatures match the reviewed baseline ($TOTAL hits)."
    exit 0
fi

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
