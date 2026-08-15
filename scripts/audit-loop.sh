#!/usr/bin/env bash
# Audit-loop wrapper. Runs every health-check that the project tracks
# and reports a single pass/fail summary. Intended for periodic local
# / CI runs (every ~15 minutes during active development) so drift
# between adapters, the rule pack, the engine, and the docs is caught
# early.
#
# Layers (each runs independently; failures don't short-circuit):
#
#   1. pack-validate     — rule schema + match-example owners agree
#   2. mega-cli          — engine emits the expected per-lang finding
#                          counts on the mega_flow fixture
#   3. sanitizer-credit  — sanitizer tag vocabulary in YAML matches the
#                          rulepack sanitizer-credit metadata
#   4. logic-alignment   — cross-rule logic checks: identical
#                          callee/regex+kind+language but different tags
#                          (silent classification drift)
#   5. duplication       — tag/severity/cwe drift between source and
#                          sanitizer rules that share a name
#   6. matrix-tests      — taint engine language matrix
#   7. cli-e2e-tests     — CLI / engine end-to-end matrix
#   8. cli-docs          — documented commands and flags match the release CLI
#
# Use `--quick` to skip the long-running matrix + cli-e2e tests when
# you want a fast structural sweep.

set -u
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/.." && pwd)
BIN="$REPO/target/release/bonsai-ninja"

QUICK=0
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
    esac
done

passes=()
fails=()

run_section() {
    local label=$1
    shift
    echo
    echo "=== $label ==="
    if "$@"; then
        passes+=("$label")
    else
        fails+=("$label")
    fi
}

require_release_binary() {
    if [[ ! -x "$BIN" ]]; then
        echo "release binary missing — running 'cargo build --release'"
        (cd "$REPO" && cargo build --release -q) || return 1
    fi
}

section_pack_validate() {
    require_release_binary || return 1
    python3 "$SCRIPT_DIR/validate-pattern-pack.py" --binary "$BIN"
}

section_mega_cli() {
    require_release_binary || return 1
    python3 "$SCRIPT_DIR/validate-mega-cli.py" --bin "$BIN" --skip-realworld
}

section_sanitizer_credit() {
    python3 "$SCRIPT_DIR/sanitizer_credit_audit.py"
}

section_logic_alignment() {
    python3 "$SCRIPT_DIR/audit_logic_alignment.py"
}

section_duplication() {
    python3 "$SCRIPT_DIR/audit_logic_alignment.py" --duplication-only
}

section_cli_docs() {
    require_release_binary || return 1
    python3 "$SCRIPT_DIR/audit-cli-docs.py" --binary "$BIN"
}

section_matrix_tests() {
    (cd "$REPO" && cargo test --release -q -p bonsai_taint --test language_matrix)
}

section_cli_e2e() {
    (cd "$REPO" && cargo test --release -q -p bonsai_cli --test taint_engine_e2e)
}

run_section "pack-validate"     section_pack_validate
run_section "mega-cli"          section_mega_cli
run_section "sanitizer-credit"  section_sanitizer_credit
run_section "logic-alignment"   section_logic_alignment
run_section "duplication"       section_duplication
run_section "cli-docs"          section_cli_docs
if (( QUICK == 0 )); then
    run_section "matrix-tests"      section_matrix_tests
    run_section "cli-e2e"           section_cli_e2e
fi

echo
echo "=== summary ==="
echo "passed: ${#passes[@]}"
for s in "${passes[@]+"${passes[@]}"}"; do echo "  ok    $s"; done
echo "failed: ${#fails[@]}"
for s in "${fails[@]+"${fails[@]}"}"; do echo "  FAIL  $s"; done

if (( ${#fails[@]} > 0 )); then
    exit 1
fi
exit 0
