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
#   2. language-gauntlets — engine emits the expected per-language finding
#                          counts on the language_gauntlet fixture
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
#   9. release-binary    — distributable contains no build-machine paths
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

section_language_gauntlets() {
    require_release_binary || return 1
    python3 "$SCRIPT_DIR/validate-language-gauntlets.py" --bin "$BIN" --skip-realworld
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
    (cd "$REPO" && cargo test --release -q -p bonsai-ninja-taint --test language_matrix)
}

section_cli_e2e() {
    (cd "$REPO" && cargo test --release -q -p bonsai-ninja --test taint_engine_e2e)
}

section_release_binary() {
    require_release_binary || return 1
    python3 "$SCRIPT_DIR/audit-release-binary.py" "$BIN"
}

# `cargo test --release` builds the package's binary targets as test
# dependencies and can therefore replace the remapped distributable at BIN
# with an ordinary local build. Preserve the exact release artifact while the
# release-only tests run, then restore it before binary/package audits.
saved_release_binary=""
preserve_release_binary() {
    require_release_binary || return 1
    saved_release_binary=$(mktemp "${TMPDIR:-/tmp}/bonsai-ninja-release.XXXXXX")
    if ! cp -p "$BIN" "$saved_release_binary"; then
        rm -f "$saved_release_binary"
        saved_release_binary=""
        return 1
    fi
}

restore_release_binary() {
    if [[ -n "$saved_release_binary" && -f "$saved_release_binary" ]]; then
        if ! cmp -s "$saved_release_binary" "$BIN"; then
            cp -p "$saved_release_binary" "$BIN"
            echo "restored remapped release binary after release-only tests"
        fi
        rm -f "$saved_release_binary"
        saved_release_binary=""
    fi
}

run_section "pack-validate"     section_pack_validate
run_section "language-gauntlets" section_language_gauntlets
run_section "sanitizer-credit"  section_sanitizer_credit
run_section "logic-alignment"   section_logic_alignment
run_section "duplication"       section_duplication
run_section "cli-docs"          section_cli_docs
if (( QUICK == 0 )); then
    if preserve_release_binary; then
        trap restore_release_binary EXIT
    else
        fails+=("release-binary-preservation")
    fi
    run_section "matrix-tests"      section_matrix_tests
    run_section "cli-e2e"           section_cli_e2e
    restore_release_binary
fi
run_section "release-binary"    section_release_binary

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
