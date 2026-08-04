#!/usr/bin/env bash
# Enforce the compiler/rulepack ownership boundary.
#
# Shared production crates may normalize typed IR, but they must not select
# behavior from a language id, package/API spelling, package-manager filename,
# or source-extension inventory. Those values belong to language adapters or
# `security-patterns/metadata.yml` / rule YAML. Numeric product/ABI constants,
# IR enum labels, CLI strings, tests, and language-adapter syntax are outside
# this check by design.
#
# Usage:
#   scripts/audit-hardcoded.sh [OUT_DIR]
#   scripts/audit-hardcoded.sh --check [OUT_DIR]

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="survey"
if [[ "${1:-}" == "--check" ]]; then
    MODE="check"
    shift
fi
OUT_DIR="${1:-/tmp/hardcoded-audit}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/stripped"
REPORT="$OUT_DIR/violations.tsv"
: > "$REPORT"

is_shared_source() {
    local path="$1"
    case "$path" in
        */tests/*|*/tests.rs|*/_tests.rs|*_test.rs|*_tests.rs)
            return 1 ;;
        crates/lang_api/*)
            return 0 ;;
        crates/lang_*/*|crates/adapters/*|crates/cli/*|crates/sdk/*|crates/testkit/*|crates/conformance/*)
            return 1 ;;
        crates/*/src/*.rs|crates/*/src/**/*.rs)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Copy production text while dropping individual `#[cfg(test)]` items. Inline
# test modules are not required to be last: stopping at the first one silently
# hid later production code in the past. The lightweight delimiter walk is
# sufficient here because it only decides which lines feed literal searches;
# architecture/behavior tests remain the semantic source of truth.
while IFS= read -r source; do
    is_shared_source "$source" || continue
    target="$OUT_DIR/stripped/$source"
    mkdir -p "$(dirname "$target")"
    awk '
        function brace_delta(line, opens, closes) {
            opens = gsub(/\{/, "{", line)
            closes = gsub(/\}/, "}", line)
            return opens - closes
        }
        skipping_test {
            test_depth += brace_delta($0)
            if (test_depth <= 0 && ($0 ~ /}/ || $0 ~ /;[[:space:]]*$/)) {
                skipping_test = 0
                test_depth = 0
            }
            next
        }
        /^[[:space:]]*#\[cfg\(test\)\]/ { pending_test_cfg = 1; next }
        pending_test_cfg && /^[[:space:]]*#\[/ { next }
        pending_test_cfg {
            pending_test_cfg = 0
            test_depth = brace_delta($0)
            if (test_depth > 0 || $0 !~ /;[[:space:]]*$/) {
                skipping_test = 1
            }
            next
        }
        { print }
    ' "$source" > "$target"
done < <(rg --files crates | LC_ALL=C sort)

record_matches() {
    local category="$1"
    local pattern="$2"
    local scope_regex="${3:-.}"
    local exclude_regex="${4:-^$}"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        local stripped_path="${line%%:*}"
        local original="${stripped_path#"$OUT_DIR/stripped/"}"
        [[ "$original" =~ $scope_regex ]] || continue
        [[ "$original" =~ $exclude_regex ]] && continue
        local rest="${line#*:}"
        printf '%s\t%s\t%s\n' "$category" "$original" "$rest" >> "$REPORT"
    done < <(rg -n -F --no-messages "$pattern" "$OUT_DIR/stripped" || true)
}

record_regex_matches() {
    local category="$1"
    local pattern="$2"
    local scope_regex="${3:-.}"
    local exclude_regex="${4:-^$}"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        local stripped_path="${line%%:*}"
        local original="${stripped_path#"$OUT_DIR/stripped/"}"
        [[ "$original" =~ $scope_regex ]] || continue
        [[ "$original" =~ $exclude_regex ]] && continue
        local rest="${line#*:}"
        printf '%s\t%s\t%s\n' "$category" "$original" "$rest" >> "$REPORT"
    done < <(rg -n --no-messages "$pattern" "$OUT_DIR/stripped" || true)
}

LANGUAGE_IDS=(
    python rust java javascript typescript go ruby perl php kotlin swift scala
    erlang elixir lua dart objc solidity csharp cpp
)
for language in "${LANGUAGE_IDS[@]}"; do
    # `lang_api` type/trait docs legitimately show opaque id examples; the
    # architecture invariant for concrete branches remains on engine crates.
    record_matches "language-id" "\"$language\"" '^crates/' '^crates/lang_api/'
done

# Shared crates must not regain a union of source-language punctuation. Exact
# syntax belongs to the active adapter's capability/GrammarHandler data;
# language-neutral name helpers may only use structural character classes.
SHARED_SYNTAX_INVENTORIES=(
    IDENTIFIER_SIGILS REFERENCE_SIGILS ALL_NAME_PUNCTUATION
    QUALIFIED_NAME_SEPARATORS PROJECTION_CANONICALIZATION_VECTORS
)
for inventory in "${SHARED_SYNTAX_INVENTORIES[@]}"; do
    record_matches "source-syntax-inventory" "$inventory"
done
CALLABLE_SYNTAX_LITERALS=(
    '.strip_prefix("fun ")' '.strip_prefix("\\&")'
    '.strip_prefix("method(")'
)
for literal in "${CALLABLE_SYNTAX_LITERALS[@]}"; do
    record_matches "callable-source-syntax" "$literal"
done

# Caller-visible write-back syntax is classified by the active language
# adapter and lowered to `ArgumentPassingMode`; shared flow/IDG code must not
# regain a cross-language union of address/ref/out grammar spellings.
WRITEBACK_SYNTAX_LITERALS=(
    '"out_argument"' '"ref_expression"' '"inout_expression"'
    '"reference_expression"' '"address_of_expression"' '"ref_kind_keyword"'
)
for literal in "${WRITEBACK_SYNTAX_LITERALS[@]}"; do
    record_matches "writeback-source-syntax" "$literal"
done

# Concrete provider/API identities that have previously leaked into shared
# analyzers. Extend this list when a review finds another class; the correct
# fix is to move the spelling to rules, not to baseline the violation.
API_IDENTITIES=(
    're.compile' 'urlparse' 'XMLParser' 'resolve_entities' 'no_network'
    'setLocation' 'github.com/golang-jwt' 'encoding/xml' 'CharsetReader'
    'NewDecoder' 'Method.Alg' 'psycopg2-binary' 'djangorestframework'
)
for identity in "${API_IDENTITIES[@]}"; do
    record_matches "api-identity" "$identity"
done

# Language/ecosystem import spellings and review-profile path inventories are
# metadata too. Match source literals/normalization calls rather than prose so
# architecture comments can name the historical failure without failing CI.
PACKAGE_SYNTAX_LITERALS=(
    '.strip_prefix("node:")' '.strip_suffix(".h")'
    '.strip_suffix(".hpp")' '.strip_suffix(".hxx")'
)
for literal in "${PACKAGE_SYNTAX_LITERALS[@]}"; do
    record_matches "package-syntax" "$literal" '^crates/security/'
done

PROFILE_PATH_LITERALS=(
    '"_test.go"' '"_test.py"' '".test.ts"' '".spec.ts"'
    '"test.java"' '"test.scala"' '"test.kt"' '"test.cs"'
    '"node_modules/"' '"site-packages/"' '"src/test/"'
    '"_spec.rb"' '"_test.exs"'
)
for literal in "${PROFILE_PATH_LITERALS[@]}"; do
    record_matches "profile-path" "$literal" '^crates/(security|cli)/'
done
record_matches "profile-path" 'PRODUCTION_EXCLUDES' '^crates/(security|cli)/'

# Shared analysis may compare typed enum/capability values, but must never
# switch on an authored security tag or reintroduce a compiled taxonomy table.
record_matches "security-taxonomy" "const MAPPING" '^crates/security/'
record_matches "security-taxonomy" '.tag.as_deref() == Some("' '^crates/security/'
record_matches "security-taxonomy" '.tag.as_deref() != Some("' '^crates/security/'
record_matches "security-taxonomy" 'matches!(tag, "' '^crates/security/'

# Derive the complete authored tag vocabulary from the rules and forbid those
# exact literals in shared implementation code. `rule.rs` is the one explicit
# exception: its typed payload enum owns stable wire labels, not rule policy.
while IFS= read -r tag; do
    [[ -n "$tag" ]] || continue
    record_matches \
        "security-tag" \
        "\"$tag\"" \
        '^crates/security/' \
        '^crates/security/src/rule\.rs$'
done < <(
    rg --no-filename '^\s+tag:\s+' security-patterns/langs -g '*.yml' \
        | sed -E "s/^[[:space:]]*tag:[[:space:]]*['\"]?([^ '\"#]+).*/\1/" \
        | LC_ALL=C sort -u
)

# Categories are authored policy just like tags. Shared code may carry the
# category value as data but must not select behavior by comparing its text.
while IFS= read -r category; do
    [[ -n "$category" ]] || continue
    record_matches \
        "security-category" \
        "\"$category\"" \
        '^crates/security/' \
        '^crates/security/src/rule\.rs$'
done < <(
    rg --no-filename '^\s+category:\s+' security-patterns/langs -g '*.yml' \
        | sed -E "s/^[[:space:]]*category:[[:space:]]*['\"]?([^ '\"#]+).*/\1/" \
        | LC_ALL=C sort -u
)

# Historical compiler-boundary regressions. These are implementation shapes,
# not a complete source-syntax vocabulary: the correct production replacement
# is adapter-owned Tree-sitter facts or structural qualified-name helpers.
record_matches "constructor-source-syntax" '.strip_prefix("new ")'
record_matches "constructor-source-syntax" '.strip_suffix(".new")'
record_matches "shared-call-inventory" 'COMMON_CALL_KINDS.contains'
record_matches "rendered-taint-reparse" 'argument_text_calls('
QUALIFIED_SEPARATOR_UNIONS=(
    ".split(['.', ':'])" ".split(&['.', ':'])"
    ".split([':', '.'])" ".split(&[':', '.'])"
    ".rsplit(['.', ':'])" ".rsplit(&['.', ':'])"
    ".rsplit([':', '.'])" ".rsplit(&[':', '.'])"
    '[".", "->", "::"]' '["::", "->", "."]'
    'for sep in [".", "->", "::"' 'for separator in [".", "->", "::"'
)
for pattern in "${QUALIFIED_SEPARATOR_UNIONS[@]}"; do
    record_matches "qualified-separator-union" "$pattern" '^crates/'
done
record_regex_matches \
    "qualified-separator-union" \
    'contains\((?:'\''\.'\''|"->"|"::")\).*contains\((?:'\''\.'\''|"->"|"::")\)' \
    '^crates/'

# Security dependency/package discovery is rulepack metadata. Compiler cache
# freshness in `bonsai_common` may still classify build files because that is
# a product/ABI concern rather than security semantics.
MANIFEST_NAMES=(
    package.json Cargo.toml pom.xml go.mod Pipfile setup.py build.gradle
    composer.json requirements.txt packages.config
)
for manifest in "${MANIFEST_NAMES[@]}"; do
    record_matches "security-manifest" "\"$manifest\"" '^crates/security/'
done

# Browse/navigation must derive source suffixes from registered workspace
# adapters/files, never from a parallel extension list.
SOURCE_SUFFIXES=(.py .rb .php .go .js .ts .lua .java .kt .scala .cs .cpp .cxx .hpp)
for suffix in "${SOURCE_SUFFIXES[@]}"; do
    record_matches "browse-extension" "\"$suffix\"" '^crates/browse/'
done

LC_ALL=C sort -u "$REPORT" -o "$REPORT"
TOTAL="$(wc -l < "$REPORT" | tr -d ' ')"

if (( TOTAL == 0 )); then
    echo "Hardcoded-knowledge boundary clean: 0 production violations."
    exit 0
fi

echo "Hardcoded-knowledge boundary violations: $TOTAL" >&2
column -t -s $'\t' "$REPORT" >&2 || cat "$REPORT" >&2
echo "Move syntax to the owning adapter and provider/security values to rulepack YAML." >&2
if [[ "$MODE" == "check" ]]; then
    exit 1
fi
