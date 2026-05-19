#!/usr/bin/env bash
# Generate adapter-capability matrix from per-adapter source files.
#
# Counts how many times each adapter mentions a capability-relevant
# field/helper in its source. The counts are coarse but stable — they
# detect drift from the snapshot in `docs/contributing/adapter-capabilities.mdx`.
#
# Usage:
#   scripts/audit-adapter-capabilities.sh         # print table
#   scripts/audit-adapter-capabilities.sh --check # diff against doc
#
# Exit 1 on drift when --check is passed.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CHECK_MODE=0
case "${1:-}" in
    --check) CHECK_MODE=1 ;;
esac

# Capabilities surveyed:
# - vis: Visibility::Private/Public + visibility_by_span hits
# - aliases: type_aliases population
# - bases: decl.bases assignment
# - rfw: receiver_field_writes population
# - panns: param_annotations population
# - exports: module_export_aliases (LanguageCapabilities field)
# - super: super_dispatch handling

generate_table() {
    printf '%-20s %-3s %-7s %-5s %-3s %-5s %s\n' \
        "Adapter" "vis" "aliases" "bases" "rfw" "panns" "exports"
    for adapter in "$ROOT_DIR"/crates/lang_*; do
        name="$(basename "$adapter")"
        [[ "$name" == "lang_api" ]] && continue
        src="$adapter/src/lib.rs"
        [[ -f "$src" ]] || continue
        bases=$(grep -cE 'decl\.bases\s*=|\.bases\s*=' "$src" 2>/dev/null)
        aliases=$(grep -cE 'type_aliases' "$src" 2>/dev/null)
        # `receiver_field_writes` is populated automatically by the kit
        # whenever the adapter declares `implicit_receiver_names`
        # (every OO adapter). Counting `implicit_receiver_names` here
        # rather than the literal field name reflects what actually
        # gates population. The smoke test
        # `crates/taint/tests/receiver_field_writes_smoke.rs` verifies
        # the behavioural truth across Java, C#, Python, JS, TS.
        rfw=$(grep -cE 'implicit_receiver_names\s*[:=]|with_fn_kinds_and_implicit_receivers' "$src" 2>/dev/null)
        # `param_annotations` is populated by the kit's
        # `extract_param_annotations` (called from
        # `decl_index_with_handler`) for every adapter. Counting the
        # literal field name here only catches adapters that do
        # *additional* annotation post-processing (Python's binder
        # merge, Ruby's attr_*). The kit covers Java/Kotlin/C#
        # natively, verified by
        # `crates/taint/tests/param_annotations_smoke.rs`.
        panns=$(grep -cE 'param_annotations|extract_param_annotations|param_decoration_kinds' "$src" 2>/dev/null)
        # Visibility population: count every concrete `Visibility::Variant`
        # assignment, plus the `visibility_by_span` cache key. Adapters
        # legitimately use `Module` (Erlang `-export`, Go uppercase rule,
        # Dart `_`-prefix), `Private` (C `static`, Python dunder), or
        # `Public` (explicit) — all are real evidence that the adapter
        # populates the field.
        visi=$(grep -cE 'visibility_by_span|Visibility::(Private|Public|Module|Crate|Protected|Internal)' "$src" 2>/dev/null)
        exports=$(grep -cE 'module_export_aliases' "$src" 2>/dev/null)
        printf '%-20s %-3d %-7d %-5d %-3d %-5d %d\n' \
            "$name" "$visi" "$aliases" "$bases" "$rfw" "$panns" "$exports"
    done
}

if (( CHECK_MODE == 1 )); then
    table="$(generate_table)"
    doc="$ROOT_DIR/docs/contributing/adapter-capabilities.mdx"
    snapshot="$ROOT_DIR/.snapshots/ADAPTER_CAPABILITIES.snapshot"
    if [[ ! -f "$doc" ]]; then
        echo "ERROR: $doc missing"
        exit 1
    fi

    # Row-count gate: the canonical doc has a primary table where
    # every row starts with `| lang_<name>`. Drift in the row count
    # likely means an adapter was added or removed.
    rows=$(grep -c '^| lang_' "$doc")
    expected=21
    if (( rows != expected )); then
        echo "DRIFT: docs/contributing/adapter-capabilities.mdx has $rows lang_* rows, expected $expected"
        echo ""
        echo "Live capability counts:"
        echo "$table"
        exit 1
    fi

    # Per-cell drift gate: compare the live counts against the
    # frozen snapshot at .snapshots/ADAPTER_CAPABILITIES.snapshot. Any
    # difference (an adapter newly populated a Decl field, or
    # regressed) requires explicit acknowledgement by regenerating
    # the snapshot via `scripts/audit-adapter-capabilities.sh > .snapshots/ADAPTER_CAPABILITIES.snapshot`.
    if [[ -f "$snapshot" ]]; then
        if ! diff -u "$snapshot" <(echo "$table") > /tmp/capabilities-diff.txt 2>&1; then
            echo "DRIFT: live capability counts differ from baseline."
            echo ""
            echo "Diff (snapshot → live):"
            cat /tmp/capabilities-diff.txt
            echo ""
            echo "If the change is intentional, regenerate the snapshot:"
            echo "  scripts/audit-adapter-capabilities.sh > .snapshots/ADAPTER_CAPABILITIES.snapshot"
            exit 1
        fi
    else
        echo "WARN: .snapshots/ADAPTER_CAPABILITIES.snapshot missing. Capture with:"
        echo "  scripts/audit-adapter-capabilities.sh > .snapshots/ADAPTER_CAPABILITIES.snapshot"
    fi

    echo "Capability matrix: $rows/$expected rows present in doc; per-cell counts match snapshot."
    exit 0
fi

generate_table
