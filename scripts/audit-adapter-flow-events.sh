#!/usr/bin/env bash
# Per-adapter FlowEvent emission audit.
#
# For every `crates/lang_*/src/lib.rs`, count how many times the
# adapter emits each FlowEvent variant. The counts are coarse —
# multiple emissions in one match arm collapse into one number — but
# they're stable and detect adapter-side gaps that block matrix cells.
#
# Usage:
#   scripts/audit-adapter-flow-events.sh         # print table
#   scripts/audit-adapter-flow-events.sh --check # diff against snapshot
#
# See `docs/decisions/0004-test-matrix-canon.md` and ADR 0003.

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CHECK_MODE=0
case "${1:-}" in
    --check) CHECK_MODE=1 ;;
esac

# FlowEvent variants surveyed. Add to this list when the engine grows
# a new event kind.
declare -a EVENTS=(Call Assign Return Throw Catch Branch ForEach Param)

generate_table() {
    printf '%-20s' "Adapter"
    for ev in "${EVENTS[@]}"; do
        printf ' %-7s' "$ev"
    done
    printf ' %-12s\n' "PseudoCall"

    for adapter in "$ROOT_DIR"/crates/lang_*; do
        name="$(basename "$adapter")"
        [[ "$name" == "lang_api" ]] && continue
        # Walk the entire adapter source tree, not just lib.rs — many
        # adapters split FlowEvent emission across helper modules.
        # Match both the unqualified and module-qualified emission
        # forms (`FlowEvent::Call {` and `bonsai_lang_api::FlowEvent::Call {`).
        printf '%-20s' "$name"
        for ev in "${EVENTS[@]}"; do
            count=$(grep -rcE "(::|\\b)FlowEvent::${ev}\\s*\\{" "$adapter/src" 2>/dev/null \
                | awk -F: '{ s += $2 } END { print s+0 }')
            printf ' %-7d' "$count"
        done
        pseudo=$(grep -rcE "pseudo_call_event" "$adapter/src" 2>/dev/null \
            | awk -F: '{ s += $2 } END { print s+0 }')
        printf ' %-12d\n' "$pseudo"
    done
}

if (( CHECK_MODE == 1 )); then
    table="$(generate_table)"
    snapshot="$ROOT_DIR/.snapshots/ADAPTER_FLOW_EVENT_COVERAGE.snapshot"
    if [[ ! -f "$snapshot" ]]; then
        echo "WARN: $snapshot missing. Capture with:"
        echo "  scripts/audit-adapter-flow-events.sh > $snapshot"
        echo "$table"
        exit 1
    fi
    if ! diff -u "$snapshot" <(echo "$table") > /tmp/adapter-flow-event-diff.txt 2>&1; then
        echo "DRIFT: live FlowEvent counts differ from baseline."
        echo ""
        cat /tmp/adapter-flow-event-diff.txt
        echo ""
        echo "If the change is intentional, regenerate the snapshot:"
        echo "  scripts/audit-adapter-flow-events.sh > $snapshot"
        exit 1
    fi
    echo "FlowEvent matrix matches snapshot."
    exit 0
fi

generate_table
