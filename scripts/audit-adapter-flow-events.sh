#!/usr/bin/env bash
# Verify adapter FlowEvent coverage from emitted compiler facts.
#
# Source-text occurrence counts are not a correctness signal: a shared walker
# can inspect `FlowEvent::Branch` without emitting one, and extracting a common
# lowering helper can reduce adapter-local spellings without changing output.
# This gate therefore parses canonical valid programs through every adapter and
# checks the resulting typed event trees.
#
# `--check` is retained as the stable CI/developer interface.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/.." && pwd)

case "${1:-}" in
    ""|--check) ;;
    *)
        echo "usage: $0 [--check]" >&2
        exit 2
        ;;
esac

# Current recursive event vocabulary. Loop sub-kinds and catch parameters are
# fields on `FlowEvent::Loop` / `FlowEvent::Try`, not separate events:
# Call Branch Loop Assign Return Throw Try Break Continue Yield Await Defer Using Lifecycle
cd "$REPO"
cargo test --locked -p bonsai-ninja-conformance \
    --test flow_event_conformance \
    --test async_yield_coverage
