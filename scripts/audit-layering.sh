#!/usr/bin/env bash
# Compatibility entrypoint for the Cargo-backed architecture gate.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/tests/test_audit_layering.py"
exec python3 "$SCRIPT_DIR/audit-layering.py" "$@"
