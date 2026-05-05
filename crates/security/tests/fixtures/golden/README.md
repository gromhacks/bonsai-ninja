# Golden SARIF fixtures

Snapshot SARIF outputs for representative example workspaces. Tests
in `crates/security/tests/golden_sarif.rs` produce live SARIF for
each fixture and compare against the snapshot here.

## When the snapshot regenerates

Run with the env var set:

```sh
BONSAI_UPDATE_GOLDEN=1 cargo test -p bonsai_security --test golden_sarif
```

Without the env var, drift fails the test. With it, the test
overwrites the snapshot file. Always commit the regenerated
snapshot in the same PR as the SARIF-altering change so reviewers
see the diff.

## What's covered

The `golden_sarif` test runs `run_taint_analysis` on a small
fixed-shape Python workspace and asserts:

- `partial_sarif.json` — projection of the SARIF output containing
  `(rule_id, message, level, kind, fingerprints)` per result. The
  full SARIF is too verbose to diff cleanly; the projection is
  the load-bearing surface for GitHub Code Scanning ingest.

## Why a partial projection rather than the whole SARIF

Full SARIF includes timestamps, version metadata, and provenance
fields that drift across machines and runs even when the analysis
output is byte-identical. The projection drops these so the diff
gate fails only on real semantic change.
