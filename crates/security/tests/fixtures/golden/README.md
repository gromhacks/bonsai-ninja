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

The default finding payload is deterministic. The projection deliberately
pins the GitHub Code Scanning contract—rule id, message, level, kind, and
fingerprints—while allowing optional tool metadata and provenance fields to
evolve without turning every such addition into a large fixture rewrite.
Dedicated determinism tests cover repeated full analysis and export output.
