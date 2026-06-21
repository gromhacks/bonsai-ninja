# Release readiness

Current local deployment snapshot for `main`.

## Status

The repository is deployment-ready from a build, validation, command
surface, and large-repo behavior standpoint. The security benchmark
profile is much stronger on recall and precision than the earlier
baseline. Aggregate fixed-snapshot validation remains low because many
benchmark "fixed" snapshots are unchanged or metadata-only; actual
code-changed fixed snapshots are clean in the latest local run.

## Latest local validation

Validated on 2026-06-20 with the release binary:

- `cargo build --release` passed.
- `cargo fmt --all --check` passed.
- `git diff --check` passed.
- `./target/release/bonsai-ninja security . pack --validate --taint-replay --rules-dir security-patterns --format json --no-color --no-progress` passed with 0 warnings.
- `./target/release/bonsai-ninja security . pack --audit --context 16k --no-color --no-progress` reported no unexplained canonical sink-family gaps across the app/web taxonomy languages. Solidity is explicitly marked as a smart-contract taxonomy language, not an app/web parity row.
- `cargo test -q -p bonsai_security --test rulepack_conformance` passed.
- `cargo test -q -p bonsai_security --test sanitizer_credit_audit` passed.
- `cargo test -q -p bonsai_security --test per_lang_gap_coverage` passed.
- `cargo test -q -p bonsai_security --test matcher_batch` passed.
- `cargo test -q -p bonsai_db` passed.

Focused engine/tool checks from the same pass were green:

- `cargo test -q -p bonsai_cli --test inspect_output`
- `cargo test -q -p bonsai_cli --test command_coverage`
- `cargo test -q -p bonsai_taint --test inspect_target_graph`
- `cargo test -q -p bonsai_security --test callback_flow_audit`

## Large-repo behavior

Elasticsearch spot checks on 2026-06-20 with the release binary:

- `security ../elasticsearch taint-analysis --profile production --format json`
  completed in 39.52 seconds with 2.96 GB max RSS.
- `security ../elasticsearch sources --rule java.source.spring_request_param --format json`
  completed in 3.06 seconds with 120.6 MB max RSS and complete pagination
  metadata.
- `inspect ../elasticsearch --query execute --context 8k` completed in
  16.51 seconds and skipped the default taint overlay with an explicit
  large-broad-query warning.
- `inspect ../elasticsearch --query execute --taint-flow --context 8k`
  completed in 28.51 seconds and reported bounded taint-flow truncation
  metadata.

## Benchmark snapshot

Latest CVE-Bench tier-4 run:

- Tag: `bonsai-ninja-2026-06-20-precision-184418`
- Report: `/home/builder/Documents/augment-projects/CVEBench-SAST/runs/bonsai-ninja-2026-06-20-precision-184418/report.json`
- Detection recall: 99.13%
- Bug recall: 75.61%
- Precision: 80.57%
- Fix-validation rate: 30.43%
- False positives per KLOC: 1.60
- Actual code-changed fixed snapshots: 70/70 clean.

The CVE wrapper sanity checks were clean: 230 vulnerable SARIF files, 230
fixed SARIF files, 0 malformed JSON files, 0 empty vulnerable-result
SARIFs, and no `error`, `exception`, `traceback`, `panic`, invalid JSON,
or empty-SARIF fallback text in `scan_all.log`.

Latest OWASP Benchmark v1.2 Java run:

- SARIF: `/home/builder/Documents/augment-projects/CVEBench-SAST/runs/bonsai-ninja-2026-06-20-precision-184708-owasp/owasp.sarif.json`
- Scorecard: `/home/builder/Documents/augment-projects/owasp-benchmark/scorecard/Benchmark_v1.2_Scorecard_for_bonsai-ninja_vprecision184708.html`
- Overall score: 54.04
- LDAP TPR/FPR: 66.67% / 0.00%
- XPath TPR/FPR: 66.67% / 10.00%
- SQLi TPR/FPR: 44.12% / 2.16%

The official Maven scorecard run completed, but the local `results/`
directory contains multiple historical bonsai SARIF files with the same
generated tool/version name. That makes the generated HTML filename
ambiguous because old scorecards overwrite each other. Use the direct
category-aware scorer above, or isolate the unique SARIF in a temporary
results directory before producing a publication-grade HTML scorecard.

## Known gap

The remaining aggregate CVE fixed-snapshot gap is benchmark-data-shaped:
160 "fixed" snapshots in the latest run are unchanged or metadata-only
relative to their vulnerable version and still contain the vulnerable
code shape. Do not suppress those just to raise aggregate
fix-validation. Future sanitizer/rule precision work should stay
evidence-driven: only credit a sanitizer when it is path-ordered before
the sink and tied to the tainted value.

## Pre-release gate

Before cutting a deployable artifact from this checkout, rerun:

```bash
cargo fmt --all --check
git diff --check
cargo build --release
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress
cargo test -q -p bonsai_cli --test command_coverage
cargo test -q -p bonsai_security --test rulepack_conformance
cargo test -q -p bonsai_security --test sanitizer_credit_audit
```

Run CVE-Bench and OWASP only when the release owner explicitly wants the
long benchmark gate refreshed.
