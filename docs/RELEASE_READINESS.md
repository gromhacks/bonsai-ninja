# Release readiness

Current local deployment snapshot for `main`. This is the repository's
single source of truth for current validation and scale measurements; older
goal and benchmark documents are historical records.

## Status

The production-code baseline `b341cb5` is green across compilation, lint,
rustdoc, focused behavioral suites, architecture invariants, rulepack replay,
self-analysis, and a complete Elasticsearch production scan. The documentation
update recorded here does not change engine semantics.

The analyzer is one compiler-style pipeline:

- 21 Tree-sitter adapters own source syntax and lower it into typed compiler
  facts.
- Resolver, callgraph, IDG, security, SDK, and export consume those facts
  without shared language-name dispatch or cross-language token inventories.
- Production taint reachability is a sparse monotone IDG fixed point with no
  BFS name search, call-depth ceiling, iteration limit, or result cap.
- Paging and diagnostic path previews can be bounded, but they report
  truncation and never change the semantic result.

## Current validation

Validated on 2026-07-20:

- `cargo check --workspace --all-targets --locked` passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked` passed.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- Focused compiler/engine suites passed 641 tests:
  callgraph 76, IDG 304, resolver 37, taint 86, workspace 62,
  architecture invariants 62, and CLI page-cache 14.
- `cargo test -p bonsai_security --test rulepack_conformance` passed 28/28.
- Layering, public-API, hardcoded-knowledge, adapter-capability, and adapter
  `FlowEvent` snapshot audits passed. All 21 adapters explicitly declare the
  compiler capability fields consumed by shared analysis; the reviewed
  hardcoded-knowledge baseline contains 191 non-adapter hits.

The current deep rulepack gate is clean:

```bash
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress
```

| Measure | Result |
|---|---:|
| Rules | 7,148 |
| Enabled rules | 6,003 |
| Disabled rules | 1,145 |
| Match examples | 10,489 |
| Enabled match examples | 10,090 |
| Taint-replay misses | 0 |
| Errors | 0 |
| Warnings | 0 |

On this macOS validation host, `syspolicyd` can delay the launch of newly
linked Cargo test executables. That host-level launch latency is not analyzer
runtime and is why readiness is reported from all-target compilation plus the
focused warmed behavioral gates above, rather than claiming that every
workspace test executable was launched in one uninterrupted command.

## Self-analysis

The release binary's production security scan of this repository completed
with:

- `analysis_complete: true` and no incomplete reasons.
- 0 findings at the production profile's severity threshold.
- 4.34–4.96 seconds wall time across repeated measurements.
- Approximately 296 MiB maximum resident memory in the measured run.

This is a correctness smoke, not a claim that an empty finding set proves the
absence of all defects. It proves that the current workspace parses, resolves,
and completes the requested production analysis without hidden truncation.

## Elasticsearch scale result

The current release binary was measured against the sibling Elasticsearch
checkout with:

```bash
./target/release/bonsai-ninja security ../elasticsearch taint-analysis \
  --profile production \
  --format json \
  --all \
  --no-color \
  --no-progress
```

The 2026-07-20 run completed successfully:

| Measure | Result |
|---|---:|
| Indexed source files | 30,055 |
| First-party files | 28,462 |
| Dependency files | 104 |
| Generated files | 1,068 |
| Excluded files | 421 |
| Source rule matches | 356 |
| Sink rule matches | 1,507 |
| Sanitizer rule matches | 47 |
| Findings at production threshold | 0 |
| `analysis_complete` | `true` |
| Incomplete reasons | 0 |
| Wall time | 57.98 s |
| Maximum RSS | 2,505,703,424 bytes (about 2.33 GiB) |
| Swaps | 0 |

The result is not capped. `--all` removes output paging, while the semantic
IDG closure itself is uncapped regardless of rendering flags. The streamed IDG
sidecar has no source-file-count ceiling. Exact compressed export is used for
potentially quadratic derived path families; `--full-propagations` is the
explicit opt-in when a consumer requires every propagation record
materialized.

Earlier notes reported parser diagnostics and
`analysis_complete: false` on this checkout. That was a real frontend/adapter
completeness signal, not harmless noise: any parser or semantic diagnostic
that prevents required facts must remain visible as an incomplete reason.
The current measured production scan reports `analysis_complete: true` with
an empty reason list, so that older caveat no longer describes the current
binary.

## Historical external benchmark snapshot

The most recent recorded CVE-Bench tier-4 run predates the current engine
baseline:

- Tag: `bonsai-ninja-2026-06-20-precision-184418`
- Detection recall: 99.13%
- Bug recall: 75.61%
- Precision: 80.57%
- Fix-validation rate: 30.43%
- False positives per KLOC: 1.60
- Code-changed fixed snapshots: 70/70 clean.

The wrapper produced 230 vulnerable and 230 fixed SARIF files with no
malformed JSON, empty vulnerable-result SARIF, panic, traceback, or fallback
text. The aggregate fixed-snapshot score remains benchmark-data-shaped: 160
"fixed" snapshots were unchanged or metadata-only relative to their
vulnerable version. Do not suppress real vulnerable code merely to improve
that aggregate.

The recorded OWASP Benchmark v1.2 Java snapshot had an overall score of
54.04, with LDAP TPR/FPR 66.67%/0.00%, XPath 66.67%/10.00%, and SQL injection
44.12%/2.16%. These numbers are historical evidence, not a current regression
gate. Refresh external benchmarks only from isolated, reproducible artifacts
and record a new dated snapshot here.

## Pre-release gate

Before cutting a deployable artifact, run:

```bash
cargo fmt --all -- --check
git diff --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps \
  --document-private-items --locked

./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress

cargo test -p bonsai_conformance --test architecture_invariants
cargo test -p bonsai_security --test rulepack_conformance
scripts/audit-layering.sh
scripts/audit-hardcoded.sh --check
scripts/audit-public-api.sh --check
scripts/audit-adapter-capabilities.sh --check
scripts/audit-adapter-flow-events.sh --check
```

Run the Elasticsearch and external benchmark gates when engine, resolver,
adapter, security, cache, or export semantics change. Documentation-only
changes still run the documentation, link, formatting, and rustdoc checks.
