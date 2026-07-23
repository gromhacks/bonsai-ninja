# Release readiness

Current local deployment snapshot for `main`. This is the repository's
single source of truth for current validation and scale measurements; older
goal and benchmark documents are historical records.

## Status

The current local `main` has been validated across compilation, lint, rustdoc,
behavioral suites, architecture invariants, rulepack replay, self-analysis, a
complete Elasticsearch production scan, and a memory-bounded native export.
The measurements below identify the exact command and whether the selected
analysis scope was complete.

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

Validated on 2026-07-23:

- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed;
  this strict gate compiled the complete workspace and every test target.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked` passed.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- Release suites passed for callgraph (81/81), resolver (37/37), IDG (322
  unit plus 5 integration), taint (all binaries, including the 1,440-case
  language contract matrix), security (all binaries), and conformance (all
  binaries, including 68/68 architecture invariants).
- Focused regressions passed for generation-scoped IDG pipeline-hash reuse,
  fixed-width symbolic fact/transform paging, external-run merge boundaries,
  and every symbolic transform algebra variant.
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

### Native export under a 3 GiB compiler budget

The unfiltered whole-checkout native export was measured on 2026-07-23 with:

```bash
BONSAI_MEMORY_BUDGET_MB=3072 MIMALLOC_PURGE_DELAY=0 \
  ./target/release/bonsai-ninja export ../elasticsearch \
  --all \
  --format json \
  --output-path /tmp/bonsai-es-export.json \
  --no-color \
  --no-progress
```

| Measure | Result |
|---|---:|
| Compiler functions summarized | 359,716 |
| Symbolic-sensitive functions | 129,082 |
| Contextual summary edges | 877,014 |
| Parsed call facts | 3,495,591 |
| Proven structural call records | 3,163,650 |
| Numeric summary/runtime ready | 127.68 s |
| Total wall time | 386.94 s |
| JSON bytes | 5,683,867,076 |
| Peak physical footprint | 3,088,476,608 bytes (about 2.88 GiB) |
| macOS maximum RSS | 4,249,305,088 bytes |
| Swaps | 0 |
| Streaming JSON validation | passed (`jq --stream`) |
| `analysis_complete` | `false` |

The export finished without a file, edge, closure, call-depth, iteration, or
elapsed-time cap. `--all` kept propagation in complete canonical `compiled_idg`
form; it did not materialize the much larger per-entry transitive row product.
Its incomplete status is an evidence boundary, not resource saturation: the
unfiltered checkout reports `dynamic-call-sites:903`,
`receiver-type-gaps:558627`, and `unresolved-call-sites:1276805`. Those calls
cannot be presented as resolved compiler facts when their implementation/type
evidence is absent or dynamic. The production security profile above is a
different, explicitly filtered first-party scope and remains complete.

The export streams top-level JSON sections and uses exact compressed graph
representations for potentially quadratic path families. Fixed-width symbolic
fact/transform pages and bounded external sort runs keep the semantic relation
on disk while source-index offsets remain resident. A smaller cache can add
I/O and wall time; it does not remove facts. The final measured binary includes
generation-scoped pipeline-hash reuse for the IDG unload/reload boundary.

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
