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

Validated on 2026-07-27:

- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed;
  this strict gate compiled the complete workspace and every test target.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --release --locked` passed.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- `cargo test --workspace --locked` passed in one exhaustive invocation
  across all crates, integration binaries, adapter suites, and doc tests.
- Behavioral suites passed for callgraph, resolver, IDG, taint, security, SDK/CLI
  parity, the 1,076-case per-language CLI matrix, the 121-case end-to-end taint
  engine suite, conformance architecture invariants, and the exhaustive
  rule-example collision validator.
- The 1,441-case taint matrix now enforces positive and negative contracts for
  every supported language. Valid-source conformance rejects parser/adapter
  diagnostics, malformed-source conformance requires an explicit incomplete
  parser scope, and the capability matrix fails on every unexplained
  `Missing` cell.
- Focused regressions passed for generation-scoped IDG pipeline-hash reuse,
  fixed-width symbolic fact/transform paging, external-run merge boundaries,
  and every symbolic transform algebra variant.
- Layering, public-API, hardcoded-knowledge, adapter-capability, and adapter
  `FlowEvent` snapshot audits passed. All 21 adapters explicitly declare the
  compiler capability fields consumed by shared analysis; the reviewed
  hardcoded-knowledge baseline contains 187 non-adapter hits.

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
| Rules | 7,152 |
| Enabled rules | 5,999 |
| Disabled rules | 1,153 |
| Match examples | 10,499 |
| Enabled match examples | 10,084 |
| Taint-replay misses | 0 |
| Errors | 0 |
| Warnings | 0 |

On this macOS validation host, `syspolicyd` can delay the launch of newly
linked Cargo test executables. That host-level launch latency is not analyzer
runtime; the final release suite nevertheless completed in one uninterrupted
workspace invocation.

## Self-analysis

The release binary's production security scan of this repository completed
with:

- `analysis_complete: true` and no incomplete reasons.
- 0 findings at the production profile's severity threshold.
- 41.58 seconds wall time.
- 441,139,200 bytes maximum resident memory (about 420.7 MiB).
- 0 swaps under `BONSAI_MEMORY_BUDGET_MB=3072`.

This is a correctness smoke, not a claim that an empty finding set proves the
absence of all defects. It proves that the current workspace parses, resolves,
and completes the requested production analysis without hidden truncation.

## Structural tree command

`tree` is a filesystem-only navigation command. It never opens the compiler,
builds semantic graphs, loads a rulepack, or runs security analysis.
Scanner-owned `.bonsai`, `.bonsai-agent`, and transient case-probe state are
excluded from the structural view.

The release binary rendered `examples/python/mega_flow` as 8 files and one
directory in 0.02 seconds with 9,273,344 bytes maximum RSS. The output contains
neither a synthetic `0 findings` claim nor a severity footer. `--all` lifts
presentation caps without enabling semantic work.

On the local Elasticsearch checkout, `tree --max-depth 3 --compact` completed
in 0.09 seconds with 9,895,936 bytes maximum RSS. An intentional uncapped
`tree --all --compact` covered 43,108 files and 13,350 directories in 0.96
seconds with 35,110,912 bytes maximum RSS.

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

The 2026-07-26 run completed successfully under
`BONSAI_MEMORY_BUDGET_MB=3072`:

| Measure | Result |
|---|---:|
| Indexed source files | 30,055 |
| First-party files | 28,462 |
| Dependency files | 104 |
| Generated files | 1,068 |
| Excluded files | 421 |
| Source rule matches | 356 |
| Sink rule matches | 1,515 |
| Sanitizer rule matches | 47 |
| Findings at production threshold | 0 |
| `analysis_complete` | `true` |
| Incomplete reasons | 0 |
| Wall time | 169.71 s |
| Maximum RSS | 1,665,384,448 bytes (about 1.55 GiB) |
| Swaps | 0 |

The result is not capped. `--all` removes output paging, while the semantic
IDG closure itself is uncapped regardless of rendering flags. The streamed IDG
sidecar has no source-file-count ceiling. Exact compressed export is used for
potentially quadratic derived path families; `--full-propagations` is the
explicit opt-in when a consumer requires every propagation record
materialized.

The same multi-file Python compiler flow was also run with 512 MiB and
3,072 MiB scheduling budgets. Both runs completed with no incomplete reasons
and byte-identical JSON (SHA-256
`d2ac3c461569283b10855eff4bfda012a9be03c7480c2f09003703801ee8fc02`).
This is a direct regression check that a smaller budget changes concurrency,
cache retention, and spill frequency only—not analyzed syntax or semantic
results.

Earlier notes reported parser diagnostics and
`analysis_complete: false` on this checkout. That was a real frontend/adapter
completeness signal, not harmless noise: any parser or semantic diagnostic
that prevents required facts must remain visible as an incomplete reason.
The current measured production scan reports `analysis_complete: true` with
an empty reason list, so that older caveat no longer describes the current
binary.

The exact large-workspace integration suite also passed 4/4 under the same
3 GiB budget. It covers production security, inspect with taint evidence,
nine navigation commands, and security inventories. Its completely cold
semantic-sidecar run took 5,377.36 seconds. That is honest first-build latency,
not bounded or omitted work: the one-heavy-unit scheduler stayed below the
budget and built the requested Tree-sitter/compiler facts exactly. Use
`index --semantic` or keep `index --watch` running when repeated interactive
queries need those sidecars warm.

### Targeted inspect under a 3 GiB compiler budget

The cold exact query
`inspect ../elasticsearch --query execute --taint-flow` completed in
278.25 seconds with maximum RSS 3,101,949,952 bytes (about 2.89 GiB), zero
swaps, 3,182 declaration hits, 200 rendered occurrence hits, and 100 rendered
taint flows. Its output was byte-identical across the compared exact runs.
The hit/flow counts are presentation windows; the semantic analysis itself was
not capped.

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

## External benchmark snapshot

The 2026-07-25 CVEBench-SAST run used isolated temporary copies of every
vulnerable and fixed repository and did not mutate the benchmark checkout.
All 460 scans completed with zero failures, timeouts, or incomplete scans:
191.2 seconds total, 0.415 seconds mean, 0.849 seconds p95, and 1.083 seconds
maximum.

The benchmark's published aggregation reports:

- Detection recall: 99.6%.
- Precision: 84.5% (99.6% under its off-chain-noise exclusion).
- File/line localization: 99.6%.
- Source / sink / flow evidence: 99.1% / 99.6% / 99.1%.
- Decoy trip rate: 0.1%.
- Fix-validation rate: 30.4%.

The underlying artifact audit is stronger and also exposes dataset defects.
Every one of the 230 primary source-to-sink flows was found. The sole apparent
primary miss is an internally contradictory case whose planted sink is also
listed as a safe decoy. Of the fixed snapshots, 141 are source-identical to
their vulnerable snapshot and 19 more differ only by a missing `go.sum`; all
70 snapshots with an actual source change are clean. The benchmark also labels
safe allowlisted SQL, quoted shell arguments, strict numeric validation,
defused/hardened XML parsing, SSRF private-IP guards, and even non-sink lines
as secondary bugs. Those labels are not a reason to weaken compiler evidence
or deliberately add false positives.

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
