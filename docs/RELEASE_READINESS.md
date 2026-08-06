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

Validated on 2026-08-05 (dated measurements below retain their run date):

- `cargo clippy --workspace --all-targets --locked -- -D warnings` passed;
  this strict gate compiled the complete workspace and every test target.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
  --document-private-items --locked` passed.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- The last complete `cargo test --workspace --locked` baseline passed across
  all crates, integration binaries, adapter suites, and doc tests. The final
  architecture/lifecycle changes were then revalidated through their complete
  release suites listed below.
- Behavioral suites passed for callgraph, resolver, IDG, taint, security, SDK/CLI
  parity, the 1,076-case per-language CLI matrix, the 121-case end-to-end taint
  engine suite, conformance architecture invariants, and the exhaustive
  rule-example collision validator.
- The August compiler-guard regression set is pinned at the fact boundary:
  Java constructor locals keep lexical scope, declared receiver types do not
  collapse fluent call receivers, nested receiver-call arguments retain their
  inputs, Go composite literals retain qualified receiver types, Python finite
  literal-map membership is scope/mutation checked, exact configured character
  substitutions require complete mappings, and URL rebuild guards prove scheme,
  host allowlist, path, and redirect options from typed IR.
- The 1,441-case taint matrix now enforces positive and negative contracts for
  every supported language. Valid-source conformance rejects parser/adapter
  diagnostics, malformed-source conformance requires an explicit incomplete
  parser scope, and the capability matrix fails on every unexplained
  `Missing` cell.
- Focused regressions passed for generation-scoped IDG pipeline-hash reuse,
  fixed-width symbolic fact/transform paging, external-run merge boundaries,
  every symbolic transform algebra variant, incomplete target-relevance
  fallback, C++ direct/base-constructor initialization lowered from the
  Tree-sitter AST, Ruby template instance-variable inputs, and Swift computed
  getter receiver state across constructor/inheritance hops. The IDG suite
  also pins parameter-less receiver-root mapping and finite composition of a
  resolved receiver place plus selector demand.
- `security sanitizers` inventories only credit-bearing sanitizer matches.
  Rulepack-compatible passthrough transfers and generic non-crediting
  validation markers remain available to taint propagation but cannot be
  mislabeled by that command surface.
- Layering, public-API, hardcoded-knowledge, adapter-capability, and adapter
  `FlowEvent` snapshot audits passed. The hardcoded-knowledge audit excludes
  test fixtures and classifies production literals by ownership: grammar
  syntax in adapters, API/security identities in rule data, and only typed
  IR/protocol/product constants in shared crates. This gate is zero-tolerance:
  it has no baseline that can normalize an existing violation.

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
| Rules | 7,159 |
| Enabled rules | 5,996 |
| Disabled rules | 1,163 |
| Match examples | 10,523 |
| Enabled match examples | 10,088 |
| Taint-replay misses | 0 |
| Errors | 0 |
| Warnings | 0 |

On this macOS validation host, `syspolicyd` can delay the launch of newly
linked Cargo test executables. That host-level launch latency is not analyzer
runtime. Release-profile affected-crate suites are the final-change gate on
this host; CI still runs the complete workspace command.

## Self-analysis

The release binary's production security scan of this repository completed
with:

- `analysis_complete: true` and no incomplete reasons.
- 0 findings at the production profile's severity threshold.
- 1.90 seconds wall time from an empty workspace cache.
- 682,590,208 bytes maximum resident memory (about 651.0 MiB).
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

On the local Elasticsearch checkout, `tree --max-depth 3` completed
in 0.09 seconds with 9,895,936 bytes maximum RSS. An intentional uncapped
`tree --all` covered 43,108 files and 13,350 directories in 0.96
seconds with 35,110,912 bytes maximum RSS.

## Elasticsearch scale result

The current release pipeline is measured against the sibling 30,055-source
Elasticsearch checkout. The final 2026-08-05 ABI-v61 exact large-workspace
integration gate passed 5/5 in 222.95 seconds under a 3 GiB scheduling budget.
It starts fresh
processes and covers fresh-cache taint planning, warm semantic reuse, nine
navigation commands, targeted inspect with taint evidence, security inventory,
and production taint. Its enforced ceilings are 15 seconds for warm semantic
reuse and 30 seconds for each measured query/analysis command.

The cached generation validation/open phase completed in 5.57 seconds and the
immediate fresh-process warm reuse completed in 2.58 seconds. Default inspect
completed in 10.77 seconds. The broad exact
`inspect execute --taint-flow` regression query completed in 29.68 seconds and
reported 3,895 declaration hits, 26,047 other syntax hits, 198,718 unique raw
taint flows, and 12,233/12,233 scoped-IDG entry closures. A matching timed run
used 3,420,733,440 bytes maximum RSS, a 2,775,017,280-byte peak physical
footprint, and zero swaps. The scheduler charges the measured non-reclaimable
linkage/output reserve plus 128 MiB per sparse rooted closure; it does not treat
clean file-backed factstore pages as committed transient memory. Subject to
CPU availability, 3 GiB permits up to ten workers, 2 GiB up to two, and 1 GiB
one worker. Concurrency changes only scheduling, never entries, targets,
closure, or output.

The same current generation was also built once from an empty semantic cache.
That explicit, opt-in `index --semantic` compiler prewarm completed in
1,727.39 seconds (28m47s). The compiler-object worker remained near 1.0 GiB
RSS, exited before IDG replay began, and the IDG worker remained below the
3 GiB scheduling budget. Normal commands do
not force that whole-workspace prewarm: fresh-cache production taint completed
in 30.83 seconds, warm production taint in 26.70 seconds, and exact syntax
commands hydrate only the product they request. The long explicit prewarm is
recorded honestly because it remains a bulk cache-publication operation, not
an interactive-command latency claim.

Raw-flow pagination is presentation-only and remains exhaustive. Each closure
worker records a conservative row-size estimate while the row is hot; the
renderer then plans page boundaries without serializing or rescanning all
198,718 paths. It formats and caches only the requested raw-taint page instead
of eagerly rendering future pages. Page/cursor navigation still addresses the
complete deterministic unit stream.

The IDG query accelerator's dense compiler header is a fixed-width,
little-endian representation with checked row counts and exact byte-length,
ownership, boundary, and identity validation. It does not deserialize the
15-million-node core through a generic object codec. Inspect occurrence
collection uses an exact hash identity set, so a broad query is linear in
surviving compiler hits instead of comparing every hit with every prior row.
Both properties are covered by the exact Elasticsearch gate; neither changes
the admitted syntax facts, graph, closure, or rendered paging contract.

Symbolic projection admission is likewise compiler-driven. Exact projected
fact keys and typed whole-aggregate consumer markers are persisted in the
runtime accelerator. Backwards demand uses lazy sparse/spill sets and admits a
wildcard base only for an AST-proven aggregate consumer; generic reads and
callee-name matching cannot manufacture field flow. Regression tests pin
scalar-to-receiver mapping, sibling-field isolation, clean output-argument
overwrites, Java record accessors, and C# expression-bodied properties.

The final gate measured source inventory at 3.57 seconds, the exhaustive
high-severity sink inventory at 22.25 seconds, credit-bearing sanitizer
inventory at 17.16 seconds, and dependency inventory at 11.02 seconds. These
are syntax/compiler and rulepack facts, not Elasticsearch-specific name lists.

Production security in the integration gate reports
`analysis_complete: true`. The result is not capped: `--all` changes output
pagination only, while sparse IDG closure runs to a fixed point regardless of
rendering flags. Earlier cold timings in the thousands of seconds and broad
query timings above 150 seconds describe superseded architectures that
reparsed bodies or rebuilt workspace graphs; they are retained only in
historical goal documents.

The same multi-file compiler flow was also run with 512 MiB and 3,072 MiB
scheduling budgets. Both runs completed with no incomplete reasons and
byte-identical JSON (SHA-256
`d2ac3c461569283b10855eff4bfda012a9be03c7480c2f09003703801ee8fc02`).
Memory settings may serialize workers, evict exact bodies, or spill relation
pages; they do not change admitted files, facts, fixed-point scope, or results.

### Native export under a 2 GiB compiler scheduling budget

The unfiltered whole-checkout native export was measured on 2026-07-29 with
the exact compressed call relation that is now the only native-export chain
mode:

```bash
BONSAI_MEMORY_BUDGET_MB=2048 MIMALLOC_PURGE_DELAY=0 \
BONSAI_DEBUG=idg-summary,export-phase \
  ./target/release/bonsai-ninja export ../elasticsearch \
  --format json \
  --output-path /tmp/bonsai-es-export.json \
  --no-color \
  --no-progress
```

| Measure | Result |
|---|---:|
| Compiler functions summarized | 359,716 |
| Symbolic-sensitive functions | 128,890 |
| Contextual summary edges | 878,631 |
| Parsed call facts | 3,495,591 |
| Proven structural call records | 3,163,799 |
| Numeric summary/runtime ready | 114.09 s |
| Total wall time | 344.50 s |
| JSON bytes | 5,715,406,923 |
| Peak physical footprint | 4,435,817,024 bytes |
| macOS maximum RSS | 5,085,003,776 bytes |
| Sampled dirty resident memory | about 2.4 GiB |
| Swaps reported by `/usr/bin/time` | 0 |
| Streaming JSON validation | passed |
| SHA-256 | `6df0c041d9b1abc19ecf208604ff2c0d8afcfa44515f1ef4c19d7921acf1a51e` |

This is a 5.7 GB artifact produced at about 16.6 MB/s, not interactive query
latency. The exact symbolic/contextual fixed point consumed 114.09 seconds and
JSON/phase streaming consumed the remainder. Native export never enumerates
simple paths: the resolved callgraph is the exact linear-space
representation, and the capped prefix mode and its CLI/SDK switch no longer
exist. One-shot export writes directly to the requested sink and never builds
then copies a hidden multi-gigabyte cache. Only the explicit
`cache rebuild --export` workflow publishes a reusable export cache.

`BONSAI_MEMORY_BUDGET_MB` is a compiler scheduling/spill budget, not an OS
hard-RSS promise. The measured dirty working set was about 2.4 GiB; the larger
macOS footprint/RSS includes clean memory-mapped compiler/factstore pages and
allocator arenas that the OS may reclaim under pressure. A smaller machine
can therefore trade paging and recomputation for time without losing facts,
but exact export still needs storage for the output artifact and its live
compiler relation. The regression contract is semantic identity plus
phase-bounded residency, not a misleading claim that the operating system can
be forced below the selected scheduler value.

The default artifact intentionally omits concrete per-entry propagation rows
and reports that omission. `--all` retains the complete propagation language
in canonical `compiled_idg` form; `--full-propagations` materializes the much
larger per-entry row product only when a downstream consumer explicitly needs
it. Unfiltered workspace incompleteness remains an evidence boundary rather
than resource saturation: dynamic calls, receiver-type gaps, and unresolved
external implementations cannot be presented as resolved compiler facts.

## External benchmark snapshot

The final 2026-08-05 ABI-v61 CVEBench-SAST artifact used isolated copies of
every vulnerable and fixed repository, disabled analyzer caches between cases,
and requested uncapped SARIF. All 460 scans exited successfully in 208.4
seconds with no incomplete analysis: per-scan latency was 0.456 seconds mean,
0.571 seconds p95, and 0.705 seconds maximum. Its verified report records
229/230 primary detections, 100% sanitizer recognition, 0 duplicate findings,
92.71% precision, 100% precision excluding off-chain findings, 100% fix
validation, zero decoy trips, zero false positives per kLOC, 100% cross-file
and hard-case recall, and a 4.9565 mean score.

The sole empty vulnerable scan is the documented `XSSFWorkbook` case: the
benchmark labels normal spreadsheet construction as an XXE sink even though
that API does not parse attacker-controlled XML. Bonsai intentionally does not
add a false sink to make that invalid case pass. The TypeScript
`fast-xml-parser` case is reported as its actual configuration hazard
(entity-expansion denial of service, CWE-776); the rule does not falsely claim
that this library resolves external `SYSTEM` entities.

The artifact records 11 decoy trips, all copies of one shared Flask
`/raw` route. That route passes attacker-controlled JSON to SQL whenever
`APP_ENV=dev-internal`; a production deployment file currently selects a
different environment, but the source route remains registered and reachable
under a supported runtime configuration. Suppressing it would make compiler
flow depend on one deployment snapshot and hide a real configuration-dependent
attack path, so the engine reports it. This is an intentional soundness choice,
not a benchmark-specific exception. The benchmark also scores Python
`os.path.join` as the planted path-traversal sink even when Bonsai reports the
downstream `FileResponse` emission sink; that location mismatch does not change
the detected source-to-filesystem flow.

Benchmark metrics are evidence about the checked corpus, not a substitute for
the 21-language adapter/rule conformance gates. Dataset corrections must be
versioned and rescored separately; they must never be encoded as shared-engine
API guesses.

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
  --document-private-items --release --locked

cargo build --release -p bonsai_cli --locked

./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress

cargo test -p bonsai_conformance --test architecture_invariants
cargo test -p bonsai_security --test rulepack_conformance
python3 scripts/sanitizer_credit_audit.py
python3 scripts/sync_skill.py --check
scripts/audit-layering.sh
scripts/audit-hardcoded.sh --check
scripts/audit-public-api.sh --check
scripts/audit-adapter-capabilities.sh --check
scripts/audit-adapter-flow-events.sh --check

cargo test --release -p bonsai_cli --test elasticsearch_large_repo -- \
  --nocapture
```

Run the Elasticsearch and external benchmark gates when engine, resolver,
adapter, security, cache, or export semantics change. Documentation-only
changes still run the documentation, link, formatting, and rustdoc checks.
