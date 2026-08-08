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

- 20 Tree-sitter adapters own source syntax and lower it into typed compiler
  facts.
- Resolver, callgraph, IDG, security, SDK, and export consume those facts
  without shared language-name dispatch or cross-language token inventories.
- Production taint reachability is a sparse monotone IDG fixed point with no
  BFS name search, call-depth ceiling, iteration limit, or result cap.
- Paging and diagnostic path previews can be bounded, but they report
  truncation and never change the semantic result.

## Current validation

Validated through 2026-08-08 (dated measurements below retain their run date):

- A direct release-binary audit exercised every documented root, browse,
  navigation, inspect, trace, slice, stable-ID, debug-dump, cache, export, and
  security command without a wrapper script. It also covered structural,
  semantic, watch, text, JSON, SARIF, HTML, GraphML, Cypher, NetworkX,
  baseline, summary, explain, pagination, and invalid-input behavior. The
  resulting contract fixes are pinned by tests: semantic index runs always
  return a cache summary; security text carries its `S:`/`F:`/`G:` identities;
  baseline JSON carries an aggregate diff; filtered totals remain truthful;
  invalid stable IDs and out-of-range pages fail closed; `--page next` reuses
  a validated eager page; selective cache clearing leaves a fresh manifest;
  and token estimates describe the same complete result on every page.
- The current candidate passed `cargo test --release -p bonsai_cli
  --all-targets -- --skip elasticsearch_` and the optimized SDK, security,
  taint, IDG, and conformance package matrix with zero failures. It also
  passed strict all-target release Clippy, private-item release rustdoc with
  warnings denied, formatting, diff hygiene, and direct deep rulepack replay
  of all 9,965 enabled examples from 7,053 rules with zero errors or warnings.

- The ABI-v64 release candidate passed `cargo check --release --workspace
  --all-targets --locked`, strict release all-target Clippy with warnings
  denied, and full release rustdoc with private items and warnings denied.
  `cargo test --release --workspace --all-targets` then executed the complete
  local workspace matrix with zero failures. That run includes the 1,029-case
  per-language CLI matrix, CLI/SDK parity, adapter and rulepack conformance,
  end-to-end taint suites, paging/completeness contracts, output formats, and
  the five-scenario Elasticsearch SLO gate. The standalone adapter `FlowEvent`
  audit also passed after compiling its locked debug harness from a cold cache.
- The release-binary command matrix passed 1,279 command/switch cases across
  all 20 languages. Rulepack validation replayed 9,965 enabled examples from
  7,053 rules with zero misses, errors, or warnings. Self-security completed
  with no incomplete reasons or production-threshold findings; SARIF 2.1.0,
  HTML, JSON, and NetworkX output smokes parsed successfully.
- A FastAPI `15410ee4bfd1` real-repository trial pinned and fixed four compiler
  contracts: compound expressions no longer become same-named callback
  references, Python receiver fields retain exact annotated types, a direct
  parameter-default call is a typed `param_default_calls` fact rather than a
  framework guess, and plain `read-file` opens one exact compiler object
  without constructing the workspace callgraph. `FastAPI.add_api_route` now
  resolves to `APIRouter.add_api_route` as one receiver-type-narrowed hop; the
  false callback edge is absent. The full 1,140-file production security scan
  completed in 1.40 seconds with zero findings and no `docs_src` leakage.
  Qualified `FastAPI.add_api_route` to `APIRouter.add_api_route` endpoint
  inspection now resolves every compiler identity and renders the exact
  connected corridor; resolver diagnostics report the same workspace-relative
  path spelling accepted by `--in-file`.

- Commit `bdd6125` removes the Solidity frontend, grammar dependency,
  fixtures, rulepack, package metadata, and documentation after the product
  decision to keep one application/code-analysis model. The shipped registry
  and release package now contain exactly the 20 adapters listed in
  [Language Support](language-support.mdx); no disabled Solidity path or
  orphaned smart-contract rules remain. The post-removal release build,
  1,386-case taint matrix, 33-case rulepack conformance suite, adapter metadata
  checks, and deep rulepack validation are green.

- The `d510043` baseline and the current ABI-v64 candidate passed `cargo
  clippy --workspace --all-targets --locked -- -D warnings`.
- The baseline and current candidate passed full-workspace release rustdoc
  with private items and warnings denied.
- `cargo fmt --all -- --check` and `git diff --check` passed.
- The final `cargo test --workspace --locked --no-fail-fast` pass completed
  across all crates, integration binaries, adapter suites, and doc tests at
  the `d510043` release-gate baseline. The final ABI-v62 delta then compiled
  every target under strict Clippy and reran its affected optimized adapter,
  IDG, security, callback, rulepack, architecture, and CLI suites.
- Behavioral suites passed for callgraph, resolver, IDG, taint, security, SDK/CLI
  parity, the 1,029-case per-language CLI matrix, the end-to-end taint engine
  suites, conformance architecture invariants, and the exhaustive
  rule-example collision validator.
- The August compiler-guard regression set is pinned at the fact boundary:
  Java constructor locals keep lexical scope, declared receiver types do not
  collapse fluent call receivers, nested receiver-call arguments retain their
  inputs, Go composite literals retain qualified receiver types, Python finite
  literal-map membership is scope/mutation checked, exact configured character
  substitutions require complete mappings, and URL rebuild guards prove scheme,
  host allowlist, path, and redirect options from typed IR.
- The 1,386-case taint matrix now enforces positive and negative contracts for
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
- Inline source callbacks are now pinned at the compiler-fact boundary. An
  adapter records parsed callback parameter bindings on the exact call
  argument; rule data selects the callback and delivered parameter positions;
  the IDG binds that source into the already-inlined body. Positive JavaScript
  and destructured TypeScript cases, a no-source negative, and the complete
  vulnerable/fixed CVEBench pair set pass without provider names in shared
  Rust.
- `security sanitizers` inventories only credit-bearing sanitizer matches.
  Rulepack-compatible passthrough transfers and generic non-crediting
  validation markers remain available to taint propagation but cannot be
  mislabeled by that command surface.
- Dart `Uri.http` and `Uri.https` constructors are audit-only rather than SSRF
  sinks: constructing a URI performs no network I/O. A live rulepack regression
  test requires both constructor shapes to remain finding-free until an actual
  network client consumes the value.
- Layering, public-API, hardcoded-knowledge, adapter-capability, and adapter
  `FlowEvent` behavioral audits passed. The hardcoded-knowledge audit excludes
  test fixtures and classifies production literals by ownership: grammar
  syntax in adapters, API/security identities in rule data, and only typed
  IR/protocol/product constants in shared crates, the SDK, and the CLI. This
  gate is zero-tolerance: it has no baseline that can normalize an existing
  violation.
- Corpus-independence and shared-production clone audits passed. Production
  Rust and rule YAML contain no benchmark case/snapshot identity or developer
  home path, and shared production crates contain no exact clone of 20 or more
  logical lines. Adapter-to-adapter similarities remain legal because each
  frontend owns its language semantics and can only be generalized after the
  shared contract is genuinely identical.
- The locked dependency graph passed unused-edge, advisory, source-integrity,
  and SPDX license-policy gates: every package declares a reviewed expression
  with at least one distributable license branch. Release archives are then
  executed from a relocated temporary working directory so security-rule
  discovery is proven against the packaged layout rather than the source tree.
- The release workflow's native CLI smoke was executed command-for-command on
  the current binary. `index` and `diagnostics` remain intentional text-only
  commands, while inspect/trace/export JSON, SARIF, and HTML outputs are parsed
  as their declared formats. Repository policy now rejects unsupported
  `--format`/`--all` combinations in that workflow, semantic gate timeouts, or
  omission of documentation and deep rulepack audits.

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
| Rules | 7,053 |
| Enabled rules | 5,913 |
| Disabled rules | 1,140 |
| Match examples | 10,403 |
| Enabled match examples | 9,965 |
| Taint-replay misses | 0 |
| Errors | 0 |
| Warnings | 0 |

On this macOS validation host, `syspolicyd` can delay the first launch of a
newly linked debug Cargo test executable by several minutes even when the test
itself runs in milliseconds. That host-level launch latency is not analyzer
runtime. The release-profile workspace/all-target suite avoids relying on that
distinction: it executed to completion locally, and CI repeats the complete
workspace command independently.

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
Elasticsearch checkout. The 2026-08-08 ABI-v64 exact warm-generation gate
passed 5/5 in 231.33 seconds under a 3 GiB scheduling budget. Semantic
generation readiness completed in 12.36 seconds and immediate fresh-process
reuse in 2.37 seconds. Fresh-cache production taint completed in 29.77
seconds, warm production taint in 28.34 seconds, default inspect in 7.09
seconds, and exact raw-taint inspect in 26.91 seconds. Navigation timings were
tree 0.03 seconds, search 4.10 seconds, definitions 15.31 seconds, imports
7.64 seconds, classes 8.40 seconds, entrypoints 24.26 seconds, calls 3.43
seconds, arguments 3.46 seconds, and scoped `read-file` 1.78 seconds. Source,
sink, sanitizer, and dependency inventories completed in 3.46, 24.54, 18.16,
and 9.83 seconds. Every enforced SLO passed; the gate completed exact work and
did not cap files, graph depth, closure, or results. This is the current
interactive-scale release reference.

The 2026-08-07 ABI-v64 exact cache-migration gate
passed 5/5 in 1,883.15 seconds under a 3 GiB scheduling budget. Its required
one-time compiler-object/IDG generation took 1,672.82 seconds after the ABI
change; immediate fresh-process reuse took 2.34 seconds. Fresh-cache
production taint completed in 29.89 seconds, default inspect in 7.38 seconds,
broad exact raw-taint inspect in 27.11 seconds, and warm production taint in
28.46 seconds. Navigation timings included tree 0.03 seconds, search 4.30
seconds, definitions 14.72 seconds, imports 6.74 seconds, classes 7.46
seconds, entrypoints 23.00 seconds, calls 3.25 seconds, arguments 3.29
seconds, and a scoped `read-file` in 1.31 seconds. Source, sink, sanitizer,
and dependency inventories took 4.34, 21.05, 15.65, and 9.95 seconds. Every
enforced SLO passed. The compiler worker remained near 0.9 GiB RSS while
rebuilding all exact objects and stayed within the 3 GiB scheduler budget.
ABI-v64 binds callgraph and compatibility flow sidecars to the compiler
frontend ABI, so adapter-fact changes cannot silently reuse an older derived
graph. This is the current cache-migration and release reference.

The prior 2026-08-07 ABI-v63 exact large-workspace gate
passed 5/5 in 1,945.09 seconds under a 3 GiB scheduling budget. Its required
one-time compiler-object/IDG generation took 1,720.68 seconds after the ABI
change; immediate fresh-process reuse took 2.34 seconds. Fresh-cache
production taint completed in 34.30 seconds, default inspect in 10.35 seconds,
broad exact raw-taint inspect in 29.69 seconds, and warm production taint in
29.85 seconds. Every enforced SLO passed. Navigation timings included search
4.07 seconds, definitions 13.03 seconds, imports 6.92 seconds, classes 7.21
seconds, entrypoints 24.04 seconds, calls 3.46 seconds, arguments 3.38 seconds,
and a scoped `read-file` in 1.62 seconds. Source, sink, sanitizer, and
dependency inventories took 4.15, 21.91, 17.34, and 10.68 seconds. The
compiler worker remained near 1 GiB RSS and the IDG phase remained within the
3 GiB scheduler budget.

The final ABI-v63 warm-generation repeat, after the shared parameter-fact
refinement, passed 5/5 in 220.51 seconds with the same limits. Semantic
generation validation/reuse took 5.11/2.34 seconds, default inspect 10.02
seconds, broad exact raw-taint inspect 28.53 seconds, fresh-cache production
taint 30.44 seconds, warm production taint 27.47 seconds, and scoped
`read-file` 1.33 seconds. The five benchmark scenarios share a test lock so
Rust's parallel harness cannot make one measured SLO depend on another
scenario; analyzer workers, exact scope, memory scheduling, and SLOs are
unchanged.

The final ABI-v63 2026-08-07 release-candidate repeat passed 5/5 in 217.85 seconds
under the same limits. Inspect's file-local compiler-object pass now uses the
shared source-size-weighted scheduler and applies owned facts in canonical path
order; measured Elasticsearch syntax hydration fell from about 5.2 seconds to
2.0 seconds without changing semantic work. Semantic generation
validation/reuse took 5.15/2.41 seconds, default inspect 7.05 seconds, broad
exact raw-taint inspect 25.71 seconds, fresh-cache production taint 31.59
seconds, warm production taint 27.00 seconds, and scoped `read-file` 1.54
seconds. Navigation and all four security inventories remained within their
30-second SLOs. This remains the pre-ABI-v64 warm-generation comparison.

The prior final 2026-08-06 ABI-v62 exact large-workspace
integration gate passed 5/5 in 1,760.06 seconds under a 3 GiB scheduling
budget, including the required one-time rebuild from the incompatible ABI-v61
compiler-object generation. It starts fresh
processes and covers fresh-cache taint planning, warm semantic reuse, nine
navigation commands, targeted inspect with taint evidence, security inventory,
and production taint. Its enforced ceilings are 15 seconds for warm semantic
reuse and 30 seconds for each measured query/analysis command.

The ABI-v62 generation rebuild completed in 1,541.88 seconds and the immediate
fresh-process warm reuse completed in 2.32 seconds. Default inspect completed
in 10.33 seconds. The broad exact
`inspect execute --taint-flow` regression query completed in 29.58 seconds and
reported 3,895 declaration hits, 26,047 other syntax hits, 198,718 unique raw
taint flows, and 12,233/12,233 scoped-IDG entry closures. A separate
ABI-v61 RSS-profiled run used 3,420,733,440 bytes maximum RSS, a
2,775,017,280-byte peak physical footprint, and zero swaps. The scheduler
charges the measured non-reclaimable
linkage/output reserve plus 128 MiB per sparse rooted closure; it does not treat
clean file-backed factstore pages as committed transient memory. Subject to
CPU availability, 3 GiB permits up to ten workers, 2 GiB up to two, and 1 GiB
one worker. Concurrency changes only scheduling, never entries, targets,
closure, or output.

The ABI-v62 run was a real cache migration: changing serialized callback facts
invalidated every ABI-v61 compiler object rather than silently reusing stale
data. The explicit `index --semantic` compiler worker remained near 0.9 GiB
RSS, exited before IDG replay began, and the IDG worker remained below the
3 GiB scheduling budget. Normal commands do
not force that whole-workspace prewarm: fresh-cache production taint completed
in 30.22 seconds against its 45-second cold SLO, warm production taint in
25.90 seconds, and exact syntax
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

The final gate measured source inventory at 3.85 seconds, the exhaustive
high-severity sink inventory at 22.63 seconds, credit-bearing sanitizer
inventory at 18.32 seconds, and dependency inventory at 10.42 seconds. These
are syntax/compiler and rulepack facts, not Elasticsearch-specific name lists.

Production security in the integration gate reports
`analysis_complete: true`. The result is not capped: `--all` changes output
pagination only, while sparse IDG closure runs to a fixed point regardless of
rendering flags. Earlier cold timings in the thousands of seconds and broad
query timings above 150 seconds describe superseded architectures that
reparsed bodies or rebuilt workspace graphs; they are retained only in
historical goal documents.

The 2026-08-07 final warm-generation release repeat passed the complete 5/5
gate in 234.09 seconds under the same 3 GiB schedule. Immediate semantic reuse
took 2.48 seconds, default inspect 10.02 seconds, exact broad raw-taint inspect
29.53 seconds, fresh-cache production taint 34.28 seconds, and warm production
taint 27.74 seconds. The broad query retained 12,233/12,233 entry closures and
198,025 unique pageable paths. Reusing callable declarations already selected
by the compiler pass and accepting direct AST/IDG target owners without a
second relevance proof changes only duplicate lookup work; the target-demand
relation and every forward fixed point remain unchanged.

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

The final 2026-08-06 ABI-v62 CVEBench-SAST artifact used isolated copies of
every vulnerable and fixed repository, disabled analyzer caches between cases,
and requested uncapped SARIF. All 460 scans exited successfully in 226.69
seconds with no incomplete analysis: vulnerable-scan latency was 0.496 seconds
mean, 0.621 seconds p95, and 0.745 seconds maximum. Its verified report records
229/230 primary detections, 99.13% file localization, 98.70% line localization,
100% sanitizer recognition, 0 duplicate findings, 92.71% precision, 100%
precision excluding off-chain findings, 100% fix validation, zero decoy trips,
zero false positives per kLOC, and a 4.9565 mean score. The ABI-v62 run restores
both TypeScript inline-callback regressions to full 5.0 source/sink/flow matches
while every fixed snapshot remains clean.

The sole empty vulnerable scan is the documented `XSSFWorkbook` case: the
benchmark labels normal spreadsheet construction as an XXE sink even though
that API does not parse attacker-controlled XML. Bonsai intentionally does not
add a false sink to make that invalid case pass. The TypeScript
`fast-xml-parser` case is reported as its actual configuration hazard
(entity-expansion denial of service, CWE-776); the rule does not falsely claim
that this library resolves external `SYSTEM` entities.

The benchmark scores Python `os.path.join` as the planted path-traversal sink
even when Bonsai reports the downstream `FileResponse` emission sink; that
location mismatch does not change the detected source-to-filesystem flow.

Benchmark metrics are evidence about the checked corpus, not a substitute for
the 20-language adapter/rule conformance gates. Dataset corrections must be
versioned and rescored separately; they must never be encoded as shared-engine
API guesses.

The recorded OWASP Benchmark v1.2 Java snapshot had an overall score of
54.04, with LDAP TPR/FPR 66.67%/0.00%, XPath 66.67%/10.00%, and SQL injection
44.12%/2.16%. These numbers are historical evidence, not a current regression
gate. Refresh external benchmarks only from isolated, reproducible artifacts
and record a new dated snapshot here.

## Pre-release gate

The tag workflow is the authoritative publish gate. A tag must be an ancestor
of `main`, use `v<workspace-semver>`, and pass the preflight job before any
platform build starts. Publishing waits for both all six native build/test
jobs and the pinned Elasticsearch scale job. The pinned Elasticsearch commit
is test input only: its names, paths, APIs, and benchmark cases are forbidden
from production Rust and rule data by `audit-corpus-independence.py`.

The gates cover distinct failure classes:

| Gate | What it prevents |
|---|---|
| Provenance and version | Releasing an arbitrary commit or a tag that disagrees with Cargo metadata |
| Format, compile, Clippy, rustdoc | Broken builds, warnings, malformed public documentation |
| Full workspace tests and release builds on six native targets | Cross-crate, adapter, platform, and binary integration regressions; optimized binaries are exercised by CLI, package, rulepack, and large-repository gates |
| Capability, `FlowEvent`, architecture, and taint matrices | Silent language gaps or a second syntax/flow implementation outside adapters |
| Hardcoded and corpus-independence audits | Shared language/API guesses and benchmark-specific tuning |
| Rule validation, collision audit, and taint replay | Invalid YAML, warnings, empty audit coverage, ambiguous ownership, or examples the engine cannot reproduce |
| Public API, layering, dependency, license, and clone audits | Accidental API drift, dependency cycles, stale dependencies, advisories, unreviewed licensing, and copy-paste architecture |
| Documentation consistency | Broken local links or headings, navigation/language-count drift, and examples that retain retired CLI flags |
| Self-security plus JSON/SARIF/HTML and relocated-package smokes | Incomplete self-analysis, broken consumer output contracts, silent rulepack loss, or an archive that only works from the source checkout |
| Exact Elasticsearch gate under 3 GiB | Cold/warm cache, navigation, inspect, security correctness, latency, or memory-scheduling regressions; release CI fails closed if its corpus or binary is unavailable |
| Checksums and immutable action pins | Corrupt release archives and mutable CI dependencies |

The compiler/rule boundary is a release invariant, not a style preference.
Adapters may contain Tree-sitter node kinds and source grammar for their own
language. Rulepack YAML may contain provider APIs, package identities,
taxonomy, trust, severity, configuration values, and sanitizer policy. Shared
analysis may contain only typed IR, generic fixed-point algorithms, persisted
protocol/schema constants, and product behavior. A new framework or project
must therefore be supportable by rule data and existing adapter facts; it must
not require adding its API names to the engine. The hardcoded-knowledge gate
derives provider-shaped callable identities and the supported-language
vocabulary from the current rulepack, so adding a framework or language also
expands the boundary audit automatically.

Before cutting a deployable artifact, run:

```bash
cargo fmt --all -- --check
git diff --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps \
  --document-private-items --release --locked

cargo build --release -p bonsai_cli --locked
cargo machete --with-metadata
cargo audit --deny warnings
python3 scripts/audit-dependency-licenses.py

./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress

cargo test --workspace --locked --no-fail-fast
cargo test --release --locked -p bonsai_conformance --test architecture_invariants
cargo test --release --locked -p bonsai_security --test rulepack_conformance
python3 scripts/sanitizer_credit_audit.py
python3 scripts/sync_skill.py --check
python3 scripts/audit-docs.py
scripts/audit-layering.sh
scripts/audit-hardcoded.sh --check /tmp/hardcoded-audit
python3 scripts/audit-corpus-independence.py
python3 scripts/audit-rust-duplication.py
scripts/audit-public-api.sh --check
scripts/audit-adapter-capabilities.sh --check
scripts/audit-adapter-flow-events.sh --check
scripts/audit-loop.sh

BONSAI_ELASTICSEARCH_ROOT=../elasticsearch \
BONSAI_REQUIRE_ELASTICSEARCH_GATE=1 \
BONSAI_MEMORY_BUDGET_MB=3072 \
  cargo test --release --locked -p bonsai_cli --test elasticsearch_large_repo -- \
  --nocapture
```

The release workflow always fetches the documented pinned Elasticsearch
snapshot and runs the exact gate. During development, run it whenever engine,
resolver, adapter, query, security, cache, or export semantics change. External
security benchmarks remain isolated evidence rather than release logic.
Documentation-only changes still run the documentation, link, formatting, and
rustdoc checks.
