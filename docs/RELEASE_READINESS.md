# Release readiness

This page is the single source of truth for the current local release
candidate. It records completed gates and their interpretation; user guides do
not duplicate dated performance history.

## Status

The v0.2.16 candidate incorporates the expanded compiler, adapter, rulepack,
CLI, cache, scheduling, and publication checks described below. Local status
is determined from a fresh run of the listed commands; historical measurements
are retained only where they document a reproducible scale baseline. A tag is
not published until the complete current workspace gate, release build,
relocated-binary smoke, exact large-workspace gate, and public metadata/privacy
audits all pass from the same committed tree.

The tag workflow remains authoritative for cross-platform packaging, parser
delivery, signed provenance, checksums, and crates.io publication. Its hosted
runner thresholds are calibrated from completed exact runs and never turn a
timeout, work cap, or unexpected compiler gap into a pass. Coverage assertions
also pin known unsupported dependency formats: those reports must retain
`analysis_complete: false` and their explicit reasons, not claim a complete
negative dependency result.

The product contains:

- 20 registered Tree-sitter language adapters;
- one adapter-lowered compiler IR and one production sparse IDG taint engine;
- 6,482 bundled rules, of which 6,482 are enabled;
- 11,919 enabled rule examples;
- native CLI, Rust SDK, SARIF 2.1.0, JSON, HTML, and graph-export surfaces.

## v0.2.16 local verification — 2026-09-06

All 47 workspace packages and the embedded rulepack marker use `0.2.16`.
Every internal dependency remains exactly pinned to that version; the lockfile
bump changes no third-party dependency. The 45 publishable crate names passed
the registry ownership audit, and none had a published `0.2.16` version at
preparation time. Conformance and testkit remain repository-only.

The release preparation passed:

| Gate | Result |
|---|---|
| Compact workspace correctness | 8,323 passed, 0 failed, 0 ignored across 372 test/doc-test targets; Elasticsearch cases run separately |
| Optimized Elasticsearch target | All 12 passed in 919.57 s; existing reference-host SLOs and 3 GiB scheduling budget unchanged |
| Command/switch matrix | 1,440 cases across all 20 languages; all passed |
| Live rulepack replay | All 11,919 enabled examples passed; 0 errors and 0 warnings |
| Rust checks | Formatting, strict all-target Clippy, private-item rustdoc, and adapter FlowEvent checks passed |
| Release scripts | All 40 Python tests passed, including tar/zip README assets and registry link resolution |
| Publication inputs | All 45 Cargo source inventories passed; local archive includes docs, skills, schemas, rule sources, and the README GIF |
| Runtime packaging | Binary-only relocation with an empty parser cache retained the expected critical Python flow; SARIF and HTML smoke passed |
| Self-security | Complete production high-severity analysis returned no findings |
| Static audits | Documentation/help, skill sync, public API, architecture, parser bundles, licenses, dependencies, workflow syntax, and secret checks passed |

Selected completed scale measurements were 53.65 s for fresh structural index,
2.81 s for warm structural index, 117.70 s for fresh-cache production taint,
45.23 s for inspect, 231.27 s for full native export, 84.19 s for warm production
taint, 44.47 s for dependency analysis, 76.48 s for sink lineage, and 4.14 s for
source analysis. Warm inventory pages completed in 0.88–0.99 s.
This run reused a validated semantic generation; its 11.25 s readiness check
and 2.57 s warm reopen are not cold-generation measurements. The fresh-generation
baseline is recorded in the rule-review section below. Known Gradle dependency
coverage warnings remain explicit and do not become complete negative results.

Release preparation also corrected the stale C# source-count snapshot after
constructor effects moved to resolved IDG calls, and includes the refreshed
24-second terminal demo in both tar and zip archives. Generated Cargo artifacts
were cleaned before the fresh correctness build; the combined artifact budget
passed. The Rust example's 72 command checks passed again after removing its
generated lockfile. These local checks are distinct from hosted CI, six-platform
release builds, attestations, and registry publication; the tag workflow and
post-release checks below establish publication status.

## CLI presentation verification — 2026-09-06

The UI follow-up preserves canonical JSON facts and analysis scope while making
terminal and HTML reports easier to scan:

- Severity labels use a consistent red/orange/yellow/blue/gray-blue scale across
  themes, including findings, inventories, source overlays, and HTML badges.
- Browse pages lead with command-specific counts. Dense tables reflow into
  labeled records on narrow terminals, retaining fields and copyable IDs;
  cross-module evidence keeps its existing `used in (cross-module)` section.
- Findings lead with their compiler-provided route and endpoint locations.
  Diagnostic messages precede capability reference tables, with exact byte
  locations joined through one file lookup index.
- Rendered-page cache identities include effective theme, color mode, and width.
  Progress transitions clear and detach the previous terminal-line owner before
  drawing the next; report output suppresses new bars until it completes.
- Footers distinguish findings, source flows, types, imports, and other actual
  result units. Corridor target matches are explicitly distinguished from
  compiler-proven reachability; backend details remain in JSON/debug output.

The final compact CLI suite passed **1,970 tests across 27 targets**, with zero
failures or ignored tests. Its 11 large Elasticsearch cases were selected out
and verified in the dedicated optimized target: **all 12 tests passed in
922.77 s**, including streaming-JSON validation. The 3 GiB scheduling budget and
all existing SLOs were unchanged. This run reused the existing immutable semantic
generation; the fresh-generation baseline remains recorded below.

The release-binary command matrix passed **1,280 command/switch combinations
across all 20 languages** (1,424 invocations including evidence setup). The
validator now pins the exact known unsupported Go, Objective-C, and Swift
dependency-manifest warnings, matching the Rust coverage gate; additional gaps
and falsely complete envelopes still fail validation.

Presentation review also exercised 37 text command views at both 80 and 140
columns. Ten real-terminal captures checked color, theme/width cache changes,
`NO_COLOR`, and progress clearing, including the secure-code-game reproduction.
All 37 Python script tests, strict workspace/all-target Clippy, formatting,
documentation/help audits, and synchronized skill validation passed. Build
artifacts remained within the 32 GiB budget. These are local candidate results,
not a claim of a new commit, tag, hosted pipeline, or registry publication.

## Command-surface follow-up — 2026-09-06

The follow-up command review corrected misleading help and strengthened the
release validator without changing compiler facts or native JSON schemas:

- `index --semantic --watch` now fails at argument parsing instead of silently
  completing the one-shot semantic job and ignoring watch mode.
- Sanitizer help distinguishes credit-bearing inventory matches from proof of
  path safety. Source-analysis examples explicitly opt into inferred sources;
  pack help includes non-finding `typing` models.
- The language matrix reopens all seven stable-ID families through `show`,
  preserving resolver/source context and asserting that the returned document
  retains the requested ID. Its edge-ID discovery now reads the canonical
  `rows` envelope; an obsolete bare-array reader had skipped edge-selector
  checks. A script regression pins that envelope.
- CLI regressions cover empty results and cross-module sections for all twelve
  browse commands, plus the corrected argument/help contracts. Documentation
  clarifies structured JSON pagination, streaming watch events, and the
  distinction between inventory severity and vulnerability findings.

The expanded manual report check passed 267 invocations: 37 HTML/JSON report
views, complete cursor walks across all twelve browse commands (132 pages,
887 rows equal to the corresponding exhaustive results), native JSON, SARIF,
NetworkX and GraphML edge-reference integrity, Cypher structure, invalid-argument
help routing, and atomic report preservation. Live watch checks also covered
modification, addition, and deletion with matching fresh browse results.

The final rebuilt release passed **1,974 compact CLI tests across 27 targets**
with zero failures or ignored tests. The expanded release matrix passed
**1,440 command/switch cases across all 20 languages** (1,584 invocations
including setup). All seven `show` families executed for every language.
The 37 text views at 80/140 columns and ten real-terminal captures were rerun
successfully, including the original progress-bar reproduction, all four
themes, and `NO_COLOR`.

Strict workspace/all-target Clippy, formatting, 38 Python script tests,
documentation/help audits, and skill synchronization passed. Build artifacts
occupied 23.46 GiB of the 32 GiB budget. This follow-up changed CLI argument/help
contracts, tests, and documentation only; it did not rerun the dedicated
Elasticsearch target or change the previously measured compiler/query engine.
These checks were recorded on an uncommitted local candidate; they are not
publication claims.

## Rule-review verification — 2026-09-06

The language-by-language review tightened context-free encoder/quoting credit
and added missing boundary models. The principal changes are:

- URL/shell transforms remain visible without sanitizer credit; LDAP DN and
  filter escaping have separate contexts, and PHP tag stripping is not a
  general XSS protection.
- Executable selection and variadic code arguments have dedicated models,
  including JavaScript/TypeScript spawn and Function calls, Python scalar
  subprocess/executable arguments, and Perl open forms.
- PHP PDO execution and case-insensitive Location headers, C/C++ libcurl TLS
  options, inherited C# redirect methods, and qualified Erlang decoding retain
  their actual API boundaries.
- FastAPI implicit scalar inputs exclude call-default dependencies; SwiftUI
  URL callbacks and Kotlin/Swift factory typing use rule-owned providers and
  compiler-emitted callback/receiver facts.
- Parser/deserializer rules no longer borrow unsupported execution or XXE
  semantics from similarly named libraries. Fixed local redirect-prefix
  exceptions require exact compiler string-composition evidence.
- Swift getter lowering, Python direct-argument compositions, and ignored-root
  SDK refresh preserve the same facts in fresh and persisted analysis. The
  compiler-object frontend ABI is 203; older generations are rebuilt normally.

See [Security Specification](security-spec.mdx#sanitizer-credit) for the
classification contract and [Rule Testing](rule-testing.mdx) for executable
coverage and near-miss requirements.

The current rule-review tree passed the compact workspace suite with **8,307
tests, 0 failures, and 0 ignored tests** across 371 test/doc-test targets.
The 11 Elasticsearch cases were selected out of that compact run and executed
in the separate optimized target, which passed **all 12 tests in 1,283.54 s**
(including its small streaming-JSON validation test). Strict workspace/all-target
Clippy passed, and the release CLI was rebuilt from the same source tree.

Rulepack validation with live taint replay passed all **11,919 examples** with
zero errors and warnings. Independent API-shaped CLI fixtures cover all twenty
languages, including safe controls, exact source/sink locations, transform
evidence, complete pagination, and cached/fresh equality after file mutations.
Additional regressions pin Swift computed-getter callbacks, Python argument
compositions, lexical callable shadowing, and ignored-root SDK refresh.

The optimized Elasticsearch run used the unchanged 3 GiB scheduling budget and
reference-host SLOs. Unlike the earlier baseline below, this run built a fresh
semantic generation after the compiler-object frontend ABI changed:

| Operation | Completed time | SLO |
|---|---:|---:|
| Fresh-cache structural index | 53.84 s | 100 s |
| Warm structural index | 2.79 s | 12 s |
| Fresh-cache production taint | 119.97 s | 170 s |
| Cold semantic generation | 358.32 s | 600 s |
| Warm semantic reuse | 2.57 s | 18 s |
| Default inspect | 46.24 s | 60 s |
| Full native export | 226.12 s | 300 s |
| Warm production taint | 90.78 s | 135 s |
| Dependency analysis | 46.12 s | 135 s |
| Selected-sink upstream analysis | 79.80 s | 120 s |
| Source analysis | 4.37 s | 35 s |

Navigation, compiler diagnostics, security inventories, and stable-ID reopening
also passed. Warm security inventory pages completed in 0.93–1.00 s. Known
unsupported Gradle dependency formats retain their explicit coverage warnings;
the gate does not convert those warnings into a complete negative result.
No timing threshold, semantic-work cap, or fixture-specific production
exception was introduced for these changes.

The documentation follow-up passed the 48-file/35-page structure and link audit,
the binary-help audit (276 invocations, 103 reference flags, 39 help surfaces),
skill synchronization/validation, and strict private-item workspace rustdoc.
The documented Python gauntlet command returned its single expected
unsanitized finding with complete analysis and a final page. These checks
update local candidate evidence only; they do not assert a new commit, tag,
hosted pipeline result, or registry publication.

## Pre-rule-review verification baseline — 2026-09-06

The candidate before the language-by-language rule review passed the compact workspace suite with **8,294 tests,
0 failures, and 0 ignored tests** across 370 test/doc-test targets. Strict
workspace/all-target Clippy and private-item rustdoc also passed. The ordinary
suite includes the 20-language native-schema and CLI/SDK parity checks.

The separate optimized Elasticsearch target passed all 12 tests in 927.07
seconds under the 3 GiB scheduling budget, with unchanged reference-host SLOs:

| Operation | Completed time | SLO |
|---|---:|---:|
| Fresh-cache structural index | 54.39 s | 100 s |
| Warm structural index | 3.53 s | 12 s |
| Fresh-cache production taint | 119.99 s | 170 s |
| Default inspect | 46.89 s | 60 s |
| Full native export | 228.28 s | 300 s |
| Warm production taint | 85.27 s | 135 s |
| Dependency analysis | 45.38 s | 135 s |
| Selected-sink upstream analysis | 77.66 s | 120 s |
| Source analysis | 4.17 s | 35 s |

This run reused an already-valid semantic generation; its 5.52-second
validation is not a cold semantic build measurement. Native export validation
parsed the entire multi-gigabyte document, not just its envelope. Retained
regressions cover CFG-local field-copy convergence, repeated/self-copy,
coexisting value/field evidence, and removal of overwritten fields. These
changes introduce no analysis cap. Known Gradle dependency-frontend gaps remain
explicit, as described below.

Documentation/help audits, all three skill copies, the public API snapshot,
and the shared production-duplication audit passed. These are local candidate
results, not a claim that a tag, cross-platform archive, or registry release
has been published. The remaining historical tables are comparison baselines.

## Correctness and architecture gates

The release gate consists of these checks. The results below are the
previously recorded release baseline, not a live certification of later
working-tree changes. A new release claim requires rerunning every applicable
gate on the same committed tree. Use `security . pack --validate` for current
rule and example counts.

| Gate | Previously recorded result |
|---|---|
| Release all-target compile | Passed |
| Strict Clippy (`-D warnings`) | Passed |
| Strict rustdoc with private items (`-D warnings`) | Passed |
| Formatting and diff hygiene | Passed |
| Complete workspace test suite | Passed with 0 failed and 0 ignored tests |
| 20 adapter/parser conformance suites | Passed |
| Adapter `FlowEvent` behavioral audit | Passed |
| Cross-language taint target | 1,386 tests passed, including 1,233 applicable scenario/language cells |
| IDG, taint, resolver, callgraph, workspace, and architecture invariants | Passed |
| Full optimized security package | Passed |
| Rulepack taint replay | 0 errors, 0 warnings, 0 misses |
| Release CLI command/language matrix | 1,320 combinations passed |
| Focused CLI integration suites | Passed |
| Layering and public API snapshots | Passed |
| Hardcoded-knowledge boundary | 0 production violations |
| Corpus-independence audit | 0 violations |
| Shared production clone audit | 0 clones at the configured threshold |
| Dependency advisories, unused edges, and SPDX policy | Passed |
| Full reachable-history secret scan | Passed |
| GitHub Actions syntax and immutable action pins | Passed |
| Cargo and public repository metadata | Passed |
| Release binary build-path privacy | Passed |
| Documentation structure, links, navigation, binary help claims, and skill copies | Passed |
| Native archive checksum and fresh-profile relocation smoke | Passed on macOS arm64 |
| Build-artifact size gate | 3.30 GiB / 32 GiB limit (`target` plus isolated release target) |

The artifact measurement follows a completed exhaustive workspace test run,
an explicit `cargo clean`, and the isolated privacy-safe release build. It
remains below the enforced local and CI budget; generated analysis caches and
test outputs are not release inputs.

Run the current rulepack replay with:

```bash
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress
```

| Rulepack measure | Result |
|---|---:|
| Rules | 6,482 |
| Enabled rules | 6,482 |
| Disabled rules | 0 |
| Examples | 11,919 |
| Enabled examples | 11,919 |
| Errors | 0 |
| Warnings | 0 |

## Compiler and taint invariants

Release conformance enforces these product contracts:

- Each language adapter owns its Tree-sitter grammar, syntax recognition,
  declarations, imports, values, receiver/type facts, and `FlowEvent`
  lowering.
- Shared crates do not branch on language IDs or contain framework/package API
  inventories.
- Security identities, values, taxonomy, trust, severity, sanitizers, package
  evidence, and profile policy live in rule data.
- Compiler objects are content-addressed and validated by path, adapter,
  frontend ABI, and SHA-256 source content before reuse.
- Derived semantic sidecars include compiler and analysis policy identities;
  incompatible artifacts are rejected rather than reused.
- Production taint is a sparse monotone IDG fixed point with no BFS name
  search, depth ceiling, iteration limit, file limit, or result cap.
- Structured control retains exact adapter-owned destinations: post-test loops
  execute before their first condition, unconditional loops have no fabricated
  fallthrough, labels target the named loop, and PHP lexical levels are typed
  depth facts rather than parsed strings in shared analysis.
- Memory settings change scheduling, cache retention, or spill representation
  only. They do not change admitted facts or fixed-point scope.
- Paging and diagnostic previews are presentation controls. Any truncation is
  explicit and never feeds semantic reachability.
- Dynamic calls without sufficient static evidence remain unresolved and make
  the affected scope explicit; the resolver does not guess an edge.

## Historical self-analysis baseline

The previously recorded cold production-profile security scan of this
repository completed with:

| Measure | Result |
|---|---:|
| `analysis_complete` | `true` |
| Incomplete reasons | 0 |
| Findings at the production threshold | 0 |
| Wall time | 10.12 s |
| Maximum RSS | 1,188,691,968 bytes (about 1.11 GiB) |
| Swaps | 0 |
| Scheduling budget | 3,072 MiB |

Command:

```bash
./target/release/bonsai-ninja cache clear .
BONSAI_MEMORY_BUDGET_MB=3072 \
  ./target/release/bonsai-ninja security . taint-analysis \
  --profile production \
  --format json \
  --all \
  --output-path /tmp/bonsai-self-security.json \
  --no-color \
  --no-progress
```

This is a completeness and output-contract smoke, not proof that the
repository contains no defect.

## Real-project language matrix

On 2026-08-21 and 2026-08-22, the release candidate was exercised against one
public production repository for every registered language adapter. Each
checkout was shallow, processed alone under `/tmp`, and removed with its
workspace cache before the next checkout. The matrix covered libuv, fmt,
Polly, dart-lang/http, Phoenix, Cowboy, Gin, Hadoop, ESLint, Ktor, Kong,
AFNetworking, Mojolicious, Laravel, Django, Rails, Tokio, Cats, SwiftNIO, and
Nest.

Across those 20 checkouts, the compiler admitted 31,325 source files. Every
adapter completed structural indexing, diagnostics, and a production-profile
security analysis without a work cap or guessed call edge. The largest Java
case was Hadoop at 9,114 admitted files; its empty-analysis-cache production
taint run completed in 49.42 seconds with 2.54 GB maximum RSS. A separate
Express checkout exercised every public top-level command, all security and
debug subcommands, structural and semantic indexing, watch refresh, paging,
selectors, HTML output, all four export formats, cache lifecycle operations,
and captured/no-color output. JSON, SARIF, HTML, GraphML, Cypher, and NetworkX
artifacts were parsed or structurally checked after emission.

This is a command and frontend integration gate, not a claim that every file
in every repository has complete static semantics. C/C++ preprocessor
environments, Objective-C SDK macros, mutually exclusive Swift build
branches, and Kotlin syntax newer than the bundled grammar can remain
unresolved without the build configuration or grammar support needed to parse
them exactly. Those files produce syntax or resolution diagnostics and make
`analysis_complete` false; they are never silently skipped, capped, or
connected through guessed edges. The run exposed and closed C# file-directive,
Ruby ERB statement-boundary, and TypeScript import-type recovery defects.
Temporary checkouts and their generated workspace caches are not retained
after the gate.

## Large-workspace scale gate

The required release test uses the sibling 30,055-source Elasticsearch
checkout pinned by the release workflow at `e9741368da0`. The August 31
baseline passed all 11 large-repository tests in 1,131.62
seconds under the 3 GiB scheduler. This duration includes the complete native
export as well as every interactive and security surface. An empty
current-schema semantic generation took 425.55 seconds and a fresh process
validated and reopened it in 2.74
seconds. The suite owns every public leaf command in the curated root menu,
including the full native export, and its help-derived invariant fails if a
new command has no scale-test owner. The SLOs below include small host-noise
buffers over the reviewed limits. They are evaluated only after exact work
completes and never truncate or narrow semantic work. A separate subprocess
watchdog fails and terminates a probable hang; it cannot turn partial analyzer
output into a pass. The pinned local gate uses 900 seconds, while the slower
shared release runner receives 1,800 seconds without relaxing any completed-
operation SLO. The shared release runner completed the same exact cold semantic
generation in 999.71 seconds. Its independently tested runner-class threshold
is therefore 1,200 seconds (about 20% headroom); the product/reference threshold
remains 600 seconds. The release invocation uses one test thread so unrelated
large-repository cases cannot distort one another's latency measurements.
Elasticsearch's Java Gradle build, settings, and properties files currently
lack a dependency frontend. Security gates require the three explicit
`dependency-manifest:unsupported:java:` warning kinds with positive file
counts and reject every other incompleteness reason. This checks completed
compiler/IDG work without misrepresenting dependency coverage; it does not
relax any latency threshold or allow capped analysis.
For memory context, the prior instrumented
August 20 empty-cache semantic run recorded 3,788,292,096 bytes maximum RSS
and zero swaps; its fresh-process reopen used 99,287,040 bytes maximum RSS.

Security selectors are views over one cached complete report: `taint-analysis`
seeds every loaded source rule (the production profile's `trust: remote` is a
view), and `sink-analysis` attaches security-source proofs for every loaded
source rule to its selected sink set (`--sink` remains its one analysis-scope
selector because lineage is compiled per sink). The taint rows below therefore
measure the complete analysis, not a trust-scoped subset. Re-measured
2026-09-02 on the pinned local host.

| Operation | Time | Enforced SLO |
|---|---:|---:|
| Fresh-cache structural index | 47.63 s | 100 s |
| Warm structural index | 4.22 s | 12 s |
| Cold semantic generation | 425.55 s | 600 s |
| Fresh-process semantic reuse | 2.74 s | 18 s |
| Default inspect (compiler flows attached) | 21.46 s | 60 s |
| Compiler-proven raw-taint inspect | 35.13 s | 60 s |
| Fresh-cache production taint (complete report, every source rule) | 132.87 s | 170 s |
| Warm production taint (complete report, every source rule) | 97.66 s | 135 s |
| Sink-centric upstream analysis (5 matched endpoints, proofs for every source rule) | 71.26 s | 120 s |
| `tree --max-depth 1` | 0.11 s | 35 s |
| Search | 1.07 s | 35 s |
| Definitions | 1.05 s | 35 s |
| Imports | 0.99 s | 35 s |
| Classes | 0.99 s | 35 s |
| Entry points | 0.82 s | 35 s |
| Calls | 0.83 s | 35 s |
| Arguments | 0.82 s | 35 s |
| Scoped `read-file` | 1.77 s | 35 s |
| Context summary | 1.07 s | 35 s |
| Compressed corridor (`inspect-graph --from/--to`) | 5.37 s | 35 s |
| Complete diagnostics | 8.29 s | 35 s |
| `dump-hir` | 3.57 s | 35 s |
| `dump-cfg` | 3.07 s | 35 s |
| `dump-callgraph` | 1.19 s | 35 s |
| `dump-resolution` | 10.17 s | 35 s |
| `dump-ast` | 1.58 s | 35 s |
| `dump-resolve` | 8.82 s | 35 s |
| `dump-taint` | 11.20 s | 35 s |
| Variable inventory | 1.97 s | 35 s |
| String inventory | 1.65 s | 35 s |
| Comment inventory | 1.61 s | 35 s |
| Operation inventory | 1.11 s | 35 s |
| Reference lookup | 1.60 s | 35 s |
| Exact persisted edge lookup (`show E:<id>`) | 7.30 s | 35 s |
| Exact edge dump | 7.64 s | 35 s |
| Source inventory | 4.93 s | 35 s |
| High-severity sink inventory | 1.04 s | 35 s |
| Sanitizer inventory | 1.00 s | 35 s |
| Dependency inventory | 1.11 s | 35 s |
| Source-centric forward analysis | 4.89 s | 35 s |
| Complete embedded rulepack audit | 28.95 s | 70 s |
| Exact native export | 251.31 s | 300 s |

The interactive rows above are the recorded baseline gate values and may reuse a
validated rendered-page entry from an earlier exact run. Separate runs with an
empty rendered-page cache measured default inspect at 10.46 seconds and
the same query with expanded taint flows at 28.99 seconds with byte-identical output. Semantic
and rendered caches affect recomputation only; they do not change the selected
facts.

Command:

```bash
BONSAI_ELASTICSEARCH_ROOT=../elasticsearch \
BONSAI_REQUIRE_ELASTICSEARCH_GATE=1 \
BONSAI_MEMORY_BUDGET_MB=3072 \
  cargo test --release --locked -p bonsai-ninja \
  --test elasticsearch_large_repo -- --nocapture --test-threads=1
```

The test normally waits for every command to finish before evaluating latency
and completeness. Its independent subprocess watchdog exists only to turn a
genuine hang into a failed test with captured stdout and stderr; a terminated
process can never pass. The default is 900 seconds and the slower shared
release runner explicitly uses 1,800 seconds. Memory scheduling may serialize workers,
but neither the product nor the gate caps files, rules, graph edges, closure
steps, paths, or findings.

The table records the default SLO class on the identified M1 Pro reference
host. The tag workflow also runs the complete gate on GitHub's shared
`ubuntu-22.04` runner with runner-class thresholds calibrated from complete
exact runs. The v0.2.11 tag attempt completed the current cold semantic
generation in 999.71 seconds; that measurement established the 1,200-second
shared-runner threshold without changing the 600-second product/reference
SLO. The first v0.2.6 tag attempt measured 255.94 seconds for the exact cold
structural index, 1,162.71 seconds for cold semantic generation, 1.80
seconds for fresh-process semantic reuse, 32.89 seconds for fresh-cache taint,
62.89 seconds for raw-taint inspect, and 15.60 seconds for warm taint. All
correctness checks passed; the cold structural measurement exceeded only the
provisional 240-second hosted-runner threshold, which is now 300 seconds with
ordinary shared-runner headroom. Hardware calibration changes only the
post-completion latency assertion; the 100-second reference-host SLO, analysis
inputs, memory schedule, completeness checks, and results remain identical.

The August 21 structural-index profile used an independently empty cache. A
full-CST lookup nested under per-fact Java enrichment made the original cold
run take 254.04 seconds and 2,106.10 CPU-seconds. Replacing that shared
adapter-kit lookup with Tree-sitter's range-directed descendant/ancestor path
reduced the same exact 30,055-file generation to 66.20 seconds and 449.58
CPU-seconds (3.84x wall-clock, 4.69x CPU), at 1,243,004,928 bytes maximum RSS
and zero swaps. The fix is shared by every adapter that maps emitted spans
back to its CST. Root-only warm generation validation reduced default `index`
from 8.41 to 4.05 seconds and maximum RSS from roughly 690 MB to 77,070,336
bytes; it still rebuilds on any source-ledger mismatch.

That release gate subsequently measured the same exact structural work
at 50.51 seconds cold and 4.29 seconds warm. The earlier figures above remain
the instrumented CPU/RSS run; the later figures are the release SLO run.

The cold semantic row is a deliberate one-time whole-workspace build, not a
normal command startup cost. It rebuilt exact compiler objects, linkage,
callgraph, retrieval, and IDG sidecars for all 30,055 sources after the cache
was explicitly cleared. The validated cache directory was 7,114,762,932 bytes
(about 6.63 GiB): 888,833,012 bytes of compiler objects, 317,949,495 bytes of
callgraph, 1,505,969,092 bytes of linkage, 224,742,044 bytes of retrieval, and
4,161,426,830 bytes of IDG, plus the manifest. Ordinary commands compute exact
requested facts on demand; users only pay this full prewarm when they
explicitly run `index --semantic`. A fresh process in that gate reused
the completed semantic generation in 2.42 seconds.

Two scale defects were fixed during the August 30 command-completeness pass.
Full diagnostics previously parsed and retained every syntax tree before
streaming the same compiler objects again. It now performs one exact streaming
compiler-object pass, and compiler-object admission is canonical so later
files cannot retain all memory permits while an earlier publication head waits.
That changed Elasticsearch diagnostics from a reproducible hang to 8.98
seconds. Stable `show E:<id>` lookup previously regenerated and hashed roughly
1.7 million rendered edge IDs. The resolved-callgraph sidecar now carries an
independently decodable, collision-preserving stable-edge-ID index and opens
only the exact partition candidates, reducing that lookup from 36.98 to 8.09
seconds without changing the public ID or edge set.

The August 25 sink-inventory gate initially failed at 34.25 seconds despite
producing the correct 7,578 matches. Profiling found a rule-by-source literal
scan followed by an eager per-file package-evidence build. Literal target and
package anchors are now compiled into one language-batch multi-pattern pass;
its compact presence/call-shape evidence is carried into header planning, and
the exact package set is built only when a surviving rule cannot prove its
package literal directly. The process-local package cache keys on the unique
VFS instance, stable FileId, edit-monotonic file version, and package-context
fingerprint rather than hashing the complete source again. The final command
completed in 27.72 seconds and its rendered 7,578-match page was byte-identical
to the pre-optimization artifact.

The August 17 security-planning correction restored immutable compiler-object
attachment for path-filtered workspaces that retain deterministic
full-workspace `FileId`s. Before the fix, a warm production profile silently
fell back to Tree-sitter declaration/flow lowering for 13,270 raw-anchor
candidates. The corrected planner validates each selected id, path, adapter,
content hash, and SHA-256 digest, decodes compact syntax headers, and opens
only the five surviving bodies. On the same cache and host, warm production
taint fell from 29.44 to 11.87 seconds in isolated runs; maximum RSS fell from
2,067,922,944 to 682,688,512 bytes. The current enforced gate completed warm
production taint in 15.89 seconds.

Commit `dd37c87afca7c4d5f606906410d3a02777b7675a` replaced compiler-object
batch barriers with a continuous, source-weighted worklist. Completed payloads
are persisted immediately while the FactStore key index and metadata remain
canonical. On the identical repository, cache schema, and 3 GiB schedule,
that reduced cold generation from 1,613.79 seconds to 606.50 seconds. That
optimization pass also replaced 29,522 one-segment IDG lowering barriers with
a bounded source-weighted worker window. Workers lower independent typed
segments concurrently, memory permits remain held until the canonical
stitcher consumes each result, and a bounded reorder map preserves ascending
`SegmentId` publication. The IDG build fell from 117.36 seconds to 95.55
seconds. That parser-pack/ABI verification completed in 600.59 seconds:
2.69x faster and 62.8% less wall time than the original baseline, with the same
semantic scope and a 7,113,750,880-byte validated cache directory. At the
preceding compiler ABI, a candidate that parallelized global header replay was
rejected after the controlled cold gate slowed from 566.14 to 572.00 seconds;
phase-local speedups are not accepted when allocator residency reduces later
exact-work concurrency.

The August 18 IDG correction removed two independent repeated-decode paths in
semantic prewarm. Receiver-state projection now reuses the already-open outer
segment instead of reopening source and target segments for every projected
edge. Interprocedural summary input is compiled by one canonical segment pass
into exact fixed-width node-address, local-edge, and call-boundary spools;
bounded page caching changes only locality. On the compiler ABI and cache
schema used by that run, the isolated IDG phase fell from 220.17 to 187.06 seconds
(15.0%), and complete cold generation fell from 637.62 to 601.99 seconds
(5.6%). The resulting sidecar sizes and semantic scope are unchanged, and the
IDG suite covers recursion, scope, page eviction, and outer-segment reuse.

The August 21 follow-up applied that same representation invariant to
cross-file projected edges in the contextual accelerator. Those rows were
still reopening both compiler-spooled segments once per edge. They are now
grouped by exact source/target segment pair, and each pair is decoded once
without changing edge admission, ordering, or fixed-point scope.
On the same 627-file local release workload, contextual accelerator compilation
fell from 57.42 to 2.70 seconds (21.3x); the complete accelerator fell from
58.59 to 4.22 seconds. This local regression measurement supplements rather
than replaces the named Elasticsearch release gate.

## Production-scale native export measurement

Native export is a bulk artifact path rather than an interactive navigation
command. It was measured separately on August 14, 2026 because the regular
large-workspace gate intentionally does not write a multi-gigabyte export on
every CI runner.

The export measurement used bonsai-ninja commit
`d5c5fe418a3b86fdb1cbe2c4d1443ee8f2adef88`; the optimized cold semantic row
is the controlled August 14 RSS measurement retained for comparison. Both used
Elasticsearch commit `e9741368da0cb5465f5cf76c668a09fd780583be`, an Apple
M1 Pro with 16 GiB of
physical memory, macOS 26.3.1, and `BONSAI_MEMORY_BUDGET_MB=3072`. Output was
streamed through a byte counter instead of being retained on disk. Both export
commands were fresh processes reading the same validated semantic generation;
no reusable default-export cache existed.

| Operation | Wall time | Output bytes | Maximum RSS |
|---|---:|---:|---:|
| Cold semantic generation | 556.61 s (9m 16.6s) | 7,113,425,453 cache bytes | 3,189,686,272 bytes |
| Default native JSON (`compiled_idg`) | 244.98 s (4m 05.0s) | 4,540,419,571 | 4,815,470,592 bytes |
| Native JSON with `--full-propagations` | 456.43 s (7m 36.4s) | 6,421,445,325 | 4,744,691,712 bytes |
| Full-materialization delta | +211.45 s (+86.3%) | +1,881,025,754 (+41.4%) | no material increase |

The default and full forms represent the same exact interprocedural
propagation relation. Default export retains it as the compiled IDG and avoids
enumerating every per-entry row. `--full-propagations` is for consumers that
require those concrete rows; it does not make analysis more accurate.

The 3 GiB memory value is a semantic-worker scheduling budget, not a hard RSS
limit. Clean file-backed pages and allocator arenas are reclaimable under
pressure, so maximum RSS can exceed that scheduling value; the cold build
peaked at 3,189,686,272 bytes and completed without swaps. Both export forms
peaked near 4.8 GB RSS while streaming their
multi-gigabyte JSON. Streaming means the exporter does not construct one
matching in-memory JSON document, but its shared semantic projection still has
a larger resident set than the scheduling budget. Treat the table as the
recorded production export baseline for the identified commits and review any
increase in time, bytes, or memory as a possible regression under comparable
conditions.

## Output and packaging gates

The release workflow verifies:

- native text and JSON output;
- SARIF 2.1.0 parsing and code-flow metadata;
- HTML report generation from the canonical JSON result;
- native JSON and graph export formats;
- native JSON schema v14 validation across every language fixture and
  materialized propagation mode;
- stable IDs and page/cursor reopening;
- the locked parser manifest contains every adapter grammar and all six native
  platform bundles before package builds begin;
- relocated binary-only security execution with no adjacent rulepack, an empty
  user/parser cache, and an empty workspace cache;
- readable `security-patterns/` source in the archive for inspection and
  customization, independently of the embedded runtime default;
- a 45-package, production-only crates.io graph under the `bonsai-ninja`
  namespace; the conformance and testkit crates remain repository-only;
- the versioned native export JSON Schema under `schemas/`;
- checksums and immutable workflow action pins;
- signed GitHub/Sigstore provenance for every tagged archive and checksum;
- Linux, macOS, and Windows archives for x64 and arm64.

`tree` is separately pinned: it walks the filesystem first, attaches
declarations, resolved imports, and cross-file call edges only for the files it
renders (from the structural workspace and persisted callgraph), and never
loads a rulepack, runs security, or opens the IDG; `--files-only` is a plain
listing. `--html-output` renders a command's canonical JSON result and cannot
enable additional analysis.

## Publish gate

The tag workflow is authoritative. A release tag must:

1. be an ancestor of `main`;
2. use `v<workspace-semver>`;
3. agree with the Cargo workspace version;
4. pass preflight, documentation, architecture, rulepack, dependency, and
   self-security checks;
5. pass all six native build/test jobs;
6. pass the pinned large-workspace scale job;
7. produce archives and checksum files that execute from a relocated
   directory;
8. verify and publish every crates.io package in production dependency order,
   with an exact workspace-version requirement on each internal edge;
9. sign archive provenance through GitHub artifact attestations before
   publication;
10. verify every downloaded archive and checksum attestation again in the
    isolated publish job before creating the GitHub release.

The implementation is locally ready for that workflow. GitHub's tag-triggered
OIDC identity signs provenance without a long-lived signing key. crates.io uses
the repository's `CARGO_REGISTRY_TOKEN` secret; `scripts/publish-crates.py`
makes a partial upload resumable only after verifying the `gromhacks` registry
owner and canonical identity of every already-published package path, file,
mode, link, generated manifest, and VCS record. Gzip and tar container metadata
do not affect that comparison. New-crate HTTP 429 responses are retried at the
registry-provided UTC time with a safety margin, and transient API connection
resets/timeouts use bounded exponential backoff, so a temporary registry
failure does not abort the release before the first upload. Each Cargo package
verification runs in disposable build storage and removes its staging archive
after use, preventing a many-crate release from retaining one compiled
dependency graph per package. Remote CI state and publication permissions
remain external deployment conditions and are not asserted by a local test
run.

## Preparing a new version

Version preparation is local; it does not publish a tag or upload packages.
Keep the release candidate separate from the latest published release until
the tag workflow and post-release checks below finish successfully.

1. Check the remote tags, GitHub releases, and crates.io registry before choosing
   the next version. Never replace a published version or move an existing tag.
2. Update `[workspace.package].version` and every exact internal dependency
   requirement in the root `Cargo.toml`, plus `security-patterns/VERSION`.
   All 47 workspace packages share the version; 45 are publishable, while
   conformance and testkit remain private.
3. Refresh `Cargo.lock` with `cargo metadata --offline --format-version 1`,
   then inspect the diff. A release-number-only change must not update unrelated
   third-party dependencies. Run `python3 scripts/audit-release-metadata.py` and
   `python3 scripts/publish-crates.py --check-registry` to verify the package
   graph, exact pins, ownership, and availability of the chosen version.
4. Rebuild through `bash scripts/build-release.sh`, not a plain distributable
   Cargo build, so builder paths are remapped. Run the applicable correctness,
   scale, rulepack, documentation, skill-sync, and privacy gates below against
   that binary. Keep logs, scratch notes, and temporary recordings outside the
   tracked release inputs.
5. Review and commit the candidate on `main`. Check `git status --short` is
   empty, then validate each publishable payload with `cargo package -p <name>
   --locked --no-verify --list`. This source-list check is not package build
   verification: new exact-version dependencies do not exist on crates.io yet.
   The publisher verifies each archive in dependency order before upload.
6. When publication is authorized, push `main`, wait for its required checks,
   and create and push `v<workspace-semver>` at that verified commit. Do not
   confuse a successful main-branch build with a published release. Check hosted
   runs at roughly five-minute intervals; no rapid polling is needed.
7. Follow the post-release checks below. Retrying a partially completed tagged
   workflow must use the original commit and version; the publisher verifies
   existing archives before resuming.

Both tar and zip archives include `assets/` beside the README, preserving its
terminal demo in the downloadable package as well as on GitHub. The GIF's
documented commands target the example in a source checkout.

Cargo packages share `crates/README.md`, whose image and documentation links
are absolute. crates.io resolves relative links under each crate's repository
subdirectory, so inheriting the root README would send readers to nonexistent
paths such as `crates/cli/assets/`. The root README keeps relative links for
the repository and downloadable archives. Keep both surfaces accurate when
changing the demo or documentation entry points.

## Post-release verification

A successful release workflow dispatched against `main` proves the release
preflight, exact scale gate, and six platform build jobs, but it intentionally
skips the crates.io and GitHub publication jobs. Publication is enabled only
for a `v<workspace-semver>` tag. Do not report a main-branch workflow as a
published release unless the registry and release records are checked
separately.

After a tagged workflow completes, verify the same commit and every
publishable package from a clean checkout:

```bash
git status --short --branch
git fetch origin main --tags
git rev-parse HEAD origin/main
python3 scripts/publish-crates.py --check-registry
gh run view <release-run-id> --json conclusion,jobs,headSha,url
gh release view v<workspace-semver>
```

The registry audit is the authoritative package check. It reads Cargo
metadata, validates the production dependency order and exact internal
version requirements, then checks every publishable crate name, repository,
owner, and requested version on crates.io. A successful result must report
zero available names and all publishable packages already present at the
workspace version. The tag release job uses the same package graph with
`--publish --resume --confirm-version`; a resumed publication skips only an
identical version already verified on crates.io.

The release job must show successful preflight, scale, all six build jobs,
`publish crates.io workspace`, and `publish GitHub release`. The release
record and downloaded archive checksums are the final confirmation that the
published binaries correspond to the committed tag.

## Commands to repeat before tagging

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" \
  cargo doc --workspace --no-deps --document-private-items --release --locked

python3 scripts/audit-docs.py
python3 scripts/audit-cli-docs.py --binary ./target/release/bonsai-ninja
python3 scripts/audit-release-metadata.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/publish-crates.py --check-registry
python3 scripts/realworld-lang-benchmark.py --check
python3 scripts/sync_skill.py --check
bash scripts/audit-workflows.sh
bash scripts/audit-secrets.sh
bash scripts/audit-layering.sh
bash scripts/audit-hardcoded.sh --check /tmp/bonsai-hardcoded-release
python3 scripts/audit-corpus-independence.py
python3 scripts/audit-rust-duplication.py
bash scripts/audit-public-api.sh --check
bash scripts/audit-build-artifacts.sh
bash scripts/audit-github-actions.sh
python3 scripts/audit-dependency-licenses.py
cargo audit --deny warnings
cargo machete --with-metadata

bash scripts/audit-loop.sh
```

Run the large-workspace command from the preceding section whenever compiler,
adapter, resolver, IDG, taint, query, cache, security, or export semantics
change. Documentation-only changes still require documentation, binary-help
claim, formatting, link, skill-sync, and rustdoc gates.
