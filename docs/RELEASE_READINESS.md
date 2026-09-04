# Release readiness

This page is the single source of truth for the current local release
candidate. It records completed gates and their interpretation; user guides do
not duplicate dated performance history.

## Status

The v0.2.13 candidate incorporates the expanded compiler, adapter, rulepack,
CLI, cache, scheduling, and publication checks described below. Local status
is determined from a fresh run of the listed commands; historical measurements
are retained only where they document a reproducible scale baseline. A tag is
not published until the complete current workspace gate, release build,
relocated-binary smoke, exact large-workspace gate, and public metadata/privacy
audits all pass from the same committed tree.

The tag workflow remains authoritative for cross-platform packaging, parser
delivery, signed provenance, checksums, and crates.io publication. Its hosted
runner thresholds are calibrated from completed exact runs and never turn a
timeout, work cap, or incomplete analysis into a pass.

The validated product contains:

- 20 registered Tree-sitter language adapters;
- one adapter-lowered compiler IR and one production sparse IDG taint engine;
- 6,478 bundled rules, of which 6,478 are enabled;
- 11,875 enabled rule examples;
- native CLI, Rust SDK, SARIF 2.1.0, JSON, HTML, and graph-export surfaces.

## Correctness and architecture gates

The release gate consists of these checks. A release claim is made only from
the current committed tree after every row passes:

| Gate | Result |
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

The rulepack replay command was:

```bash
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns \
  --format json \
  --no-color \
  --no-progress
```

| Rulepack measure | Result |
|---|---:|
| Rules | 6,478 |
| Enabled rules | 6,478 |
| Disabled rules | 0 |
| Examples | 11,875 |
| Enabled examples | 11,875 |
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

## Self-analysis

A cold production-profile security scan of this repository completed with:

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
checkout pinned by the release workflow at `e9741368da0`. On August 31, the
current release candidate passed all 11 large-repository tests in 1,131.62
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
| Default inspect (compiler flows attached) | 21.46 s | 45 s |
| Compiler-proven raw-taint inspect | 35.13 s | 45 s |
| Fresh-cache production taint (complete report, every source rule) | 132.87 s | 170 s |
| Warm production taint (complete report, every source rule) | 97.66 s | 135 s |
| Sink-centric upstream analysis (5 matched endpoints, proofs for every source rule) | 71.26 s | 90 s |
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

The interactive rows above are the observed final gate values and may reuse a
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

The current release gate subsequently measured the same exact structural work
at 50.51 seconds cold and 4.29 seconds warm. The earlier figures above remain
the instrumented CPU/RSS run; the current figures are the release SLO run.

The cold semantic row is a deliberate one-time whole-workspace build, not a
normal command startup cost. It rebuilt exact compiler objects, linkage,
callgraph, retrieval, and IDG sidecars for all 30,055 sources after the cache
was explicitly cleared. The validated cache directory was 7,114,762,932 bytes
(about 6.63 GiB): 888,833,012 bytes of compiler objects, 317,949,495 bytes of
callgraph, 1,505,969,092 bytes of linkage, 224,742,044 bytes of retrieval, and
4,161,426,830 bytes of IDG, plus the manifest. Ordinary commands compute exact
requested facts on demand; users only pay this full prewarm when they
explicitly run `index --semantic`. A fresh process in the current gate reused
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
- native JSON schema v12 validation across every language fixture and
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
registry-provided UTC time with a safety margin, so throttling pauses the
release instead of leaving a failed partial publication. Each Cargo package
verification runs in disposable build storage and removes its staging archive
after use, preventing a many-crate release from retaining one compiled
dependency graph per package. Remote CI state and publication permissions
remain external deployment conditions and are not asserted by a local test
run.

## Commands to repeat before tagging

```bash
cargo fmt --all -- --check
cargo check --release --workspace --all-targets --locked
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
