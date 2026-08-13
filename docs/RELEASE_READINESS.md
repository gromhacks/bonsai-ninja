# Release readiness

This page is the single source of truth for the current local release
candidate. It records completed gates and their interpretation; user guides do
not duplicate dated performance history.

## Status

Validated on 2026-08-13. Local `main` has no known failing release gate.
Publishing still requires the tag workflow because signing, packaging, and
platform-specific execution happen there.

The validated product contains:

- 20 registered Tree-sitter language adapters;
- one adapter-lowered compiler IR and one production sparse IDG taint engine;
- 7,130 bundled rules, of which 5,987 are enabled;
- 10,040 enabled positive/negative rule examples;
- native CLI, Rust SDK, SARIF 2.1.0, JSON, HTML, and graph-export surfaces.

## Correctness and architecture gates

The final local pass completed these checks with zero failures:

| Gate | Result |
|---|---|
| Release all-target compile | Passed |
| Strict Clippy (`-D warnings`) | Passed |
| Release rustdoc with private items (`-D warnings`) | Passed |
| Formatting and diff hygiene | Passed |
| 20 adapter/parser conformance suites | Passed |
| Adapter `FlowEvent` behavioral audit | Passed |
| 1,386-case cross-language taint matrix | Passed |
| IDG, taint, resolver, callgraph, workspace, and conformance suites | Passed |
| Full optimized security package | Passed |
| Rulepack taint replay | 0 errors, 0 warnings, 0 misses |
| Release CLI command/language matrix | 1,280 combinations passed |
| CLI end-to-end suite | 117 tests passed |
| Layering and public API snapshots | Passed |
| Hardcoded-knowledge boundary | 0 production violations |
| Corpus-independence audit | 0 violations |
| Shared production clone audit | 0 clones at the configured threshold |
| Dependency advisories, unused edges, and SPDX policy | Passed |
| Documentation structure, links, navigation, and skill copies | Passed |
| Build-artifact size gate | 5.96 GiB / 32 GiB limit |

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
| Rules | 7,130 |
| Enabled rules | 5,987 |
| Disabled rules | 1,143 |
| Examples | 10,483 |
| Enabled examples | 10,040 |
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
| Wall time | 1.68 s |
| Maximum RSS | 737,165,312 bytes (about 703.0 MiB) |
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

The release candidate was exercised against one current, public production
repository for every registered language adapter. Each checkout was shallow,
pinned to the tested commit, processed alone, and deleted before the next
checkout. The matrix covered jq, fmt, CommandLineParser, args, Plug, Cowboy,
chi, Gson, Express, Timber, LuaSocket, AFNetworking, Mojolicious, Slim,
Requests, Rack, ripgrep, os-lib, Alamofire, and Axios.

Across the 20 checkouts, the CLI indexed 2,388 source files, 38,264
declarations, and 251,735 call sites. The matrix exercised filesystem and
context views, structural indexing, declarations, classes, imports,
entrypoints, calls, diagnostics, search, references, inspect, trace,
read-file, AST/HIR/CFG debugging, resolution, native export, security
inventories, taint analysis, and cache reporting. A selected exact declaration
in every language round-tripped through inspect and the AST/HIR/CFG views, and
every JSON/export/security result passed schema parsing.

This is a command and frontend integration gate, not a claim that every file
in every repository has complete static semantics. C/C++ preprocessor
environments, Objective-C SDK macros, Perl grammar gaps, and mutually
exclusive Swift build branches can remain unresolved without the build-time
configuration that selects or expands them. Those files produce syntax or
resolution diagnostics and make `analysis_complete` false; they are never
silently skipped, capped, or connected through guessed edges. The run exposed
and closed adapter-selection, parse-recovery, and rule-precision defects in
C/C++, C#, Dart, Elixir, Kotlin, Objective-C, and Swift. Temporary checkouts
and their generated workspace caches are not retained after the gate.

## Large-workspace scale gate

The required release test uses the sibling 30,055-source Elasticsearch
checkout pinned by the release workflow at `e9741368da0`. The frontend-ABI
migration rebuilt the semantic generation from an empty cache in 1,571.52
seconds. The following complete five-scenario gate passed in 214.27 seconds
under the 3 GiB scheduler.

| Operation | Time | Enforced SLO |
|---|---:|---:|
| Cold semantic generation | 1,571.52 s | completion required |
| Fresh-process semantic reuse | 2.30 s | 15 s |
| Default inspect | 7.04 s | 30 s |
| Exact raw-taint inspect | 24.82 s | 30 s |
| Fresh-cache production taint | 30.18 s | 45 s |
| Warm production taint | 25.27 s | 30 s |
| `tree --max-depth 1` | 0.02 s | 30 s |
| Search | 3.62 s | 30 s |
| Definitions | 12.83 s | 30 s |
| Imports | 7.09 s | 30 s |
| Classes | 7.40 s | 30 s |
| Entry points | 25.76 s | 30 s |
| Calls | 3.42 s | 30 s |
| Arguments | 3.36 s | 30 s |
| Scoped `read-file` | 1.60 s | 30 s |
| Source inventory | 3.32 s | 30 s |
| High-severity sink inventory | 22.52 s | 30 s |
| Sanitizer inventory | 19.16 s | 30 s |
| Dependency inventory | 9.81 s | 30 s |

Command:

```bash
BONSAI_ELASTICSEARCH_ROOT=../elasticsearch \
BONSAI_REQUIRE_ELASTICSEARCH_GATE=1 \
BONSAI_MEMORY_BUDGET_MB=3072 \
  cargo test --release --locked -p bonsai_cli \
  --test elasticsearch_large_repo -- --nocapture
```

The test waits for every command to finish before evaluating latency and
completeness. It never uses a timeout to turn incomplete work into a pass.
Memory scheduling may serialize workers, but the test does not cap files,
rules, graph edges, closure steps, paths, or findings.

The cold semantic row is a deliberate one-time frontend-ABI migration, not a
normal command startup cost. It rebuilt exact compiler objects, linkage,
callgraph, retrieval, and IDG sidecars for all 30,055 sources after the cache
was explicitly cleared. The resulting cache is 7,113,741,889 bytes (about
6.62 GiB), including an 888,832,952-byte compiler-object store (about
847.66 MiB). Ordinary commands compute exact requested facts on demand; users
only pay this full prewarm when they explicitly run `index --semantic`. A
fresh process reused the completed semantic generation in 2.37 seconds.

## Output and packaging gates

The release workflow verifies:

- native text and JSON output;
- SARIF 2.1.0 parsing and code-flow metadata;
- standalone HTML generation;
- native JSON and graph export formats;
- stable IDs and page/cursor reopening;
- relocated archive execution with the packaged `security-patterns/` tree;
- checksums and immutable workflow action pins;
- Linux, macOS, and Windows archives for x64 and arm64.

`tree` is separately pinned as a filesystem-only command: it does not open the
compiler, rulepack, callgraph, or IDG. `--html-output` wraps a command's text
view and cannot enable additional analysis.

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
   directory.

The implementation is locally ready for that workflow. Signing credentials,
remote CI state, and publication permissions are external deployment
conditions and are not asserted by a local test run.

## Commands to repeat before tagging

```bash
cargo fmt --all -- --check
cargo check --release --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" \
  cargo doc --workspace --no-deps --document-private-items --release --locked

python3 scripts/audit-docs.py
python3 scripts/sync_skill.py --check
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
change. Documentation-only changes still require documentation, formatting,
link, skill-sync, and rustdoc gates.
