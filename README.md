<img src="docs/assets/bonsai-ninja.png" alt="bonsai-ninja banner" width="100%">

# bonsai-ninja

A code intelligence engine for the whole development lifecycle. Map a
codebase, debug across files, and run security analysis at scale from a
single binary, with no cloud upload, no hosted backend, and no paywall.

bonsai-ninja supports 20 parser/navigation adapters out of the box: C,
C++, C#, Dart, Elixir, Erlang, Go, Java, JavaScript, Kotlin, Lua,
Objective-C, Perl, PHP, Python, Ruby, Rust, Scala, Swift, and TypeScript.
All supported languages use the general-purpose compiler and app/web taint
pipeline.

## More Than A Security Tool

bonsai-ninja is a code intelligence engine. Security analysis is one mode
it runs in, not the whole product. The same engine that traces taint from
source to sink also answers the questions developers ask every day:

- **Map a codebase** with `tree`, `defs`, `entrypoints`, `inspect`, and
  `search`. Drop into an unfamiliar repo and get a real picture of
  structure, public API, imports, callable roots, and hot files quickly.
- **Debug across files** with `trace`, `calls`, `refs`, and `args`. Walk
  behavior through assignments, function calls, and cross-file
  boundaries without starting from raw grep.
- **Read the dataflow** with `dump-callgraph`, `dump-cfg`, `dump-hir`,
  `dump-edges`, and `dump-taint`. The engine exposes its own facts, so
  you can see why it reached a conclusion.
- **Run security at scale** with `security taint-analysis`. The same
  analyzer engine that powers navigation builds source-specific taint
  evidence for SARIF 2.1.0 findings, including concrete source-to-sink
  chains for review or CI gating.

One engine, one binary, one set of facts. Whatever role you are in, you
are querying the same model of the codebase.

That model is built like a compiler. Each language adapter uses its own
Tree-sitter grammar and owns the lowering of declarations, imports,
receivers, constructors, calls, branches, assignments, fields, and other
source syntax into typed cross-language facts. Shared resolver, callgraph,
IDG, taint, security, and export passes consume those facts; they do not
guess language behavior from source strings or a hardcoded union of API
names. Security provider identities, dependency manifests, package spelling,
profile/test-path policy, package aliases, taxonomy and sanitizer-credit
relationships, trust/severity/CWE values, and safe or unsafe configuration
values live in rulepack YAML. Taint reachability
is a sparse monotone IDG fixed point, not a BFS:
there is no semantic call-depth ceiling, iteration limit, or result cap.
Pagination and diagnostic path previews are separate presentation layers
and report any truncation explicitly.

`security sanitizers` is intentionally narrower than the sanitizer rule
directory: it lists only matched rules that can make a credit-bearing
sanitizer claim. Passthrough declarations remain part of exact propagation and
are rendered as taint transforms, never as sanitizer evidence.

For semantic prewarm, each immutable source snapshot is lowered once into a
content-addressed compiler object containing declarations, imports, flow
events, syntax facts, and diagnostics. Objects are keyed by workspace-relative
path, selected adapter, frontend ABI, and a full SHA-256 source digest, then
published as one atomic generation. Callgraph, retrieval, linkage, IDG,
security, inspect, and export stream that same typed generation. The persisted
IDG identity includes the compiler-object frontend ABI, so any lowering change
invalidates every graph derived from the older facts even when source bytes are
unchanged. The IDG path lowers transfer facts once: it spools the compact typed
stitch record and canonical node map, then replays them one file segment at a
time without reparsing or a second transfer pass. `index --semantic` derives
and publishes the default semantic contextual CSR plus compact function/node
directories from that same immutable graph. Warm queries validate and install
that query accelerator directly; it changes startup representation only, and
removing it causes the exact fixed point to be recomputed.

Large workspaces do not retain every function body beside the graph. The
workspace linker keeps declaration, type, module, inheritance, and import
headers; exact consumers hydrate one adapter-lowered body at a time and remap
it to those stable symbols. A byte-weighted hot cache may retain recently used
bodies, but eviction changes only recomputation and wall time—not facts or
coverage.

## Open Source On Purpose

Enterprise-grade code intelligence should not be locked behind paywalls.
The maintainers writing the libraries everyone depends on, the small
teams shipping critical infrastructure, and the students learning to
build safely deserve serious analysis tools too.

bonsai-ninja is MIT-licensed. It is free for commercial use, free for
personal use, and free for the maintainer of the package five layers down
in your dependency graph. No tiers, no hosted requirement, no telemetry
requirement, no "Pro" gate.

## Built For Real Codebases

bonsai-ninja is designed for production trees: large repositories,
multi-language services, and CI environments where reproducibility
matters. It indexes locally, runs deterministically, and emits stable IDs
for flows, findings, edges, AST nodes, resolver candidates, and taint
records.

There is no CI database build step and no code upload. The release binary
operates on your source tree and writes local cache state only when that
helps performance.

`bonsai-ninja index` is the syntax/construct warm-up command: it parses
supported files and builds declaration/import indexes without forcing an
expensive whole-workspace semantic prewarm. Query commands still validate
persisted sidecars and compute missing exact facts on demand when needed.
For editor and agent workflows, `bonsai-ninja index --watch` stays running
and hot-reloads saved file changes into the live workspace. Pass
`--semantic` only when you intentionally want structural semantic sidecars
prewarmed up front. `--prewarm-dataflow` explicitly materializes the
compatibility dataflow projection used by older SDK/query surfaces; it is
not a second taint engine.

Explicit semantic producers write binary factstores for speed and
`manifest.json` in the workspace's external OS cache for visibility. The
default is a canonical-path-keyed directory under the platform cache root
(`cache stats <workspace>` prints the exact path); `BONSAI_WORKSPACE_DIR`
overrides it. Analysis caches never dirty the inspected repository. The manifest records sidecar
coverage, producer fingerprints, paths, and missing reasons; commands still
validate and read the binary sidecars before reusing analysis facts. Cache
coverage includes the immutable compiler-object generation; an edit rebuilds
only mismatched objects while unchanged compressed payloads are copied into
the next atomic generation. Compiler concurrency is weighted by actual source
unit size, the process's current resident set, safety headroom, and the detected
host/container memory budget. Linux detection follows the process's active
nested cgroup v1/v2 path as well as root controller files. Under a 3 GiB
budget, weighted batches still compile several small files concurrently while
isolating a genuinely large unit. Resource scheduling can reduce parallelism
but never files, graph closure, or facts. Revisited exact file bodies share a byte-weighted hot cache sized from
that same budget. Eviction or an undersized body cache only causes exact
Tree-sitter lowering to be replayed; an oversize body is still analyzed and is
simply not retained. Cache stats validate sidecar payloads, not just path/size
metadata, so a corrupt same-size factstore is reported stale instead of
silently treated as warm. IDG publication is single-flight in process and
target-locked across processes: waiters reuse a peer's validated immutable
generation, and only lock-proven staging files from terminated writers are
cleaned. Saved-file edits take generation ownership before VFS mutation, so
analysis never mixes old compiler indexes with new source text.
The retrieval sidecar is a deterministic candidate index over persisted
facts. Exact indexes decide candidates; canonical facts and semantic graph
verification decide truth. Vector similarity is never evidence. Search and
literal-filtered browse commands can validate a fresh retrieval sidecar from
source/dependency/schema fingerprints before candidate lookup; large-workspace
inspect can use that warmed sidecar only to select a pre-open file scope. All
displayed rows and chains are then hydrated through canonical APIs. Missing or
stale sidecars fall back to exact syntax facts. Search may build retrieval on
demand for a small complete workspace; inspect does not build it during normal
query hydration, and a scoped workspace never publishes partial retrieval
state under the complete workspace's external cache directory.

Interactive commands render progress on stderr for each visible stage:
workspace ingest/parse, sidecar/cache checks, optional sidecar prewarms,
query collection, analysis phases, pagination/cache writes, and final
rendering. Progress never writes to stdout, so JSON, SARIF, DOT, and
`--output-path` payloads stay clean. Use `--no-progress` or
`NO_PROGRESS=1` to suppress the bars; progress is also hidden
automatically when stderr is not a TTY.
Security analysis progress includes scope and cache notes: file/rule
counts, source/sink match counts, taint-graph cache hit/miss state, and
whether a sidecar write-through finished.

Broad security planning is staged on cold workspaces. Raw anchors are tested in
the bounded worker pool, then exact import/package and file-local syntax
targets run before global inheritance; the global receiver table is opened
only for a typed call whose verdict can change through a base class. Parser
coverage is remembered for every exact source snapshot, including clean files,
so the final `analysis_complete` audit parses only unchecked files and never
materializes declaration/flow bodies just for diagnostics.

The final 2026-08-06 ABI-v62 release gate completed a fresh-cache exact
Elasticsearch taint scan in 30.22 seconds under
`BONSAI_MEMORY_BUDGET_MB=3072`; the required one-time ABI-v61-to-v62 semantic
generation rebuild took 1,541.88 seconds and immediate fresh-process reuse
completed in 2.32 seconds. Broad exact
`inspect execute --taint-flow` completed in 29.58 seconds
for 198,718 pageable paths, and exhaustive high-severity sink inventory
completed in 22.63 seconds. The integration gate protects cold planning, warm
production taint, navigation, inspect, and security inventories without
terminating, skipping, or capping semantic work.

The 2026-08-07 final warm-generation repeat passed all five scale tests in
234.09 seconds. Exact broad `inspect execute --taint-flow` completed in 29.53 seconds
for 198,025 unique pageable paths after reusing declaration targets already
selected by the compiler pass and avoiding redundant relevance proofs for
entries that own exact target nodes. Fresh-cache production taint completed in
34.28 seconds, warm production taint in 27.74 seconds, and immediate semantic
reuse in 2.48 seconds under the same 3 GiB schedule and unchanged SLOs.

## Human-First And LLM-First

Most code tooling and most LLM coding workflows still force a model to
reason over raw files and arbitrary line chunks. That breaks down on
large repositories and makes local open-weight models far less useful
than they should be.

bonsai-ninja is built for a different interaction model:

- **Context and paging controls.** Use `--context`, `--page`, `--all`,
  and JSON output to shape results for humans, scripts, small local
  models, or larger hosted models.
- **Semantic chunks, not random windows.** Commands page around
  definitions, call chains, flow groups, source snippets, and findings
  instead of arbitrary line counts.
- **Facts, not just tokens.** Ask for the call graph, dataflow graph,
  taint path, resolved symbol table, imports, refs, args, strings, and
  classes directly.

That makes a local model on a laptop viable for work that would otherwise
require shoving entire repositories into a frontier model context window.

## Structured Exports For Code-Aware Models

The same fact pipeline that feeds humans and agents at inference time can
also produce structured training or evaluation data. `export` emits the
graph underneath the code: call edges, resolved references, flow chains,
taint propagation records, CFG/HIR-derived structure, and source
locations.

Train or evaluate on relationships between definitions and uses, not just
the text of each line. We have not run those training experiments
ourselves, but the engine is open, the formats are documented, and the
Rust implementation is built to make large corpus indexing practical.

## Enterprise Workflows Without The Enterprise Contract

Code navigation, structural search, cross-file flow tracing, and taint
analysis are often split across paid products, hosted services, or
enterprise subscriptions. bonsai-ninja brings those workflows into one
MIT-licensed local tool.

Clone the repo, build the binary, ship it inside CI, internal devtools,
or a product. The engine is open. The rules are open. The output formats
are open.

The design target is straightforward: the simplicity and speed people
like in Semgrep-style workflows, with the deeper cross-file reasoning
people expect from CodeQL-style analysis. A single local binary should be
easy to run, fast enough to use during normal development, and precise
enough to explain real source-to-sink paths instead of only matching
surface syntax.

## Deploys Where Hosted Tools Cannot

- **Single local binary.** No daemon or hosted backend required.
- **No code leaves the machine.** Suitable for private, regulated,
  customer-confidential, air-gapped, and government source trees.
- **Deterministic output.** Same input and config produce the same
  output, so findings are diffable across commits.
- **Standards-conformant SARIF 2.1.0.** `security taint-analysis
  --format sarif` emits code flows, taxa, regions, and stable metadata
  for SARIF consumers.
- **20 parser adapters on day one.** Python, JavaScript, TypeScript, Go,
  Java, Kotlin, Rust, C, C++, C#, Ruby, PHP, Swift, Scala, and more, all
  using the same compiler and app/web taint architecture.

## Honest About Where We Are

bonsai-ninja is in beta. It has rough edges. Some rules over-fire, some
under-fire, and some language frontends are sharper than others.

The current, dated validation and scale evidence is documented in
[Release Readiness](docs/RELEASE_READINESS.md). It is the single source
of truth for build gates, rulepack counts, Elasticsearch measurements,
release provenance, and external benchmark snapshots so this overview cannot
silently drift from the tested binary. A release tag is publishable only when
it belongs to `main`, matches the Cargo workspace version, and passes the
compiler, architecture, rulepack, self-security, cross-platform CLI/output,
and pinned large-repository gates described there.

We are shipping anyway because the fastest way to make this useful is to
put it in the hands of maintainers, security teams, researchers,
integrators, and model builders who will run it on real code and tell us
where it breaks.

## Contributing

We want people to adopt it, play with it, and tell us what is broken.
Run it on real repositories. File the false positives. File the missed
flows. Show us rules that over-fire or under-fire. Add fixtures for the
language features the engine does not follow yet.

Good places to help:

- Improve source, sanitizer, and sink rules in `security-patterns/`.
- Improve typing/runtime models and pack-wide ecosystem metadata in
  `security-patterns/langs/<language>/typing/` and
  `security-patterns/metadata.yml` instead of adding API, package syntax,
  profile path, or security-taxonomy inventories to Rust.
- Add or tighten language fixtures under `examples/` and crate tests.
- Build LLM skills, agent workflows, API wrappers, and local-model
  integrations around the JSON and paged text output.
- Improve SARIF, CI, and export consumers.
- Stress-test it on large private or open-source codebases and report
  where precision, speed, or ergonomics falls short.

This project is still early enough that serious users can shape it. Open
an issue, send a PR, build an integration, or fork it into something we
did not think of. Let us work together and see where it goes.

## Install

```sh
git clone https://github.com/gromhacks/bonsai-ninja.git
cd bonsai-ninja
cargo build --release
ls target/release/bonsai-ninja
```

The binary is statically linked aside from the system C library.

Release artifacts are built for Linux, macOS, and Windows on x64 and
arm64. Source builds for other CPU architectures need the Rust target
std library, a suitable native toolchain, and a parser bundle or parser
source build path for that platform. See
[Platform And Architecture Support](docs/platform-support.mdx) and run
`scripts/check-targets.sh` before publishing a new target.

## Quickstart

```sh
# Index a project
./target/release/bonsai-ninja index ./my-app

# Keep the index hot while editing
./target/release/bonsai-ninja index ./my-app --watch

# Explain workspace roots, manifests, and skipped generated/dependency trees
./target/release/bonsai-ninja context ./my-app

# Map the tree
./target/release/bonsai-ninja tree ./my-app --max-depth 3

# Search indexed facts
./target/release/bonsai-ninja search ./my-app verify_token

# Trace a function
./target/release/bonsai-ninja trace ./my-app handle_request

# Find ranked semantic call paths between two callables
./target/release/bonsai-ninja path ./my-app --from handle_request --to run_admin_command

# Slice one unambiguous symbol backwards; add --line/--file only to disambiguate
./target/release/bonsai-ninja slice ./my-app --symbol result

# Inspect syntax facts for a target
./target/release/bonsai-ninja inspect ./my-app os.system

# Add exact raw taint paths explicitly
./target/release/bonsai-ninja inspect ./my-app --query os.system --taint-flow

# Request structural source-body evidence for a large inspect result set
./target/release/bonsai-ninja inspect ./my-app --query os.system --graph-flow

# Run the security taint analysis
./target/release/bonsai-ninja security ./my-app taint-analysis --profile production

# SARIF for code scanning
./target/release/bonsai-ninja security ./my-app taint-analysis --format sarif --output-path findings.sarif.json
```

## Commands

| Family | Highlights |
|---|---|
| Flow | `inspect`, `trace`, `path`, `slice`, `show` |
| Workspace | `index`, `context`, `export` |
| Cache | `cache stats`, `cache clear`, `cache rebuild` |
| Browse | `defs`, `entrypoints`, `calls`, `imports`, `vars`, `strings`, `comments`, `args`, `operations`, `classes`, `refs`, `search` |
| Navigation | `tree`, `read-file` |
| Security | `security sources`, `sinks`, `sanitizers`, `deps`, `taint-analysis`, `source-analysis`, `pack` |
| Debug | `dump-ast`, `dump-hir`, `dump-cfg`, `dump-callgraph`, `dump-edges`, `dump-resolution`, `dump-resolve`, `dump-taint`, `diagnostics` |

Run `./target/release/bonsai-ninja --help` for the full command and flag
surface. Root help is grouped by command family before global `OPTIONS`,
and help sections use uppercase headings consistently across commands.

## Output And Paging

`--format text` renders themed terminal output, `--format json` emits a
stable machine-consumable schema, and `--format sarif` is available for
`security taint-analysis` findings. `security source-analysis` is
text/json-only source-flow mapping; requesting SARIF for it fails clearly
instead of emitting a misleading vulnerability report.

Commands with `--format` also accept `--output-path <PATH>` to write the
selected text, JSON, SARIF, DOT, or graph export payload directly to a
file instead of stdout.

Use global `--html-output <PATH>` for a standalone responsive report in the
active bonsai color theme. This wraps the command's normal human-readable
view without enabling extra analysis; it is mutually exclusive with
`--output-path`.

Accuracy is one mode: public analysis facts are emitted only when backed
by exact or narrowed static evidence. When static analysis cannot prove a
fact precisely enough, bonsai-ninja reports the limitation through
coverage/provenance/incomplete metadata instead of downgrading to a
guess.

Text output names the evidence type directly: `inspect --graph-flow` renders
generic `FLOW` call paths, `inspect --taint-flow` renders rulepack-free `T:`
taint paths, `security source-analysis` renders `SOURCE FLOW`, and
`security taint-analysis` renders `TAINT FLOW` with source, argument
propagation, and sink annotations. Plain `inspect` is the lightweight indexed
syntax view. Use `inspect --taint-flow` to request raw taint paths for large result
sets, and `inspect --graph-flow` to request structural source-body
evidence for large result sets that would otherwise render syntax/index
facts only. These flags change output scope, not analysis accuracy.

`inspect` obtains raw taint rows through the workspace syntax-flow
facade. Candidate discovery is a separate Tree-sitter/compiler-object phase:
it records exact matching spans, releases syntax-body and callgraph caches,
and only then opens a fresh persisted IDG. Matching spans resolve to typed IDG
nodes in one segment-streaming pass; spans without a carrier retain their
owning function as an explicit conservative fallback. Broad entry batches
share one sparse backward target-demand fixed point, while every admitted
forward path still runs to exact closure. If no warmed IDG exists, the facade
builds an exact query-scoped source/target IDG; the canonical dataflow cache is
the final compatibility fallback. `dump-taint` and the cached graph path share
the same default entry seed helper so params, assignment targets, and bare
call-argument carriers are interpreted consistently.

Most review commands page by default:

```sh
./target/release/bonsai-ninja defs ./my-app --context 100
./target/release/bonsai-ninja defs ./my-app --page 2
./target/release/bonsai-ninja defs ./my-app --all
```

Use `--no-color --no-progress --context 16k` for LLM-readable review
pages, and `--format json --no-color --no-progress` for scripts.

## Configuration

- `BONSAI_RULES_DIR` - alternative rulepack location
- `BONSAI_PARSE_TIMEOUT_MS` - optional per-file parse timeout; unset or `0` is uncapped
- `BONSAI_MEMORY_BUDGET_MB` - lower the detected memory budget; this changes concurrency and cache retention, never analyzed facts
- `BONSAI_NO_DATAFLOW=1` - skip explicit dataflow prewarm and trace eager hydration
- `BONSAI_THEME` - terminal theme
- `BONSAI_WORKSPACE_DIR` - exact per-workspace cache-directory override
- `BONSAI_CONTEXT` - default text and JSON paging budget
- `BONSAI_NO_CACHE=1` - disable in-process caches for a command
- `NO_COLOR` / `NO_PROGRESS` - disable ANSI styling or progress output

## SDK

There is also a Rust SDK if you want to embed the analyzer:

```toml
[dependencies]
bonsai_sdk = "0.1"
```

```rust
use bonsai_sdk::Bonsai;

let project = Bonsai::new()
    .with_rulepack("./security-patterns")?
    .index("./my-app")?;

let report = project.security().taint_analysis(Default::default())?;
for finding in report.findings {
    println!(
        "{}: {} -> {}",
        finding.finding_id,
        finding.source.rule_id,
        finding.sink.rule_id
    );
}
```

Long-lived SDK projects refresh from disk before command facades run, so
embedded tools see saved file changes without reopening the whole project.
Projects opened through literal, path, or include/exclude reduced-open
helpers keep that reduced scope stable by default.
Security phase progress and cache/scope notes are exposed through the same
SDK progress event stream the CLI renders on stderr.

Full API notes live in [docs/contributing/sdk.mdx](docs/contributing/sdk.mdx).

## Documentation

- Start here: [docs/index.mdx](docs/index.mdx)
- Getting started: [docs/getting-started.mdx](docs/getting-started.mdx)
- Concepts: [docs/concepts.mdx](docs/concepts.mdx)
- CLI reference: [docs/cli-reference.mdx](docs/cli-reference.mdx)
- Rule authoring: [docs/rule-authoring-tutorial.mdx](docs/rule-authoring-tutorial.mdx)
- Pattern guide: [docs/pattern-guide.mdx](docs/pattern-guide.mdx)
- Security spec: [docs/security-spec.mdx](docs/security-spec.mdx)
- Contributor docs: [docs/contributing/contributing.mdx](docs/contributing/contributing.mdx)
- Coverage baselines: [docs/COVERAGE_BASELINE.md](docs/COVERAGE_BASELINE.md),
  [docs/TAINT_COVERAGE_MATRIX.md](docs/TAINT_COVERAGE_MATRIX.md), and
  [docs/MEGA_FLOW_COVERAGE.md](docs/MEGA_FLOW_COVERAGE.md)

## License

MIT - see [LICENSE](LICENSE). Dependency attribution lives in
[docs/contributing/third-party-licenses.mdx](docs/contributing/third-party-licenses.mdx).
