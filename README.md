<img src="docs/assets/bonsai-ninja.png" alt="bonsai-ninja banner" width="100%">

# bonsai-ninja

[![CI](https://github.com/gromhacks/bonsai-ninja/actions/workflows/ci.yml/badge.svg)](https://github.com/gromhacks/bonsai-ninja/actions/workflows/ci.yml)
[![Hardening checks](https://github.com/gromhacks/bonsai-ninja/actions/workflows/hardening-checks.yml/badge.svg)](https://github.com/gromhacks/bonsai-ninja/actions/workflows/hardening-checks.yml)
[![Rulepack audit](https://github.com/gromhacks/bonsai-ninja/actions/workflows/pack-audit.yml/badge.svg)](https://github.com/gromhacks/bonsai-ninja/actions/workflows/pack-audit.yml)

bonsai-ninja is a local code-intelligence and static-analysis engine. It maps
repositories, resolves symbols and calls, traces behavior across files,
inspects dataflow, exports graph facts, and reports source-to-sink security
findings from one compiler-style pipeline.

The project is MIT licensed. It does not require a hosted service, upload
source code, or reserve analysis features for a paid tier.

## Why agents use it

**Give agents facts, not file dumps.** With tight symbol, file, and kind
selectors, bonsai-ninja lets an agent ask for the smallest useful slice of a
repository: the definition, callers, references, arguments, path, backward
slice, raw dataflow, or source file around one symbol. That means less prompt
waste, less repeated reading, and answers tied to compiler evidence.

| Capability | Practical benefit |
|---|---|
| Tree-sitter compiler frontends | Parse 20 languages into typed declarations, calls, imports, values, control flow, and dataflow facts |
| Focused `search`, `refs`, `calls`, and `read-file` | Retrieve a small, source-backed context slice before asking for heavier semantics |
| Compiler-resolved `inspect`, `trace`, `path`, and `slice` | Follow statically proven behavior across files and report unresolved dynamic edges instead of inventing them |
| AST, HIR, CFG, resolver, edge, and taint diagnostics | Debug both the target program and the analyzer's reasoning instead of guessing from text |
| Sparse IDG taint fixed point | Prove exact source-to-sink reachability without a hidden depth, file, iteration, or result cap |
| Stable IDs, explicit page cursors, JSON, and the Rust SDK | Let agents cite evidence, detect when coverage continues, and automate repeatable review workflows |
| JSON, GraphML, Cypher, and NetworkX export | Build retrieval indexes, graph features, training examples, evaluation sets, or tool-using agents from structured code facts and explicit completeness metadata |
| Local execution and external caches | Keep source on the machine while reusing validated compiler work across queries |

**From symbol to side effect, across files.** Use it to map an unfamiliar
codebase, explain behavior, trace a bug, triage a finding, or prepare
structured code data for downstream models. Export supplies the data;
task-specific evaluation still determines whether a training approach
improves a model.

## Scale, measured

**30,055 source files. Exact analysis. Warm navigation in seconds.** A current
Elasticsearch verification under a 3 GiB scheduling budget reopened the
content-addressed semantic generation in 3.2 seconds; search and call lookup
took about 4.1 seconds, default inspect 7.3 seconds, and complete warm
production taint analysis 27.9 seconds.

The cold full semantic generation is real work, not hidden startup: the
measured rebuild takes about 26–27 minutes on this checkout. Ordinary commands
do not force that prewarm; users request it explicitly with
`index --semantic`, then reuse the exact generation. The controlled release
methodology and exact gate measurements live in
[Release Readiness](docs/RELEASE_READINESS.md).

**A complete production-scale graph export takes minutes, not hours.** Against
the same warmed 30,055-file generation, native JSON streamed 4.54 GB of
compiler, callgraph, flow, and IDG-backed facts in 4 minutes 5 seconds. Explicit
`--full-propagations` materialized the same exact propagation relation as
individual rows: 6.42 GB in 7 minutes 36 seconds. The default therefore saved
1.88 GB and 3 minutes 31 seconds without reducing accuracy. These whole-repo
exports peaked near 4.8 GB RSS; the 3 GiB setting schedules semantic workers
and is not a hard operating-system RSS limit.

## Supported languages

The release includes 20 Tree-sitter frontends:

C, C++, C#, Dart, Elixir, Erlang, Go, Java, JavaScript, Kotlin, Lua,
Objective-C, Perl, PHP, Python, Ruby, Rust, Scala, Swift, and TypeScript.

Each adapter owns its grammar and lowers language-specific syntax into typed
declarations, imports, call sites, receiver/type evidence, assignments,
branches, fields, callbacks, and flow events. Shared resolver, callgraph, IDG,
taint, security, SDK, and export layers consume that IR. They do not select
behavior from language IDs or shared API-name lists.

Library, framework, package, trust, severity, CWE, sanitizer, and
configuration knowledge belongs in `security-patterns/`. This keeps the
compiler reusable across projects and keeps security policy reviewable as
data.

## What it does

- Maps workspace structure, manifests, languages, imports, declarations, and
  entry points.
- Finds definitions, references, calls, arguments, variables, strings,
  comments, and operations using compiler facts.
- Resolves qualified symbols and traces paths across files.
- Inspects structural graph paths and rulepack-free raw taint paths.
- Runs rule-driven source, sink, sanitizer, dependency, and taint analysis.
- Exposes AST, HIR, CFG, resolution, call-edge, and taint diagnostics.
- Exports native JSON, GraphML, Cypher, NetworkX, and other supported graph
  formats for downstream tools.
- Produces terminal, JSON, SARIF 2.1.0, and standalone HTML reports where the
  selected command supports them.

## Accuracy contract

bonsai-ninja treats analysis as a compiler pipeline:

```text
source -> Tree-sitter adapter -> typed compiler IR -> resolver/callgraph
       -> IDG fixed point -> query, security, SDK, and export views
```

Production taint reachability is a sparse monotone IDG fixed point. It has no
BFS name search, call-depth ceiling, iteration limit, file limit, or result
cap. Memory budgets can change worker concurrency, cache retention, and spill
behavior; they do not change semantic scope.

Static analysis cannot resolve every runtime-generated call. Reflection,
unexpanded macros, computed imports, dynamic dispatch, and metaprogramming can
lack enough source evidence. In those cases the tool reports diagnostics or
`analysis_incomplete_reasons`; it does not invent a resolved edge. Always
check completion metadata before treating an empty result as proof that no
path exists.

Pagination is presentation only. If output reports another page, follow the
printed page or cursor before claiming complete coverage. `--all` removes
paging for an intentional exhaustive artifact; it does not enable a different
analysis mode.

## Install

Build the release binary from source:

```bash
git clone https://github.com/gromhacks/bonsai-ninja.git
cd bonsai-ninja
cargo build --release --locked -p bonsai_cli
./target/release/bonsai-ninja --version
```

Release archives target Linux, macOS, and Windows on x64 and arm64. See
[Platform And Architecture Support](docs/platform-support.mdx) for source-build
requirements and parser delivery constraints on other targets. Each archive
has a SHA-256 checksum and signed GitHub/Sigstore provenance. Verify both before
installing:

```bash
shasum -a 256 -c bonsai-ninja-<target>.tar.gz.sha256
gh attestation verify bonsai-ninja-<target>.tar.gz \
  --repo gromhacks/bonsai-ninja
```

## Quickstart

Use the release binary. Add `--no-color --no-progress` for scripts and agent
workflows.

```bash
# Explain workspace roots and language coverage.
./target/release/bonsai-ninja context ./my-app --no-color --no-progress

# Optional syntax/declaration warm-up for a query session.
./target/release/bonsai-ninja index ./my-app --no-progress

# Map and search the repository.
./target/release/bonsai-ninja tree ./my-app --max-depth 3 \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja search ./my-app --query verify_token \
  --context 8k --no-color --no-progress

# Pivot from an anchor to compiler facts.
./target/release/bonsai-ninja refs ./my-app --symbol verify_token \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls ./my-app --callee verify_token \
  --context 8k --no-color --no-progress

# Follow behavior.
./target/release/bonsai-ninja inspect ./my-app --query verify_token \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace ./my-app --symbol handle_request \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja path ./my-app \
  --from handle_request --to verify_token \
  --context 16k --no-color --no-progress

# Request rulepack-free raw taint paths explicitly.
./target/release/bonsai-ninja inspect ./my-app --query verify_token \
  --taint-flow --context 16k --no-color --no-progress

# Run production-oriented security analysis.
./target/release/bonsai-ninja security ./my-app taint-analysis \
  --profile production --context 16k --no-color --no-progress

# Write a complete SARIF artifact for CI.
./target/release/bonsai-ninja security ./my-app taint-analysis \
  --profile production --format sarif --all \
  --output-path findings.sarif.json --no-color --no-progress
```

Run `./target/release/bonsai-ninja --help` and the relevant command's
`--help` before relying on an unfamiliar option.

Workspace paths are normal positional operands. Query-like values have named
forms such as `--query`, `--symbol`, `--file`, `--from`, `--to`, and `--id`;
prefer those in scripts and agent workflows. The concise positional selector
forms remain available for interactive use, but passing both forms is an
error instead of silently choosing one. Output files accept
`-o`, `--output`, or the canonical `--output-path` spelling.

## Choose the smallest command

| Need | Command |
|---|---|
| Files and directories | `tree` |
| Workspace and language summary | `context` |
| Text or symbol anchor | `search` |
| Declarations, classes, imports, entry points | `defs`, `classes`, `imports`, `entrypoints` |
| Calls, arguments, references | `calls`, `args`, `refs` |
| Local facts around one target | `inspect` |
| Source-to-target call path | `path` |
| Execution trace from an entry | `trace` |
| Backward influence around a symbol | `slice` |
| One source file and connected context | `read-file` |
| Reopen a stable result ID | `show` |
| Parser or semantic internals | `dump-*`, `diagnostics` |
| Security model or findings | `security` |
| Downstream graph artifact | `export` |

`tree` is a direct filesystem walk. It does not initialize the compiler,
rulepack, callgraph, IDG, or security engine. Syntax inventory commands also
avoid whole-workspace semantic work unless their requested result requires it.

## Index and cache behavior

Commands compute exact requested facts on demand. Indexing is useful when a
workspace will receive several queries:

```bash
# Normal syntax and declaration warm-up.
./target/release/bonsai-ninja index ./my-app --no-progress

# Explicit semantic prewarm for repeated broad inspect/security/export work.
./target/release/bonsai-ninja index ./my-app --semantic --no-progress

# Keep saved-file changes warm during active editing.
./target/release/bonsai-ninja index ./my-app --watch --no-progress
```

Analysis sidecars live in a canonical-path-keyed operating-system cache, not
inside the inspected repository. `cache stats <workspace>` prints the exact
location and `BONSAI_WORKSPACE_DIR` overrides it. Repository-local
`.bonsai/rules/` is reserved for rule overlays and is not an analysis cache.

Compiler objects and semantic sidecars are validated against source content,
adapter/frontend ABI, dependency metadata, and analysis policy before reuse.
Stale or corrupt artifacts are rejected and rebuilt.

## Output and paging

- Use `--context 16k --no-color --no-progress` for readable agent output.
- Use `--format json --no-color --no-progress` for automation.
- Use `--output-path <file>` for large artifacts.
- Use `--html-output <file>` for a standalone themed human report. It wraps
  the command's text view and never enables additional analysis.
- Preserve stable IDs such as `S:`, `F:`, `G:`, `T:`, `E:`, `R:`, and `N:`;
  reopen them with `show` or the command that emitted them.

Security `S:` identifiers name findings, `F:` identifiers name taint paths,
and `G:` identifiers name finding groups. Structural commands also emit flow
and group IDs; use the command context shown in the report when reopening
them.

## Security rules

Bundled rules live under:

```text
security-patterns/langs/<language>/{sources,sinks,sanitizers,typing}
```

`typing` entries are non-finding compiler models for external return and
callback types. Passthrough rules preserve taint and appear as taint
transforms; they are not sanitizers. `security sanitizers` lists only matched
rules eligible to make a credit-bearing sanitizer claim.

Validate rule changes with:

```bash
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns --format json --no-color --no-progress
./target/release/bonsai-ninja security . pack --audit \
  --context 16k --no-color --no-progress
cargo test --release --locked -p bonsai_security --test rulepack_conformance
```

See [Rule Authoring Tutorial](docs/rule-authoring-tutorial.mdx),
[Pattern Guide](docs/pattern-guide.mdx), and
[Security Analysis Specification](docs/security-spec.mdx).

## Rust SDK

The `bonsai_sdk` crate exposes the same workspace, browse, inspect, trace,
security, diagnostics, show, and export facades used by the CLI. Long-lived
projects refresh saved files before command facades run.

```rust
use bonsai_sdk::Bonsai;

let project = Bonsai::new()
    .with_rulepack("./security-patterns")?
    .index("./my-app")?;

let report = project.security().taint_analysis(Default::default())?;
for finding in report.findings {
    println!("{}", finding.finding_id);
}
```

See [SDK](docs/contributing/sdk.mdx) for the complete API surface.

## Documentation

- [Documentation home](docs/index.mdx)
- [Getting Started](docs/getting-started.mdx)
- [Concepts](docs/concepts.mdx)
- [CLI Reference](docs/cli-reference.mdx)
- [Language Support](docs/language-support.mdx)
- [Output Formats](docs/output-formats.mdx)
- [Configuration](docs/configuration.mdx)
- [CI Integration](docs/ci-integration.mdx)
- [Contributing](docs/contributing/contributing.mdx)
- [Release Readiness](docs/RELEASE_READINESS.md)

Generated and executable coverage evidence lives in
[Taint Coverage Matrix](docs/TAINT_COVERAGE_MATRIX.md),
[Coverage Baseline](docs/COVERAGE_BASELINE.md), and
[mega_flow Coverage](docs/MEGA_FLOW_COVERAGE.md).

## Project status

bonsai-ninja is pre-1.0 software. A green test suite does not prove the absence
of every bug, and static analysis cannot recover runtime facts absent from
source. The release gates require deterministic, complete requested analysis;
positive and negative fixtures for every supported adapter; rule replay;
cross-platform builds; output-contract smokes; self-analysis; and a pinned
production-scale repository test.

Current validation evidence and exact release commands live in
[Release Readiness](docs/RELEASE_READINESS.md).

## Contributing and license

Contributions should preserve the compiler/rule boundary and include the
smallest positive and negative tests that prove the behavior. Start with
[Contributing](CONTRIBUTING.md) and the
[PR Review Checklist](docs/contributing/review-checklist.mdx). Participation is
governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

Use the guided GitHub issue forms for reproducible product defects, analysis
quality reports, and feature proposals. Do not attach private source code,
credentials, generated analysis caches, or proprietary findings to a public
issue.

Report exploitable vulnerabilities through the private process in
[Security Policy](SECURITY.md), not through a public issue.

bonsai-ninja is licensed under the [MIT License](LICENSE). Dependency license
policy is documented in
[Third-Party Licenses](docs/contributing/third-party-licenses.mdx).
