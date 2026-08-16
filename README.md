<img src="docs/assets/bonsai-ninja.png" alt="bonsai-ninja banner" width="100%">

# bonsai-ninja

[![CI](https://github.com/gromhacks/bonsai-ninja/actions/workflows/ci.yml/badge.svg)](https://github.com/gromhacks/bonsai-ninja/actions/workflows/ci.yml)
[![Hardening checks](https://github.com/gromhacks/bonsai-ninja/actions/workflows/hardening-checks.yml/badge.svg)](https://github.com/gromhacks/bonsai-ninja/actions/workflows/hardening-checks.yml)
[![Rulepack audit](https://github.com/gromhacks/bonsai-ninja/actions/workflows/pack-audit.yml/badge.svg)](https://github.com/gromhacks/bonsai-ninja/actions/workflows/pack-audit.yml)

> **Project maturity:** bonsai-ninja is an ambitious early-stage project.
> Compiler-backed analysis and security modeling across 20 languages leave a
> lot of room for parser gaps, unresolved dynamic behavior, incorrect findings,
> performance problems, and ordinary bugs. The current local release gates
> pass and the tool is ready for people to use, but it is not perfect and
> should not be the sole basis for a security decision. We are publishing it
> now to gather real-world feedback, failing examples, rule contributions, and
> engineering help from the community.

bonsai-ninja is a local code-intelligence and static-analysis engine. It maps
repositories, resolves symbols and calls, traces behavior across files,
inspects dataflow, exports graph facts, and reports source-to-sink security
findings from one compiler-style pipeline.

The project is MIT licensed. It does not require a hosted service, upload
source code, or reserve analysis features for a paid tier.

## Use cases

### Code intelligence for agents and developers

**Give agents facts, not file dumps.** With tight symbol, file, and kind
selectors, bonsai-ninja lets an agent ask for the smallest useful slice of a
repository: the definition, callers, references, arguments, path, backward
slice, raw dataflow, or source file around one symbol. That means less prompt
waste, less repeated reading, and answers tied to compiler evidence.

Use it to map an unfamiliar repository, find the code behind a symptom, follow
behavior across files, review change impact, or debug the analyzer itself with
AST, HIR, CFG, resolver, call-edge, and taint diagnostics.

### Security review

Use the same compiler facts to inventory sources, sinks, sanitizers, and
dependencies, then prove modeled source-to-sink paths with the sparse IDG
fixed point. Findings can be reviewed in the terminal, emitted as JSON or
SARIF for automation, or shared as a standalone HTML report. The analysis is
evidence for human review—not a guarantee that code is safe—and completion
metadata makes unresolved static behavior visible.

### Structured export for model and agent research

Native export exposes compiler, symbol, callgraph, control-flow, dataflow, and
compiled-IDG facts in a machine-readable form. GraphML, Cypher, and NetworkX
views support graph tooling. These artifacts can be inputs to retrieval,
training-data construction, evaluations, code-reasoning experiments, or
tool-using agents; bonsai-ninja produces the evidence and does not train or
validate a model by itself. The versioned native contract is published as
[JSON Schema v7](schemas/bonsai-native-export-v7.schema.json).

Our small exploratory tests produced encouraging results, but they are not a
general model-quality claim. We would love to see independent teams take the
idea further, publish reproducible evaluations, and tell us where it fails—
whether that is OpenAI, Anthropic, Google, Poolside/Laguna, Qwen, DeepSeek,
academic and independent labs, or local-model hobbyists.

### What the pipeline provides

| Capability | Practical benefit |
|---|---|
| Tree-sitter compiler frontends | Parse 20 languages into typed declarations, calls, imports, values, control flow, and dataflow facts |
| Focused `search`, `refs`, `calls`, and `read-file` | Retrieve a small, source-backed context slice before asking for heavier semantics |
| Compiler-resolved `inspect`, `trace`, `path`, and `slice` | Follow compiler-evidenced behavior across files and report unresolved dynamic edges instead of inventing them |
| AST, HIR, CFG, resolver, edge, and taint diagnostics | Inspect both the target program and the analyzer's reasoning instead of guessing from text |
| Sparse IDG taint fixed point | Complete source-to-sink reachability over the admitted static graph without a hidden depth, file, iteration, or result cap |
| Stable IDs, explicit page cursors, JSON, and the Rust SDK | Let agents cite evidence, detect when coverage continues, and automate repeatable review workflows |
| JSON, GraphML, Cypher, and NetworkX export | Feed structured compiler evidence and explicit completeness metadata into downstream research and tooling |
| Local execution and external caches | Keep source on the machine while reusing validated compiler work across queries |

## Scale, measured

**30,055 source files. Completed modeled analysis. Warm navigation in
seconds.** The current Elasticsearch measurements use a 3 GiB semantic-worker
scheduling budget and
separate the first explicit semantic index from commands run after it exists:

| Cache state and operation | Measured time | Result |
|---|---:|---|
| Empty cache: `index --semantic` | 9m 26.1s | 7.11 GB validated reusable cache under the 3 GiB scheduling profile |
| After index: semantic generation reopen | 2.3s | Existing compiler objects, linkage, callgraph, retrieval, and IDG validated and reused |
| After index: search | 3.9s | Exact requested matches |
| After index: call lookup | 3.7s | Compiler-resolved call rows |
| After index: default inspect | 7.4s | Structural evidence for the requested target |
| After index: complete production taint analysis | 26.7s | Requested fixed point completed without a semantic cap |
| After index: default native export | 4m 05s | 4.54 GB compiler, callgraph, flow, and compiled-IDG facts |
| After index: `--full-propagations` export | 7m 36s | 6.42 GB with the same exact propagation relation materialized as individual rows |

The measured cold operation is specifically `index --semantic`, which users
request when they want every reusable semantic sidecar prepared up front.
Ordinary `index` is the lighter syntax/declaration warm-up and does not force a
whole-workspace callgraph or IDG build; ordinary commands can also compute
their requested facts on demand.

The cold row is an intentional one-time whole-workspace prewarm, not normal
command startup. The 3 GiB setting schedules semantic workers rather than
limiting operating-system RSS, and compressed export changes representation,
not graph meaning. Full methodology, component sizes, memory measurements, and
the optimization history live in
[Release Readiness](docs/RELEASE_READINESS.md).

## Supported languages

The release includes 20 Tree-sitter frontends:

C, C++, C#, Dart, Elixir, Erlang, Go, Java, JavaScript, Kotlin, Lua,
Objective-C, Perl, PHP, Python, Ruby, Rust, Scala, Swift, and TypeScript.

Each adapter owns its grammar and language syntax; shared analysis consumes
typed compiler facts, while framework and security meaning stays in
`security-patterns/`. See [Language Support](docs/language-support.mdx) for the
frontend contract and known dynamic limits.

The release binary embeds that YAML rulepack and uses the same loader and
validator after materializing a content-addressed OS-cache generation. Security
commands therefore work outside the source checkout; `--rules-dir` remains the
deterministic custom/editable-pack override.

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

Throughout this documentation, **exact** or **exhaustive** describes completion
over the static facts admitted by the frontends and resolver: the engine does
not silently stop that modeled work at a product-imposed cap. It does not mean
that the static model recovers every possible runtime behavior, that every
adapter or rule is bug-free, or that an empty result proves a program safe.

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

Install the published Rust package from crates.io:

```bash
# Requires Rust 1.88 or newer.
cargo install bonsai-ninja --locked
bonsai-ninja --version
```

To replace an older Cargo-installed release with the current one:

```bash
cargo install bonsai-ninja --locked --force
```

Or build the release binary from a checkout:

```bash
git clone https://github.com/gromhacks/bonsai-ninja.git
cd bonsai-ninja
cargo build --release --locked -p bonsai-ninja
./target/release/bonsai-ninja --version
```

The tag workflow publishes the same version to crates.io and builds release
archives for Linux, macOS, and Windows on x64 and arm64. See
[Platform And Architecture Support](docs/platform-support.mdx) for source-build
requirements and parser delivery constraints on other targets. When a tagged
archive is published, verify its SHA-256 checksum and GitHub/Sigstore
provenance before installing:

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

# Find an anchor before requesting heavier semantic work.
./target/release/bonsai-ninja search ./my-app --query verify_token \
  --context 8k --no-color --no-progress

# Inspect the target and request raw dataflow only when needed.
./target/release/bonsai-ninja inspect ./my-app --query verify_token \
  --taint-flow --context 16k --no-color --no-progress

# Run production-oriented security analysis.
./target/release/bonsai-ninja security ./my-app taint-analysis \
  --profile production --context 16k --no-color --no-progress

# Or write an exhaustive SARIF artifact for CI.
./target/release/bonsai-ninja security ./my-app taint-analysis \
  --profile production --format sarif --all \
  --output-path findings.sarif.json --no-color --no-progress
```

The complete walkthrough is in [Getting Started](docs/getting-started.mdx).
For any unfamiliar option, use the binary's `--help` and the
[CLI Reference](docs/cli-reference.mdx).

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

## Go deeper

- [Documentation home](docs/index.mdx)
- [Getting Started](docs/getting-started.mdx)
- [Concepts](docs/concepts.mdx)
- [CLI Reference](docs/cli-reference.mdx)
- [Language Support](docs/language-support.mdx)
- [Output Formats](docs/output-formats.mdx)
- [Configuration](docs/configuration.mdx)
- [CI Integration](docs/ci-integration.mdx)
- [Rule Authoring Tutorial](docs/rule-authoring-tutorial.mdx)
- [Rust SDK](docs/contributing/sdk.mdx)
- [Contributing](docs/contributing/contributing.mdx)
- [Release Readiness](docs/RELEASE_READINESS.md)

Generated and executable coverage evidence lives in
[Taint Coverage Matrix](docs/TAINT_COVERAGE_MATRIX.md),
[Coverage Baseline](docs/COVERAGE_BASELINE.md), and
[mega_flow Coverage](docs/MEGA_FLOW_COVERAGE.md). Current validation evidence
and release commands live only in
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
