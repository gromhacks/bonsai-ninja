<img src="docs/assets/bonsai-ninja.png" alt="bonsai-ninja banner" width="100%">

# bonsai-ninja

A code intelligence engine for the whole development lifecycle. Map a
codebase, debug across files, and run security analysis at scale from a
single binary, with no cloud upload, no hosted backend, and no paywall.

bonsai-ninja supports 21 languages out of the box: C, C++, C#, Dart,
Elixir, Erlang, Go, Java, JavaScript, Kotlin, Lua, Objective-C, Perl,
PHP, Python, Ruby, Rust, Scala, Solidity, Swift, and TypeScript.

## More Than A Security Tool

bonsai-ninja is a code intelligence engine. Security analysis is one mode
it runs in, not the whole product. The same engine that traces taint from
source to sink also answers the questions developers ask every day:

- **Map a codebase** with `tree`, `defs`, `inspect`, and `search`. Drop
  into an unfamiliar repo and get a real picture of structure, public
  API, imports, entry points, and hot files quickly.
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

`bonsai-ninja index` is incremental: it reuses `.bonsai/dataflow.v2.bin`
across runs, validates cached facts by source-content hashes and
dependency hashes, and recomputes only stale entries. For editor and
agent workflows, `bonsai-ninja index --watch` stays running and
hot-reloads saved file changes into the live workspace.

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
- **21 languages on day one.** Python, JavaScript, TypeScript, Go, Java,
  Kotlin, Rust, C, C++, C#, Ruby, PHP, Swift, Scala, Solidity, and more.

## Honest About Where We Are

bonsai-ninja is in beta. It has rough edges. Some rules over-fire, some
under-fire, and some language frontends are sharper than others.

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

## Quickstart

```sh
# Index a project
./target/release/bonsai-ninja index ./my-app

# Keep the index hot while editing
./target/release/bonsai-ninja index ./my-app --watch

# Map the tree
./target/release/bonsai-ninja tree ./my-app --max-depth 3

# Search indexed facts
./target/release/bonsai-ninja search ./my-app verify_token

# Trace a function
./target/release/bonsai-ninja trace ./my-app handle_request

# Every call chain reaching a target
./target/release/bonsai-ninja inspect ./my-app os.system

# Run the security taint analysis
./target/release/bonsai-ninja security ./my-app taint-analysis

# SARIF for code scanning
./target/release/bonsai-ninja security ./my-app taint-analysis --format sarif > findings.sarif.json
```

## Commands

| Family | Highlights |
|---|---|
| Flow | `index`, `trace`, `inspect` |
| Browse | `defs`, `calls`, `imports`, `refs`, `vars`, `strings`, `args`, `classes`, `comments`, `search`, `read-file`, `tree` |
| Dump | `dump-hir`, `dump-cfg`, `dump-callgraph`, `dump-ast`, `dump-resolve`, `dump-edges`, `dump-taint` |
| Export | `export` as JSON, NetworkX, GraphML, or Cypher |
| Security | `security sources`, `sinks`, `sanitizers`, `deps`, `taint-analysis`, `source-analysis`, `pack` |

Run `./target/release/bonsai-ninja --help` for the full command and flag
surface.

## Output And Paging

`--format text` renders themed terminal output, `--format json` emits a
stable machine-consumable schema, and `--format sarif` is available for
`security taint-analysis` findings.

Text output names the evidence type directly: `inspect` renders generic
`FLOW` call paths, `security source-analysis` renders `SOURCE FLOW`, and
`security taint-analysis` renders `TAINT FLOW` with source, argument
propagation, and sink annotations.

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
- `BONSAI_PARSE_TIMEOUT_MS` - per-file parse timeout, default 30 seconds
- `BONSAI_NO_DATAFLOW=1` - skip dataflow prewarm during indexing
- `BONSAI_THEME` - terminal theme
- `BONSAI_WORKSPACE_DIR` - per-workspace state directory

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
