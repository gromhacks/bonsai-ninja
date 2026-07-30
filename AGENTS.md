# bonsai-ninja

Use `bonsai-ninja` when you need structural code intelligence: map a
repo, find symbols, trace behavior, debug dataflow, or run SAST.

Command truth comes from the binary:

```shell
./target/release/bonsai-ninja --help
./target/release/bonsai-ninja <command> --help
./target/release/bonsai-ninja security --help
```

Prefer `./target/release/bonsai-ninja`; use debug only if release is
missing. For scripts use `--format json --no-color --no-progress`; add
`--all` or `--context uncapped` only for intentional exhaustive
artifacts. For LLM-readable text use `--no-color --no-progress
--context 16k`.
For save-time workflows, keep `index <workspace> --watch --no-progress`
running; command and SDK facades refresh saved file changes before they
render.
`index <workspace>` is the syntax/construct warm-up path: it parses source
and builds declaration/import indexes without forcing a whole-workspace
semantic prewarm. Use `index <workspace> --semantic` only when you
intentionally want structural semantic sidecars and
`.bonsai/manifest.json` built up front; commands still validate sidecar
headers/payloads before reuse and compute requested exact facts on demand.
Retrieval is candidate lookup only: search and literal-filtered browse can
reuse a fresh sidecar before candidate lookup, and large-workspace inspect can
use a warmed sidecar only before opening a scoped workspace. Rendered facts
still hydrate through canonical APIs, and scoped query workspaces do not
publish partial retrieval sidecars under the full workspace cache.

Treat the analyzer as a compiler pipeline. Each language adapter owns its
Tree-sitter grammar, source-syntax recognition, declaration/import lowering,
and `FlowEvent`/capability facts. Shared analysis consumes that typed IR; do
not add language-id branches, cross-language token inventories, or API-name
guesses to shared crates. The production taint engine is the sparse IDG
fixed-point closure. It has no BFS name search, call-depth ceiling, iteration
limit, or result cap. Paging and diagnostic path limits affect rendering only
and must report truncation explicitly.

`index --semantic` first publishes an immutable content-addressed generation
of per-file compiler objects. Each object is exact adapter-lowered IR plus
diagnostics, validated by path, adapter, frontend ABI, and SHA-256 source
content. Import indexes and compact syntax-target facts (calls, assignment
aliases, factory assignments, and receiver/type evidence) are
integrity-checked compiler headers inside the same generation and must remain
independently decodable from declaration/flow bodies. Broad rule planning
filters raw source anchors, exact import/package headers, and exact syntax
targets in that order before decoding a surviving body. Later phases stream
those objects; they must not reparse source or invent a parallel lowering
path. Persisted IDG construction lowers transfer facts once, spools typed
stitch records/node maps, and replays them per segment. Memory scheduling may
weight or serialize units, but must never cap semantic work. After the
isolated workers finish, the parent validates that every sidecar describes one
current workspace snapshot and reruns the exact sequence if a file changed
between phases.

External-memory IDG structures must be lazy. Resident-only fixed points start
with empty sparse sets/frontiers; Bloom filters, positive caches, dense
workspace bitsets, and temporary spill files are created only when actual
relation density crosses their representation threshold. Promotion and spill
change storage only, never admitted facts or fixed-point scope. Keep the lazy
allocation tests and conformance invariant: eagerly reserving maximum spill
pages per function is a large-repository performance regression.

For broad analysis, retain only workspace linkage headers (declarations,
types, modules, imports, inheritance, and stable symbol identities) and stream
exact adapter-lowered bodies on demand. Never make all project bodies resident
beside the IDG. Body-cache eviction may cause exact recomputation; it must not
change analyzed files, edges, or closure.
The persisted linkage artifact has independently decodable symbol-header,
receiver-ancestry, and call-linkage payloads. Syntax lookup reads only the
symbol payload; file-local inventory reads only receiver ancestry; neither
may decode unrelated call linkage or inflate every `CompiledFileObject`.
Exact selected bodies remap against stable headers when global symbols are
required.
IDG queries must reuse `IdgQueryService::global_linkage_index()`; calling
`AnalyzerDb::global_index()` while an IDG is open rebuilds every body beside
the graph and is an architecture regression.

Native export always represents the exact call/path language as
`compressed_callgraph`. Do not add a capped/BFS path-prefix mode, a graph-size
heuristic, or a `complete_chains` switch. Export structural/callgraph rows,
release all canonical callgraph owners, stream exact file-local body
projections, release the body cache, and only then open the IDG. A one-shot
export writes directly to its requested sink; only explicit
`cache rebuild --export` may publish a reusable export cache.

Keep command phases intentional. `tree` is a direct filesystem walk. Syntax
inventories (`search`, `defs`, `classes`, `entrypoints`, `calls`, `args`,
`refs`, `strings`, `comments`, `vars`, and `operations`) may use compact
headers or stream file-local compiler objects, but must not materialize the
whole-workspace body index, resolved graph, IDG, or rulepack unless the command
explicitly requests that semantic product. Apply file/name/kind predicates
while walking compiler IR, before allocating result rows. Never initialize a
lazy workspace-wide cache from inside a Rayon file loop. Scoped query
workspaces preserve the full workspace's deterministic `FileId` ordinal so
they can reuse content-addressed compiler objects without reparsing.

Performance gates measure completed exact work; they never terminate, skip, or
cap analysis. When query/cache/engine code changes, build release and run
`cargo test --release -p bonsai_cli --test elasticsearch_large_repo
-- --nocapture` with the sibling checkout (or
`BONSAI_ELASTICSEARCH_ROOT`). The gate enforces warm semantic reuse and
navigation/inspect/security SLOs under a 3 GiB scheduling budget. Update the
measured baseline only for an intentional, reviewed architecture change.

Always treat pagination as correctness. If output says more pages exist,
continue with `--page 2`, `--page next`, or the printed `P:...` cursor
before claiming coverage. Use `--all` only for tight filters or explicit
exhaustive artifacts.

## Map A Codebase

Start with shape, then follow one concrete behavior.

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
# Optional explicit semantic sidecar prewarm:
./target/release/bonsai-ninja index <workspace> --semantic --no-progress
# Explicit spelling for default syntax/construct indexing:
./target/release/bonsai-ninja index <workspace> --structural-only --no-progress
# Optional during active editing:
./target/release/bonsai-ninja index <workspace> --watch --no-progress
./target/release/bonsai-ninja context <workspace> --no-color --no-progress
./target/release/bonsai-ninja tree <workspace> --max-depth 3 --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> --context 16k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --kind function --context 16k --no-color --no-progress
./target/release/bonsai-ninja entrypoints <workspace> --context 16k --no-color --no-progress
./target/release/bonsai-ninja classes <workspace> --context 16k --no-color --no-progress
```

Find anchors with `search`, then pivot to structured facts:

```shell
./target/release/bonsai-ninja search <workspace> <route|symbol|error|config|sink> --context 8k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee <callee> --context 8k --no-color --no-progress
```

Understand behavior:

```shell
./target/release/bonsai-ninja inspect <workspace> --query <target> --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <target> --syntax-only --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <target> --taint-flow --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
./target/release/bonsai-ninja show <workspace> F:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry-function> --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
```

`inspect` is rulepack-free by default: targeted queries include bounded
raw taint paths and source-body flow evidence that contain the query. Use
`--syntax-only` when you deliberately want indexed facts without flow
evidence, `--taint-flow` to request bounded raw taint paths for large
result sets, and `--graph-flow` to request structural source-body
evidence for large result sets that would otherwise render syntax/index
facts only. These flags change output scope, not analysis accuracy:
emitted graph facts still use the exact/narrowed static evidence
contract. Inspect raw taint paths go through the workspace syntax-flow
facade: a warmed IDG target cut is used only when already available,
otherwise the canonical cached dataflow graph is used.

Record understanding as:

```text
entry point -> validation -> business logic -> storage/external call -> response/side effect
```

Use `export <workspace> --format json` when downstream tooling needs the
full graph.

## Debug And Develop

Use the tool to narrow the bug before editing.

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
./target/release/bonsai-ninja search <workspace> <symptom> --context 16k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> <symbol> --context 16k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
```

If high-level output disagrees with source, use the debug ladder:

```shell
./target/release/bonsai-ninja dump-ast <workspace> --file <file> --function <fn> --context 16k --no-color --no-progress
./target/release/bonsai-ninja dump-hir <workspace> <fn> --no-color --no-progress
./target/release/bonsai-ninja dump-cfg <workspace> <fn> --no-color --no-progress
./target/release/bonsai-ninja dump-resolve <workspace> <callee> --in-file <file> --no-color --no-progress
./target/release/bonsai-ninja dump-edges <workspace> --from <caller> --to <callee> --context 8k --no-color --no-progress
./target/release/bonsai-ninja dump-taint <workspace> --source <entry> --seed <param> --no-color --no-progress
```

Then patch, test, and rerun the smallest command that proves the fix.
Long-lived commands and SDK projects refresh saved files automatically;
use `index --watch` when you want the sidecar kept hot continuously.

## Security Review

Start from externally reachable input, then prove source-to-sink paths.

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --profile production --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --profile production --context 16k --no-color --no-progress
```

`--profile production` sets remote-trust defaults, `severity high` for
taint findings, `context 16k`, and excludes common non-production paths:
tests, specs, fixtures, mocks, samples, examples, demos, e2e/integration
harnesses, vendored deps, package caches, build outputs, generated code,
docs, scripts, deploy files, migrations, and language-specific test
layouts. Use `--exclude-tests` alone when you want only the narrower
test-path filter. Security file and profile filters are workspace-relative:
an ancestor directory outside the selected workspace does not make the
workspace generated, vendored, or test code.

Inventory when needed:

```shell
./target/release/bonsai-ninja security <workspace> sources --trust remote --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sinks --severity high --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sanitizers --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> deps --severity high --context 8k --no-color --no-progress
```

Filter findings by rule class:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --severity high --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --tag command-injection --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --source <source-rule> --sink <sink-rule> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --flow F:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --group G:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --format sarif --no-color --no-progress > findings.sarif.json
```

For each issue, cite `S:` finding id, `F:` flow id, `G:` group id, source line, sink
line, sanitizer status, and the exact page/cursor coverage reviewed.
Security `F:` ids are taint-path flow ids and security `G:` ids are
taint-path group ids; reopen them with `show F:<id>` / `show G:<id>` or
`security taint-analysis --flow F:<id>` / `--group G:<id>`. Use
`inspect --flow` / `inspect --group` for structural ids printed by
code-navigation commands.

Solidity is a smart-contract security pack, not an app/web taint parity
language. Treat its findings as on-chain hazards such as reentrancy,
delegatecall, selfdestruct, oracle/randomness misuse, token hazards, and
access control. Do not expect or add fake SQLi/XSS/SSRF/path/cmdi
coverage for Solidity.

## Rulepack Work

Rules live under `security-patterns/langs/<lang>/{sources,sinks,sanitizers,typing}`.
Enable rules when they represent a real security boundary and the current
constraints can keep common safe APIs quiet. Do not enable generic print,
log, join, or parse patterns without a security-specific constraint.
`typing` rules are non-finding compiler models for rulepack-declared factory
return types; they must never be used to smuggle API names into the engine.

Validate before reporting:

```shell
./target/release/bonsai-ninja security . pack --validate --format json --no-color --no-progress
./target/release/bonsai-ninja security . pack --audit --context 16k --no-color --no-progress
cargo test -q -p bonsai_security --test rulepack_conformance
```
