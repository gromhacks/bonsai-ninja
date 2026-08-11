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
Use `--html-output <file>` for a standalone themed human report; it wraps the
selected command's text view and must never enable additional analysis.
For save-time workflows, keep `index <workspace> --watch --no-progress`
running; command and SDK facades refresh saved file changes before they
render.
`index <workspace>` is the syntax/construct warm-up path: it parses source
and builds declaration/import indexes without forcing a whole-workspace
semantic prewarm. Use `index <workspace> --semantic` only when you
intentionally want structural semantic sidecars and
the external workspace-cache `manifest.json` built up front; commands still validate sidecar
headers/payloads before reuse and compute requested exact facts on demand.
Retrieval is candidate lookup only: search and literal-filtered browse can
reuse a fresh sidecar before candidate lookup, and large-workspace inspect can
use a warmed sidecar only before opening a scoped workspace. Rendered facts
still hydrate through canonical APIs, and scoped query workspaces do not
publish partial retrieval sidecars under the full workspace cache.

Analysis sidecars live in a canonical-path-keyed OS cache directory, not in
the inspected repository; `cache stats <workspace>` reports it and
`BONSAI_WORKSPACE_DIR` overrides it. The cache root carries a locked canonical
workspace binding so dependency-manifest freshness cannot be lost when a
sidecar path is outside the source tree. Workspace-local rule overlays remain
under `<workspace>/.bonsai/rules/` and are not analysis caches.

Treat the analyzer as a compiler pipeline. Each language adapter owns its
Tree-sitter grammar, source-syntax recognition, declaration/import lowering,
literal/value node inventories, and `FlowEvent`/capability facts. Shared
analysis consumes that typed IR; do
not add language-id branches, cross-language token inventories, or API-name
guesses to shared crates. Library/package/framework identities and every
security-sensitive value belong in `security-patterns/langs/<lang>`, not in
shared analysis or an adapter; adapters emit generic syntax/capability facts
and rule data assigns their security meaning. Pack-wide package spelling,
review profiles, test-path policy, dependency metadata, and taxonomy live in
`security-patterns/metadata.yml`. The production taint engine is the sparse IDG
fixed-point closure. It has no BFS name search, call-depth ceiling, iteration
limit, or result cap. Paging and diagnostic path limits affect rendering only
and must report truncation explicitly.

`index --semantic` first publishes an immutable content-addressed generation
of per-file compiler objects. Each object is exact adapter-lowered IR plus
diagnostics, validated by path, adapter, frontend ABI, and SHA-256 source
content. Import indexes, direct-call receiver-field initializer linkage, and
compact syntax-target facts (calls, assignment aliases, factory assignments,
inline callbacks, exact assignment/return/call-argument value shapes, typed callables, and
receiver/type evidence) are
integrity-checked compiler headers inside the same generation and must remain
independently decodable from declaration/flow bodies. Broad rule planning
filters raw source anchors, exact import/package headers, and exact syntax
targets in that order before decoding a surviving body. Later phases stream
those objects; they must not reparse source or invent a parallel lowering
path. Rulepack return typing retains its declared imports; exact workspace
values and ordinary functions shadow external `kind: new` models, and mixed
or ambiguous callable identities fail closed. Every derived semantic pipeline
identity includes the compiler-object frontend ABI; a lowering change
invalidates older callgraph/IDG sidecars even when source bytes are unchanged,
and root-only validators reconstruct the same identity as a full workspace
open. Persisted IDG construction lowers transfer facts once, spools typed
stitch records/node maps, and replays them per segment. Memory scheduling may
weight or serialize units, but must never cap semantic work. After the
isolated workers finish, the parent validates that every sidecar describes one
current workspace snapshot and reruns the exact sequence if a file changed
between phases.

When a rulepack-only external type is required for receiver-state transfer,
compile the complete rule match to exact AST call spans before IDG
construction. Include those spans in the transfer fingerprint and graph cache
identity. The IDG may consume that typed span evidence, but must not interpret
the provider, type, or method name itself.
Semantic prewarm also persists the compact function/node directories and
default semantic contextual fixed point derived from that exact graph. Warm
open validates the query accelerator and must not decode every IDG segment to
rebuild those structures. A canonical graph without the optional accelerator
is a valid cold-query artifact, but it does not satisfy `index --semantic`.

External-memory IDG structures must be lazy. Resident-only fixed points start
with empty sparse sets/frontiers; Bloom filters, positive caches, dense
workspace bitsets, and temporary spill files are created only when actual
relation density crosses their representation threshold. Promotion and spill
change storage only, never admitted facts or fixed-point scope. Keep the lazy
allocation tests and conformance invariant: eagerly reserving maximum spill
pages per function is a large-repository performance regression.

Schedule entry-rooted closures from the named non-reclaimable linkage/output
reserve plus the bounded sparse frontier per worker. Do not use live RSS for
this phase: clean file-backed IDG pages are reclaimable and page-cache history
must not serialize identical work. Subject to CPU availability, the
resource-profile tests pin maximum concurrency of ten workers at 3 GiB, two at
2 GiB, and one at 1 GiB. These values schedule concurrency only; every entry
and fixed point remains exact.

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

Security endpoint planning is also staged. Apply raw/import/syntax-target
filters before global receiver ancestry. Open ancestry only when a typed
adapter-emitted call has a matching method whose verdict can change through a
base class, or an explicit receiver-type constraint can change. Rerun those
candidates with the exact base map before body matching. Treat parser coverage
as real per-snapshot state: completion audits run an exact Tree-sitter
syntax-diagnostic pass only for unchecked files; they must not lower
declarations or flow bodies merely to compute `analysis_complete`. Edits
invalidate both parser coverage and compiler diagnostic rows.
Retain exact syntax/import headers for ancestry-deferred candidates and recheck
those headers after enrichment; do not reopen their compiler objects or rerun
already-proven non-deferred plans. Raw workspace reads may overlap in
memory-weighted windows, but VFS publication remains in canonical path order.
Raw-anchor candidate tests run on that bounded pool as read-only planning;
never rescan every file/rule pair serially while the worker pool is idle.
Broad matcher headers and bodies run as continuous CPU worklists behind
source-size-weighted memory permits; small units may overlap while a large
unit consumes more of the same scheduling budget. Derive only the secondary
matcher views demanded by each surviving rule batch (for example decorators,
must-alias closure, runtime narrowing, or lifecycle state), and include that
projection in the derived-fact cache identity. This changes recomputation
only: the compiler object remains complete. Do not reintroduce per-CPU-batch
barriers or eagerly derive every optional view for every candidate body.

Performance gates measure completed exact work; they never terminate, skip, or
cap analysis. When query/cache/engine code changes, build release and run
`cargo test --release -p bonsai_cli --test elasticsearch_large_repo
-- --nocapture` with the sibling checkout (or
`BONSAI_ELASTICSEARCH_ROOT`). The gate enforces warm semantic reuse and
navigation/inspect/security SLOs under a 3 GiB scheduling budget. Update the
measured baseline only for an intentional, reviewed architecture change.
Run exhaustive correctness with the compact test profile (`cargo test
--workspace`), not `cargo test --release --workspace`: ThinLTO-linking every
integration target duplicates the complete language graph and is not a valid
runtime-performance measurement. `scripts/audit-build-artifacts.sh` enforces
the 32 GiB generated-artifact budget; use `cargo clean` when accumulated local
generations exceed it. Release optimization remains required for the CLI build
and the named Elasticsearch SLO target.

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
./target/release/bonsai-ninja inspect <workspace> --query <target> --taint-flow --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
./target/release/bonsai-ninja show <workspace> F:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry-function> --context 16k --no-color --no-progress
./target/release/bonsai-ninja slice <workspace> --symbol <symbol> --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
```

Use qualified `Owner.member` trace selectors when short method names collide;
`path:name` and `path:line:name` provide exact file disambiguation. When both
endpoints are known, prefer `trace --from <entry> --to <target>`: declared
endpoints are projected to the complete compiler-resolved graph corridor
before symbolic interpretation, without interpreting sibling branches first.

For `slice`, omit `--line` when the symbol has one compiler syntax-flow site.
If the result reports ambiguity, add the printed `--line` and optionally
`--file`; the command never falls back to raw-text matching.

`inspect` is rulepack-free by default and renders indexed syntax facts. Use
`--graph-flow` to add structural source-body evidence and `--taint-flow` to
explicitly add rulepack-free raw taint paths. These flags change output scope,
not analysis accuracy: emitted graph facts still use the exact/narrowed static
evidence contract. Inspect raw taint paths go through the workspace syntax-flow
facade. Syntax discovery records exact matching Tree-sitter spans and releases
body/callgraph caches before a persisted IDG opens. A warm query batch resolves
those spans to typed target nodes and reuses one sparse backward demand proof;
a sidecar miss builds an exact query-scoped source/target IDG, with the
canonical cached dataflow graph retained only as the compatibility fallback.
Broad raw-flow reports compute every exact path before pagination, reuse
worker-precomputed row costs, and format/cache only the requested page. Follow
the printed page or cursor for more; page 1 never eagerly renders later pages.

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

The bundled rulepack's `--profile production` sets remote-trust defaults,
`severity high` for taint findings, `context 16k`, and excludes common
non-production paths:
tests, specs, fixtures, mocks, samples, examples, demos, e2e/integration
harnesses, vendored deps, package caches, build outputs, generated code,
docs, scripts, deploy files, migrations, and language-specific test
layouts. These values and test conventions come from
`security-patterns/metadata.yml`. Use `--exclude-tests` alone when you want only the narrower
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

`security sanitizers` lists only matched rules that can make a
credit-bearing sanitizer claim. Passthrough transforms and generic
non-crediting validation markers remain available to flow analysis but do not
appear as sanitizer inventory.

Filter findings by rule class:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --severity high --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --tag command-injection --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --source <source-rule> --sink <sink-rule> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --flow F:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --group G:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --format sarif --all --output-path findings.sarif.json --no-color --no-progress
```

For each issue, cite `S:` finding id, `F:` flow id, `G:` group id, source line, sink
line, sanitizer status, and the exact page/cursor coverage reviewed.
Security `F:` ids are taint-path flow ids and security `G:` ids are
taint-path group ids; reopen them with `show F:<id>` / `show G:<id>` or
`security taint-analysis --flow F:<id>` / `--group G:<id>`. Use
`inspect --flow` / `inspect --group` for structural ids printed by
code-navigation commands.

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
