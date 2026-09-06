---
name: bonsai-ninja
description: "Use bonsai-ninja as compiler-backed structural evidence when mapping a codebase, finding symbols, tracing behavior, inspecting dataflow, debugging across files, reviewing change impact, exporting graph facts, or running SAST."
---

# bonsai-ninja

Use this skill when an agent needs structural evidence from a local source
workspace: repository mapping, symbol lookup, cross-file behavior, dataflow,
security review, compiler diagnostics, or graph export.

Do not start with a broad semantic command when a filesystem or syntax query
answers the question. `tree` is a direct filesystem walk; it is not a security
scan.

## Role in an agent workflow

Use Bonsai to reduce repository-navigation turns and the amount of source that
must enter model context. Ask one concrete structural question, run the
smallest command that can answer it, and pivot from returned symbols or stable
IDs. Do not invoke Bonsai merely because it is available.

Bonsai provides static evidence; it does not replace code reasoning, direct
source inspection, compilation, tests, logs, or a runtime debugger. Verify a
conclusion with the narrowest relevant source and executable check before
editing or reporting it. If one command does not narrow the question, change
the selector or evidence type instead of repeating the same broad query.

Prefer ordinary filesystem or shell tools when the relevant file is already
known and the question is purely local. Prefer Bonsai when identity,
reachability, cross-file relationships, dataflow, or security semantics would
otherwise require manually reading many files.

## Command truth

The installed binary is authoritative. Check help before using an unfamiliar
command or flag:

```shell
./target/release/bonsai-ninja --help
./target/release/bonsai-ninja <command> --help
./target/release/bonsai-ninja security --help
./target/release/bonsai-ninja security <workspace> <command> --help
```

Prefer `./target/release/bonsai-ninja`; use the debug binary only when release
is unavailable.

Keep the workspace as the positional operand. Prefer explicit selector flags
(`--query`, `--symbol`, `--file`, `--from`, `--to`, `--id`) in agent and
script invocations; concise positional selectors remain supported for humans,
but the CLI rejects supplying both forms. Use `-o`, `--output`, or
`--output-path` for files.

For agent-readable text, normally add:

```text
--context 16k --no-color --no-progress
```

For scripts, normally add:

```text
--format json --no-color --no-progress
```

`index`, `diagnostics`, `dump-hir`, and `dump-cfg` print readable text by
default and one structured object with `--format json`; pass `--format json`
explicitly before piping to `jq`. Use `--output-path <file>` for large
artifacts when the command supports it. Use `--html-output <file>` for a human
report rendered from the command's canonical JSON result; it never enables
more analysis.
Browse locations use one-based byte columns as well as lines. Keep the full
locator when reopening a row: separate writes, references, or neighboring
functions can share a line. Enclosing-function labels and cross-module
`used in` evidence use the exact location, not the first name on that line.
For `vars`, review the complete `source_names` list of a matching write;
multiple RHS projections are not multiple writes or a proven taint path.
Check `used_in_complete` separately from syntax `analysis_complete`. A cold
file-scoped view can lack cross-module caller evidence; `index <workspace>
--semantic` makes the full validated relation available without expanding
the syntax query. An unavailable relation is not proof of no callers.
Class summaries and uses refer to compiler-owned members of that exact type,
not unrelated methods with the same short name.
`read-file` reports call-evidence coverage as `connections.calls_complete`;
source syntax coverage alone does not prove that every cross-file relation
was available. Reopen after semantic prewarm when that relation is needed.
When investigating cache discrepancies, compare a normal invocation with
`--no-cache`: the selected source, declarations, and locations must agree.
Full `diagnostics` performs one exact streaming compiler-object pass. Stable
`show E:<id>` drilldown uses the persisted exact edge directory; neither
command requires a duplicate whole-workspace lowering or edge scan.

## Evidence rules

1. Pagination is correctness. Follow `--page next` or the printed `P:...`
   cursor whenever output says more pages exist.
2. Use `--all` only for a tight filter or an intentional exhaustive artifact.
   It changes rendering, not analysis accuracy.
3. Check `analysis_complete` and `analysis_incomplete_reasons` before treating
   an empty result as proof that no path or finding exists.
   For security overlays, check report-level completion even when there are
   no findings. Intentional file filters and incomplete analysis are distinct.
4. Preserve stable IDs (`S:`, `F:`, `G:`, `T:`, `E:`, `R:`, `N:`) and reopen
   them with `show` or the command that emitted them.
5. Use `search` to find an anchor, then pivot to compiler facts. Text matches
   alone do not prove identity, reachability, or taint.
6. Narrow by file, function, symbol, source, sink, rule, tag, or severity
   before requesting exhaustive output.

## Choose the smallest command

| Need | Command |
|---|---|
| Files and directories | `tree` |
| Workspace and language summary | `index` (prints the workspace `context`) |
| Text or symbol anchor | `search` |
| Declarations, classes, imports, entry points | `defs`, `classes`, `imports`, `entrypoints` |
| Calls, arguments, references | `calls`, `args`, `refs` |
| Variables, strings, comments, operations | `vars`, `strings`, `comments`, `operations` |
| One target, nearby behavior, and its bounded compiler packet | `inspect-graph --query` |
| Exact compressed corridor between two targets | `inspect-graph --from ... --to ...` |
| Backward influence around a symbol | No CLI command: `inspect-graph --query` on the symbol plus `refs` / `vars` for read and write sites; the SDK `slices` API for programmatic slices |
| One file with optional connected context | `read-file` |
| Reopen stable evidence | `show` |
| Parser, HIR, CFG, resolution, edge, taint internals | `dump-*`, `diagnostics` |
| Security inventory or findings | `security` |
| Downstream graph artifact | `export` |

## Map a repository

For an unfamiliar repository, start with only the shape needed for the task.
Usually `index` plus a shallow `tree` is enough; add imports, entry points, or
declarations only when they help answer the current question:

```shell
./target/release/bonsai-ninja index <workspace> --no-color --no-progress --format json
./target/release/bonsai-ninja tree <workspace> --max-depth 3 \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja entrypoints <workspace> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --kind function \
  --context 16k --no-color --no-progress
```

Find one concrete anchor, then inspect its relationships:

```shell
./target/release/bonsai-ninja search <workspace> --query <query> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> --symbol <symbol> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee <callee> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja inspect-graph <workspace> --query <symbol> \
  --context 16k --no-color --no-progress
```

Summarize behavior as:

```text
entry point -> validation -> business logic -> storage/external call -> response or side effect
```

## Trace behavior and dataflow

`inspect-graph` is rulepack-free. It attaches one bounded compiler evidence
unit (a stable `F:` flow) to every matching callable and expands every raw
taint flow through a match into its full call stack.

For lookup, start with plain `inspect-graph`, `refs`, or `calls`. Each
`inspect-graph` declaration hit is a self-contained packet with source,
signature, imports, direct resolved callers/callees (stable `E:` edge ids),
and explicit external calls; it never enumerates transitive caller/callee
paths. When both endpoints are known, use `inspect-graph --from ... --to ...`
for the exact compressed compiler corridor.

```shell
./target/release/bonsai-ninja inspect-graph <workspace> --query <target> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect-graph <workspace> \
  --from <entry> --to <target> \
  --context 16k --no-color --no-progress
```

Use qualified `Owner.member` selectors when short method names collide. When
both ends are known, prefer the narrowed `--from`/`--to` corridor.

For local evidence:

```shell
./target/release/bonsai-ninja refs <workspace> --symbol <symbol> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja vars <workspace> --name <symbol> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> --file <path> --lines A:B \
  --context 16k --no-color --no-progress
```

There is no CLI backward slice. For "what influences this symbol?", combine
`inspect-graph --query <symbol>` with `refs` / `vars` for its read and write
sites; the SDK `slices` API remains available for programmatic slices.
`read-file` is file-local by default;
connected or security overlays are explicit options.
Prefer an exact workspace-relative file path. An ambiguous suffix is not a
unique file selector and must be narrowed instead of choosing the first match.

## Security review

Start from externally reachable input and prove source-to-sink paths:

```shell
./target/release/bonsai-ninja security <workspace> source-analysis \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sink-analysis \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --context 16k --no-color --no-progress
```

The bundled `production` profile is the default. It selects remote input,
every sink severity, a 16k context budget, and common non-production path
exclusions from rulepack metadata. Add `--severity <level>` only when an
explicit severity floor is wanted. Separately, compiler-backed commands
exclude adapter-classified minified JavaScript/TypeScript before parsing,
graph construction, security, and export. Use global `--minified-js` when
bundle internals are intentionally in scope. Use `--profile all
--minified-js` together for an unfiltered security audit over every supported
source representation. `tree` is a direct filesystem view and remains
unfiltered. Explicit security flags override profile values.

Inspect the security model when a finding or gap needs explanation:

Use `source-analysis` for “where can this input go?”, `sink-analysis` for
“what compiler-proven value lineage feeds each dangerous endpoint?”, and
`dependency-analysis` for “which source-to-sink taint flows cross this flagged
package, and where is it imported, bound, called, or matched by a rule?”
(`deps` is the one-row-per-package inventory behind it). Dependency flows
include source, sink, and exact propagation evidence, not merely package-name
matches. Check each subcommand's help for selectors: profile, trust, and
source/sink flags are not shared by every security command. Filters narrow
the requested view or analysis scope; they never make the admitted facts
less exact.
Sink-analysis does not require a security source: `upstream_flows` is
source-independent, while `security_source_flows` separately answers which
selected security sources reach the endpoint.

```shell
./target/release/bonsai-ninja security <workspace> sources --trust remote \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sinks --severity high \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sanitizers \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> deps --severity high \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> dependency-analysis \
  --framework <package> --context 16k --no-color --no-progress
```

Narrow and reopen findings:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --source <source-rule> --sink <sink-rule> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --flow F:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --group G:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja show <workspace> --id S:<id> \
  --context 16k --no-color --no-progress
```

For every reported issue, retain the finding, flow, and group IDs; exact
source and sink locations; sanitizer status; completion status; and reviewed
page/cursor coverage. A `TAINT TRANSFORM` preserves taint; only a `SANITIZER`
step can support a sanitized classification.
Use `taint-analysis --show-sanitized` when reviewing that classification.
Check the exact guard's comparison polarity, binding ownership, and execution
order; a similar-looking check or configuration after consumption is not a
proof. A reassigned value or a same-named binding in another module or callback
cannot borrow the original guard. A rejection must actually exit the guarded
path; a conditional return or a return inside a callback is not sufficient.
Do not infer rejection from a callee's name: a response method or an
exit-named helper may return normally. Loop transfers do not make later
unreachable returns or throws into guard evidence.
Compound allowlist checks must require every predicate, and the checked object,
allowlist, and security configuration must remain unchanged until consumption.
For finite allowlists, inspect every selected
output: a string containing runtime interpolation is not a literal constant.
When changing guard support, retain a valid case and a one-condition-broken
regression that still exposes the source-to-sink flow.
For predicate guards, trace the exact call result through the complete boolean
condition. An unknown wrapper does not preserve predicate truth, and non-null
does not generally mean truthy. A stronger result-domain contract must come
from the matched rule, not a shared method-name guess. Keep comparison and
wrapper near-misses in the end-to-end security tests.

Write SARIF with:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --format sarif --all \
  --output-path findings.sarif.json --no-color --no-progress
```

## Debug disagreements

For dependency inventory, check the evidence for each package individually.
A generic manifest or lockfile filename is not proof that every provider on
a multi-framework rule is installed. Use `security dependency-analysis` to
inspect that package's usage sites and complete source-to-sink flows.

Reproduce the smallest high-level mismatch, then descend only as far as
needed:

```shell
./target/release/bonsai-ninja dump-ast <workspace> \
  --file <file> --function <function> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja dump-hir <workspace> --symbol <function> \
  --no-color --no-progress
./target/release/bonsai-ninja dump-cfg <workspace> --symbol <function> \
  --no-color --no-progress
./target/release/bonsai-ninja dump-resolve <workspace> --name <callee> \
  --in-file <file> --no-color --no-progress
./target/release/bonsai-ninja dump-edges <workspace> \
  --from <caller> --to <callee> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja dump-taint <workspace> \
  --source <entry> --seed <parameter> --no-color --no-progress
./target/release/bonsai-ninja diagnostics <workspace> \
  --no-color --no-progress
```

After a patch, rerun the smallest command that proves the fix before the
broader test suite.

For sanitizer disagreements, inspect the exact checked and consumed values,
comparison direction, binding ownership, and intervening operations. A numeric
upper bound does not establish nonnegativity, and filtering one array element
does not constrain another. Verify provider/type/boundary evidence against the
rule, then retain a safe case and a one-condition-broken unsafe case in tests.

## Index and cache only when useful

Commands compute exact requested facts on demand. Prewarm when a workspace
will receive repeated queries:

```shell
# Syntax/declaration warm-up.
./target/release/bonsai-ninja index <workspace> --no-progress

# Reusable semantic sidecars for repeated broad semantic work.
./target/release/bonsai-ninja index <workspace> --semantic --no-progress

# Refresh saved changes during an editing session.
./target/release/bonsai-ninja index <workspace> --watch --no-progress

# Inspect validated external cache state.
./target/release/bonsai-ninja cache stats <workspace> \
  --format json --no-color --no-progress
```

Do not use semantic prewarm for `tree`, `index`, or a single narrow syntax
query. Analysis sidecars live in an OS cache keyed by the canonical workspace,
not in the repository. `<workspace>/.bonsai/rules/` is only a rule overlay.
Inspect `cache stats` before cleanup. `cache clear --legacy` removes only
recognized inactive in-tree analysis files, preserving rules and unknown data;
never replace it with recursive deletion of `.bonsai`. Ordinary `cache clear`
requires a workspace-bound cache and refuses project roots or unknown entries.
`cache clear --orphans` removes only attributed caches whose source root is
confirmed missing; age or a missing manifest alone is not enough.
Root-only SDK manifest publication binds the cache before writing; inspection
and cleanup must never create a binding merely to permit deletion.
Repeated default `index` runs validate the compiler generation root-only and
do not reopen source bodies; a stale generation is rebuilt exactly.

## Export

Use native JSON when downstream tooling needs the complete graph:

```shell
./target/release/bonsai-ninja export <workspace> --format json \
  --output-path bonsai-export.json --no-color --no-progress
```

Use `networkx`, `graphml`, or `cypher` only when the consumer requires that
projection. Request `--full-propagations` only when a consumer explicitly
needs materialized per-entry propagation rows; the default compressed graph
representation remains exact.

Treat a whole-workspace native export as a bulk artifact, not agent-readable
prompt text. It can be multi-gigabyte on a production repository, so write it
with `--output-path` and let downstream code stream or index it. Do not request
`--full-propagations` merely to improve accuracy; it changes representation
only.

Native JSON documents identify themselves as `bonsai-native-export` plus a
numeric `schema_version` (currently 13). Validate artifacts against
`schemas/bonsai-native-export-v13.schema.json`; release archives include the
same Draft 2020-12 schema.
Version 13 adds `predicate_call_span` to call-backed type-test conditions.
This is the same canonical callee identity used by call events; the tested
value and an outer wrapper's result are distinct evidence. Never infer a
successful predicate merely because its call occurs inside a condition.
Class rows also retain their exact byte column in `classes[].column`.

## Rulepack work

Rules live under
`security-patterns/langs/<language>/{sources,sinks,sanitizers,typing}`.
Ordinary security commands use the immutable rulepack embedded in the binary,
so they work from any current directory. Pass `--rules-dir` only when selecting
an editable/custom base pack; an invalid explicit path fails instead of falling
back. Workspace-local `.bonsai/rules/` overlays remain additive.
Validate changes with:

```shell
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns --format json --no-color --no-progress
./target/release/bonsai-ninja security . pack --audit \
  --rules-dir security-patterns --context 16k --no-color --no-progress
cargo test -q -p bonsai-ninja-security --test rulepack_conformance
```

When modifying bonsai-ninja itself, keep syntax in language adapters,
security/API/package meaning in rule data, and shared crates language-neutral.
Do not add framework names or cross-language token inventories to shared
analysis.
Compiler-object reuse requires the current frontend ABI as well as exact
source identity. Rebuild incompatible generations through the adapters;
rewriting an old cache header is not a valid compiler migration.
Keep a fresh release CLI for integration tests, and do not edit Rust files
while Cargo builds or tests are running. Use the compact `cargo test
--workspace` correctness profile; reserve release-mode tests for the named
Elasticsearch performance gate. Use command-local `--no-progress` instead of
exporting `NO_PROGRESS` into the Cargo test environment.
Update the public API snapshot when crate-root exports change, and run
`bash scripts/audit-public-api.sh --check`. This is only a root-declaration
drift check: it does not replace SDK contract tests or verify nested public
fields, methods, or resolved re-exports.
