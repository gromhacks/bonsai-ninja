---
name: bonsai-ninja
description: "Use bonsai-ninja to map a codebase, find symbols, trace behavior, inspect dataflow, debug across files, export graph facts, and run SAST."
---

# bonsai-ninja

Use this skill when an agent needs structural evidence from a local source
workspace: repository mapping, symbol lookup, cross-file behavior, dataflow,
security review, compiler diagnostics, or graph export.

Do not start with a broad semantic command when a filesystem or syntax query
answers the question. `tree` is a direct filesystem walk; it is not a security
scan.

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

For agent-readable text, normally add:

```text
--context 16k --no-color --no-progress
```

For scripts, normally add:

```text
--format json --no-color --no-progress
```

`index`, `diagnostics`, `dump-hir`, and `dump-cfg` are JSON-only and do not
accept `--format`. Use `--output-path <file>` for large artifacts when the
command supports it. Use `--html-output <file>` only for a standalone human
report; it wraps the selected text view and never enables more analysis.

## Evidence rules

1. Pagination is correctness. Follow `--page next` or the printed `P:...`
   cursor whenever output says more pages exist.
2. Use `--all` only for a tight filter or an intentional exhaustive artifact.
   It changes rendering, not analysis accuracy.
3. Check `analysis_complete` and `analysis_incomplete_reasons` before treating
   an empty result as proof that no path or finding exists.
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
| Workspace and language summary | `context` |
| Text or symbol anchor | `search` |
| Declarations, classes, imports, entry points | `defs`, `classes`, `imports`, `entrypoints` |
| Calls, arguments, references | `calls`, `args`, `refs` |
| Variables, strings, comments, operations | `vars`, `strings`, `comments`, `operations` |
| One target and nearby behavior | `inspect` |
| Call path between two targets | `path` |
| Execution trace from an entry | `trace` |
| Backward influence around a symbol | `slice` |
| One file with optional connected context | `read-file` |
| Reopen stable evidence | `show` |
| Parser, HIR, CFG, resolution, edge, taint internals | `dump-*`, `diagnostics` |
| Security inventory or findings | `security` |
| Downstream graph artifact | `export` |

## Map a repository

Start with shape:

```shell
./target/release/bonsai-ninja context <workspace> --no-color --no-progress
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
./target/release/bonsai-ninja search <workspace> <query> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> <symbol> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee <callee> \
  --context 8k --no-color --no-progress
```

Summarize behavior as:

```text
entry point -> validation -> business logic -> storage/external call -> response or side effect
```

## Trace behavior and dataflow

`inspect` is rulepack-free by default. Add `--graph-flow` for structural
source-backed paths or `--taint-flow` for raw taint paths.

```shell
./target/release/bonsai-ninja inspect <workspace> --query <target> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <target> \
  --taint-flow --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> \
  --from <entry> --to <target> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja path <workspace> \
  --from <entry> --to <target> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry> \
  --context 16k --no-color --no-progress
```

Use qualified `Owner.member` selectors when short method names collide.
`path:name` and `path:line:name` provide file disambiguation. When both ends
are known, prefer the narrowed `--from`/`--to` corridor.

For local evidence:

```shell
./target/release/bonsai-ninja slice <workspace> --symbol <symbol> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B \
  --context 16k --no-color --no-progress
```

`slice` infers the line when one compiler syntax-flow site exists. If it
reports ambiguity, add the printed `--line` and optionally `--file`; it does
not fall back to raw-text matching. `read-file` is file-local by default;
connected or security overlays are explicit options.

## Security review

Start from externally reachable input and prove source-to-sink paths:

```shell
./target/release/bonsai-ninja security <workspace> source-analysis \
  --profile production --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --profile production --context 16k --no-color --no-progress
```

The bundled `production` profile selects remote input, high-severity taint
findings, a 16k context budget, and common non-production path exclusions from
rulepack metadata. Explicit flags override profile values.

Inspect the security model when a finding or gap needs explanation:

```shell
./target/release/bonsai-ninja security <workspace> sources --trust remote \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sinks --severity high \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sanitizers \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> deps --severity high \
  --context 8k --no-color --no-progress
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
./target/release/bonsai-ninja show <workspace> S:<id> \
  --context 16k --no-color --no-progress
```

For every reported issue, retain the finding, flow, and group IDs; exact
source and sink locations; sanitizer status; completion status; and reviewed
page/cursor coverage. A `TAINT TRANSFORM` preserves taint; only a `SANITIZER`
step can support a sanitized classification.

Write SARIF with:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --profile production --format sarif --all \
  --output-path findings.sarif.json --no-color --no-progress
```

## Debug disagreements

Reproduce the smallest high-level mismatch, then descend only as far as
needed:

```shell
./target/release/bonsai-ninja dump-ast <workspace> \
  --file <file> --function <function> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja dump-hir <workspace> <function> \
  --no-color --no-progress
./target/release/bonsai-ninja dump-cfg <workspace> <function> \
  --no-color --no-progress
./target/release/bonsai-ninja dump-resolve <workspace> <callee> \
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

Do not use semantic prewarm for `tree`, `context`, or a single narrow syntax
query. Analysis sidecars live in an OS cache keyed by the canonical workspace,
not in the repository. `<workspace>/.bonsai/rules/` is only a rule overlay.

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

## Rulepack work

Rules live under
`security-patterns/langs/<language>/{sources,sinks,sanitizers,typing}`.
Validate changes with:

```shell
./target/release/bonsai-ninja security . pack --validate --taint-replay \
  --rules-dir security-patterns --format json --no-color --no-progress
./target/release/bonsai-ninja security . pack --audit \
  --rules-dir security-patterns --context 16k --no-color --no-progress
cargo test -q -p bonsai_security --test rulepack_conformance
```

When modifying bonsai-ninja itself, keep syntax in language adapters,
security/API/package meaning in rule data, and shared crates language-neutral.
Do not add framework names or cross-language token inventories to shared
analysis.
