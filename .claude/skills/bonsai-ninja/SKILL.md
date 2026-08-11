---
name: bonsai-ninja
description: "Use bonsai-ninja to map a codebase, find symbols, trace behavior, inspect dataflow, debug across files, export graph facts, and run SAST."
---

# bonsai-ninja

Use this skill when you need structural code intelligence from a local
workspace:

- understand an unfamiliar repository;
- find declarations, references, imports, callers, arguments, or entry points;
- follow behavior across functions and files;
- inspect source-to-target dataflow;
- debug resolution, CFG, HIR, callgraph, or taint behavior;
- review security sources, sinks, sanitizers, dependencies, and findings;
- export exact graph facts for downstream tooling.

Do not use `tree` as a security scan. It is a fast filesystem view only.

## Command Truth

Read help from the binary before relying on an unfamiliar option:

```shell
./target/release/bonsai-ninja --help
./target/release/bonsai-ninja <command> --help
./target/release/bonsai-ninja security --help
./target/release/bonsai-ninja security <workspace> <command> --help
```

Prefer `./target/release/bonsai-ninja`. Use the debug binary only when release
does not exist.

For agent-readable text, normally add:

```text
--context 16k --no-color --no-progress
```

For scripts and structured inspection, normally add:

```text
--format json --no-color --no-progress
```

JSON-only compiler reports (`index`, `diagnostics`, `dump-hir`, and
`dump-cfg`) already emit JSON and intentionally have no `--format` switch;
use only `--no-color --no-progress` with those commands. `diagnostics` reports
capabilities only for adapters present in the workspace, so its payload stays
proportional to the repository being inspected.

Use `--output-path <file>` for large artifacts instead of shell redirection
when the command supports it.
Use `--html-output <file>` only when a human-readable standalone report is
the desired artifact; it preserves the selected command's scope and adds no
analysis work.

## Non-Negotiable Reading Rules

1. Pagination is part of correctness. If output reports another page, follow
   `--page 2`, `--page next`, or the printed `P:...` cursor before claiming
   complete coverage.
2. Use `--all` only for a narrow filter or an intentionally exhaustive
   artifact. It changes rendering scope, not analysis accuracy.
3. Check `analysis_complete` and `analysis_incomplete_reasons` in structured
   output. Never describe an incomplete result as proof that no path or issue
   exists.
4. Preserve stable IDs such as `S:`, `F:`, `G:`, `T:`, `E:`, `R:`, and `N:`.
   Reopen them with `show` or the command that emitted them.
5. Prefer structured facts over text search once you have an anchor.
6. Narrow first. Add file, function, symbol, rule, source, sink, tag, or
   severity filters before requesting an exhaustive result.

## Indexing Strategy

Commands can compute exact requested facts on demand. Indexing is useful when
you will issue several queries:

```shell
# Syntax and construct warm-up. This is the normal default.
./target/release/bonsai-ninja index <workspace> --no-progress

# Warm reusable semantic sidecars for repeated inspect/security/export work.
./target/release/bonsai-ninja index <workspace> --semantic --no-progress

# Keep saved-file changes warm during an editing session.
./target/release/bonsai-ninja index <workspace> --watch --no-progress
```

Do not use `--semantic` merely to run `tree`, `context`, or one narrow syntax
query. Semantic prewarm publishes a validated query-ready IDG representation;
warm semantic commands reuse it instead of rebuilding the default fixed point
from every source segment.

Warm sidecars are accelerators, never authority. Their identity includes the
source snapshot, adapter/compiler frontend ABI, dependency metadata, transfer
semantics, and rule-selected graph options; a mismatch is rejected and rebuilt
without narrowing semantic work.

Compiler objects retain exact callback/type syntax headers and direct-call
receiver-field initializer linkage. Adapters prove syntax; complete-workspace
linking resolves class/constructor identity. Neither capitalization nor callee
spelling alone is type evidence. Rulepack typing keeps its import constraints,
and exact workspace values/functions shadow external `kind: new` models; the
matcher fails closed on mixed or ambiguous callable identities.

Compiler objects also retain adapter-owned assignment, return, and
call-argument value shapes. A literal/static fact may prove a clean output
value; a carrier-free unknown expression, rendered text, and ALL_CAPS spelling
never do.

Rulepack-only receiver types are compiled through the canonical matcher into
exact AST call spans before IDG construction. Those spans participate in the
transfer fingerprint; the IDG consumes the proven sites and never interprets
provider, class, or method spellings. Import and workspace-shadowing checks
therefore remain exact in both warm and cold analysis.

Persisted analysis artifacts live in a canonical-path-keyed OS cache, not in
the repository. `cache stats <workspace>` prints the exact directory;
`BONSAI_WORKSPACE_DIR` supplies an explicit override. The repository-local
`<workspace>/.bonsai/rules/` path is only a rule overlay.
Current compiler-object publication prunes unlocked older recognized schema
generations automatically. Use `cache clear <workspace>` only when you
intentionally want to discard every reusable sidecar; it never changes source.

When this skill is used to modify bonsai-ninja itself, preserve the compiler
boundary: adapters own Tree-sitter syntax lowering, including literal/value
node inventories; rulepack YAML owns
library/package/framework identities and security-sensitive values; shared
crates consume typed facts without language-id or API-name branches.

## Choose The Smallest Command

| Need | Start with |
|---|---|
| Files and directories | `tree` |
| Workspace/language summary | `context` |
| Text, symbol, route, error, config, or API anchor | `search` |
| Declarations | `defs` |
| Classes and methods | `classes` |
| Imports | `imports` |
| Entry points | `entrypoints` |
| Call sites | `calls` |
| Call arguments | `args` |
| References to a symbol | `refs` |
| Variables, strings, comments, or operations | `vars`, `strings`, `comments`, `operations` |
| One target with surrounding behavior | `inspect` |
| Call path between two targets | `path` |
| Execution trace from an entry | `trace` |
| Local influence around a source location | `slice` |
| Source file with connected context | `read-file` |
| Reopen a stable result ID | `show` |
| Parser/HIR/CFG/resolution/edge/taint internals | `dump-*` |
| Full downstream graph artifact | `export` |
| Security review | `security` |

## Map An Unfamiliar Repository

Start with shape, then follow one real behavior:

```shell
./target/release/bonsai-ninja context <workspace> \
  --no-color --no-progress
./target/release/bonsai-ninja tree <workspace> --max-depth 3 \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja entrypoints <workspace> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --kind function \
  --context 16k --no-color --no-progress
```

Find a concrete anchor:

```shell
./target/release/bonsai-ninja search <workspace> <query> \
  --context 8k --no-color --no-progress
```

Then pivot to semantic facts:

```shell
./target/release/bonsai-ninja refs <workspace> <symbol> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee <callee> \
  --context 8k --no-color --no-progress
```

Record the behavior as:

```text
entry point -> validation -> business logic -> storage/external call -> response or side effect
```

## Understand Behavior And Dataflow

Use `inspect` for the combined view:

```shell
./target/release/bonsai-ninja inspect <workspace> --query <target> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> \
  --from <entry> --to <target> \
  --context 16k --no-color --no-progress
```

Choose scope deliberately:

- The default is a rulepack-free syntax/index view. It does not run taint
  analysis.
- `--graph-flow` adds structural call-graph paths and source-body evidence.
- `--taint-flow` explicitly adds rulepack-free raw taint-engine paths.
- On a large repository, run `index <workspace> --semantic` before repeated
  broad `--taint-flow` queries. Inspect still starts from the exact matching
  syntax spans and pages only after all requested semantic work completes;
  `--all` is never a performance or accuracy switch.
- Broad raw-flow reports compute the complete exact result before paging, but
  format and cache only the requested page. Continue with the printed page or
  cursor; requesting page 1 does not eagerly render unrelated future pages.
- Use `--compact` with graph flows when you need path steps without inlined
  source bodies.
- Reopen a structural `F:` or `G:` with `show` in the same workspace. Fresh
  page metadata restores the original scoped query, so `show` does not need a
  broad security scan. If an old ID has no provenance, rerun the narrowed
  `inspect --query ... --graph-flow` command first.

Use focused commands when you need one relation:

```shell
./target/release/bonsai-ninja path <workspace> \
  --from <entry> --to <target> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry-function> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja slice <workspace> --symbol <symbol> \
  --context 16k --no-color --no-progress
```

`slice` resolves an unambiguous compiler syntax-flow site from the symbol.
Add `--line <N>` and, if needed, `--file <path>` only when the output reports
multiple candidate sites. A missing or ambiguous site is explicit incomplete
analysis, never a raw-text fallback.

`read-file --all` disables output paging only. It does not enable security or
whole-workspace graph work; request overlays explicitly, and use
`--max-inlined-bodies 0` only when every connected body is intentional.
Without `--rules-dir`, `--from`, `--to`, or `--max-inlined-bodies`, it is a
file-local compiler-object view and does not build a callgraph or IDG.

For standalone structural endpoint queries, use qualified `Owner.member`
spellings when methods share a short name. `inspect --from Source.run --to
Target.run` resolves the compiler identities as sets and keeps only the exact
connected corridor. `trace <workspace> Owner.member` uses the same
adapter-emitted qualified identity; use `path:name` or `path:line:name` when
file/line disambiguation is needed. A declared `trace --from/--to` pair is
projected to its complete graph corridor before symbolic interpretation; use
that shape instead of a broad entry trace when the question already names a
target. `dump-resolve --in-file` accepts and reports workspace-relative
paths. Pass the exact adapter-lowered call spelling (for example
`self.inner.spawn`) to join that syntax site to the canonical callgraph; add
`--line` only when repeated spellings resolve differently. Compiler-qualified
identities printed by `defs` can be passed directly to `dump-hir` and
`dump-cfg`.

## Debug A Code-Intelligence Disagreement

First reproduce the mismatch with the smallest high-level command. Then walk
down this ladder only as far as necessary:

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
  --source <entry> --seed <parameter> \
  --no-color --no-progress
```

After a patch, rerun the smallest command that proves the fix before running
the broader suite.

## Security Review

Start from reachable input and then prove source-to-sink paths:

```shell
./target/release/bonsai-ninja security <workspace> source-analysis \
  --profile production --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --profile production --context 16k --no-color --no-progress
```

The bundled rulepack's `--profile production` applies remote-input defaults, a
high-severity taint threshold, a 16k context window, and common non-production
path exclusions. Profile values and test-path conventions come from
`security-patterns/metadata.yml`; explicit CLI flags override them.
Use `--exclude-tests` when you only want the narrower test-path exclusion.

Inventory the model when a finding or gap needs explanation:

```shell
./target/release/bonsai-ninja security <workspace> sources \
  --trust remote --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sinks \
  --severity high --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sanitizers \
  --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> deps \
  --severity high --context 8k --no-color --no-progress
```

Dependency evidence paths are complete and workspace-relative. Preserve the
whole path when citing or filtering them; do not shorten nested monorepo paths
to their final components.

`security sanitizers` lists only matched rules that can make a
credit-bearing sanitizer claim. Rulepack declarations that preserve taint or
carry a generic non-crediting validation marker remain available to the flow
engine, but appear as `TAINT TRANSFORM` evidence in findings rather than as
sanitizer inventory rows.

Narrow findings:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --tag command-injection \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --source <source-rule> --sink <sink-rule> \
  --context 16k --no-color --no-progress
```

For each reported issue, retain:

- `S:` finding ID;
- `F:` taint-path ID;
- `G:` finding-group ID;
- source and sink file/line;
- sanitizer status;
- precision and completeness;
- reviewed page or cursor coverage.

Treat `TAINT TRANSFORM` / `taint-transform` steps as propagation evidence,
not sanitization. Only `SANITIZER` steps and `sanitizer_rule_ids` can explain a
sanitized status.

Reopen evidence:

```shell
./target/release/bonsai-ninja show <workspace> S:<id> \
  --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --flow F:<id> --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --group G:<id> --context 16k --no-color --no-progress
```

For CI artifacts:

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis \
  --profile production --format sarif \
  --all --output-path findings.sarif.json \
  --no-color --no-progress
```

## Rulepack Work

Rules live under:

```text
security-patterns/langs/<language>/{sources,sinks,sanitizers,typing}
```

Validate and audit before reporting rule changes:

```shell
./target/release/bonsai-ninja security . pack --validate \
  --format json --no-color --no-progress
./target/release/bonsai-ninja security . pack --audit \
  --context 16k --no-color --no-progress
cargo test -q -p bonsai_security --test rulepack_conformance
```

Do not enable generic print, log, join, or parse patterns without a
security-specific constraint. `typing` rules model compiler return types; they
do not emit findings.

## Export

Use native JSON when downstream tooling needs the full exact graph:

```shell
./target/release/bonsai-ninja export <workspace> \
  --format json --output-path bonsai-export.json \
  --no-color --no-progress
```

Request `--full-propagations` only when the consumer truly requires
materialized per-entry propagation rows; the normal artifact carries the
exact compiled graph representation without that much larger row product.
