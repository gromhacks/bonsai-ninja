---
title: Bonsai Ninja Command Reference
description: Detailed CLI command surface for bonsai-ninja.
---

# Command Reference

Use this when you need the detailed filter surface for a
`bonsai-ninja` command. Prefer `./target/release/bonsai-ninja` when it
exists.

## Global Flags

```shell
--no-color
--theme <moss|bonsai|forest|earthy-dark|dracula|retro-amber>
--no-cache
--no-progress
-h, --help
-V, --version
```

Agent defaults:

- Text review: `--no-color --no-progress --context 16k`.
- Scripts and exact counts: `--format json --no-color --no-progress`.
- Index before inspect, trace, security, export, and debug work:
  `index <workspace> --no-progress`.

## Formats

| command family | formats |
|---|---|
| Browse, inspect, security inventories, source-analysis, pack, dump-callgraph, dump-edges, dump-ast, dump-taint | `--format text`, `--format json` |
| `security taint-analysis` | `--format text`, `--format json`, `--format sarif` |
| `security source-analysis` | `--format text`, `--format json` |
| Trace | `--format text`, `--format json`, `--format dot` |
| Export | `--format json`, `--format networkx`, `--format graphml`, `--format cypher` |
| HIR and CFG dumps | JSON-only |

SARIF is SARIF 2.1.0 and carries bonsai stable IDs in
`properties.bonsai`.

## Pagination

Treat pagination as correctness:

- If a footer says more pages exist, continue with `--page 2`,
  `--page next`, or the printed `P:xxxxxxxx` cursor.
- Include page coverage in reports.
- Do not summarize a large command as complete after page 1.
- `--all` is for tight filters or explicit exhaustive artifacts.

## Workspace And Cache

| command | purpose | key switches |
|---|---|---|
| `index <workspace>` | Build parsed facts and persisted dataflow. | `--no-progress` |
| `export <workspace>` | Dump the full graph for downstream tooling. | `--format json|networkx|graphml|cypher`, `--full-propagations` |
| `cache stats [workspace]` | Show cache config and dataflow sidecar status. | optional workspace |
| `cache clear [workspace]` | Remove on-disk sidecars. | `--dataflow-only` |
| `cache rebuild [workspace]` | Clear and rebuild persisted graph. | optional workspace |

## Browse Commands

All browse commands support text/JSON and pagination unless noted.
Most support `--context`, `--page`, `--all`, and `--limit`.

| command | purpose | high-value filters |
|---|---|---|
| `defs` | Declarations. | `--kind`, `--file`, `--name`, `--has-callee`, `--has-decorator`, `--has-param`, `--regex`, `--no-flows` |
| `calls` | Call sites. | `--callee`, `--file`, `--caller`, `--call-kind`, `--regex`, `--no-flows` |
| `imports` | Imports/includes/aliases/requires. | `--file`, `--module`, `--alias`, `--wildcard`, `--regex`, `--no-flows` |
| `vars` | Assignment targets and simple sources. | `--name`, `--file`, `--in-fn`, `--source`, `--regex`, `--no-flows` |
| `strings` | String and char literals. | `--category`, `--contains`, `--file`, `--in-fn`, `--min-len`, `--regex`, `--no-flows` |
| `comments` | Comment nodes and classifications. | `--kind`, `--contains`, `--file`, `--in-fn`, `--min-len`, `--regex` |
| `args` | Call arguments. | `--callee`, `--file`, `--in-fn`, `--value`, `--position`, `--keyword`, `--regex`, `--no-flows` |
| `classes` | Classes, structs, traits, interfaces, enums. | `--name`, `--file`, `--kind`, `--has-method`, `--min-methods`, `--regex`, `--no-flows` |
| `refs` | References to a symbol. | positional symbol or `--symbol`, `--kind`, `--file`, `--in-fn`, `--regex`, `--no-flows` |
| `search` | Prefix-first fuzzy search across indexed facts. | positional query or `--query`, `--kind`, `--file`, `--regex`, `--no-flows` |

## Connected Views

| command | purpose | high-value filters |
|---|---|---|
| `tree` | Workspace tree with finding/flow annotations and cross-file edge overlays. | `--max-depth`, `--file`, `--exclude-file`, `--severity`, `--compact`, `--rules-dir`, `--context`, `--page`, `--all`, `--limit`, `--format` |
| `read-file` | Single-file source view with marks, findings, flows, callers, and callees. | `--lines`, `--from`, `--to`, `--max-inlined-bodies`, `--compact`, `--rules-dir`, `--context`, `--page`, `--all`, `--format` |

`--exclude-file` is accepted by `tree`, `read-file`, and `security`
commands. Browse fact commands use `--file`.

## Inspect

Use `inspect` for patternless traversal over indexed facts plus flows
that reach them.

```shell
./target/release/bonsai-ninja inspect <workspace> --query <target>
./target/release/bonsai-ninja inspect <workspace> <positional-query>
./target/release/bonsai-ninja inspect <workspace> --query <module> --kind import
./target/release/bonsai-ninja inspect <workspace> --query <symbol> --kind decl
./target/release/bonsai-ninja inspect <workspace> --query <classname> --kind class
./target/release/bonsai-ninja inspect <workspace> --query <callee> --kind call
```

Key filters:

- `--query` or positional query.
- `--regex`.
- Repeatable `--kind`: `decl`, `call`, `import`, `class`, `var`, `string`,
  `arg`, `ref`, `decorator`.
- `--from`, `--to`.
- `--from-kind`, `--to-kind`: `decl`, `call`, `read`, `write`, `arg`,
  `string`, `import`, `class`.
- `--file`, `--in-fn`.
- `--max-flows`, `--max-entry-probes`, `--max-hits`.
- `--flow F:xxxxxxxx`, `--group G:xxxxxxxx`.
- `--view trace|grouped|auto`.
- `--compact`, `--all`, `--context`, `--page`, `--format text|json`.

## Trace

Use `trace` for entrypoint and source-to-sink path expansion.

Key filters:

- Positional symbol or `--function`.
- `--from` and `--to`; `--to` requires `--from`.
- `--context`, `--page`, `--all`.
- `--format text|json|dot`.

## Debug Dumps

| command | purpose | high-value filters |
|---|---|---|
| `dump-ast` | Tree-sitter parse tree. | positional symbol, `--file`, `--function`, `--compact`, `--max-depth`, `--node`, `--context`, `--page`, `--all`, `--limit`, `--format` |
| `dump-hir` | Adapter FlowEvent tree for one function. | positional symbol or `--symbol` |
| `dump-cfg` | CFG for one function. | positional symbol or `--symbol` |
| `dump-callgraph` | Functions with inbound and reachable outbound counts. | `--context`, `--page`, `--all`, `--limit`, `--format` |
| `dump-edges` | Resolved call edges and precision. | `--from`, `--to`, `--precision`, `--compact`, `--edge`, `--context`, `--page`, `--all`, `--format` |
| `dump-resolve` | Resolver stage trace for a name. | positional name or `--name`, `--in-file`, `--compact`, `--candidate`, `--format` |
| `dump-taint` | Taint propagation records from a source. | `--source`, repeatable `--seed`, repeatable `--sanitizer`, `--sink`, `--budget`, `--compact`, `--taint`, `--format` |
| `diagnostics` | Adapter diagnostic pass. | command help for exact flags |

`dump-edges --precision` accepts `exact`, `narrowed`,
`over-approximate`, and `unknown`.

## Security Commands

Security subcommands are invoked as:

```shell
./target/release/bonsai-ninja security <workspace> <action> [--rules-dir <dir>]
```

Rulepack discovery when omitted: `BONSAI_RULES_DIR`,
`<workspace>/security-patterns/`, `<workspace>/../security-patterns/`,
then `./security-patterns/`.

| action | purpose | high-value filters |
|---|---|---|
| `sources` | Source rule matches. | `--rule`, `--rule-regex`, `--trust`, `--category`, `--tag`, repeatable `--file`, repeatable `--exclude-file`, `--context`, `--page`, `--all`, `--format` |
| `sinks` | Sink rule matches. | `--rule`, `--rule-regex`, `--severity`, `--tag`, repeatable `--file`, repeatable `--exclude-file`, `--context`, `--page`, `--all`, `--format` |
| `sanitizers` | Sanitizer rule matches. | `--rule`, `--rule-regex`, `--tag`, repeatable `--file`, repeatable `--exclude-file`, `--context`, `--page`, `--all`, `--format` |
| `deps` | Package/import evidence named by rules. | `--severity`, `--tag`, repeatable `--file`, repeatable `--exclude-file`, `--context`, `--page`, `--all`, `--format` |
| `source-analysis` | Downstream paths from source rules. | `--profile`, `--source`, `--trust`, `--tag`, `--category`, repeatable `--file`, repeatable `--exclude-file`, `--inferred-sources`, `--context`, `--page`, `--all`, `--no-compact`, `--format` |
| `taint-analysis` | Source-to-sink taint findings. | `--profile`, `--source`, `--trust`, `--category`, `--sink`, `--severity`, `--tag`, repeatable `--file`, repeatable `--exclude-file`, `--exclude-tests`, `--inferred-sources`, `--show-sanitized`, `--context`, `--page`, `--all`, `--no-compact`, `--format` |
| `pack` | Rulepack inventory, audit, tree, and validation. | `--lang`, `--category`, `--kind`, `--severity`, `--audit`, `--tree`, `--validate`, `--context`, `--page`, `--all`, `--limit`, `--format` |

Security notes:

- `--profile production` applies production review defaults:
  production excludes, `--trust remote`, high severity where relevant,
  and `--context 16k`. Explicit flags override profile defaults.
- `source-analysis` and `taint-analysis` do not include inferred
  per-function entry sources unless `--inferred-sources` is passed.
- Text flow labels are semantic: `SOURCE FLOW` is source-seeded forward
  taint without sink attribution, `TAINT FLOW` is source-to-sink
  propagation with tainted argument or receiver evidence, and generic
  `FLOW` belongs to `inspect` navigation output.
- `source-analysis --format sarif` is rejected intentionally. It is
  source-flow mapping, not SARIF finding output; use `--format json`.
- `taint-analysis --exclude-tests` drops findings whose source OR
  sink lives in a `path_is_test_file` path before per-source graph
  and chain build. Surviving findings carry `from_test: true` in
  JSON when their evidence still touches a test path. It is a strict
  subset of `--profile production`.
- `taint-analysis --show-sanitized` includes credit-cleared paths with
  `status: sanitized` and sanitizer evidence for sanitizer rule audits.
- Severity filters are strict floors: `info`, `low`, `medium`, `high`,
  `critical`.
- Trust classes: `remote`, `local`, `service`, `ipc`, `database`,
  `library`, `config`, `physical`.
- `pack --validate` checks strict schema loading, required metadata,
  match examples, and enabled-rule example collisions.

## Export

`export` emits the indexed taint graph used by inspect, trace, and
security:

```shell
./target/release/bonsai-ninja export <workspace> --format json
./target/release/bonsai-ninja export <workspace> --format networkx
./target/release/bonsai-ninja export <workspace> --format graphml
./target/release/bonsai-ninja export <workspace> --format cypher
./target/release/bonsai-ninja export <workspace> --full-propagations
```

Use `--full-propagations` only when the downstream consumer needs
exhaustive propagation records.
