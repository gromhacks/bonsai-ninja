---
name: bonsai-ninja
description: "Use this skill when working with the bonsai-ninja static analysis CLI or SDK to do one of three jobs: (1) understand a codebase - entry points, architecture, data flow, dependencies, configs; (2) debug & fix issues - reproduce bugs, trace root cause, patch with tests; (3) security review - check auth, input validation, secrets, dependencies, attack surfaces. Covers code search, inspect, trace, export, source-analysis, taint-analysis, pagination, command filters, and rulepack triage."
compatibility: "Agent Skills canonical spec for repository-specific bonsai-ninja guidance."
---

# Bonsai Ninja

Use this skill when working with `bonsai-ninja`, its CLI/SDK, or this
repository's shipped security rulepack. Load the reference files only
when you need the detailed command matrix or workflow recipes:

- `references/command-reference.md`
- `references/workflows.md`

## Purpose

`bonsai-ninja` is an LLM navigation and analysis tool. Use it when you
need to understand a repository, find code, answer "where is this used",
debug a missing or wrong flow, review implementation quality, or triage
security issues.

The CLI indexes a workspace into structural facts and a call/taint graph:

- Declarations, calls, imports, vars, strings, comments, args, classes,
  and refs.
- Cross-file call edges and flow chains.
- Source, sink, sanitizer, and taint findings when a rulepack is loaded.
- Stable IDs for flows, groups, findings, edges, AST nodes, resolver
  candidates, and taint records.

Think of the tool as three layers:

1. `tree`, `read-file`, `search`, and browse commands help you move
   around source quickly.
2. `inspect`, `trace`, and debug dumps explain execution flow.
3. `security source-analysis` and `security taint-analysis` explain
   attack surface and source-to-sink risk.

## Operational Defaults

Prefer the release binary when present:

```shell
./target/release/bonsai-ninja <command> ...
```

If release is missing, use `./target/debug/bonsai-ninja` or build the
release binary before relying on performance-sensitive output.

Run `index` before inspect, trace, security, export, or debug work:

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
```

Use LLM-readable text for review:

```shell
./target/release/bonsai-ninja <command> ... --no-color --no-progress --context 16k
```

Use JSON for scripts, parity checks, exact counts, and post-processing:

```shell
./target/release/bonsai-ninja <command> ... --format json --no-color --no-progress
```

Treat pagination as correctness, not a display detail. `--context` limits
how much the tool can render, so a command result may be only one slice
of a larger section. Always read the footer. If it says `page 1 of N`,
`showing N of TOTAL`, or prints a `P:xxxxxxxx` cursor, continue with
`--page 2`, `--page next`, or the printed cursor until the section
needed for the task has been reviewed end-to-end. Never claim coverage
from page 1 alone, and never assume increasing `--context` removed the
need to check the page count.

Avoid `--all` on large repositories unless the user asked for an
exhaustive artifact or your filters make the output small. Prefer
`--context 8k` or `16k`, `--file`, `--kind`, `--from`, `--to`,
`--trust`, `--tag`, and `--severity`. `--exclude-file` is only
accepted by `tree`, `read-file`, and the `security` commands —
the browse-fact commands (`defs`, `calls`, `imports`, etc.)
support `--file` only.

## The Agent Loop

Use `bonsai-ninja` the way an experienced reviewer reasons about an
unknown system: start with a question, build a map, trace one concrete
path, read only the source that matters, then verify the smallest claim
with evidence.

The shared mental model for repository understanding, debugging, code
review, and security review is:

```text
question
  -> entry point or anchor
  -> data/control flow
  -> decision points
  -> side effects and sinks
  -> source lines and tests that prove the claim
```

Use this loop for almost every task:

1. **Frame the question.** Decide whether you are learning behavior,
   finding usage, debugging a symptom, reviewing quality, or proving a
   security risk. Do not start by reading files randomly.
2. **Map the workspace.** Run `index`, then use `tree`, `imports`,
   `defs`, and, when external input matters, `security source-analysis
   --trust remote` to identify entry points, frameworks, and hot files.
3. **Find an anchor.** Use `search` for the route, symbol, error, table,
   config key, permission name, log text, or sink. Switch to `defs`,
   `calls`, `refs`, `args`, `vars`, `strings`, or `comments` once the
   fact type is clear.
4. **Expand the path.** Use `inspect --query`, `inspect --from --to`,
   `inspect --flow`, or `trace` to move from isolated facts to execution
   or data flow.
5. **Page through the section.** After every `--context`-bounded command,
   inspect the footer before reasoning from the result. If there are more
   pages, keep using `--page 2`, `--page next`, or the printed cursor
   until the relevant table, flow group, finding set, or file section is
   complete enough for the task.
6. **Read the decisive source.** Use `read-file` on the smallest useful
   file and line range. Prefer `read-file` over raw `sed` when marks,
   callers, callees, sources, sinks, or findings matter.
7. **Drill down only on disagreement.** Use debug dumps only when the
   high-level output is missing, ambiguous, or suspected wrong.
8. **Verify.** Rerun the smallest command that proves the claim, then run
   the relevant tests or reproduce the behavior outside the tool. Include
   page coverage or cursor coverage when the evidence was paginated.

Good first commands on an unknown workspace:

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
./target/release/bonsai-ninja tree <workspace> --max-depth 3 --compact --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> --context 16k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --kind function --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --trust remote --context 16k --no-color --no-progress
```

Prefer this order because it mirrors how humans learn code: first locate
entry points and architectural shape, then follow one concrete feature or
value end-to-end.

## Workflows By Intent

### Learn A Codebase

Goal: understand layout, entry points, frameworks, hot paths, core data
models, and important files before editing.

Human question:

```text
What does this system do, where does behavior start, and how does data
move from input to output?
```

Use:

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
./target/release/bonsai-ninja tree <workspace> --max-depth 3 --compact --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> --context 16k --no-color --no-progress
./target/release/bonsai-ninja classes <workspace> --context 16k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --kind function --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --trust remote --context 16k --no-color --no-progress
```

Read the output as a map:

- `tree` answers "where should I look first?"
- `imports` answers "what frameworks, SDKs, and architectural boundaries
  shape the app?"
- `classes` and `defs` answer "what public and internal objects exist?"
- `source-analysis --trust remote` answers "what can outside users,
  webhooks, sockets, jobs, or cloud events reach?"
- Flow IDs in browse output can be pasted into `inspect --flow`.

Then pick one important behavior and trace it end-to-end:

```shell
./target/release/bonsai-ninja search <workspace> <route-or-feature-term> --context 8k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <handler-or-symbol> --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry-function> --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
```

Record only durable understanding:

```text
entry point -> validation -> business logic -> storage/external call -> response/side effect
```

Do not attempt to understand every file. Build a working map, then add
detail as new questions require it.

### Search And Navigate

Goal: find a precise symbol, route, config, string, call site, usage, or
error path without manually browsing the repository.

Start broad with one high-signal anchor:

```shell
./target/release/bonsai-ninja search <workspace> <term> --context 8k --no-color --no-progress
```

Good anchors include:

```text
route path, function name, class name, table name, config key,
environment variable, permission string, error message, log text,
external API name, feature flag, queue name, event name
```

Then switch to the structural command that matches the question:

```shell
./target/release/bonsai-ninja defs <workspace> --name <name> --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> --context 8k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee <callee> --position 0 --context 8k --no-color --no-progress
./target/release/bonsai-ninja vars <workspace> --name <name> --context 8k --no-color --no-progress
./target/release/bonsai-ninja strings <workspace> --contains <literal> --context 8k --no-color --no-progress
```

Use regex only after a substring pass shows the naming shape:

```shell
./target/release/bonsai-ninja search <workspace> --query 'handle_.*|route|controller' --regex --context 8k --no-color --no-progress
```

Use `--no-flows` on huge workspaces when you only need the fact table
and not chain IDs yet. Once the question becomes "how does execution get
here?", switch from browse facts to `inspect` or `trace`.

### Code Review

Goal: review implementation quality by finding risky patterns, stale
code, dead-ish code, missing checks, architectural inconsistencies, and
behavior that does not match the intended design.

Human question:

```text
Does this code do what it claims, where could it break, and what evidence
proves that concern?
```

Recommended flow:

1. **Map the review surface.** Use `tree`, `imports`, `defs`, and, for a
   bounded change, `read-file --lines A:B` on changed files.
2. **Identify decision points.** Search for auth checks, validation,
   branching, feature flags, retries, error handling, persistence, and
   external calls.
3. **Trace important paths.** Use `inspect` or `trace` for handlers,
   jobs, or public APIs touched by the change.
4. **Sweep for risky patterns.** Use browse facts to find TODOs,
   secrets, dangerous calls, role checks, and state changes.
5. **Confirm with source and tests.** Use `read-file` for exact lines and
   cite the smallest command that proves the claim.

Useful sweeps:

```shell
./target/release/bonsai-ninja comments <workspace> --kind todo --context 8k --no-color --no-progress
./target/release/bonsai-ninja comments <workspace> --kind fixme --context 8k --no-color --no-progress
./target/release/bonsai-ninja comments <workspace> --kind security --context 8k --no-color --no-progress
./target/release/bonsai-ninja strings <workspace> --contains '(?i)(secret|token|password|api[_-]?key)' --regex --context 8k --no-color --no-progress
./target/release/bonsai-ninja vars <workspace> --name 'secret|token|password|state|role|admin' --regex --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee 'exec|system|spawn|eval|deserialize|query|open|write' --regex --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee 'redirect|query|execute|open|write|spawn|exec' --regex --context 8k --no-color --no-progress
```

For potentially unused code, do not trust static absence blindly. Tests,
reflection, framework routing, generated code, and dynamic dispatch can
hide usage. Use missing refs as a suspicion generator:

```shell
./target/release/bonsai-ninja refs <workspace> <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --name <symbol> --context 8k --no-color --no-progress
```

Then confirm against framework wiring, tests, generated files, and
runtime entry points. Do not delete code only because a static search
shows no refs.

### Debug A Bug Or Missing Flow

Goal: reproduce the symptom, locate the first divergence from expected
behavior, expand the relevant flow, then drill into compiler/tool stages
only if the high-level evidence is wrong or incomplete.

Human question:

```text
Where does actual behavior first diverge from expected behavior?
```

Recommended flow:

1. **Reproduce or restate the symptom.** Capture the error text, failing
   route, failing function, bad output, or missing edge.
2. **Define expected vs actual.** Write the smallest clear statement:
   "expected X, observed Y".
3. **Find the nearest anchor.** Search for the error text, route,
   function, symbol, log message, or failing sink.
4. **Locate the failure boundary.** Trace input -> validation ->
   transformation -> storage/external call -> output.
5. **Test one hypothesis at a time.** Use facts, flows, and source lines
   to confirm or reject the cause.
6. **Patch only after the failing stage is known.** Verify with the
   smallest command and then tests.

Start:

```shell
./target/release/bonsai-ninja search <workspace> <error-or-symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --name <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> <symbol> --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee <callee> --context 8k --no-color --no-progress
```

Expand:

```shell
./target/release/bonsai-ninja inspect <workspace> --query <symbol> --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry> --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
```

Use the debug ladder only if a flow is missing, wrong, or ambiguous:

```shell
./target/release/bonsai-ninja dump-ast <workspace> --file <file> --function <function> --context 16k --no-color --no-progress
./target/release/bonsai-ninja dump-hir <workspace> <function> --no-color --no-progress
./target/release/bonsai-ninja dump-cfg <workspace> <function> --no-color --no-progress
./target/release/bonsai-ninja dump-resolve <workspace> <callee> --in-file <file> --no-color --no-progress
./target/release/bonsai-ninja dump-edges <workspace> --from <caller> --to <callee> --context 8k --no-color --no-progress
./target/release/bonsai-ninja dump-taint <workspace> --source <entry> --seed <param> --no-color --no-progress
```

Interpretation:

- `dump-ast`: parser shape. Use when syntax is not being seen.
- `dump-hir`: adapter FlowEvents. Use when AST exists but facts do not.
- `dump-cfg`: block/control-flow shape. Use for branch, loop, and
  try/catch issues.
- `dump-resolve`: name-resolution stages. Use when a call target is
  wrong.
- `dump-edges`: callgraph edge and precision. Use for cross-file hops.
- `dump-taint`: propagation records from a seeded entry. Use when data
  should or should not reach a sink.

For a report or PR comment, include:

```text
symptom -> anchor -> failing flow or missing edge -> source lines -> fix -> regression test
```

### Security Review

Goal: map externally reachable input, identify trust boundaries, trace
untrusted data to sensitive sinks, review sanitizer/auth evidence, and
separate exploitable paths from inventory.

Human question:

```text
Who controls this input, what boundary does it cross, what can it reach,
and what impact follows if the assumption is false?
```

Security review flow:

1. **Map attack surface.** Identify remote sources, routes, handlers,
   webhooks, sockets, jobs, and cloud events.
2. **Identify trust boundaries.** Look for unauthenticated ->
   authenticated, user -> admin, tenant A -> tenant B, external service
   -> internal service, user input -> parser, and frontend validation ->
   backend action.
3. **Trace source to sink.** Follow untrusted input through validation,
   transformation, authorization, persistence, and dangerous operations.
4. **Review auth and authorization.** Confirm identity checks,
   permission checks, ownership checks, tenant scoping, and ordering of
   checks before side effects.
5. **Review validation and canonicalization.** Confirm allowlists,
   normalization, path/URL parsing, decoding, encoding, and parser
   behavior.
6. **Review dangerous operations.** Pay attention to shell execution,
   dynamic evaluation, deserialization, SQL/NoSQL construction,
   filesystem access, template rendering, redirects, outbound HTTP, XML,
   archive extraction, token issuance, password reset, payment, and
   permission changes.
7. **Prove impact safely.** A finding needs attacker control, reachable
   sink or broken control, impact, and source-line evidence.

Production default:

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --profile production --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --profile production --context 16k --no-color --no-progress
```

If not using `--profile production`, at minimum start with remote trust
and exclude non-production code:

```shell
./target/release/bonsai-ninja security <workspace> source-analysis --trust remote --exclude-file test --exclude-file tests --exclude-file fixtures --exclude-file vendor --exclude-file node_modules --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --exclude-file test --exclude-file tests --exclude-file fixtures --exclude-file vendor --exclude-file node_modules --exclude-tests --context 16k --no-color --no-progress
```

Use `source-analysis --trust remote` to map APIs, handlers, cloud
events, sockets, and other attacker-reachable entry points. It is an
attack-surface map, not a vulnerability report by itself.

Use `taint-analysis --trust remote` for vulnerability triage. It
requires a source, a sink, and tainted argument evidence.
`taint-analysis --exclude-tests` drops findings whose source OR sink
lives in a test path (`/test/`, `/tests/`, `/__tests__/`,
`_test.go`, `*.spec.ts`, `*Test.java`, `conftest.py`, …) before the
chain-build phase; surviving findings carry `from_test: true` in JSON
when their evidence still touches a test path. It is a strict subset
of `--profile production`.

Inventory evidence when needed:

```shell
./target/release/bonsai-ninja security <workspace> sources --trust remote --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sinks --severity high --context 8k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> sanitizers --tag shell-escape --context 8k --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee 'exec|system|spawn|eval|deserialize|query|open|write|redirect|request|get|post' --regex --context 8k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee 'exec|system|spawn|eval|query|redirect|open|write' --regex --context 8k --no-color --no-progress
```

Triage each finding:

1. Record `S:` finding ID and `F:` flow ID.
2. Confirm source trust, source category, and source line.
3. Confirm sink rule, sink line, severity, CWE, and tainted arg.
4. Confirm auth, ownership, tenant, and permission checks on the path.
5. Confirm sanitizer evidence. Sanitized does not mean safe; it means
   the path deserves bypass review.
6. Re-render the focused flow:

   ```shell
   ./target/release/bonsai-ninja inspect <workspace> --flow F:xxxxxxxx --context 16k --no-color --no-progress
   ```

7. Use `read-file` on the sink file, source file, and any authorization
   or sanitizer file that decides exploitability:

   ```shell
   ./target/release/bonsai-ninja read-file <workspace> <sink-file> --from <source> --to <sink> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja read-file <workspace> <auth-or-sanitizer-file> --lines A:B --context 16k --no-color --no-progress
   ```

Use trust widening deliberately:

```shell
./target/release/bonsai-ninja security <workspace> source-analysis --trust service --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --trust ipc --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --trust database --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> source-analysis --trust local --context 16k --no-color --no-progress
```

Use `--inferred-sources` only for audit-style coverage when named source
rules are thin. Do not mix inferred findings into default vulnerability
counts without saying so.

Do not report:

- a source as a vulnerability without a sink or broken control;
- a sink inventory item as reachable without taint or manual flow
  evidence;
- sanitizer credit as proof of safety;
- an auth check as sufficient without confirming ownership, tenant, or
  permission semantics where relevant.

A good security finding format is:

```text
attacker-controlled source -> missing or bypassed control -> reachable sink -> impact -> stable IDs -> source lines -> recommended fix
```

### Rulepack Or Tool Maintenance

Most application review should not start with rulepack inventory,
dependency inventory, adapter-health commands, or debug dumps.

Use those only when the user is working on bonsai itself, validating
rule coverage, or debugging adapter/tool behavior. They are intentionally
not part of the default LLM guide for repository understanding,
debugging, code review, or security triage.

Dependency inventory is package/import evidence, not a CVE scanner.
Rulepack coverage is not application risk. Adapter health is not source
navigation.

For rulepack edits, validate both the CLI-visible pack and the repository
pattern validator when possible:

```shell
./target/release/bonsai-ninja security <workspace> pack --validate --format json --no-color --no-progress
python3 scripts/validate-pattern-pack.py --binary ./target/release/bonsai-ninja --json-out build/pattern-pack-validator.json
```

Keep rule behavior data-driven. Prefer YAML rule fields, `match_examples`,
argument-position constraints, and explicit source/sink/sanitizer rules over
hardcoded matcher token lists. Avoid broad input-name checks such as
`request|payload|body` in engine or script logic unless there is no
AST-safe or rulepack-level representation.

## Command Playbook

### Workspace And Cache

| Command | Use it for | Agent note |
|---|---|---|
| `index` | Build or refresh parsed facts and persisted dataflow. | First command before serious analysis. |
| `export` | Full graph JSON for downstream tooling or exact evidence. | Use JSON; expect large output. |
| `cache stats` | Check sidecar and cache state. | Useful before slow runs. |
| `cache clear` | Remove `.bonsai/` sidecars. | Use only when stale cache is suspected. |
| `cache rebuild` | Clear and immediately rebuild dataflow. | Good for validating cache bugs. |

### Navigation

| Command | Use it for | Best filters |
|---|---|---|
| `tree` | Project map with severity, findings, flow IDs, and cross-file edge overlays. | `--max-depth`, `--compact`, `--file`, `--exclude-file`, `--severity`. |
| `read-file` | Single-file review with source/sink/finding marks and caller/callee context. | `--lines A:B`, `--from`, `--to`, `--compact`, `--max-inlined-bodies`. |

Prefer `tree` before opening many files. Prefer `read-file` over raw
`sed` when analysis context matters.

### Browse Facts

| Command | Question it answers | High-value filters |
|---|---|---|
| `defs` | What functions/classes/methods exist? | `--kind`, `--name`, `--file`, `--has-callee`, `--has-decorator`, `--has-param`. |
| `calls` | Where is a callee invoked? | `--callee`, `--caller`, `--call-kind`, `--file`, `--regex`. |
| `imports` | What modules/frameworks/packages are wired in? | `--module`, `--alias`, `--wildcard`, `--file`, `--regex`. |
| `vars` | What assignments exist and where does RHS text come from? | `--name`, `--source`, `--in-fn`, `--file`, `--regex`. |
| `strings` | What literals exist? | `--contains`, `--category`, `--min-len`, `--in-fn`, `--file`, `--regex`. |
| `comments` | What TODO/FIXME/security/doc comments exist? | `--kind`, `--contains`, `--in-fn`, `--file`, `--regex`. |
| `args` | What values are passed to a call? | `--callee`, `--position`, `--keyword`, `--value`, `--in-fn`, `--regex`. |
| `classes` | What types and methods exist? | `--name`, `--kind`, `--has-method`, `--min-methods`, `--file`, `--regex`. |
| `refs` | Where is a symbol referenced? | positional symbol, `--kind`, `--in-fn`, `--file`, `--regex`. |
| `search` | Fast fuzzy search across all browse facts. | `--query`, positional query, `--kind`, `--file`, `--regex`. |

Use browse facts for evidence. Use `inspect` once the question becomes
"how does execution reach this?"

### Flow Analysis

| Command | Use it for | Agent note |
|---|---|---|
| `inspect` | Patternless query plus every flow reaching the match. | Best default for "how is this reached?" |
| `trace` | Expand one entry point's call tree. | Best for following a handler end-to-end. |

Important `inspect` moves:

```shell
./target/release/bonsai-ninja inspect <workspace> --query os.system --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query exec --kind call --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query express --kind import --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query app --kind decl --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query UserService --kind class --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query queryUser --kind call --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --from handle_request --to os.system --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --flow F:xxxxxxxx --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --group G:xxxxxxxx --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query exec --view grouped --compact --context 16k --no-color --no-progress
```

Use `--from-kind` and `--to-kind` when you need rule-like precision:
`decl`, `call`, `read`, `write`, `arg`, `string`, `import`, or `class`.

`inspect` is the structural command to pivot between these surfaces:
- **imports**: `--query <module> --kind import`
- **defs/declarations**: `--query <symbol> --kind decl`
- **classes/types**: `--query <class-name> --kind class`
- **calls**: `--query <callee> --kind call`

Pair these selectors with `--from`/`--to` when you need to prove a caller → sink path.

### Security

| Command | Use it for | Agent note |
|---|---|---|
| `security source-analysis` | Map downstream paths from source matches. | Best for API and trust-boundary mapping. Start with `--trust remote`. |
| `security taint-analysis` | Source-to-sink findings with sanitizer evidence. | Best for vulnerability triage. Start with `--trust remote`. |
| `security sources` | Inventory source matches. | Use to explain attack surface coverage. |
| `security sinks` | Inventory dangerous operations. | Use to review sensitive APIs even without source reachability. |
| `security sanitizers` | Inventory credited sanitizers. | Use to verify auth/escaping/validation coverage. |

Security text labels carry evidence semantics. `SOURCE FLOW` is a
source-seeded forward taint map without sink attribution. `TAINT FLOW` is
a source-to-sink finding path with tainted argument and receiver evidence.
Generic `FLOW` remains the navigation-oriented label used by `inspect`.

### Debug Dumps

| Command | Use it for |
|---|---|
| `dump-ast` | Parser/tree-sitter shape for a file, function, or AST node ID. |
| `dump-hir` | Adapter FlowEvents for one function. |
| `dump-cfg` | Basic blocks derived from FlowEvents. |
| `dump-callgraph` | Hottest functions by caller/outgoing counts. |
| `dump-edges` | Resolved call edges, precision, and call sites. |
| `dump-resolve` | Resolver stage trace for a name. |
| `dump-taint` | Propagation records from a seeded entry. |
Do not begin normal code review with debug dumps. They are for
explaining disagreements between expected and observed high-level
output.

## Stable IDs

Use IDs as handles between commands and in reports:

| ID | Meaning | Re-render |
|---|---|---|
| `F:xxxxxxxx` | Flow | `inspect --flow F:xxxxxxxx` |
| `G:xxxxxxxx` | Flow group | `inspect --group G:xxxxxxxx` |
| `S:xxxxxxxx` | Security finding | cite in report; inspect associated flow |
| `E:xxxxxxxx` | Call edge | `dump-edges --edge E:xxxxxxxx` |
| `N:xxxxxxxx` | AST node | `dump-ast --node N:xxxxxxxx` |
| `R:xxxxxxxx` | Resolver candidate | `dump-resolve --candidate R:xxxxxxxx` |
| `T:xxxxxxxx` | Taint record | `dump-taint --taint T:xxxxxxxx` |

When citing a finding or flow, cite the stable ID and the exact command
used to render it. Do not cite page numbers as durable evidence.

## Output And Paging

Text output is LLM-readable and budgeted. JSON is complete and best for
scripts. Treat paginated text output like a sequence of evidence chunks:
the first chunk is useful, but it is not the whole result unless the
footer proves there are no more pages.

Use:

```shell
--no-color --no-progress --context 16k
```

for LLM-facing review. Use:

```shell
--format json --no-color --no-progress
```

for exact processing.

Read compact output carefully:

- `↑ same` means the code cell is the same source line as the previous
  row; the rest of the row still matters.
- `(body already rendered above)` means the function body exists earlier
  on the same page.
- `showing N of TOTAL` means the table is truncated by row cap. Keep
  narrowing filters or paging until the rows relevant to the task are
  covered.
- `page 1 of N` means continue with `--page 2`, `--page next`, or the
  printed cursor before claiming complete review.
- `P:xxxxxxxx` is a durable cursor for the next slice of the same result.
  Prefer the printed cursor when available because it preserves the exact
  traversal state.
- `context X / Y tokens` is the rendered budget, not full project size.
  Raising `--context` may fit more rows, but the footer still decides
  whether more pages exist.

Paging rule for agents:

1. Run the focused command with `--context 8k` or `--context 16k`.
2. Read the footer before drawing conclusions.
3. If the footer says there are more pages, run the same command with
   `--page next`, `--page 2`, or the printed `P:xxxxxxxx` cursor.
4. Continue until the relevant section is exhausted, the filters have
   been narrowed to the exact target, or you explicitly state that the
   review covered only a bounded subset.
5. In reports, record page coverage such as `pages 1-4 of 4 reviewed`,
   `cursor P:abcd... through P:wxyz... reviewed`, or `page 1 only;
   remaining pages not reviewed`.

End-to-end section coverage examples:

```shell
./target/release/bonsai-ninja inspect <workspace> --query <symbol> --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <symbol> --page next --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <symbol> --page P:xxxxxxxx --context 16k --no-color --no-progress
```

```shell
./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --page next --context 16k --no-color --no-progress
```

```shell
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --page next --context 16k --no-color --no-progress
```

Use `--compact` when surveying many flows. Use `--no-compact` for a
focused security finding when repeated function bodies need to be
inline.

## Python Fixture Examples

These are good sanity-check commands when learning the tool:

```shell
./target/release/bonsai-ninja index examples/python/mega_flow --no-progress
./target/release/bonsai-ninja tree examples/python/mega_flow --max-depth 3 --compact --context 8k --no-color --no-progress
./target/release/bonsai-ninja search examples/python/mega_flow exec --context 8k --no-color --no-progress
./target/release/bonsai-ninja inspect examples/python/mega_flow --query exec --kind call --context 8k --no-color --no-progress
./target/release/bonsai-ninja security examples/python/mega_flow source-analysis --trust remote --context 8k --no-color --no-progress
./target/release/bonsai-ninja security examples/python/mega_flow taint-analysis --trust remote --context 8k --no-color --no-progress
./target/release/bonsai-ninja read-file examples/python/mega_flow executor.py --compact --context 8k --no-color --no-progress
./target/release/bonsai-ninja dump-edges examples/python/mega_flow --from perform --to execute --context 8k --no-color --no-progress
```

Expected lesson from that fixture:

- `tree` highlights `executor.py` as the finding-bearing file.
- `search exec` finds declarations, calls, imports, comments, and flow
  IDs.
- `inspect --query exec --kind call` shows how calls reach `execute`.
- `source-analysis --trust remote` maps Flask request entry paths.
- `taint-analysis --trust remote` reports the command-injection finding.
- `read-file executor.py --compact` shows the marked sink line and
  cross-file callers.
- `dump-edges --from perform --to execute` confirms the exact call edge.

## Reporting Checklist

For code review, debugging, or security reports, include:

- Workspace and commit reviewed.
- Exact bonsai commands and filters.
- Text context budget or JSON mode.
- Page coverage, including total pages reviewed and cursors whenever
  pagination appeared in the footer.
- Stable IDs for important flows/findings/edges.
- Files and lines confirmed with `read-file` or source reads.
- Trust classes reviewed or intentionally skipped.
- Test, fixture, vendor, generated, and build exclusions used for
  security review.
- Parser/indexing/tool caveats if the evidence is incomplete.

## What Not To Do

- Do not grep blindly before trying `search` or the browse commands.
- Do not open many files before using `tree`.
- Do not report `source-analysis` as a vulnerability without a sink.
- Do not treat sink inventory as reachable without `taint-analysis` or
  manual flow evidence.
- Do not treat sanitizer credit as final proof of safety.
- Do not call page 1 complete when the footer says more pages exist.
- Do not ignore pagination because `--context 16k` or a larger context was
  used; `--context` changes page size, not the obligation to check the
  footer and finish the relevant section.
- Do not delete "dead" code solely from no refs; account for tests,
  fixtures, reflection, generated code, and framework wiring.
- Do not use rulepack inventory or adapter-health commands as normal
  application review steps unless the user is working on bonsai internals.
