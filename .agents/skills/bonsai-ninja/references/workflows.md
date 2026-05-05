---
title: Bonsai Ninja Workflows
description: Runnable bonsai-ninja command sequences for mapping, debugging, security review, and rulepack maintenance.
---

# Workflows

Use this reference when the task needs a complete operating sequence.
The main skill has the principles; this file has runnable command
sequences.

Always prefer:

```shell
./target/release/bonsai-ninja <command> ... --no-color --no-progress
```

Use `--context 8k` or `16k` for LLM review, JSON for scripts, and page
through every relevant footer before claiming coverage.

## Job 1 - Understand The Codebase

Use this when the user drops you into an unknown codebase and asks you
to understand it before changing or reviewing it.

1. Project shape and entrypoints:

   ```shell
   ./target/release/bonsai-ninja index <workspace> --no-progress
   ./target/release/bonsai-ninja tree <workspace> --max-depth 3 --compact --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja imports <workspace> --context 16k --no-color --no-progress
   ```

2. Public surface and architecture:

   ```shell
   ./target/release/bonsai-ninja defs <workspace> --kind function --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja classes <workspace> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> source-analysis --trust remote --context 16k --no-color --no-progress
   ```

   `source-analysis --trust remote` maps externally reachable handlers
   and source-driven paths. It is not a vulnerability report by itself.

3. Per-route or per-handler logic:

   ```shell
   ./target/release/bonsai-ninja search <workspace> <route-or-feature-term> --context 8k --no-color --no-progress
   ./target/release/bonsai-ninja inspect <workspace> --query <handler-or-symbol> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja trace <workspace> <entry-function> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
   ```

4. Cross-module flow:

   ```shell
   ./target/release/bonsai-ninja inspect <workspace> --from <source-fn> --to <sink-fn> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja dump-edges <workspace> --from <caller> --to <callee> --context 8k --no-color --no-progress
   ./target/release/bonsai-ninja dump-callgraph <workspace> --context 8k --no-color --no-progress
   ```

5. Configuration, feature flags, and comments:

   ```shell
   ./target/release/bonsai-ninja inspect <workspace> --query 'DEBUG\\s*=|FEATURE_|FLAG_|ENABLED_' --regex --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja strings <workspace> --contains 'localhost|127.0.0.1|internal|TODO|FIXME' --regex --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja comments <workspace> --kind todo --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja comments <workspace> --kind fixme --context 16k --no-color --no-progress
   ```

Record durable understanding as:

```text
entry point -> validation -> business logic -> storage/external call -> response/side effect
```

## Job 2 - Debug And Fix Issues

Use this for reproducing a bug, walking it to root cause, patching, and
verifying with a test.

1. Refresh the index:

   ```shell
   ./target/release/bonsai-ninja index <workspace> --no-progress
   ```

2. Search broadly for the symptom:

   ```shell
   ./target/release/bonsai-ninja search <workspace> <term> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja search <workspace> --query '<regex>' --regex --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja search <workspace> <term> --format json --no-color --no-progress
   ```

3. Pivot to structured facts:

   ```shell
   ./target/release/bonsai-ninja defs <workspace> --name <term> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja calls <workspace> --callee <callee> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja refs <workspace> <symbol> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja args <workspace> --callee <callee> --context 16k --no-color --no-progress
   ```

4. Trace root cause:

   ```shell
   ./target/release/bonsai-ninja inspect <workspace> --query <target> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja trace <workspace> <entry> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja trace <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
   ```

5. If high-level output disagrees with source, use the debug ladder:

   ```shell
   ./target/release/bonsai-ninja dump-ast <workspace> --file <file> --function <function> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja dump-hir <workspace> <function> --no-color --no-progress
   ./target/release/bonsai-ninja dump-cfg <workspace> <function> --no-color --no-progress
   ./target/release/bonsai-ninja dump-resolve <workspace> <callee> --in-file <file> --no-color --no-progress
   ./target/release/bonsai-ninja dump-edges <workspace> --from <caller> --to <callee> --context 8k --no-color --no-progress
   ./target/release/bonsai-ninja dump-taint <workspace> --source <entry> --seed <param> --no-color --no-progress
   ```

6. Patch with tests, then re-index and re-inspect the corrected flow:

   ```shell
   ./target/release/bonsai-ninja refs <workspace> <symbol> --file '_test|tests?/' --regex --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja index <workspace> --no-progress
   ./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
   ```

Report shape:

```text
symptom -> anchor -> failing flow or missing edge -> source lines -> fix -> regression test
```

## Job 3 - Security Review

Goal: map externally reachable input, identify trust boundaries, trace
untrusted data to sensitive sinks, review sanitizer/auth evidence, and
separate exploitable paths from inventory.

1. Establish project shape:

   ```shell
   ./target/release/bonsai-ninja index <workspace> --no-progress
   ./target/release/bonsai-ninja tree <workspace> --max-depth 3 --compact --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja defs <workspace> --kind function --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja classes <workspace> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja imports <workspace> --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja comments <workspace> --kind security --context 16k --no-color --no-progress
   ```

2. Production default:

   ```shell
   ./target/release/bonsai-ninja security <workspace> source-analysis --profile production --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> taint-analysis --profile production --context 16k --no-color --no-progress
   ```

   Without `--profile production`, at minimum start with remote trust and
   exclude non-production code:

   ```shell
   ./target/release/bonsai-ninja security <workspace> source-analysis --trust remote --exclude-file test --exclude-file tests --exclude-file fixtures --exclude-file vendor --exclude-file node_modules --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --exclude-file test --exclude-file tests --exclude-file fixtures --exclude-file vendor --exclude-file node_modules --exclude-tests --context 16k --no-color --no-progress
   ```

   `--exclude-tests` drops findings whose source OR sink lives in a
   `path_is_test_file` path; surviving findings carry
   `from_test: true` in JSON when evidence still touches a test path.

3. Inventory evidence when needed:

   ```shell
   ./target/release/bonsai-ninja security <workspace> sources --trust remote --context 8k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> sinks --severity high --context 8k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> sanitizers --tag shell-escape --context 8k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> deps --severity high --context 8k --no-color --no-progress
   ```

4. Trace source to sink:

   ```shell
   ./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> taint-analysis --severity high --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> taint-analysis --tag command-injection --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> taint-analysis --source '<source-rule-regex>' --sink '<sink-rule-regex>' --context 16k --no-color --no-progress
   ```

   Use `--show-sanitized` for sanitizer coverage audits, not for default
   vulnerability counts:

   ```shell
   ./target/release/bonsai-ninja security <workspace> taint-analysis --trust remote --show-sanitized --context 16k --no-color --no-progress
   ```

5. Widen trust deliberately:

   ```shell
   ./target/release/bonsai-ninja security <workspace> source-analysis --trust service --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> source-analysis --trust ipc --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> source-analysis --trust database --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> source-analysis --trust local --context 16k --no-color --no-progress
   ```

6. Use `--inferred-sources` only for audit-style coverage when named
   source rules are thin:

   ```shell
   ./target/release/bonsai-ninja security <workspace> source-analysis --inferred-sources --category inferred --context 16k --no-color --no-progress
   ./target/release/bonsai-ninja security <workspace> taint-analysis --inferred-sources --category inferred --context 16k --no-color --no-progress
   ```

7. Triage each finding:

   - Record `S:` finding ID and `F:` flow ID.
   - Confirm source trust, source category, and source line.
   - Confirm sink rule, sink line, severity, CWE, and tainted arg.
   - Confirm auth, ownership, tenant, and permission checks.
   - Confirm sanitizer evidence. Sanitized means bypass review is still
     needed.
   - Re-render focused evidence:

     ```shell
     ./target/release/bonsai-ninja inspect <workspace> --flow F:xxxxxxxx --context 16k --no-color --no-progress
     ./target/release/bonsai-ninja read-file <workspace> <sink-file> --from <source> --to <sink> --context 16k --no-color --no-progress
     ```

Do not report source inventory as a vulnerability without a sink, sink
inventory as reachable without flow evidence, or sanitizer credit as
proof of safety.

## Rulepack Or Tool Maintenance

Use these only when working on bonsai itself, validating rule coverage,
or debugging adapter/tool behavior.

```shell
./target/release/bonsai-ninja security <workspace> pack --audit --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> pack --tree --lang python --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> pack --validate --format json --no-color --no-progress
python3 scripts/pack_audit.py --duplicates
python3 scripts/validate-pattern-pack.py --binary ./target/release/bonsai-ninja --json-out build/pattern-pack-validator.json
python3 scripts/rule_example_coverage.py security-patterns
```

When investigating parser/adapter behavior:

```shell
./target/release/bonsai-ninja diagnostics <workspace> --no-color --no-progress
./target/release/bonsai-ninja dump-ast <workspace> --file <file> --function <function> --context 16k --no-color --no-progress
./target/release/bonsai-ninja dump-hir <workspace> <function> --no-color --no-progress
./target/release/bonsai-ninja dump-edges <workspace> --from <caller> --to <callee> --context 8k --no-color --no-progress
```

Rulepack maintenance gates:

- `pack --validate` must report zero errors.
- `scripts/pack_audit.py --duplicates` must report zero duplicate IDs,
  duplicate enabled shapes, cross-family API collisions, and family file
  mismatches.
- Match examples must exist for enabled rules and fire their owner rule.
- Collision findings should be merged or made more specific in YAML, not
  hidden in engine code.
- Rule precision should live in YAML rule constraints, `match_examples`,
  and AST-safe argument-position checks. Do not add hardcoded broad input
  token lists such as `request|payload|body` to matcher logic unless a
  documented engine limitation leaves no rulepack-level option.

## Business Logic Review

Business-logic bugs are correct-looking flows that violate an invariant.
Bonsai accelerates manual review by letting you ask flow-shaped
questions instead of grep questions.

```shell
./target/release/bonsai-ninja inspect <workspace> --query '\\.save\\(\\)|\\.update\\(|\\.create\\(' --kind call --regex --context 16k --no-color --no-progress
./target/release/bonsai-ninja vars <workspace> --in-fn <handler_name> --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query 'select_for_update|with_lock|advisory_lock|idempotency_key' --regex --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query 'status\\s*=|state\\s*=|transition\\s*\\(|advance\\s*\\(' --regex --context 16k --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query 'price|amount|total|discount|refund|charge|invoice|quantity' --regex --context 16k --no-color --no-progress
```

Trace suspicious paths end-to-end and cite stable IDs.

## Sensitive API Review

Do not rely only on security findings. Inspect sensitive APIs directly:

```shell
./target/release/bonsai-ninja calls <workspace> --callee 'system|exec|popen|spawn|eval|deserialize|query|open|write|redirect' --regex --context 16k --no-color --no-progress
./target/release/bonsai-ninja args <workspace> --callee 'system|exec|popen|spawn|eval|query|redirect|open|write' --regex --context 16k --no-color --no-progress
./target/release/bonsai-ninja strings <workspace> --category sql --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> --module 'crypto|jwt|yaml|pickle|serde|xml|http|ldap|mongo|sql' --regex --context 16k --no-color --no-progress
./target/release/bonsai-ninja refs <workspace> --regex 'password|secret|token|key' --context 16k --no-color --no-progress
```

Treat each sensitive API family and each output page as its own review
task.

## Large Repository Defaults

Use this sequence on large real-world projects:

```shell
./target/release/bonsai-ninja cache stats <workspace> --no-color --no-progress
./target/release/bonsai-ninja index <workspace> --no-progress
./target/release/bonsai-ninja search <workspace> <term> --context 8k --no-flows --no-color --no-progress
./target/release/bonsai-ninja calls <workspace> --callee <callee> --context 8k --no-flows --no-color --no-progress
./target/release/bonsai-ninja inspect <workspace> --query <target> --compact --context 16k --no-color --no-progress
./target/release/bonsai-ninja security <workspace> taint-analysis --profile production --context 16k --no-color --no-progress
```

Avoid `--all` until filters are tight enough or an exhaustive artifact is
explicitly needed.

## Report Template

```text
Scope:
Workspace / commit:
Commands:
Output mode:
Context budget:
Pagination:
Trust classes and excludes:
Findings / flows / stable IDs:
Parser/indexing caveats:
Skipped or intentionally omitted areas:
Confidence:
Next checks:
```
