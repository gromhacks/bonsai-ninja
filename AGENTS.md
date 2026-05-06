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
missing. For scripts use `--format json --no-color --no-progress`. For
LLM-readable text use `--no-color --no-progress --context 16k`.
For save-time workflows, keep `index <workspace> --watch --no-progress`
running; command and SDK facades refresh saved file changes before they
render.

Always treat pagination as correctness. If output says more pages exist,
continue with `--page 2`, `--page next`, or the printed `P:...` cursor
before claiming coverage. Use `--all` only for tight filters or explicit
exhaustive artifacts.

## Map A Codebase

Start with shape, then follow one concrete behavior.

```shell
./target/release/bonsai-ninja index <workspace> --no-progress
# Optional during active editing:
./target/release/bonsai-ninja index <workspace> --watch --no-progress
./target/release/bonsai-ninja tree <workspace> --max-depth 3 --compact --context 16k --no-color --no-progress
./target/release/bonsai-ninja imports <workspace> --context 16k --no-color --no-progress
./target/release/bonsai-ninja defs <workspace> --kind function --context 16k --no-color --no-progress
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
./target/release/bonsai-ninja inspect <workspace> --from <entry> --to <target> --context 16k --no-color --no-progress
./target/release/bonsai-ninja trace <workspace> <entry-function> --context 16k --no-color --no-progress
./target/release/bonsai-ninja read-file <workspace> <path> --lines A:B --context 16k --no-color --no-progress
```

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
test-path filter.

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
./target/release/bonsai-ninja security <workspace> taint-analysis --format sarif --no-color --no-progress > findings.sarif.json
```

For each issue, cite `S:` finding id, `F:` flow id, source line, sink
line, sanitizer status, and the exact page/cursor coverage reviewed.

## Rulepack Work

Rules live under `security-patterns/langs/<lang>/{sources,sinks,sanitizers}`.
Enable rules when they represent a real security boundary and the current
constraints can keep common safe APIs quiet. Do not enable generic print,
log, join, or parse patterns without a security-specific constraint.

Validate before reporting:

```shell
./target/release/bonsai-ninja security . pack --validate --format json --no-color --no-progress
./target/release/bonsai-ninja security . pack --audit --context 16k --no-color --no-progress
cargo test -q -p bonsai_security --test rulepack_conformance
```
