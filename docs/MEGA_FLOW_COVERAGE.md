# mega_flow coverage

Per-language fixtures live at `examples/<lang>/mega_flow/`. They are the
correctness fixtures for the taint engine and CLI surfaces: each threads
a user-input -> sink chain across 3-6 files through every source-visible
flow construct the language adapter is expected to model. The fixtures
are deliberately dense: language-specific constructs are present as real
source code, and taint-relevant constructs are kept on the canonical
source->sink path where the adapter can follow them.

Each fixture is parsed by that language's Tree-sitter adapter and lowered into
typed compiler facts. Shared analysis does not recognize these constructs from
a cross-language list of strings. The production taint check runs the sparse
IDG closure to its fixed point without a BFS depth, iteration budget, or result
cap.

CI pins this in `crates/cli/tests/security_commands.rs` with two checks:
every language must expose its declared construct markers in source, and
`security taint-analysis --format json --all` must match the default
finding counts listed below. Zero-count rows are valid when the enabled
default rulepack has no source-to-sink rule firing for that fixture;
pattern-only and no-path matches are intentionally excluded from default
taint-analysis text/JSON output. SARIF enables exact source-independent
API/config misuse findings automatically and omits `codeFlows` for those
local pattern rows; lifecycle-audit transition sites stay out of
taint/SARIF findings until the later same-value use is proved. Each
fixture must also include an explicit
`NEGATIVE` clean-twin sink of the same sink kind that receives only a
constant value; the exact finding count fails if that decoy starts
reporting. The same test suite also exports each fixture and verifies the
adapter facts the taint engine depends on: declaration params,
imports/includes, call and string refs, per-language `FlowEvent`
families, resolved call edges, reachable facts, argument/write refs,
import/symbol alias maps where the fixture uses aliases, assignment
chains, and intraprocedural taint. Dedicated cross-file and assignment
audit tests pin source-to-sink chains across all 20 adapters. The complete
release-binary CLI/switch sweep lives in
`scripts/validate-mega-cli.py`; it runs every command family, output mode,
public switch, stable-id drilldown, and cache command against every
language's `mega_flow`.

Run one language:

```
./target/release/bonsai-ninja security examples/<lang>/mega_flow \
    taint-analysis --rules-dir ./security-patterns --all
```

Run the full release gate:

```bash
cargo build --release
scripts/validate-mega-cli.py --bin ./target/release/bonsai-ninja
```

## Current default `security taint-analysis` results

Generated with the release CLI:

```bash
./target/release/bonsai-ninja security examples/<lang>/mega_flow \
  taint-analysis --rules-dir ./security-patterns --format json --all \
  --no-color --no-progress
```

| Lang       | Findings | Primary chain when emitted                                                                          |
| ---------- | -------: | --------------------------------------------------------------------------------------------------- |
| c          |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| cpp        |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| csharp     |        1 | Handle -> OrchestrateAsync -> Orchestrate -> Persist -> Run@Storage.cs:38 -> Run@Storage.cs:27      |
| dart       |        2 | handle_request -> orchestrate -> persist -> AuditedRepository -> run -> execute                     |
| elixir     |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| erlang     |        0 | No default finding (real flow detected with `--inferred-sources`)                                   |
| go         |        1 | handleRequest -> Orchestrate -> Persist -> Run -> Execute                                           |
| java       |        1 | handle -> orchestrate -> persist -> run -> execute                                                  |
| javascript |        1 | handle_request -> orchestrate -> persist -> run -> execute                                          |
| kotlin     |        1 | handle -> orchestrate -> persist -> run -> execute                                                  |
| lua        |        1 | handle_request -> orchestrate -> persist -> run -> execute                                          |
| objc       |        1 | handle_request -> orchestrate -> persist -> run@Storage.m:41 -> run@Storage.m:31 -> executeCmd      |
| perl       |        1 | handle_request -> orchestrate -> StorePersist -> persist -> run -> execute                          |
| php        |        2 | handle_request -> orchestrate -> persist -> run@storage.php:33 -> run@storage.php:27 -> execute     |
| python     |        1 | handle_request -> run_pipeline -> orchestrate -> persist -> perform -> execute                      |
| ruby       |        2 | wrap -> persist -> run -> execute                                                                   |
| rust       |        0 | No default finding                                                                                  |
| scala      |        1 | handle -> orchestrate -> persist -> run -> execute                                                  |
| swift      |        1 | handle_request -> orchestrate -> persist -> run@Storage.swift:30 -> run@Storage.swift:23 -> execute |
| typescript |        1 | handle_request -> orchestrate -> persist -> run -> execute                                          |

> Refresh procedure: rebuild release (`cargo build --release -p bonsai_cli --bin bonsai-ninja`), clear each fixture's external analysis sidecars with `./target/release/bonsai-ninja cache clear examples/<lang>/mega_flow`, then re-run the command in this section's heading per language. Do not delete repository-local `.bonsai/rules` overlays. The full `--inferred-sources` baselines (used by the CI gate `mega_flow_security_pipeline_covers_every_language_and_flow_event_kind`) live in `crates/security/tests/security_pipeline_regressions.rs::expected_mega_flow_findings_with_inferred_sources`.

## What each fixture exercises

Beyond the linear source->sink chain, every fixture routes the tainted
value through the language-idiomatic flow constructs its adapter
reliably follows. Representative coverage:

- **Python**   - decorators, async/await, async generators, match/case,
  context managers, @property/@classmethod/@staticmethod/__call__,
  yield from, walrus, *args/**kwargs.
- **JS / TS**  - async/await, async iterators, generators, destructuring,
  destructured import aliases, spread/rest, template literals, switch,
  try/catch/finally, classes with inheritance + super + abstract,
  type guards (TS), generics (TS).
- **Ruby**    - blocks + yield, Enumerable chain, case/in pattern
  matching, begin/rescue/ensure, modules + mixins, inheritance.
- **PHP**     - closures/arrow-fns, match expressions, generators,
  try/catch/finally, traits, abstract classes + interfaces.
- **Perl**    - anonymous subs, dispatch-by-hash, map/grep, eval-blocks.
- **Imports / aliases** - each fixture includes its language's import
  or alias form where applicable (`as`, `typealias`, `use ... as`,
  aliased `require`, static imports, module aliases, or include/import
  directives). These are enforced by the marker test.
- **Lua**     - coroutines, generic-for iterators, pcall, closures.
- **Java**    - streams + method refs, enhanced switch, records,
  Optional, abstract + generic repository hierarchy.
- **Kotlin**  - sequences, scope functions, extension functions,
  data-class copy, when, sealed hierarchy, runCatching.
- **Scala**   - pattern match, Try monad, trait + abstract + override,
  curried reducers.
- **Go**      - goroutines + channels, context, defer/recover,
  select, closures, interface + struct embedding, named-type enums.
- **Rust**    - iterator fold + closure factory, Result/Option, match,
  trait + newtype delegation, generics.
- **C#**      - LINQ, delegates, switch expressions, yield iterators,
  records + `with` expressions, virtual/override.
- **Swift**   - trailing closures, enums, guard, do/try/catch,
  protocols + inheritance, computed properties.
- **C**       - structs via header, tokenise + reduce, switch +
  goto, while / do-while / for loops, pointer/buffer bookkeeping.
- **C++**     - templates, `std::function` closures, `std::accumulate`,
  smart pointers, abstract base + virtual dispatch.
- **Obj-C**   - dictionary literals, block-typedef closures, fast
  enumeration, @try/@catch/@finally, @interface hierarchy + [super run].
- **Dart**    - null-safety, sync\* generators, extension methods,
  mixins, abstract base, factory constructors.
- **Elixir**  - pipe operator, Enum/Stream, pattern-matched clause
  dispatch, with-clause, try/rescue, structs.
- **Erlang**  - list comprehensions, lists:foldl + anonymous-fun,
  pattern match on records, try/catch.

These fixtures are dense regression programs, not a complete language
specification. The executable taint matrix and adapter conformance suites own
the broader positive and negative syntax contract; see
[`TAINT_COVERAGE_MATRIX.md`](TAINT_COVERAGE_MATRIX.md) and
[`language-support.mdx`](language-support.mdx).
