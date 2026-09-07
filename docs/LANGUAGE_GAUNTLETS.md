# language_gauntlet coverage

Per-language fixtures live at `examples/<lang>/language_gauntlet/`. They are the
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

CI pins this in `crates/cli/tests/security_commands.rs` and the independent
release-binary validator with two checks:
every language must expose its declared construct markers in source, and
the default production `security taint-analysis --format json --all --no-cache` must match the
concrete rule-backed source-to-sink finding counts listed below. Every row must
be nonzero and report `analysis_complete: true`; inferred entry-point sources
are tested separately and cannot satisfy this gate. Pattern-only and no-path
matches are intentionally excluded from default taint-analysis text/JSON
output. SARIF enables exact source-independent
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
`scripts/validate-language-gauntlets.py`; it runs every command family and the maintained
output-mode, public-switch, stable-id, and cache-command matrix against every
language's `language_gauntlet`. It is not a claim that every possible flag combination
is useful or tested.

Finding-level completeness does not imply complete dependency coverage for the
workspace. The Go (`go.mod`), Objective-C (`Podfile`), and Swift
(`Package.swift`) fixtures currently retain explicit unsupported-manifest
reasons on the top-level analysis envelope. Both validators pin those exact
gaps; a new gap or an incorrectly complete envelope fails the gate.

Run one language:

```
./target/release/bonsai-ninja security examples/<lang>/language_gauntlet \
    taint-analysis --rules-dir ./security-patterns --all --no-cache
```

Run the full release gate:

```bash
cargo build --release
scripts/validate-language-gauntlets.py --bin ./target/release/bonsai-ninja
```

## Current production `security taint-analysis` results

Generated with the release CLI:

```bash
./target/release/bonsai-ninja security examples/<lang>/language_gauntlet \
  taint-analysis --rules-dir ./security-patterns --format json --all --no-cache \
  --no-color --no-progress
```

| Lang       | Findings | Primary chain when emitted                                                                          |
| ---------- | -------: | --------------------------------------------------------------------------------------------------- |
| c          |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| cpp        |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| csharp     |        1 | Handle -> OrchestrateAsync -> Orchestrate -> Persist -> Run@Storage.cs:38 -> Run@Storage.cs:27      |
| dart       |        1 | handle_request -> orchestrate -> persist -> AuditedRepository -> run -> execute                     |
| elixir     |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| erlang     |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| go         |        1 | handleRequest -> Orchestrate -> Persist -> Run -> Execute                                           |
| java       |        1 | handle -> orchestrate -> persist -> run -> execute                                                  |
| javascript |        1 | handle_request -> orchestrate -> persist -> run -> execute                                          |
| kotlin     |        1 | handle -> orchestrate -> persist -> run -> execute                                                  |
| lua        |        1 | handle_request -> orchestrate -> persist -> run -> execute                                          |
| objc       |        1 | handle_request -> orchestrate -> persist -> run@Storage.m:41 -> run@Storage.m:31 -> executeCmd      |
| perl       |        1 | handle_request -> orchestrate -> StorePersist -> persist -> run -> execute                          |
| php        |        1 | handle_request -> orchestrate -> persist -> run@storage.php:33 -> run@storage.php:27 -> execute     |
| python     |        1 | handle_request -> run_pipeline -> orchestrate -> persist -> perform -> execute                      |
| ruby       |        1 | wrap -> persist -> run -> execute                                                                   |
| rust       |        1 | main -> orchestrate -> persist -> run -> execute                                                    |
| scala      |        1 | handle -> orchestrate -> persist -> run -> execute                                                  |
| swift      |        1 | handle_request -> orchestrate -> persist -> run@Storage.swift:30 -> run@Storage.swift:23 -> execute |
| typescript |        1 | handle_request -> orchestrate -> persist -> run -> execute                                          |

> Refresh procedure: rebuild release (`cargo build --release -p bonsai-ninja --bin bonsai-ninja`), clear each fixture's external analysis sidecars with `./target/release/bonsai-ninja cache clear examples/<lang>/language_gauntlet`, then re-run the command in this section's heading per language. Do not delete repository-local `.bonsai/rules` overlays. Concrete-source release counts are authoritative for this table; the separate inferred-source regression suite must remain additive and cannot hide a missing rule-backed source.

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
