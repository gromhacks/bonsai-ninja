# mega_flow coverage

Per-language fixtures live at `examples/<lang>/mega_flow/`. They are the
correctness fixtures for the taint engine and CLI surfaces: each threads
a user-input → sink chain across 3–6 files through every source-visible
flow construct the language adapter is expected to model. The fixtures
are deliberately dense: language-specific constructs are present as real
source code, and taint-relevant constructs are kept on the canonical
source→sink path where the adapter can follow them.

CI pins this in `crates/cli/tests/security_commands.rs` with two checks:
every language must expose its declared construct markers in source, and
`security taint-analysis --format json --all` must match the default
finding counts listed below. Zero-count rows are valid when the enabled
default rulepack has no source-to-sink rule firing for that fixture;
pattern-only and no-path matches are intentionally excluded from default
taint-analysis text/JSON output. SARIF enables exact source-independent
API/config misuse findings automatically and omits `codeFlows` for those
local pattern rows. Each fixture must also include an explicit
`NEGATIVE` clean-twin sink of the same sink kind that receives only a
constant value; the exact finding count fails if that decoy starts
reporting. The same test suite also exports each fixture and verifies the
adapter facts the taint engine depends on: declaration params,
imports/includes, call and string refs, per-language `FlowEvent`
families, resolved call edges, reachable facts, argument/write refs,
import/symbol alias maps where the fixture uses aliases, assignment
chains, and intraprocedural taint. Dedicated cross-file and assignment
audit tests pin the source-to-sink chains across all 21 languages. The
complete release-binary CLI/switch sweep lives in
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

| Lang       | Findings | Primary chain when emitted                                     |
|------------|---------:|----------------------------------------------------------------|
| c          | 1        | main → orchestrate → persist → run → execute                   |
| cpp        | 0        | No default finding                                             |
| csharp     | 0        | No default finding                                             |
| dart       | 0        | No default finding                                             |
| elixir     | 0        | No default finding                                             |
| erlang     | 0        | No default finding                                             |
| go         | 1        | handleRequest → Orchestrate → Persist → Run → Execute          |
| java       | 0        | No default finding                                             |
| javascript | 1        | handle_request → orchestrate → persist → run → execute         |
| kotlin     | 1        | handle → orchestrate → persist → run → execute                 |
| lua        | 3        | handle_request → orchestrate → persist → run → execute         |
| objc       | 2        | handle_request → orchestrate → persist → run → executeCmd      |
| perl       | 1        | handle_request → orchestrate → StorePersist → persist → run → execute |
| php        | 0        | No default finding                                             |
| python     | 1        | handle_request → run_pipeline → orchestrate → persist → perform → execute |
| ruby       | 2        | handle_request → orchestrate → persist → run → execute         |
| rust       | 0        | No default finding                                             |
| scala      | 0        | No default finding                                             |
| solidity   | 1        | audit                                                          |
| swift      | 0        | No default finding                                             |
| typescript | 1        | handle_request → orchestrate → persist → run → execute         |

## What each fixture exercises

Beyond the linear source→sink chain, every fixture routes the tainted
value through the language-idiomatic flow constructs its adapter
reliably follows. Representative coverage:

- **Python**   — decorators, async/await, async generators, match/case,
  context managers, @property/@classmethod/@staticmethod/__call__,
  yield from, walrus, *args/**kwargs.
- **JS / TS**  — async/await, async iterators, generators, destructuring,
  destructured import aliases, spread/rest, template literals, switch,
  try/catch/finally, classes with inheritance + super + abstract,
  type guards (TS), generics (TS).
- **Ruby**    — blocks + yield, Enumerable chain, case/in pattern
  matching, begin/rescue/ensure, modules + mixins, inheritance.
- **PHP**     — closures/arrow-fns, match expressions, generators,
  try/catch/finally, traits, abstract classes + interfaces.
- **Perl**    — anonymous subs, dispatch-by-hash, map/grep, eval-blocks.
- **Imports / aliases** — each fixture includes its language's import
  or alias form where applicable (`as`, `typealias`, `use ... as`,
  aliased `require`, static imports, module aliases, or include/import
  directives). These are enforced by the marker test.
- **Lua**     — coroutines, generic-for iterators, pcall, closures.
- **Java**    — streams + method refs, enhanced switch, records,
  Optional, abstract + generic repository hierarchy.
- **Kotlin**  — sequences, scope functions, extension functions,
  data-class copy, when, sealed hierarchy, runCatching.
- **Scala**   — pattern match, Try monad, trait + abstract + override,
  curried reducers.
- **Go**      — goroutines + channels, context, defer/recover,
  select, closures, interface + struct embedding, named-type enums.
- **Rust**    — iterator fold + closure factory, Result/Option, match,
  trait + newtype delegation, generics.
- **C#**      — LINQ, delegates, switch expressions, yield iterators,
  records + `with` expressions, virtual/override.
- **Swift**   — trailing closures, enums, guard, do/try/catch,
  protocols + inheritance, computed properties.
- **C**       — structs via header, tokenise + reduce, switch +
  goto, while / do-while / for loops, pointer/buffer bookkeeping.
- **C++**     — templates, `std::function` closures, `std::accumulate`,
  smart pointers, abstract base + virtual dispatch.
- **Obj-C**   — dictionary literals, block-typedef closures, fast
  enumeration, @try/@catch/@finally, @interface hierarchy + [super run].
- **Dart**    — null-safety, sync\* generators, extension methods,
  mixins, abstract base, factory constructors.
- **Elixir**  — pipe operator, Enum/Stream, pattern-matched clause
  dispatch, with-clause, try/rescue, structs.
- **Erlang**  — list comprehensions, lists:foldl + anonymous-fun,
  pattern match on records, try/catch.
- **Solidity**— inheritance, modifiers, library calls, if/else,
  bounded loops, unchecked blocks, try/catch on external calls, events.

## Adapter constraints we hit

Not every construct survives the chain builder. Where an idiom breaks
dispatch, the fixture uses the closest procedural equivalent:

- **Perl / Lua** — OO via bless / metatables doesn't connect method
  dispatch to decls. Both fall back to procedural storage.
- **Rust**     — indirect function-pointer dispatch (`runner_fn p = f`)
  is opaque; use direct calls.
- **TypeScript** — a turbofish-style generic call (`persist<T>(…)`)
  isn't followed; drop the explicit type argument.

Patching those is an adapter-level fix, not a fixture change.
