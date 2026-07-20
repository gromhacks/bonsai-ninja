# Coverage baseline

Per-language static-evidence declarations for the constructs the security
engine cares about. **The headline:** every supported language gets
semantic static evidence where the construct is statically knowable; rare
or runtime-only shapes are surfaced as unsupported or incomplete rather
than widened into guessed findings.

Most cells in the table below say `Partial`, but **`Partial` is not a
user-facing accuracy mode**. It is an internal declaration that the
adapter/engine can emit proven static evidence for recognized forms and
will leave unrecognized forms as diagnostic incompleteness.

> **Reading this alongside [`TAINT_COVERAGE_MATRIX.md`](TAINT_COVERAGE_MATRIX.md)?**
> The taint matrix shows every applicable cell as `pass` - that's the
> per-scenario behavioural truth (`TAINT_COVERAGE_MATRIX.md` currently
> reports 1279 applicable scenario × language cells that run the real
> engine and assert the right answer). This doc is
> the *static-evidence declaration* - `Partial` here means "recognized
> forms produce semantic evidence, rare shapes are marked
> incomplete/unsupported," not "the test fails." Both views are correct
> simultaneously.
>
> **Should everything here be `Exact`?** No - and that is principled,
> not a gap. `Exact` means a closed static model exists for that
> construct. Real-world languages do not admit closed static models for
> reflection, FFI, runtime imports, macro expansion, actor messages, or
> framework event dispatch without extra runtime/build facts. The
> production-correct stance is to emit proven static evidence when it
> exists and surface the remaining cases as incompleteness/debug metadata
> - exactly what `Partial` denotes.
>
> **Should everything here be supported (no `Unsupported` cells)?**
> The remaining `Unsupported` cells are deliberate engineering
> tradeoffs, not omissions:
>
> - **Macros** (C, C++, Elixir, Erlang, Objective-C) - modeling
>   un-expanded macros would invent flow that may not exist after
>   preprocessing. Rust has limited support (`println!` etc.) because
>   the kit recognizes the common shapes; C-style preprocessor macros
>   require a real preprocessor pass we deliberately don't run.
> - **Reflection** (most langs) - runtime introspection
>   (`getattr(obj, dyn_str)`, `Class.forName(...)`, etc.) cannot be
>   resolved statically. Modeling it imprecisely would manufacture
>   false-precision findings.
> - **FFI** - foreign function calls cross the language boundary; we
>   cannot analyze code that isn't in the workspace.
>
> Rather than fire imprecise findings on these, the engine rejects
> rules that anchor on them at rulepack load time. That guarantees a
> clean signal-to-noise ratio over silent imprecision.

## TL;DR

- The engine runs taint analysis successfully on every language in the table.
- Public findings have one accuracy contract: exact/narrowed semantic
  evidence only. `Precision::OverApproximate` and `Precision::Unknown`
  are diagnostic-only and must not become user-facing findings.
- A `Partial` cell means *"recognized forms produce proven static
  evidence; rare forms are marked incomplete/unsupported instead of
  reported as guessed flows"*. It does NOT mean broken or unimplemented.
- An `Unsupported` cell means *"rules anchored on this construct are
  rejected at rulepack load time"* - a deliberate choice that prevents
  rules from firing on shapes the engine wouldn't analyse precisely.
- An `n/a` cell means the construct **does not exist in that
  language** (e.g. macros in JavaScript, exceptions in Rust). Rules
  targeting it would never apply anyway.
- Real coverage is verified by **per-language matrix tests** in
  `crates/security/tests/` and `crates/taint/tests/`, not by this
  capability declaration.

## What the levels mean

| Level | Internal evidence declaration | Effect on rules | When you'd see it |
|---|---|---|---|
| `Exact` | Construct has a closed static model. Findings may use `Precision::Exact`. | Rule fires whenever the static model proves a match. | Only set when an adapter has a closed-form analysis for this category (rare today; see [backlog](#backlog) below). |
| `Partial` | Recognized forms produce semantic evidence; unrecognized forms are marked incomplete/unsupported. | Rule fires only when exact/narrowed semantic evidence exists. | The conservative default. Most cells. Means "the engine works here, with honest completion metadata." |
| `Unsupported` | Construct has no static evidence model. | **Rules requiring this category are rejected at rulepack load time.** | A deliberate gate: prevents false-precision findings on shapes the engine would not analyze correctly. |
| `n/a` | Construct doesn't exist in this language. | No rule could target it anyway. | E.g. macros in JS, exceptions in Rust, generics in Lua. |

So `Partial` everywhere is **not a second accuracy level**: it is the
engine telling you "I will emit a finding only for proven static evidence,
and where I cannot prove it I will report incompleteness/diagnostics
instead of guessing."

## Capability matrix

Capabilities are grouped by what they affect.

### Tier 1 - Required for taint analysis to run

These are the constructs the resolver and CFG layer use to walk a
program. Without them, the engine can't even build a call graph.
Every supported language declares `Partial` here, meaning the engine can
analyse the language end-to-end while still rejecting unproven edges from
public findings.

| Language | Modules | Dyn dispatch | Exceptions | Receiver types | Module export aliases |
|---|---|---|---|---|---|
| c | Partial | n/a | n/a | Partial | n/a |
| cpp | Partial | Partial | Partial | Partial | n/a |
| csharp | Partial | Partial | Exact | Partial | n/a |
| dart | Partial | Partial | Partial | Partial | n/a |
| elixir | Partial | Partial | n/a | Unsupported | n/a |
| erlang | Partial | n/a | n/a | Unsupported | n/a |
| go | Partial | Partial | n/a | Partial | n/a |
| java | Partial | Partial | Exact | Partial | n/a |
| javascript | Partial | Partial | Partial | Unsupported | exports, module.exports |
| kotlin | Partial | Partial | Exact | Partial | n/a |
| lua | Partial | Partial | Partial | Unsupported | n/a |
| objc | Partial | Partial | Partial | Partial | n/a |
| perl | Partial | Partial | Partial | Unsupported | n/a |
| php | Partial | Partial | Partial | Partial | n/a |
| python | Partial | Partial | Partial | Partial | n/a |
| ruby | Partial | Partial | Partial | Unsupported | n/a |
| rust | Partial | Partial | n/a | Partial | n/a |
| scala | Partial | Partial | Partial | Partial | n/a |
| solidity | Partial | Partial | Partial | Partial | n/a |
| swift | Partial | Partial | Partial | Partial | n/a |
| typescript | Partial | Partial | Partial | Partial | exports, module.exports |

`n/a` = construct doesn't exist in that language (C has no virtual
dispatch; Rust uses `Result` instead of exceptions; Erlang has no
class hierarchy).

### Tier 2 - Required only if a rule uses the construct

These categories matter for rules that anchor on async/await,
coroutines, generics, or pattern matching. A rule that doesn't target
them is unaffected by these cells.

| Language | Generics | Async / await | Coroutines | Pattern matching |
|---|---|---|---|---|
| c | n/a | n/a | n/a | n/a |
| cpp | Partial | n/a | Partial | n/a |
| csharp | Partial | Partial | Partial | Partial |
| dart | Partial | Partial | Partial | Partial |
| elixir | n/a | n/a | Partial | Partial |
| erlang | n/a | n/a | Partial | Partial |
| go | Partial | n/a | Partial | n/a |
| java | Partial | Partial | n/a | Partial |
| javascript | n/a | Partial | Partial | n/a |
| kotlin | Partial | Partial | Partial | Partial |
| lua | n/a | n/a | Partial | n/a |
| objc | n/a | n/a | n/a | n/a |
| perl | n/a | n/a | n/a | n/a |
| php | n/a | n/a | Partial | n/a |
| python | n/a | Partial | Partial | Partial |
| ruby | n/a | n/a | Partial | Partial |
| rust | Partial | Exact | n/a | Exact |
| scala | Partial | Partial | Partial | Exact |
| solidity | n/a | n/a | n/a | n/a |
| swift | Partial | Partial | Partial | Exact |
| typescript | Partial | Partial | Partial | n/a |

The Coroutines column was previously marked `Unsupported`; it is
`Partial` now because the kit recognizes all six yield grammar
shapes (`yield`, `yield_statement`, `yield_expression`,
`yield_from_expression`, `co_yield_*`) and emits `FlowEvent::Yield`,
which the interprocedural engine treats as return-equivalent for
summary construction. The `Partial` (rather than `Exact`) caveat is that
cross-process generator-state propagation has no closed static proof and
therefore remains diagnostic/incomplete rather than a guessed finding.

### Tier 3 - Adapter conveniences (precision boosters)

These don't gate rule loading; they affect how the resolver narrows
candidate edges. `Unsupported` here means findings that go through this
construct are not emitted as semantic evidence; `Partial` means recognized
forms can emit exact/narrowed evidence and unrecognized forms stay
diagnostic-only.

| Language | Macros | Reflection | FFI |
|---|---|---|---|
| c | Partial | n/a | Unsupported |
| cpp | Partial | Unsupported | Unsupported |
| csharp | n/a | Unsupported | Unsupported |
| dart | n/a | n/a | n/a |
| elixir | Unsupported | n/a | n/a |
| erlang | Unsupported | n/a | n/a |
| go | n/a | Unsupported | Unsupported |
| java | n/a | Partial | Unsupported |
| javascript | n/a | n/a | n/a |
| kotlin | n/a | Unsupported | Unsupported |
| lua | n/a | n/a | Unsupported |
| objc | Partial | Unsupported | Unsupported |
| perl | n/a | Unsupported | n/a |
| php | n/a | Unsupported | n/a |
| python | n/a | Partial | Unsupported |
| ruby | n/a | Unsupported | n/a |
| rust | Partial | n/a | Partial |
| scala | n/a | Unsupported | n/a |
| solidity | n/a | n/a | n/a |
| swift | n/a | Unsupported | n/a |
| typescript | n/a | n/a | n/a |

## Per-language summary

A plain-English read of where each language stands today:

- **C / C++** - Core analysis works. C++ templates handled as a single
  decl with type parameters; unsupported per-instantiation specialisation
  is treated as incomplete. Macro expansion is not performed; rules
  anchored on macro-defined names won't fire. Smart-pointer move/copy
  isn't distinguished beyond the standard Assign event.
- **C#** - Standard async/await flows analysed; reflection (`Type`
  introspection, dynamic invocation) is opaque. Generic
  monomorphisation works for the closed set of instantiations seen.
- **Dart** - Standard analysis. Async/await modeled; FFI is library-
  level (not a language construct) so declared `n/a`.
- **Elixir / Erlang** - Module + protocol/behaviour resolution works;
  process boundaries (`spawn`, `send`, `receive`) are unresolved by
  design - taint cannot cross process boundaries in static analysis
  on an actor model. GenServer callbacks are recognised but the
  message protocol is opaque.
- **Go** - Standard module + interface dispatch analysis. Generics
  (1.18+) handled. `panic`/`recover` is not modeled as exceptions;
  goroutines record the spawn but happens-before is not tracked.
- **Java / Kotlin** - Standard inheritance + method-resolution
  analysis. Annotations (`@RequestBody`, etc.) are read by the
  resolver; reflection (`Class.forName`) is opaque.
- **JavaScript / TypeScript** - CommonJS + ES module analysis. The
  engine credits `module.exports = X` and `exports.X = …` to the
  module's public surface (the only languages that need this). Type
  annotations populate `Decl.type_aliases`; flow-sensitive narrowing
  isn't used by the matcher.
- **Lua** - Module-level resolution via `require` works; the
  metatable-based "method dispatch" is partially modeled (the common
  `obj:method()` shape resolves; metatable forwarding chains
  degrade).
- **Objective-C** - Standard class + protocol analysis. C-interop
  (FFI) is via direct C calls; modeled at the standard call-site
  level.
- **Perl / PHP / Python / Ruby** - Standard class + module analysis.
  Decorators (Python) and modifiers (PHP attributes, Ruby method
  visibility) feed the resolver. Dynamic dispatch (Python `getattr`,
  Ruby `send`) is opaque when the method name is computed.
- **Rust** - Trait-based dispatch analysis. `Box<dyn Trait>` calls
  emit semantic virtual edges only when the receiver set is proven. No
  exception model (Rust uses `Result`); macro expansion is partial
  (we recognise common shapes like `println!`, but `macro_rules!`
  and proc-macros aren't expanded).
- **Scala** - Inheritance + pattern-matching analysis. FFI via Scala-
  native isn't modeled (not a language-level construct).
- **Solidity** - Contract inheritance + try/catch external-call
  analysis. Inline `assembly { … }` (Yul) is parsed but not modeled;
  rules anchored on inline-assembly shapes need manual annotation.
- **Swift** - Standard class + protocol analysis. FFI via the
  Objective-C bridge or `@_cdecl` isn't modeled at the language
  level.

## Explicit adapter capability declarations

All 21 adapters explicitly declare the complete
[`LanguageCapabilities`](../crates/lang_api/src/capabilities.rs) shape.
Baseline constructors are initialization helpers only; no adapter inherits a
cross-language syntax policy by omission. Each declaration owns its grammar
coverage plus module/export aliases, module-path syntax, constructor method
forms, implicit and super receivers, universal type spellings, and field-place
completeness. Shared resolver and IDG code consume those facts without
language-id branches or token unions.

`scripts/audit-adapter-capabilities.sh --check` and the architecture
invariants reject missing declarations, shared hardcoded source inventories,
and adapter/core boundary violations.

## Backlog

Promotion candidates - places where an adapter could declare `Exact` once
the matching static model and test coverage land:

- **C# / Java / Kotlin:** `Exceptions -> Exact` (typed `throws` /
  checked exceptions / `try-catch` chains are statically analysable
  in ways Python/Ruby exception hierarchies aren't).
- **JavaScript / TypeScript:** `Modules -> Exact` for ES module graphs
  that aren't dynamic-import-shaped.
- **Scala / Swift:** `Pattern matching -> Exact` (both have exhaustive-
  by-default match expressions with compiler-validated totality).
- **Rust:** `Async / await -> Exact` once we model `Future::poll`
  happens-before relations from `tokio::spawn` / `select!`.

Each promotion lands together with: (a) the adapter override
declaration, (b) a per-language matrix test exercising the construct
end-to-end, (c) re-blessing both snapshots.

## How this doc stays honest

The matrix above is generated from runtime data plus a curated
applicability map (which constructs each language has). Two snapshots
gate it in CI:

```sh
# detect drift
cargo test -p bonsai_conformance --test coverage_baseline

# accept drift after intentional adapter or applicability change
BLESS_BASELINE=1 cargo test -p bonsai_conformance --test coverage_baseline -- --nocapture
```

- `.snapshots/COVERAGE_BASELINE.snapshot` - raw runtime levels (no
  applicability overlay). Pure drift gate against
  `LanguageCapabilities` returns.
- `.snapshots/COVERAGE_BASELINE.rendered.snapshot` - the human-readable
  table above with applicability overlay. Editing the applicability
  map in [`coverage_baseline.rs`](../crates/conformance/tests/coverage_baseline.rs)
  invalidates this snapshot and forces a re-bless.

Editing the doc table by hand without re-blessing makes the
conformance test fail. Editing an adapter's `capabilities()` without
re-blessing makes the test fail. Either is caught by CI.

## What this doc does NOT measure

Things that aren't visible in this matrix:

- **Per-language rule density.** A language with a thin rulepack and
  `Partial` capabilities may surface fewer findings than one with a fat
  rulepack and identical capabilities. That's about rule writing and
  available static evidence, not a lower public accuracy mode.
- **Real-world completion distribution.** What fraction of findings on
  a typical workspace land at `Exact` / `Narrowed` and what fraction of
  sections are marked incomplete. That's measurable by running the engine
  on a corpus and tallying public semantic evidence plus completion
  metadata.
- **CFG completeness.** Whether each adapter emits Call / Assign /
  Param / Return for every grammar shape. That's the actual taint-
  coverage question, and it's tested by the per-language matrix
  tests (`crates/taint/tests/over_taint_per_language.rs`,
  `crates/cli/tests/per_lang_cli_matrix.rs`,
  `crates/security/tests/security_pipeline_regressions.rs`), not
  declared here.

If you want a real "how good is taint coverage" view, the evidence
histogram is the metric - capability levels are a contract for rule
validation and incompleteness reporting, not a second accuracy mode.
