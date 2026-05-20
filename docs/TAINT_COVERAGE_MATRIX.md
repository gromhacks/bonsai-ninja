# Taint coverage matrix

Auto-generated from `crates/taint/tests/matrix/`. Edit the
scenario / applicability tables there, then rebless via:

```sh
BLESS_TAINT_MATRIX=1 cargo test -p bonsai_taint --test matrix_coverage_report -- --nocapture
```

**Scenarios:** 76  |  **Languages:** 21  |  **Applicable cells:** 1267

## What this matrix actually measures

This is the **engine's behavioural** matrix: for each (scenario,
language) pair, the linked test fixture exercises the real adapter
+ engine pipeline and asserts the expected taint outcome (positive
flows reach the sink, over-taint cases stay clean). Every applicable
cell shows `pass` because its per-language `#[test]` passes in the
workspace test sweep — drift would block CI.

The matrix also refuses to mark a cell `Applicable` unless the
scenario fixture file contains a concrete `fn <scenario>_<lang>()`
test. Cells without executable fixture coverage must stay explicit as
`n/a` or `deferred`; they are not counted as passing behaviour.

Two sister documents look pessimistic by comparison and that is
intentional — they measure different things:

- [`COVERAGE_BASELINE.md`](COVERAGE_BASELINE.md) reports per-construct
  *modeling level*. Cells say `Partial` because that is the engine's
  healthy default — common case modeled precisely, rare forms emit
  `Precision::OverApproximate`. `Partial` does NOT mean the scenario
  fails; it means precision is honestly flagged.
- [`adapter-capabilities.mdx`](contributing/adapter-capabilities.mdx) tracks which
  *optional* `Decl` fields each adapter populates. `—` cells are
  precision-booster backlog (e.g. tighter virtual dispatch); none of
  them gate taint analysis.

If a cell here passes but a sister-doc cell shows `Partial` /
`—`, the engine still produces the correct taint answer — it just
flags lower precision on the rarer shapes. The behavioural truth
lives in this matrix.

## Legend

- `pass` — applicable cell, per-language test exists and passes
- `fail` — applicable cell, per-language test exists but fails (would block CI; never present in a clean tree)
- `n/a` — language has no equivalent construct
- `deferred` — language has the construct, adapter doesn't model it yet

## Intra-procedural

| Scenario | Description | c | cpp | csharp | dart | elixir | erlang | go | java | javascript | kotlin | lua | objc | perl | php | python | ruby | rust | scala | solidity | swift | typescript |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `I_01` | Single assignment propagates | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_02` | Clean reassignment overwrites taint | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_03` | Augmented assignment propagates | pass | pass | pass | pass | n/a | n/a | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_04` | Tuple/multiple assignment splits taint | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_05` | Destructure from tainted RHS | n/a | pass | pass | pass | n/a | n/a | pass | pass | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | n/a | pass | pass |
| `I_06` | Ternary / conditional expression | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_07` | If-branch merge propagates | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_08` | Else-branch merge propagates | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_09` | Loop body propagation | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_10` | Loop carry across iterations | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_11` | For-each over tainted iterable | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_12` | While with tainted condition | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `I_13` | Try → throw → catch propagates | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass | pass | n/a | pass | pass | pass | pass |
| `I_14` | Catch param propagates further | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass |
| `I_15` | Finally after taint | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass |
| `I_16` | Pattern match arm body | n/a | n/a | pass | pass | pass | pass | n/a | pass | n/a | pass | n/a | n/a | n/a | n/a | pass | pass | pass | pass | n/a | pass | n/a |
| `I_17` | Switch/case fall-through | n/a | n/a | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | n/a | pass | n/a | n/a | n/a | n/a | n/a | pass | pass |
| `I_18` | Closure captures tainted local | n/a | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass |
| `I_19` | Lambda body taint | n/a | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass |
| `I_20` | Lazy init via if-not assignment | pass | pass | n/a | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass |

## Inter-procedural

| Scenario | Description | c | cpp | csharp | dart | elixir | erlang | go | java | javascript | kotlin | lua | objc | perl | php | python | ruby | rust | scala | solidity | swift | typescript |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `R_01` | Direct call with tainted arg | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_02` | Tainted return value to caller LHS | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_03` | Method receiver taint propagates | n/a | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_04` | Method tainted arg propagates | n/a | pass | pass | pass | n/a | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_05` | Constructor / new with taint | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass | pass | pass | pass | n/a | pass | pass |
| `R_06` | Static / class method propagates | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_07` | Dotted module call propagates | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_08` | Out-param / mutable reference convention | pass | pass | pass | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a |
| `R_09` | Higher-order: pass tainted to callback | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_10` | Higher-order: callback returns tainted | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_11` | Async / await propagates | n/a | n/a | pass | pass | n/a | n/a | n/a | n/a | pass | pass | n/a | n/a | n/a | n/a | pass | n/a | pass | pass | n/a | pass | pass |
| `R_12` | Generator yield reaches consumer | n/a | n/a | pass | pass | n/a | n/a | n/a | n/a | pass | pass | n/a | n/a | n/a | n/a | pass | pass | n/a | n/a | n/a | n/a | pass |
| `R_13` | Multi-return splat to LHS variables | n/a | n/a | pass | pass | pass | pass | pass | n/a | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | n/a | pass | pass |
| `R_14` | Overload dispatch considers all candidates | n/a | pass | pass | n/a | n/a | n/a | n/a | pass | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass | n/a | pass | pass |
| `R_15` | Recursive function terminates with taint | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_16` | Mutual recursion converges | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `R_17` | Callable variable / function pointer | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass |
| `R_18` | Default argument value stays clean | n/a | pass | pass | pass | n/a | n/a | n/a | n/a | pass | pass | pass | n/a | pass | pass | pass | pass | n/a | pass | n/a | pass | pass |
| `R_19` | Variadic args carry taint | n/a | pass | pass | n/a | n/a | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | n/a | pass | pass |
| `R_20` | Keyword args land on named param | n/a | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | n/a | pass | n/a | pass | pass | pass | n/a | pass | n/a | pass | pass |

## Cross-file

| Scenario | Description | c | cpp | csharp | dart | elixir | erlang | go | java | javascript | kotlin | lua | objc | perl | php | python | ruby | rust | scala | solidity | swift | typescript |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `X_01` | Direct import + call | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `X_02` | Aliased import | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | n/a | pass | pass |
| `X_03` | From-import | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass |
| `X_04` | Re-export chain A→B→C | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass |
| `X_05` | Default export (JS/TS) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass |
| `X_06` | Namespace import (import * as X) | n/a | pass | pass | pass | pass | n/a | pass | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | pass | pass | n/a | n/a | pass |
| `X_07` | Star import (from x import *) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| `X_08` | Dynamic import (string-driven) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass |
| `X_09` | CommonJS require + assign | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass |
| `X_10` | ES module ↔ CommonJS interop | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | pass |
| `X_11` | Visibility crossing — private blocks | pass | pass | pass | pass | n/a | n/a | pass | pass | pass | pass | n/a | pass | n/a | pass | n/a | pass | pass | pass | pass | pass | pass |
| `X_12` | Inheritance across files | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | pass | pass | pass | pass | n/a | pass | pass | pass | pass |
| `X_13` | Instance method on imported class | n/a | pass | pass | pass | n/a | n/a | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `X_14` | Static method on imported class | n/a | pass | pass | pass | n/a | n/a | n/a | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `X_15` | Module-level shadow — local wins | pass | pass | pass | pass | pass | pass | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | n/a | pass | pass | n/a | pass |
| `X_16` | Multi-file fan-in to same callee | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |

## Over-taint (negatives)

| Scenario | Description | c | cpp | csharp | dart | elixir | erlang | go | java | javascript | kotlin | lua | objc | perl | php | python | ruby | rust | scala | solidity | swift | typescript |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `OT_01` | Sibling field read stays clean | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_02` | Literal containing seed name stays clean | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_03` | Second-arg taint doesn't backflow to first-arg | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_04` | Tainted helper param doesn't taint sibling sink arg | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_05` | sizeof operand isn't allocator size | pass | pass | pass | n/a | n/a | n/a | pass | pass | n/a | pass | n/a | pass | n/a | n/a | n/a | n/a | pass | pass | n/a | pass | n/a |
| `OT_06` | Fixed-size pointer copy length stays clean | pass | pass | pass | n/a | n/a | n/a | pass | pass | n/a | pass | n/a | pass | n/a | n/a | n/a | n/a | pass | pass | n/a | pass | n/a |
| `OT_07` | Clean overwrite before sink clears taint | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_08` | Lifecycle / guard path stays clean | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_09` | Field carrier stays field-scoped | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_10` | Field-derived local stays clean | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_11` | Clean return after consume stays clean | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_12` | Unknown call doesn't taint independent later sink | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_13` | Sibling key/index reads stay clean | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_14` | Argparse → eval through hardcoded filter | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_15` | Constant int/bool args don't promote | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_16` | Receiver-only taint doesn't promote to scalar arg | n/a | pass | pass | pass | n/a | n/a | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_17` | Variable named like seed but unrelated | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_18` | Type annotation containing seed name | n/a | pass | pass | pass | pass | pass | n/a | pass | n/a | pass | n/a | pass | n/a | n/a | pass | n/a | pass | pass | n/a | pass | pass |
| `OT_19` | Function name with seed substring | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| `OT_20` | Module qualifier (Task #279) — os.getenv doesn't taint os | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass | pass |

## Coverage summary

| Language | Applicable cells | Tests passing | Adapter-deferred |
|---|---:|---:|---:|
| c | 45 | 45 | 0 |
| cpp | 65 | 65 | 0 |
| csharp | 70 | 70 | 0 |
| dart | 66 | 66 | 0 |
| elixir | 49 | 49 | 0 |
| erlang | 43 | 43 | 0 |
| go | 55 | 55 | 0 |
| java | 65 | 65 | 0 |
| javascript | 69 | 69 | 0 |
| kotlin | 70 | 70 | 0 |
| lua | 50 | 50 | 0 |
| objc | 64 | 64 | 0 |
| perl | 52 | 52 | 0 |
| php | 63 | 63 | 0 |
| python | 65 | 65 | 0 |
| ruby | 64 | 64 | 0 |
| rust | 60 | 60 | 0 |
| scala | 68 | 68 | 0 |
| solidity | 46 | 46 | 0 |
| swift | 67 | 67 | 0 |
| typescript | 71 | 71 | 0 |
