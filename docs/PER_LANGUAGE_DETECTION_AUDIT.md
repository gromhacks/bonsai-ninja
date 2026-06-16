# Per-language detection-correctness audit matrix

Systematic per-language probe of the shared taint engine across all 21 supported
languages, covering the workstream dimensions from the detection-correctness
goal. Each cell was probed with the release binary:

```
./target/release/bonsai-ninja security <fixture-dir> taint-analysis --inferred-sources
```

which seeds function/method **parameters** as taint sources. Every probe first
established a **baseline** (a parameter flowing *directly* into a real enabled
sink fires ≥1 finding) so that a dimension FAIL is a genuine engine gap and not a
missing sink rule or a fixture-quality artifact.

Last run: 2026-06-16 (commit history: see `WS3:`/`WS4:` commits).

## Authoritative rule-example coverage

`security <pack> pack --validate --taint-replay` replays every taint-dependent
rule's positive `match_example` through live taint across all 21 languages.

- **Result: 3 misses out of the entire pack**, all pre-existing documented deep
  gaps: `javascript.proto_pollution.recursive_merge`,
  `typescript.proto_pollution.recursive_merge` (dataflow through a nested
  `Object.keys().forEach(arrow)` recursive merge) and `perl.xss.cgi_print`
  (`.`-concat taint + parenless `print LIST`). CVE-Bench is the real recall gate
  for these.

## Engine-dimension matrix

Dimensions:
- **baseline** — param flows directly into a sink.
- **coercion** — param routed through the language's string-coercion before the
  sink (the WS3 "builtin coercions drop container/element taint" item).
- **cond-reassign** — `v = ""; if cond { v = param }; sink(v)` (WS3 conditional
  reassignment).
- **fqn-no-import** — a fully-qualified / module-qualified sink call with no
  in-file import (WS1 package gate). `N/A` where the language's sinks are global
  builtins (`system`) or member calls with no package qualifier to omit.

| lang | baseline | coercion | cond-reassign | fqn-no-import |
|------|----------|----------|---------------|---------------|
| python | PASS | PASS | PASS | PASS |
| ruby | PASS | FIXED¹ | PASS | N/A |
| php | PASS | PASS | PASS | N/A |
| javascript | PASS | FIXED¹ | PASS | PASS |
| typescript | PASS | FIXED¹ | PASS | PASS |
| lua | PASS | PASS | PASS | N/A |
| perl | PASS | PASS | PASS | N/A |
| go | PASS | PASS | PASS | PASS |
| rust | PASS | FIXED² | PASS | PASS |
| c | PASS | PASS | PASS | N/A |
| cpp | PASS | gap³ | PASS | N/A |
| java | PASS | PASS | PASS | PASS |
| csharp | PASS | PASS | PASS | PASS |
| kotlin | PASS | PASS | PASS | PASS |
| scala | PASS | FIXED² | PASS | PASS |
| swift | PASS | PASS | PASS | N/A |
| objc | PASS | PASS | PASS | N/A |
| dart | PASS | PASS | PASS | N/A |
| solidity | PASS | N/A⁴ | PASS | N/A |
| elixir | PASS | PASS | gap⁵ | PASS |
| erlang | PASS | FIXED² | PASS | PASS |

### Fixes applied this audit (rulepack passthrough rules)

1. **`String()` free-function coercion** — `{ruby,javascript,typescript}.passthrough.string_coerce`
   (`callee name: String`, `call_result_passthrough_args:[0]`). The method/operator
   forms (`.to_s`, `.toString()`, `` `${p}` ``, `p+""`) already propagated; the
   free-function `String(p)` did not (in js/ts specifically when used *inline* as a
   sink argument). Safe: only propagates when arg0 is tainted; no micro-fixture
   sanitizer-inventory pollution (verified).
2. **Module/path coercion calls** —
   `scala.passthrough.string_value_of` (`String.valueOf`, mirrors the existing Java
   rule), `rust.passthrough.string_from` (`String::from`; `.to_string()`/`format!`
   already worked), `erlang.passthrough.lists_flatten` + `lists_concat` (the
   canonical `os:cmd(lists:flatten(io_lib:format(...)))` idiom now flows). All are
   specific attribute callees — no inventory pollution.

### Known remaining engine gaps (adapter-level; deferred, regression-risky)

3. **cpp** — `std::string s = std::string(p); system(s.c_str())` drops taint, while
   the inline form `system(std::string(p).c_str())` and the implicit-conversion
   form `std::string s = p` both propagate. Root cause: the cpp adapter does not
   propagate taint when an assignment RHS is an *explicit* `std::string(...)`
   constructor call bound to a named local. Low-frequency real-world shape
   (the explicit redundant ctor is unusual). A `name: string` passthrough would
   work but `std::string` is pervasive → sanitizer-inventory pollution (the swift
   `String` lesson), so the correct fix is in the adapter's assignment handling.
4. **solidity** — no enabled injection sink consumes a string argument (the
   `call`/`delegatecall`/inline-assembly sinks key on an address operand/receiver),
   so there is no string-arg sink to route a coerced string into. Coercion is
   genuinely N/A, not a failure.
5. **elixir** — `cmd = if flag, do: input, else: ""` (and the `case` form) bound to
   a variable drops taint, while the multi-line `if ... do ... end` block form and
   passing the conditional *directly* as a call argument both propagate. Root
   cause: the elixir adapter does not flow branch-value taint to the LHS when the
   assignment RHS is the **inline keyword-list** (`, do:` / `, else:`) conditional
   form. This is the most common Elixir one-liner conditional-assignment shape.
   Adapter-level fix, deferred for regression safety.

Notes: go/c are intentionally excluded from constructor-type inference (uppercase
exported funcs / no constructor convention); their baselines use direct sinks.
`fqn-no-import = N/A` rows are languages whose probed sink is a global builtin
(`system`, `os.execute`) with no package qualifier to omit.
