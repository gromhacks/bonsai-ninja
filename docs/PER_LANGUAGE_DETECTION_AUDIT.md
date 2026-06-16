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
| cpp | PASS | FIXED³ | PASS | N/A |
| java | PASS | PASS | PASS | PASS |
| csharp | PASS | PASS | PASS | PASS |
| kotlin | PASS | PASS | PASS | PASS |
| scala | PASS | FIXED² | PASS | PASS |
| swift | PASS | PASS | PASS | N/A |
| objc | PASS | PASS | PASS | N/A |
| dart | PASS | PASS | PASS | N/A |
| solidity | PASS | N/A⁴ | PASS | N/A |
| elixir | PASS | PASS | FIXED⁵ | PASS |
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

### Engine gaps fixed in a follow-up pass

3. **cpp** — `std::string s = std::string(p); system(s.c_str())` dropped taint,
   while the inline form `system(std::string(p).c_str())` and the
   implicit-conversion form `std::string s = p` both propagated. Root cause: the
   shared kit only extracted call-argument operands for *nested* calls, so an
   assignment RHS that IS a direct `std::string(...)` constructor call contributed
   no source. FIXED with a scoped rulepack passthrough `cpp.passthrough.std_string`
   (`attribute:[std, string]`, `call_result_passthrough_args:[0]`) rather than the
   broad shared-kit change (which would alter taint semantics for all 21 langs).
   Safe: the cpp micro fixture has no `std::string(` constructor *call* (only type
   declarations, which are not calls) so `min_sanitizers_micro: 0` holds; only
   propagates when arg0 is tainted. Now → 1 finding.
4. **elixir** — `cmd = if flag, do: input, else: ""` (and `, do:` no-else) bound to
   a variable dropped taint, while the multi-line `if ... do ... end` block form and
   passing the conditional *directly* as a call argument both propagated. Root
   cause: `elixir_do_else_body` (`lang_elixir/src/lib.rs`) only parsed the block
   form (needs a standalone `do` AND a closing `end`); the inline keyword-list form
   has neither, so the assignment never got its branch sources. FIXED
   (language-scoped) with `elixir_inline_keyword_do_else_body`: detects the inline
   form by whether `do` is immediately followed by `:` and captures the branch text
   after `do:` (the condition, before `do:`, is excluded). Now → 1 finding;
   all-literal-branch control correctly stays 0 (no false positive).

### Remaining (genuinely N/A, not a failure)

5. **solidity** — no enabled injection sink consumes a string argument (the
   `call`/`delegatecall`/inline-assembly sinks key on an address operand/receiver),
   so there is no string-arg sink to route a coerced string into. Coercion is
   genuinely N/A.

Notes: go/c are intentionally excluded from constructor-type inference (uppercase
exported funcs / no constructor convention); their baselines use direct sinks.
`fqn-no-import = N/A` rows are languages whose probed sink is a global builtin
(`system`, `os.execute`) with no package qualifier to omit.
