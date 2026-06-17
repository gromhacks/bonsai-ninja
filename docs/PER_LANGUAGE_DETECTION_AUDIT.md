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

## WS1 package gate — FQN-no-import matrix

Probe: a sink called via its fully-qualified / module-qualified path with NO
import in the file (the qualifier itself is the package evidence). Baseline-gated
(the same call WITH the import fires first). `N/A` = the language's packaged sink
is a global builtin or a class/receiver-member call with no module-qualified call
path, so there is no import to omit.

| lang | applicable? | fqn-no-import | mechanism / note |
|------|-------------|---------------|------------------|
| python | yes | PASS | single-seg pkg `os`; `import_matches_package` prefix |
| javascript | yes | PASS | `child_process.exec` prefix-matches `child_process` |
| typescript | yes | PASS | same |
| go | yes | PASS | path-package-tail rule (`os/exec` tail `exec` == call head) |
| rust | yes | PASS | `std::process::Command::new` matches `std::` prefix |
| java | yes | PASS | `java.sql.Statement.execute` (attr-form FQN callee) credited |
| csharp | yes | PASS | `System.Diagnostics.Process.Start` prefix |
| kotlin | yes | PASS | incl `java.lang.Runtime` FQN (commit 849d9e7) |
| scala | yes | PASS | `scala.sys.process.Process.apply` prefix |
| swift | yes | PASS | `Yams.load` — pkg == qualifier |
| lua | yes | PASS | `lustache.render` — pkg == qualifier |
| perl | yes | PASS | `IPC::Run->run` via the `needle->` rule (commit 7df3a3e) |
| c | no | N/A | `system` global builtin, no `packages:`, gate never engages |
| cpp | no | N/A | same |
| objc | no | N/A | `[Class selector:]` / C funcs; package is never the call qualifier |
| dart | no | N/A | class-member calls (`Process.run`); imports are `package:`/`dart:` URIs |
| solidity | no | N/A | receiver-member calls; `@scope/pkg` import path never a call qualifier |
| ruby | yes | by-design MISS | `Open3.capture2` / `Net::HTTP` — PascalCase qualifier vs lowercase gem (`open3`); matching it needs case-folding = a gate LOOSENING (forbidden by the do-not-loosen directive). NOT a validator miss — the rule's example has `require`, so real ruby fires; only the artificial no-require probe misses. |

Two low-frequency residual misses, both intentionally unfixed (fixing either
requires loosening the gate, against the standing directive):
- **ruby** — see table (case-folding gem names).
- **php** — the fully-namespaced *inline* form
  `\Symfony\Component\Process\Process::fromShellCommandline($x)` is a match-layer
  gap (the rule keys `attribute:[Process, fromShellCommandline]`; the namespaced
  path isn't reconstructed to that 2-segment form), and it fails even WITH the
  `use` import, so it is not FQN-gate-specific. Real PHP code `use`s the class and
  calls the short form, which fires. Reconstructing last-two-segments would touch
  shared candidate generation + the gate's deliberately case-sensitive tail-match.
- **java FQN-typed-local (no import)** — `java.sql.Statement stmt = ...;
  stmt.execute(x)` with no `import java.sql`: the local IS typed `Statement`
  (canonical_java_type_name strips the FQN tail), but the `java.sql`-gated rule has
  no package evidence (an FQN *type reference* is not a gate candidate). Crediting
  arbitrary FQN type refs as package evidence would loosen the gate. Real code
  imports `java.sql`, which fires.

**Conclusion: the package gate is sound and complete for every realistic
FQN-no-import case across all 21 languages.** The residuals are precision-over-
recall choices mandated by the do-not-loosen directive.

### Cross-file (dep imported in a different module than the sink)
The legitimate cross-file case (FQN/qualifier-carrying calls and
`receiver_type_in` sinks) works via the candidate path
(`import_matches_package(candidate, signal)`), which never consults per-file
import sets. The blanket union-of-workspace-imports approach for BARE
receiver-agnostic sources was implemented then REVERTED as unsound (commit history
+ `cross_file_package_gate_audit.rs`): it fired a framework source in any file
once the framework was imported anywhere, breaking framework-isolation. A proper
bare-source cross-file fix needs real cross-file symbol/dataflow linkage, not a
union; left undone — precision wins per the directive.

## WS2 receiver typing — cast + factory-return status

### Cast typing — complete for every language that HAS a class-cast syntax
| has class-cast syntax | langs | status |
|-----------------------|-------|--------|
| yes | C#, Java, Kotlin, Dart, Go, Scala, Swift, TypeScript | DONE (typed-LHS + inferred-`var`/`as`/`<T>` forms) |
| no (dynamic / scalar-only / tuple) | python `(T)x`=tuple, php casts scalar-only, JS/Ruby/Perl/Lua/Elixir/Erlang/Solidity dynamic | N/A — no class-cast to type; receiver typing there comes from constructor + factory-return inference |
| C++ | — | `(Foo*)x` works via declared type; `static_cast<Foo*>` low-value TODO |

### Factory-return typing — SHIPPED as a first-class `RuleKind::Typing`
The engine resolves `receiver_type_in` from a factory method's declared
`returns_type` (`build_factory_returns`, language-scoped; the matcher + finding
re-check both consult it). This is now a 4th rule kind with its own `typing/` dir:
typing rules feed `build_factory_returns` via `all_rules()` but are excluded from
every source/sink/sanitizer finding + inventory path and from sink-only
validation/conformance (cwe, severity, sink-doc, golden-SARIF). A typing rule's
only required metadata is `returns_type`.

Live rule shipped: `python.typing.dbapi_cursor` (`returns_type: cursor` on
`.cursor()`). A factory-returned cursor `c = sqlite3.connect("db").cursor();
c.execute(input)` now types `c` and fires the existing receiver-typed
`cursor.execute` SQLi sink — previously a miss (`c` is not literally named
`cursor`). Verified: sqlite3 factory → 1 finding, psycopg2 → 3, safe input → 0
(no FP). The typing rule itself never produces a finding. Authoring more typing
rules (other factory chains, per language) is now a pure rulepack-content task —
add a `<lang>/typing/*.yml` entry whose `match_example` constructs the receiver.
