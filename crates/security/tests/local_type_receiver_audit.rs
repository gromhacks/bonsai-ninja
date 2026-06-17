//! WS2 regression: typed-local / cast / factory-return receiver typing.
//!
//! The cast type in `Foo c = (Foo) o` is stripped from the taint flow
//! event, but it surfaces on the local DECLARATION — which also captures
//! factory returns (`Foo c = make()`). Capturing locally-declared types
//! per method lets `receiver_type_in` resolve `c.run(...)` even when `c`
//! isn't a constructor result. This pins that behavior for a
//! representative spread of the capture mechanisms:
//!   * Rust   — shared `TypeAliasVocabulary` (`let_declaration`)
//!   * C#     — custom `collect_csharp_local_type_aliases`
//!   * Kotlin — custom `kotlin_param_alias` (type inside variable_declaration)
//!   * Dart   — custom `collect_dart_local_decl_aliases` (body sibling walk)
//!
//! A typed local whose declared type matches the rule's `receiver_type_in`
//! must fire; an unrelated receiver must stay clean (no over-match).

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bonsai-ws2-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
    fn write(&self, rel: &str, content: &str) {
        let p = self.path.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Run a synthetic `receiver_type_in: [Foo]` cmdi rule for `lang` over a
/// one-file workspace and return the finding count.
fn typed_local_findings(lang: &str, ext: &str, method: &str, src: &str) -> usize {
    let rules = TempTree::new(&format!("{lang}-rules"));
    // No match_examples: this test loads the pack and runs taint directly
    // (it does not invoke the example-replay validator), so examples are
    // unnecessary and keep the synthetic rule robust.
    rules.write(
        &format!("langs/{lang}/sinks/t.yml"),
        &format!(
            r#"- id: {lang}.test.typed_local_run
  enabled: true
  language: {lang}
  tag: command-injection
  severity: high
  packages: [acme]
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.{method}$"
  constraints:
  - receiver_type_in: [Foo]
  - arg_tainted:
      index: 0
  description: test
"#,
        ),
    );
    let ws = TempTree::new(&format!("{lang}-ws"));
    ws.write(&format!("m.{ext}"), src);

    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules.path).expect("rulepack");
    let workspace = bonsai_workspace::Workspace::index(&ws.path, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("taint");
    let _ = repo_root(); // keep helper referenced for future real-pack variants
    report
        .findings
        .iter()
        .filter(|f| f.finding.sink.rule_id == format!("{lang}.test.typed_local_run"))
        .count()
}

/// Like [`typed_local_findings`], but ALSO ships a `returns_type` typing
/// rule declaring that the factory method `factory` yields `Foo`. This
/// exercises the rulepack-declared factory-return mechanism: a local
/// assigned from a factory chain (`c = builder().make()`) is typed
/// `Foo` so the `receiver_type_in: [Foo]` sink on `c.run(...)` resolves.
fn factory_typed_local_findings(lang: &str, ext: &str, method: &str, factory: &str, src: &str) -> usize {
    let rules = TempTree::new(&format!("{lang}-frules"));
    rules.write(
        &format!("langs/{lang}/sinks/t.yml"),
        &format!(
            r#"- id: {lang}.test.typed_local_run
  enabled: true
  language: {lang}
  tag: command-injection
  severity: high
  packages: [acme]
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      regex: "^[A-Za-z_$][A-Za-z0-9_$]*\\.{method}$"
  constraints:
  - receiver_type_in: [Foo]
  - arg_tainted:
      index: 0
  description: test
- id: {lang}.test.foo_factory
  enabled: true
  language: {lang}
  description: factory typing rule ({factory} returns Foo)
  returns_type: Foo
  match:
    kind: call
    callee:
      name: {factory}
"#,
        ),
    );
    let ws = TempTree::new(&format!("{lang}-fws"));
    ws.write(&format!("m.{ext}"), src);

    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules.path).expect("rulepack");
    let workspace = bonsai_workspace::Workspace::index(&ws.path, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("taint");
    report
        .findings
        .iter()
        .filter(|f| f.finding.sink.rule_id == format!("{lang}.test.typed_local_run"))
        .count()
}

#[test]
fn factory_return_typing_resolves_receiver_type() {
    // Factory chain `c = builder().make()` — the constructor heuristic
    // can't type `c` (lowercase `make`), so without a `returns_type`
    // rule the `receiver_type_in: [Foo]` sink stays dark. (`import acme`
    // satisfies the sink's `packages: [acme]` gate.)
    let chain = "import acme\ndef h(x):\n    c = builder().make()\n    c.run(x)\n";
    let baseline = typed_local_findings("python", "py", "run", chain);
    assert_eq!(
        baseline, 0,
        "control: factory chain must NOT resolve without a returns_type rule, got {baseline}"
    );
    // With a `returns_type: Foo` rule on `make`, the local is typed and
    // the sink fires.
    let with_typing = factory_typed_local_findings("python", "py", "run", "make", chain);
    assert!(
        with_typing >= 1,
        "factory chain `c = builder().make()` must resolve receiver_type_in via returns_type, got {with_typing}"
    );
    // Negative: a factory whose method isn't declared stays untyped.
    let other = "import acme\ndef h(x):\n    c = builder().other()\n    c.run(x)\n";
    let untyped = factory_typed_local_findings("python", "py", "run", "make", other);
    assert_eq!(
        untyped, 0,
        "a non-declared factory method must NOT type the local, got {untyped}"
    );
}

#[test]
fn rust_typed_local_resolves_receiver_type() {
    let n = typed_local_findings(
        "rust",
        "rs",
        "run",
        "use acme::Foo;\nfn make() -> Foo { todo!() }\nfn h(x: String) { let c: Foo = make(); c.run(x); }\n",
    );
    assert!(
        n >= 1,
        "rust typed local `let c: Foo = make()` must resolve receiver_type_in, got {n}"
    );
}

#[test]
fn csharp_typed_local_resolves_receiver_type() {
    let n = typed_local_findings(
        "csharp",
        "cs",
        "Run",
        "using acme;\nclass App { void H(string x){ Foo c = Make(); c.Run(x); } Foo Make(){ return null; } }\n",
    );
    assert!(
        n >= 1,
        "csharp typed local `Foo c = Make()` must resolve receiver_type_in, got {n}"
    );
}

#[test]
fn kotlin_typed_local_resolves_receiver_type() {
    let n = typed_local_findings(
        "kotlin",
        "kt",
        "run",
        "import acme.Foo\nfun make(): Foo = TODO()\nfun h(x: String) { val c: Foo = make(); c.run(x) }\n",
    );
    assert!(
        n >= 1,
        "kotlin typed local `val c: Foo = make()` must resolve receiver_type_in, got {n}"
    );
}

#[test]
fn kotlin_as_cast_resolves_receiver_type() {
    let n = typed_local_findings(
        "kotlin",
        "kt",
        "run",
        "import acme.Foo\nfun h(x: String){ val c = make() as Foo; c.run(x) }\nfun make(): Any = TODO()\n",
    );
    assert!(n >= 1, "kotlin `val c = make() as Foo` must resolve receiver_type_in, got {n}");
}

#[test]
fn typescript_as_cast_resolves_receiver_type() {
    let n = typed_local_findings(
        "typescript",
        "ts",
        "run",
        "import {Foo} from 'acme';\nfunction make(): any { return null; }\nfunction h(x: string){ const c = make() as Foo; c.run(x); }\n",
    );
    assert!(n >= 1, "typescript `const c = make() as Foo` must resolve receiver_type_in, got {n}");
}

#[test]
fn typescript_angle_cast_resolves_receiver_type() {
    let n = typed_local_findings(
        "typescript",
        "ts",
        "run",
        "import {Foo} from 'acme';\nfunction make(): any { return null; }\nfunction h(x: string){ const c = <Foo>make(); c.run(x); }\n",
    );
    assert!(n >= 1, "typescript `const c = <Foo>make()` must resolve receiver_type_in, got {n}");
}

#[test]
fn dart_as_cast_resolves_receiver_type() {
    let n = typed_local_findings(
        "dart",
        "dart",
        "run",
        "import 'package:acme/acme.dart';\nvoid h(String x){ var c = make() as Foo; c.run(x); }\ndynamic make() => 0;\n",
    );
    assert!(n >= 1, "dart `var c = make() as Foo` must resolve receiver_type_in, got {n}");
}

#[test]
fn go_type_assertion_resolves_receiver_type() {
    let n = typed_local_findings(
        "go",
        "go",
        "Run",
        "package main\nimport \"acme\"\nfunc h(x string){ c := acme.Make().(Foo); c.Run(x) }\n",
    );
    assert!(n >= 1, "go `c := acme.Make().(Foo)` must resolve receiver_type_in, got {n}");
}

#[test]
fn scala_asinstanceof_resolves_receiver_type() {
    let n = typed_local_findings(
        "scala",
        "scala",
        "run",
        "import acme.Foo\nclass A { def h(x: String): Unit = { val c = make().asInstanceOf[Foo]; c.run(x) }; def make(): Any = ??? }\n",
    );
    assert!(n >= 1, "scala `val c = make().asInstanceOf[Foo]` must resolve receiver_type_in, got {n}");
}

#[test]
fn java_var_cast_resolves_receiver_type() {
    // WS2: Java 10+ `var c = (Foo) make()` — inferred LHS, type on cast.
    let n = typed_local_findings(
        "java",
        "java",
        "run",
        "import acme.Foo;\nclass App { void h(String x){ var c = (Foo) make(); c.run(x); } Object make(){ return null; } }\n",
    );
    assert!(
        n >= 1,
        "java `var c = (Foo) make()` cast must resolve receiver_type_in, got {n}"
    );
}

#[test]
fn csharp_var_cast_resolves_receiver_type() {
    // WS2: an inferred (`var`) LHS leaves the type only on the cast.
    let n = typed_local_findings(
        "csharp",
        "cs",
        "Run",
        "using acme;\nclass App { void H(string x){ var c = (Foo) Make(); c.Run(x); } object Make(){ return null; } }\n",
    );
    assert!(
        n >= 1,
        "csharp `var c = (Foo) Make()` cast must resolve receiver_type_in, got {n}"
    );
}

#[test]
fn csharp_var_cast_arg_does_not_mistype_receiver() {
    // WS2 precision: a cast nested in a CALL ARGUMENT must NOT type the
    // local (`var c = Wrap((Foo) o)` — c is Wrap's result, not Foo).
    let n = typed_local_findings(
        "csharp",
        "cs",
        "Run",
        "using acme;\nclass App { void H(string y){ var c = Wrap((Foo) Other()); c.Run(y); } object Wrap(object o){ return null; } object Other(){ return null; } }\n",
    );
    assert_eq!(
        n, 0,
        "a cast on a call argument must not mistype the local as the cast type, got {n}"
    );
}

#[test]
fn dart_typed_local_resolves_receiver_type() {
    let n = typed_local_findings(
        "dart",
        "dart",
        "run",
        "import 'package:acme/acme.dart';\nFoo make() => Foo();\nvoid h(String x) { Foo c = make(); c.run(x); }\n",
    );
    assert!(
        n >= 1,
        "dart typed local `Foo c = make()` must resolve receiver_type_in, got {n}"
    );
}

// ---- WS2 cast-typing probes for the remaining statically-typed langs ----

#[test]
fn cpp_declared_value_local_resolves_receiver_type() {
    // Calibration: a value-receiver local declared with the class type
    // resolves receiver_type_in (so `\.run$` matches `c.run`).
    let n = typed_local_findings(
        "cpp",
        "cpp",
        "run",
        "#include <acme>\nFoo make();\nvoid h(char* x) { Foo c = make(); c.run(x); }\n",
    );
    assert!(n >= 1, "cpp `Foo c = make()` must resolve receiver_type_in, got {n}");
}

#[test]
fn cpp_static_cast_resolves_receiver_type() {
    // `auto c = static_cast<Foo>(make())` — the type lives only on the cast.
    let n = typed_local_findings(
        "cpp",
        "cpp",
        "run",
        "#include <acme>\nvoid h(char* x) { auto c = static_cast<Foo>(make()); c.run(x); }\n",
    );
    assert!(n >= 1, "cpp `auto c = static_cast<Foo>(make())` must resolve receiver_type_in, got {n}");
}

#[test]
fn cpp_c_cast_auto_local_resolves_receiver_type() {
    // `auto c = (Foo) make()` — C-style cast, inferred local.
    let n = typed_local_findings(
        "cpp",
        "cpp",
        "run",
        "#include <acme>\nvoid h(char* x) { auto c = (Foo) make(); c.run(x); }\n",
    );
    assert!(n >= 1, "cpp `auto c = (Foo) make()` must resolve receiver_type_in, got {n}");
}

#[test]
fn rust_as_cast_resolves_receiver_type() {
    // Rust `as`-cast receiver typing — already supported via the kit vocab;
    // pinned here so the WS2 sweep covers it explicitly.
    let n = typed_local_findings(
        "rust",
        "rs",
        "run",
        "use acme::Foo;\nfn make() -> Box<dyn std::any::Any> { todo!() }\nfn h(x: String) { let c = make() as Foo; c.run(x); }\n",
    );
    assert!(n >= 1, "rust `let c = make() as Foo` must resolve receiver_type_in, got {n}");
}

/// Like [`typed_local_findings`] but the synthetic sink uses the
/// receiver-prefix-optional regex (`^(?:.*\.)?run$`) that matches an ObjC
/// `[f run:x]` message send — the strict `<ident>.run` form does not.
fn objc_typed_local_findings(src: &str) -> usize {
    let rules = TempTree::new("objc-cast-rules");
    rules.write(
        "langs/objc/sinks/t.yml",
        r#"- id: objc.test.typed_local_run
  enabled: true
  language: objc
  tag: command-injection
  severity: high
  cwe: [CWE-78]
  match:
    kind: call
    callee:
      regex: "^(?:.*\\.)?run$"
  constraints:
  - receiver_type_in: [Foo]
  - arg_tainted:
      index: 0
  description: test
"#,
    );
    let ws = TempTree::new("objc-cast-ws");
    ws.write("m.m", src);
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&rules.path).expect("rulepack");
    let workspace = bonsai_workspace::Workspace::index(&ws.path, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("taint");
    report
        .findings
        .iter()
        .filter(|f| f.finding.sink.rule_id == "objc.test.typed_local_run")
        .count()
}

#[test]
fn objc_id_cast_resolves_receiver_type() {
    // ObjC `id f = (Foo *) make()` — the dynamic `id` LHS carries no class, so
    // the receiver type lives only on the C-style cast. The declared form
    // `Foo *f = (Foo *) make()` already worked; this is the cast-into-id form.
    let declared =
        objc_typed_local_findings("Foo* make(void);\nvoid h(char *x) { Foo *f = (Foo *)make(); [f run:x]; }\n");
    assert!(declared >= 1, "objc declared `Foo *f = (Foo *)make()` must resolve, got {declared}");
    let cast =
        objc_typed_local_findings("id make(void);\nvoid h(char *x) { id f = (Foo *)make(); [f run:x]; }\n");
    assert!(cast >= 1, "objc `id f = (Foo *)make()` must resolve receiver_type_in, got {cast}");
    // Wrong-type cast must NOT fire (no false positive).
    let wrong =
        objc_typed_local_findings("id make(void);\nvoid h(char *x) { id f = (Bar *)make(); [f run:x]; }\n");
    assert_eq!(wrong, 0, "objc `id f = (Bar *)make()` must not mistype as Foo, got {wrong}");
}
