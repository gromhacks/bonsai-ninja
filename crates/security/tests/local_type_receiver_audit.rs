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
