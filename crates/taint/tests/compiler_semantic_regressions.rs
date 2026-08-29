//! Path- and phase-sensitive compiler/IDG regressions.
//!
//! These are intentionally independent of the security rulepack. A function
//! parameter is seeded directly and the compiler-lowered IDG is queried for a
//! synthetic `sink` call. This isolates language lowering and transfer
//! semantics from source/sink rule matching.

use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_taint::{
    compose_idg_seed_nodes, ensure_idg_service, interprocedural_taint, IdgSeedRequest, InterTaintConfig,
    TokenSet,
};
use bonsai_vfs::Vfs;
use std::collections::BTreeSet;
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    entry: &'static str,
    seed: &'static str,
    sink: &'static str,
    source: &'static str,
}

fn adapter_for(language: &str) -> AdapterArc {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn analyze(fixture: &Fixture) -> bonsai_taint::InterTaintResult {
    analyze_files(
        fixture.language,
        &[(fixture.path, fixture.source)],
        fixture.entry,
        fixture.seed,
    )
}

fn analyze_files(
    language: &str,
    files: &[(&str, &str)],
    entry: &str,
    seed: &str,
) -> bonsai_taint::InterTaintResult {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write(*path, Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter_for(language));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let parsed = db.parse(file).expect("fixture parse");
        assert!(
            parsed.diagnostics.is_empty(),
            "{}: valid compiler fixture emitted diagnostics: {:?}",
            language,
            parsed.diagnostics
        );
        let _ = db.decl_index(file);
    }
    let entry = bonsai_resolve::resolve_callable(&db.global_index(), entry)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{language}: missing entry `{entry}`"));
    let seed = TokenSet::from_iter([seed.to_string()]);
    interprocedural_taint(FuncId::new(entry.raw()), &seed, &InterTaintConfig::default(), &db)
}

fn sink_reached(result: &bonsai_taint::InterTaintResult, sink: &str) -> bool {
    result.tainted_calls.iter().any(|call| {
        call.name == sink
            || call.name.ends_with(&format!(".{sink}"))
            || call.name.ends_with(&format!("::{sink}"))
            || call.name.ends_with(&format!(":{sink}"))
    })
}

#[test]
fn go_nested_property_read_source_reaches_cross_file_callee_parameter() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "api/state.go",
        Arc::<str>::from(
            r#"package api
import (
    "github.com/labstack/echo/v4"
    "app/service"
)
func Register(router *echo.Echo) {
    router.POST("/restore", func(c echo.Context) error {
        defer c.Request().Body.Close()
        value, err := service.RestoreState(c.Request().Body)
        _ = value
        _ = err
        return nil
    })
}
"#,
        ),
    );
    vfs.write(
        "service/state.go",
        Arc::<str>::from(
            r#"package service
func RestoreState(body any) (any, error) { sink(body); return nil, nil }
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter_for("go"));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let parsed = db.parse(file).expect("Go fixture parse");
        assert!(
            parsed.diagnostics.is_empty(),
            "diagnostics: {:?}",
            parsed.diagnostics
        );
        let _ = db.decl_index(file);
    }
    let global = db.global_index();
    let (lambda_symbol, lambda_file) = db
        .vfs()
        .all_files()
        .into_iter()
        .find_map(|file| {
            db.decl_index(file).and_then(|index| {
                index
                    .defs
                    .iter()
                    .find(|decl| decl.name.starts_with("<lambda@"))
                    .map(|decl| (decl.symbol, decl.span.file))
            })
        })
        .expect("route lambda");
    let source_span = db
        .decl_index(lambda_file)
        .expect("lambda file index")
        .refs
        .iter()
        .filter(|reference| {
            reference.kind == bonsai_lang_api::RefKind::Read && reference.name == "c.Request().Body"
        })
        .max_by_key(|reference| reference.span.start)
        .expect("nested property read")
        .span;
    let lambda_func = FuncId::new(lambda_symbol.raw());
    let restore_func = bonsai_resolve::resolve_callable(&global, "RestoreState")
        .into_iter()
        .next()
        .expect("RestoreState callable");
    let names = TokenSet::from_iter(["c.Request().Body".to_string()]);
    let idg = ensure_idg_service(&db);
    let seeds = compose_idg_seed_nodes(
        IdgSeedRequest::read_rule_match(lambda_func, &names, Some(source_span), &[]),
        global.as_ref(),
        &idg,
    );
    let closure = idg.forward_closure(&seeds);
    let restore_params = idg.param_nodes_of(restore_func);
    let closure_points = closure
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .collect::<Vec<_>>();

    assert!(
        !seeds.is_empty(),
        "the exact property read must produce one source value seed"
    );
    assert!(
        restore_params.iter().any(|param| closure.contains(param)),
        "property-read source did not cross the compiler-resolved call: seeds={:?}; closure={:?}; points={:?}; params={:?}",
        seeds,
        closure,
        closure_points,
        restore_params
    );
}

#[test]
fn rust_trait_object_dispatch_reaches_only_declared_implementations() {
    let result = analyze(&Fixture {
        language: "rust",
        path: "trait_dispatch.rs",
        entry: "entry",
        seed: "seed",
        sink: "sink",
        source: r#"
trait Port { fn forward(&self, value: &str); }

struct LivePort;
impl Port for LivePort {
    fn forward(&self, value: &str) { sink(value); }
}

struct Unrelated;
impl Unrelated {
    fn forward(&self, value: &str) { collision(value); }
}

fn entry(port: &dyn Port, seed: &str) {
    port.forward(seed);
}
"#,
    });

    assert!(
        sink_reached(&result, "sink"),
        "compiler-declared `impl Port for LivePort` must connect typed trait-object dispatch: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "collision"),
        "same-spelled methods without an exact trait implementation must stay disconnected: {:?}",
        result.tainted_calls
    );
}

#[test]
fn rust_cross_file_trait_object_dispatch_retains_impl_identity() {
    let result = analyze_files(
        "rust",
        &[
            (
                "port.rs",
                r#"
pub trait Port { fn forward(&self, value: &str); }

pub struct LivePort;
impl Port for LivePort {
    fn forward(&self, value: &str) { crate::sink(value); }
}

pub struct Unrelated;
impl Unrelated {
    fn forward(&self, value: &str) { crate::collision(value); }
}
"#,
            ),
            (
                "entry.rs",
                r#"
use crate::port::Port;
use std::sync::Arc;

struct State<T>(T);

fn entry(State(port): State<Arc<dyn Port>>, seed: &str) {
    port.forward(seed);
}
"#,
            ),
        ],
        "entry",
        "seed",
    );

    assert!(
        sink_reached(&result, "sink"),
        "trait implementation identity must survive per-file compiler indexes: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "collision"),
        "cross-file same-name collisions must not enter trait dispatch: {:?}",
        result.tainted_calls
    );
}

const MULTI_ARM_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "case.c", entry: "entry", seed: "seed", sink: "sink", source: "void entry(char *seed, int selector) { char *value = \"clean\"; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } }\n" },
    Fixture { language: "cpp", path: "case.cpp", entry: "entry", seed: "seed", sink: "sink", source: "void entry(const char *seed, int selector) { const char *value = \"clean\"; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } }\n" },
    Fixture { language: "csharp", path: "Case.cs", entry: "Entry", seed: "seed", sink: "Sink", source: "class Case { void Entry(string seed, int selector) { string value = \"clean\"; switch (selector) { case 0: value = seed; break; case 1: Sink(value); break; default: break; } } }\n" },
    Fixture { language: "dart", path: "case.dart", entry: "entry", seed: "seed", sink: "sink", source: "void entry(String seed, int selector) { var value = 'clean'; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } }\n" },
    Fixture { language: "elixir", path: "case.ex", entry: "entry", seed: "seed", sink: "sink", source: "defmodule Case do\n  def entry(seed, selector) do\n    value = \"clean\"\n    case selector do\n      0 -> value = seed\n      1 -> sink(value)\n      _ -> :ok\n    end\n  end\nend\n" },
    Fixture { language: "go", path: "case.go", entry: "entry", seed: "seed", sink: "sink", source: "package caseflow\nfunc entry(seed string, selector int) { value := \"clean\"; switch selector { case 0: value = seed; case 1: sink(value); default: } }\n" },
    Fixture { language: "java", path: "Case.java", entry: "entry", seed: "seed", sink: "sink", source: "class Case { void entry(String seed, int selector) { String value = \"clean\"; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } } }\n" },
    Fixture { language: "javascript", path: "case.js", entry: "entry", seed: "seed", sink: "sink", source: "function entry(seed, selector) { let value = 'clean'; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } }\n" },
    Fixture { language: "kotlin", path: "case.kt", entry: "entry", seed: "seed", sink: "sink", source: "fun entry(seed: String, selector: Int) { var value = \"clean\"; when (selector) { 0 -> value = seed; 1 -> sink(value); else -> Unit } }\n" },
    Fixture { language: "lua", path: "case.lua", entry: "entry", seed: "seed", sink: "sink", source: "local function entry(seed, selector)\n  local value = 'clean'\n  if selector == 0 then value = seed elseif selector == 1 then sink(value) else return end\nend\n" },
    Fixture { language: "objc", path: "case.m", entry: "entry", seed: "seed", sink: "sink", source: "void entry(char *seed, int selector) { char *value = \"clean\"; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } }\n" },
    Fixture { language: "perl", path: "case.pl", entry: "entry", seed: "seed", sink: "sink", source: "sub entry { my ($seed, $selector) = @_; my $value = 'clean'; if ($selector == 0) { $value = $seed; } elsif ($selector == 1) { sink($value); } else { return; } }\n" },
    Fixture { language: "php", path: "case.php", entry: "entry", seed: "seed", sink: "sink", source: "<?php\nfunction entry($seed, $selector) { $value = 'clean'; switch ($selector) { case 0: $value = $seed; break; case 1: sink($value); break; default: break; } }\n" },
    Fixture { language: "python", path: "case.py", entry: "entry", seed: "seed", sink: "sink", source: "def entry(seed, selector):\n    value = 'clean'\n    match selector:\n        case 0:\n            value = seed\n        case 1:\n            sink(value)\n        case _:\n            pass\n" },
    Fixture { language: "ruby", path: "case.rb", entry: "entry", seed: "seed", sink: "sink", source: "def entry(seed, selector)\n  value = 'clean'\n  case selector\n  when 0 then value = seed\n  when 1 then sink(value)\n  else nil\n  end\nend\n" },
    Fixture { language: "rust", path: "case.rs", entry: "entry", seed: "seed", sink: "sink", source: "fn entry(seed: &str, selector: i32) { let mut value = \"clean\"; match selector { 0 => value = seed, 1 => sink(value), _ => {} }; }\n" },
    Fixture { language: "scala", path: "Case.scala", entry: "entry", seed: "seed", sink: "sink", source: "object Case { def entry(seed: String, selector: Int): Unit = { var value = \"clean\"; selector match { case 0 => value = seed; case 1 => sink(value); case _ => () } } }\n" },
    Fixture { language: "swift", path: "case.swift", entry: "entry", seed: "seed", sink: "sink", source: "func entry(seed: String, selector: Int) { var value = \"clean\"; switch selector { case 0: value = seed; case 1: sink(value); default: break } }\n" },
    Fixture { language: "typescript", path: "case.ts", entry: "entry", seed: "seed", sink: "sink", source: "function entry(seed: string, selector: number): void { let value = 'clean'; switch (selector) { case 0: value = seed; break; case 1: sink(value); break; default: break; } }\n" },
];

#[test]
fn mutually_exclusive_arms_never_share_taint_state() {
    // Erlang variables are single-assignment and cannot express the mutable
    // sibling-arm counterexample. Its multi-arm path structure is still
    // mandatory in the all-language conformance suite.
    let expected: BTreeSet<String> = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .filter(|language| language != "erlang")
        .collect();
    let covered: BTreeSet<String> = MULTI_ARM_FIXTURES
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect();
    assert_eq!(
        covered, expected,
        "mutable multi-arm fixtures must cover every applicable language"
    );

    let mut failures = Vec::new();
    for fixture in MULTI_ARM_FIXTURES {
        let result = analyze(fixture);
        if sink_reached(&result, fixture.sink) {
            failures.push(format!(
                "{} invented cross-arm taint into {}: {:?}",
                fixture.language, fixture.sink, result.tainted_calls
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "mutually exclusive arm regressions:\n{}",
        failures.join("\n")
    );
}

const C_STYLE_LOOP_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "loop.c", entry: "entry", seed: "seed", sink: "sink", source: "void entry(char *seed) { char *value = seed; for (int i = 0; i < 1; value = \"clean\", i++) { sink(value); } }\n" },
    Fixture { language: "cpp", path: "loop.cpp", entry: "entry", seed: "seed", sink: "sink", source: "void entry(const char *seed) { const char *value = seed; for (int i = 0; i < 1; value = \"clean\", i++) { sink(value); } }\n" },
    Fixture { language: "csharp", path: "Loop.cs", entry: "Entry", seed: "seed", sink: "Sink", source: "class Loop { void Entry(string seed) { string value = seed; for (int i = 0; i < 1; value = \"clean\", i++) { Sink(value); } } }\n" },
    Fixture { language: "dart", path: "loop.dart", entry: "entry", seed: "seed", sink: "sink", source: "void entry(String seed) { var value = seed; for (var i = 0; i < 1; value = 'clean', i++) { sink(value); } }\n" },
    Fixture { language: "go", path: "loop.go", entry: "entry", seed: "seed", sink: "sink", source: "package loopflow\nfunc entry(seed string) { value := seed; for i := 0; i < 1; value = \"clean\" { sink(value); i++ } }\n" },
    Fixture { language: "java", path: "Loop.java", entry: "entry", seed: "seed", sink: "sink", source: "class Loop { void entry(String seed) { String value = seed; for (int i = 0; i < 1; value = \"clean\", i++) { sink(value); } } }\n" },
    Fixture { language: "javascript", path: "loop.js", entry: "entry", seed: "seed", sink: "sink", source: "function entry(seed) { let value = seed; for (let i = 0; i < 1; value = 'clean', i++) { sink(value); } }\n" },
    Fixture { language: "objc", path: "loop.m", entry: "entry", seed: "seed", sink: "sink", source: "void entry(char *seed) { char *value = seed; for (int i = 0; i < 1; value = \"clean\", i++) { sink(value); } }\n" },
    Fixture { language: "perl", path: "loop.pl", entry: "entry", seed: "seed", sink: "sink", source: "sub entry { my ($seed) = @_; my $value = $seed; for (my $i = 0; $i < 1; $value = 'clean', $i++) { sink($value); } }\n" },
    Fixture { language: "php", path: "loop.php", entry: "entry", seed: "seed", sink: "sink", source: "<?php\nfunction entry($seed) { $value = $seed; for ($i = 0; $i < 1; $value = 'clean', $i++) { sink($value); } }\n" },
    Fixture { language: "typescript", path: "loop.ts", entry: "entry", seed: "seed", sink: "sink", source: "function entry(seed: string): void { let value = seed; for (let i = 0; i < 1; value = 'clean', i++) { sink(value); } }\n" },
];

#[test]
fn c_style_loop_update_occurs_after_the_first_body_iteration() {
    let expected = BTreeSet::from([
        "c",
        "cpp",
        "csharp",
        "dart",
        "go",
        "java",
        "javascript",
        "objc",
        "perl",
        "php",
        "typescript",
    ]);
    let covered: BTreeSet<&str> = C_STYLE_LOOP_FIXTURES
        .iter()
        .map(|fixture| fixture.language)
        .collect();
    assert_eq!(covered, expected, "C-style update-clause fixture coverage drift");

    let mut failures = Vec::new();
    for fixture in C_STYLE_LOOP_FIXTURES {
        let result = analyze(fixture);
        if !sink_reached(&result, fixture.sink) {
            failures.push(format!(
                "{} ran the update before the first body and lost seed `{}`: {:?}",
                fixture.language, fixture.seed, result.tainted_calls
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "loop phase-order regressions:\n{}",
        failures.join("\n")
    );
}

const CLOSURE_CAPTURE_FIXTURES: &[Fixture] = &[
    Fixture { language: "cpp", path: "closure.cpp", entry: "entry", seed: "seed", sink: "sink", source: "void entry(const char *seed) { auto callback = [&]() { sink(seed); }; callback(); }\n" },
    Fixture { language: "csharp", path: "Closure.cs", entry: "Entry", seed: "seed", sink: "Sink", source: "class Closure { void Entry(string seed) { System.Action callback = () => Sink(seed); callback(); } }\n" },
    Fixture { language: "dart", path: "closure.dart", entry: "entry", seed: "seed", sink: "sink", source: "void entry(String seed) { final callback = () { sink(seed); }; callback(); }\n" },
    Fixture { language: "elixir", path: "closure.ex", entry: "entry", seed: "seed", sink: "sink", source: "defmodule Closure do\n  def entry(seed) do\n    callback = fn -> sink(seed) end\n    callback.()\n  end\nend\n" },
    Fixture { language: "erlang", path: "closure.erl", entry: "entry", seed: "Seed", sink: "sink", source: "-module(closure).\n-export([entry/1]).\nentry(Seed) -> Callback = fun() -> sink(Seed) end, Callback().\n" },
    Fixture { language: "go", path: "closure.go", entry: "entry", seed: "seed", sink: "sink", source: "package closure\nfunc entry(seed string) { callback := func() { sink(seed) }; callback() }\n" },
    Fixture { language: "java", path: "Closure.java", entry: "entry", seed: "seed", sink: "sink", source: "class Closure { void entry(String seed) { Runnable callback = () -> sink(seed); callback.run(); } }\n" },
    Fixture { language: "javascript", path: "closure.js", entry: "entry", seed: "seed", sink: "sink", source: "function entry(seed) { const callback = () => sink(seed); callback(); }\n" },
    Fixture { language: "kotlin", path: "closure.kt", entry: "entry", seed: "seed", sink: "sink", source: "fun entry(seed: String) { val callback = { sink(seed) }; callback() }\n" },
    Fixture { language: "lua", path: "closure.lua", entry: "entry", seed: "seed", sink: "sink", source: "local function entry(seed)\n  local callback = function() sink(seed) end\n  callback()\nend\n" },
    Fixture { language: "objc", path: "closure.m", entry: "entry", seed: "seed", sink: "sink", source: "void entry(NSString *seed) { void (^callback)(void) = ^{ sink(seed); }; callback(); }\n" },
    Fixture { language: "perl", path: "closure.pl", entry: "entry", seed: "$seed", sink: "sink", source: "sub entry { my ($seed) = @_; my $callback = sub { sink($seed); }; $callback->(); }\n" },
    Fixture { language: "php", path: "closure.php", entry: "entry", seed: "$seed", sink: "sink", source: "<?php\nfunction entry($seed) { $callback = function() use ($seed) { sink($seed); }; $callback(); }\n" },
    Fixture { language: "python", path: "closure.py", entry: "entry", seed: "seed", sink: "sink", source: "def entry(seed):\n    callback = lambda: sink(seed)\n    callback()\n" },
    Fixture { language: "ruby", path: "closure.rb", entry: "entry", seed: "seed", sink: "sink", source: "def entry(seed)\n  callback = proc { sink(seed) }\n  callback.call\nend\n" },
    Fixture { language: "rust", path: "closure.rs", entry: "entry", seed: "seed", sink: "sink", source: "fn entry(seed: &str) { let callback = || sink(seed); callback(); }\n" },
    Fixture { language: "scala", path: "Closure.scala", entry: "entry", seed: "seed", sink: "sink", source: "object Closure { def entry(seed: String): Unit = { val callback = () => sink(seed); callback() } }\n" },
    Fixture { language: "swift", path: "closure.swift", entry: "entry", seed: "seed", sink: "sink", source: "func entry(seed: String) { let callback = { sink(seed) }; callback() }\n" },
    Fixture { language: "typescript", path: "closure.ts", entry: "entry", seed: "seed", sink: "sink", source: "function entry(seed: string): void { const callback = () => sink(seed); callback(); }\n" },
];

#[test]
fn captured_values_reach_calls_inside_first_class_closures() {
    let expected = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .filter(|language| language != "c")
        .collect::<BTreeSet<_>>();
    let covered = CLOSURE_CAPTURE_FIXTURES
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered.len(), CLOSURE_CAPTURE_FIXTURES.len());
    assert_eq!(
        covered, expected,
        "closure fixtures must cover every language with capturing closures; C function pointers cannot capture"
    );

    let mut failures = Vec::new();
    for fixture in CLOSURE_CAPTURE_FIXTURES {
        let result = analyze(fixture);
        if !sink_reached(&result, fixture.sink) {
            failures.push(format!(
                "{} lost captured seed `{}` before {}: {:?}",
                fixture.language, fixture.seed, fixture.sink, result.tainted_calls
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "closure-capture regressions:\n{}",
        failures.join("\n")
    );
}
