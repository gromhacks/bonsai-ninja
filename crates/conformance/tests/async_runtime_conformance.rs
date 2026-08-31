//! Registry-exhaustive async/coroutine syntax conformance.
//!
//! Each language is either exercised with its grammar-owned await/yield form
//! or explicitly classified as inapplicable with a language-semantic reason.
//! Library calls named `await`/`yield` do not count: this gate is about syntax
//! and evaluator suspension points emitted as `FlowEvent` facts.

use bonsai_lang_api::{FlowEvent, LanguageAdapter};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Copy, Clone, Debug)]
enum Shape {
    Await,
    Yield,
}

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const AWAIT_FIXTURES: &[Fixture] = &[
    Fixture { language: "cpp", path: "await.cpp", function: "runner", source: "task runner() { auto result = co_await fetcher(); co_return result; }\n" },
    Fixture { language: "csharp", path: "Await.cs", function: "Runner", source: "class AwaitCase { static async System.Threading.Tasks.Task<string> Runner() { var result = await Fetcher(); return result; } }\n" },
    Fixture { language: "dart", path: "await.dart", function: "runner", source: "Future<String> runner() async { final result = await fetcher(); return result; }\n" },
    Fixture { language: "javascript", path: "await.js", function: "runner", source: "async function runner() { const result = await fetcher(); return result; }\n" },
    Fixture { language: "python", path: "await.py", function: "runner", source: "async def runner():\n    result = await fetcher()\n    return result\n" },
    Fixture { language: "rust", path: "await.rs", function: "runner", source: "async fn runner() -> String { let result = fetcher().await; result }\n" },
    Fixture { language: "swift", path: "await.swift", function: "runner", source: "func runner() async -> String { let result = await fetcher(); return result }\n" },
    Fixture { language: "typescript", path: "await.ts", function: "runner", source: "async function runner(): Promise<string> { const result = await fetcher(); return result; }\n" },
];

const NO_AWAIT: &[(&str, &str)] = &[
    ("c", "C has no language-level await expression"),
    ("elixir", "process receive/task APIs are not await syntax"),
    ("erlang", "receive and process messaging are not await syntax"),
    ("go", "goroutine/channel operations are not await expressions"),
    ("java", "Future APIs are library calls, not await syntax"),
    (
        "kotlin",
        "suspension is encoded by suspend functions; await is a library call",
    ),
    ("lua", "the supported Lua grammar has no await expression"),
    ("objc", "Objective-C has no language-level await expression"),
    ("perl", "the supported Perl grammar has no await expression"),
    ("php", "the supported PHP grammar has no await expression"),
    ("ruby", "Fiber APIs are not await syntax"),
    ("scala", "Future/Await are library APIs, not language syntax"),
];

const YIELD_FIXTURES: &[Fixture] = &[
    Fixture { language: "cpp", path: "yield.cpp", function: "generator", source: "generator<int> generator() { co_yield 1; }\n" },
    Fixture { language: "csharp", path: "Yield.cs", function: "Generator", source: "class YieldCase { static System.Collections.Generic.IEnumerable<int> Generator() { yield return 1; } }\n" },
    Fixture { language: "dart", path: "yield.dart", function: "generator", source: "Stream<int> generator() async* { yield 1; }\n" },
    Fixture { language: "java", path: "Yield.java", function: "generator", source: "class YieldCase { static int generator(int value) { return switch (value) { default -> { yield 1; } }; } }\n" },
    Fixture { language: "javascript", path: "yield.js", function: "generator", source: "function* generator() { yield 1; }\n" },
    Fixture { language: "php", path: "yield.php", function: "generator", source: "<?php\nfunction generator() { yield 1; }\n" },
    Fixture { language: "python", path: "yield.py", function: "generator", source: "def generator():\n    yield 1\n" },
    Fixture { language: "ruby", path: "yield.rb", function: "generator", source: "def generator\n  yield 1\nend\n" },
    Fixture { language: "rust", path: "yield.rs", function: "generator", source: "fn generator() { yield 1; }\n" },
    Fixture { language: "typescript", path: "yield.ts", function: "generator", source: "function* generator(): Generator<number> { yield 1; }\n" },
];

const NO_YIELD: &[(&str, &str)] = &[
    ("c", "C has no language-level yield expression"),
    (
        "elixir",
        "comprehensions/process messages are not caller-block yield syntax",
    ),
    ("erlang", "comprehensions/process messages are not yield syntax"),
    (
        "go",
        "channel sends are separately modeled and are not yield syntax",
    ),
    ("kotlin", "sequence-builder yield is a library call"),
    (
        "lua",
        "coroutine.yield is a library call, not dedicated grammar syntax",
    ),
    ("objc", "Objective-C has no language-level yield expression"),
    ("perl", "the supported Perl grammar has no yield expression"),
    (
        "scala",
        "iterator/stream APIs are library abstractions, not yield syntax",
    ),
    (
        "swift",
        "accessor/coroutine internals have no supported general yield expression",
    ),
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn registered_languages() -> BTreeSet<String> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect()
}

fn assert_partition(fixtures: &[Fixture], omitted: &[(&str, &str)]) {
    let covered = fixtures
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered.len(), fixtures.len(), "duplicate language fixture");
    let omitted = omitted
        .iter()
        .map(|(language, rationale)| {
            assert!(!rationale.trim().is_empty(), "{language}: missing rationale");
            (*language).to_string()
        })
        .collect::<BTreeSet<_>>();
    assert!(covered.is_disjoint(&omitted));
    assert_eq!(
        covered.union(&omitted).cloned().collect::<BTreeSet<_>>(),
        registered_languages(),
        "every adapter must be tested or explicitly inapplicable"
    );
}

fn contains_shape(events: &[FlowEvent], shape: Shape) -> bool {
    events.iter().any(|event| {
        matches!(
            (shape, event),
            (Shape::Await, FlowEvent::Await { .. }) | (Shape::Yield, FlowEvent::Yield { .. })
        ) || match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => contains_shape(then_events, shape) || contains_shape(else_events, shape),
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                contains_shape(condition_events, shape)
                    || contains_shape(body, shape)
                    || contains_shape(update_events, shape)
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => contains_shape(body, shape),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                contains_shape(body, shape)
                    || contains_shape(catch_events, shape)
                    || contains_shape(finally_events, shape)
            }
            _ => false,
        }
    })
}

fn validate(fixtures: &[Fixture], omitted: &[(&str, &str)], shape: Shape) {
    assert_partition(fixtures, omitted);
    let mut failures = BTreeMap::new();
    for fixture in fixtures {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let index = workspace.db().global_index();
        let decl = index
            .all_files()
            .flat_map(|file| index.decls_in(file))
            .find(|decl| decl.name == fixture.function);
        let Some(decl) = decl else {
            failures.insert(fixture.language, "missing declaration".to_string());
            continue;
        };
        if !contains_shape(&decl.flow_events, shape) {
            failures.insert(
                fixture.language,
                format!("missing {shape:?} event; events={:#?}", decl.flow_events),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "async/coroutine syntax regressions:\n{failures:#?}"
    );
}

#[test]
fn grammar_owned_await_forms_emit_suspension_events() {
    validate(AWAIT_FIXTURES, NO_AWAIT, Shape::Await);
}

#[test]
fn grammar_owned_yield_forms_emit_transfer_events() {
    validate(YIELD_FIXTURES, NO_YIELD, Shape::Yield);
}
