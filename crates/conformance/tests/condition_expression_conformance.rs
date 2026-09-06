//! Typed boolean-expression conformance for every language adapter.
//!
//! Runtime guard semantics cannot be reconstructed from rendered condition
//! strings in shared analysis. Each frontend must lower conjunction,
//! disjunction, and negation to the language-neutral condition IR while
//! retaining source-ordered operand spans. These are also the operators whose
//! evaluators short-circuit, so flattening them to an opaque atom loses both
//! guard precision and execution semantics.

use bonsai_lang_api::{ConditionExpressionFact, DeclIndex, LanguageAdapter};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    source: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "condition.c", source: "void check(int left, int right) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); }\n" },
    Fixture { language: "cpp", path: "condition.cpp", source: "void check(bool left, bool right) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); }\n" },
    Fixture { language: "csharp", path: "Condition.cs", source: "class Condition { static void Check(bool left, bool right) { if (left && right) AllTaken(); if (left || right) AnyTaken(); if (!left) NotTaken(); } }\n" },
    Fixture { language: "dart", path: "condition.dart", source: "void check(bool left, bool right) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); }\n" },
    Fixture { language: "elixir", path: "condition.ex", source: "defmodule Condition do\n  def check(left, right) do\n    if left and right, do: all_taken()\n    if left or right, do: any_taken()\n    if not left, do: not_taken()\n  end\nend\n" },
    Fixture { language: "erlang", path: "condition.erl", source: "-module(condition).\n-export([check/2]).\ncheck(Left, Right) -> if Left andalso Right -> all_taken(); true -> ok end, if Left orelse Right -> any_taken(); true -> ok end, if not Left -> not_taken(); true -> ok end.\n" },
    Fixture { language: "go", path: "condition.go", source: "package condition\nfunc check(left bool, right bool) { if left && right { all_taken() }; if left || right { any_taken() }; if !left { not_taken() } }\n" },
    Fixture { language: "java", path: "Condition.java", source: "class Condition { static void check(boolean left, boolean right) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); } }\n" },
    Fixture { language: "javascript", path: "condition.js", source: "function check(left, right) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); }\n" },
    Fixture { language: "kotlin", path: "condition.kt", source: "fun check(left: Boolean, right: Boolean) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken() }\n" },
    Fixture { language: "lua", path: "condition.lua", source: "local function check(left, right)\n  if left and right then all_taken() end\n  if left or right then any_taken() end\n  if not left then not_taken() end\nend\n" },
    Fixture { language: "objc", path: "condition.m", source: "void check(BOOL left, BOOL right) { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); }\n" },
    Fixture { language: "perl", path: "condition.pl", source: "sub check { my ($left, $right) = @_; if ($left && $right) { all_taken(); } if ($left || $right) { any_taken(); } if (!$left) { not_taken(); } }\n" },
    Fixture { language: "php", path: "condition.php", source: "<?php\nfunction check($left, $right) { if ($left && $right) all_taken(); if ($left || $right) any_taken(); if (!$left) not_taken(); }\n" },
    Fixture { language: "python", path: "condition.py", source: "def check(left, right):\n    if left and right:\n        all_taken()\n    if left or right:\n        any_taken()\n    if not left:\n        not_taken()\n" },
    Fixture { language: "ruby", path: "condition.rb", source: "def check(left, right)\n  all_taken() if left && right\n  any_taken() if left || right\n  not_taken() if !left\nend\n" },
    Fixture { language: "rust", path: "condition.rs", source: "fn check(left: bool, right: bool) { if left && right { all_taken(); } if left || right { any_taken(); } if !left { not_taken(); } }\n" },
    Fixture { language: "scala", path: "Condition.scala", source: "object Condition { def check(left: Boolean, right: Boolean): Unit = { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken() } }\n" },
    Fixture { language: "swift", path: "condition.swift", source: "func check(_ left: Bool, _ right: Bool) { if left && right { all_taken() }; if left || right { any_taken() }; if !left { not_taken() } }\n" },
    Fixture { language: "typescript", path: "condition.ts", source: "function check(left: boolean, right: boolean): void { if (left && right) all_taken(); if (left || right) any_taken(); if (!left) not_taken(); }\n" },
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn assert_registry_exhaustive() {
    let registered = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect::<BTreeSet<_>>();
    let covered = FIXTURES
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, registered, "boolean fixtures must cover the registry");
    assert_eq!(covered.len(), FIXTURES.len(), "duplicate language fixture");
}

fn lowered_index(fixture: &Fixture) -> Arc<DeclIndex> {
    let workspace = bonsai_testkit::workspace_with(
        vec![adapter_for(fixture.language)],
        &[(fixture.path, fixture.source)],
    );
    let diagnostics = workspace.diagnostics();
    assert!(
        diagnostics.is_empty(),
        "{}: valid condition fixture emitted diagnostics: {diagnostics:#?}",
        fixture.language
    );
    let file = workspace
        .vfs()
        .all_files()
        .into_iter()
        .next()
        .expect("fixture file");
    workspace
        .db()
        .decl_index(file)
        .unwrap_or_else(|| panic!("{}: declaration index", fixture.language))
}

fn source_ordered(operands: &[ConditionExpressionFact]) -> bool {
    !operands.is_empty()
        && operands
            .windows(2)
            .all(|pair| pair[0].span().end <= pair[1].span().start)
}

#[test]
fn condition_call_operands_use_canonical_callee_identity_not_enclosing_call_spans() {
    let fixtures = [
        Fixture {
            language: "go",
            path: "condition.go",
            source:
                "package condition\nfunc check(value string) { if predicate(value) == true { taken() } }\n",
        },
        Fixture {
            language: "java",
            path: "Condition.java",
            source:
                "class Condition { void check(String value) { if (predicate(value) == true) taken(); } }\n",
        },
        Fixture {
            language: "javascript",
            path: "condition.js",
            source: "function check(value) { if (predicate(value) === true) taken(); }\n",
        },
        Fixture {
            language: "typescript",
            path: "condition.ts",
            source: "function check(value: string) { if (predicate(value) === true) taken(); }\n",
        },
        Fixture {
            language: "kotlin",
            path: "condition.kt",
            source: "fun check(value: String) { if (predicate(value) == true) taken() }\n",
        },
        Fixture {
            language: "lua",
            path: "condition.lua",
            source: "local function check(value) if predicate(value) == true then taken() end end\n",
        },
        Fixture {
            language: "python",
            path: "condition.py",
            source: "def check(value):\n    if predicate(value) == True:\n        taken()\n",
        },
        Fixture {
            language: "perl",
            path: "condition.pl",
            source: "sub check { my ($value) = @_; if (predicate($value) == 1) { taken(); } }\n",
        },
    ];
    for fixture in &fixtures {
        for wrapped in [false, true] {
            let source = if wrapped {
                fixture
                    .source
                    .replace("predicate(value)", "wrap(predicate(value))")
                    .replace("predicate($value)", "wrap(predicate($value))")
            } else {
                fixture.source.to_string()
            };
            let workspace = bonsai_testkit::workspace_with(
                vec![adapter_for(fixture.language)],
                &[(fixture.path, source.as_str())],
            );
            assert!(workspace.diagnostics().is_empty(), "{}", fixture.language);
            let file = workspace.vfs().all_files()[0];
            let index = workspace.db().decl_index(file).unwrap();
            let expression = index
                .branch_conditions
                .first()
                .and_then(|fact| fact.expression.as_ref())
                .unwrap();
            let ConditionExpressionFact::Equality { left, .. } = expression else {
                panic!("{}: {expression:#?}", fixture.language);
            };
            let mut expected = Vec::new();
            for decl in &index.defs {
                bonsai_lang_api::for_each_flow_event(&decl.flow_events, &mut |event| {
                    if let bonsai_lang_api::FlowEvent::Call { span, name, .. } = event {
                        if name == if wrapped { "wrap" } else { "predicate" } {
                            expected.push(*span);
                        }
                    }
                });
            }
            expected.sort_by_key(|span| (span.start, span.end));
            expected.dedup();
            assert_eq!(expected.len(), 1, "{}: {expected:?}", fixture.language);
            assert_eq!(
                left.direct_call_span,
                Some(expected[0]),
                "{} wrapped={wrapped}: {expression:#?}",
                fixture.language
            );
        }
    }
}

#[test]
fn every_language_lowers_boolean_evaluator_semantics_to_typed_ir() {
    assert_registry_exhaustive();
    let mut failures = BTreeMap::new();
    for fixture in FIXTURES {
        let index = lowered_index(fixture);
        let mut all = false;
        let mut any = false;
        let mut not = false;
        for fact in &index.branch_conditions {
            match fact.expression.as_ref() {
                Some(ConditionExpressionFact::All { operands, .. }) => {
                    all |= operands.len() == 2 && source_ordered(operands);
                }
                Some(ConditionExpressionFact::Any { operands, .. }) => {
                    any |= operands.len() == 2 && source_ordered(operands);
                }
                Some(ConditionExpressionFact::Not { operand, .. }) => {
                    not |= operand.span().start >= fact.condition_span.start
                        && operand.span().end <= fact.condition_span.end;
                }
                _ => {}
            }
        }
        if !(all && any && not) {
            failures.insert(
                fixture.language,
                format!(
                    "typed conditions missing/invalid: all={all}, any={any}, not={not}; facts={:#?}",
                    index.branch_conditions
                ),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "typed boolean-evaluator regressions:\n{failures:#?}"
    );
}
