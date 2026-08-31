//! JIT-style execution-order and termination conformance.
//!
//! Static compiler facts do not execute a program, but their ordering and
//! reachability must agree with the source language's evaluator. Presence-only
//! assertions miss reversed walks and dead statements kept on live paths.
//! These probes therefore cover every bundled adapter and validate two
//! language-neutral runtime obligations:
//!
//! 1. observable calls in a straight-line function retain source order;
//! 2. a call after an unconditional function return is absent or belongs to
//!    an unreachable CFG block;
//! 3. every language-level abrupt exception/panic form terminates the current
//!    path before a later call.

use bonsai_cfg::{SyntheticBlockKind, Terminator};
use bonsai_common::{BasicBlockId, Span};
use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const ORDER_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "eval.c", function: "evaluate", source: "void evaluate(char *input) { step_one(input); char *value = step_two(input); step_three(value); }\n" },
    Fixture { language: "cpp", path: "eval.cpp", function: "evaluate", source: "void evaluate(const char *input) { step_one(input); const char *value = step_two(input); step_three(value); }\n" },
    Fixture { language: "csharp", path: "Eval.cs", function: "Evaluate", source: "class Eval { static void Evaluate(string input) { StepOne(input); var value = StepTwo(input); StepThree(value); } }\n" },
    Fixture { language: "dart", path: "eval.dart", function: "evaluate", source: "void evaluate(String input) { step_one(input); final value = step_two(input); step_three(value); }\n" },
    Fixture { language: "elixir", path: "eval.ex", function: "evaluate", source: "defmodule Eval do\n  def evaluate(input) do\n    step_one(input)\n    value = step_two(input)\n    step_three(value)\n  end\nend\n" },
    Fixture { language: "erlang", path: "eval.erl", function: "evaluate", source: "-module(eval_order).\n-export([evaluate/1]).\nevaluate(Input) -> step_one(Input), Value = step_two(Input), step_three(Value).\n" },
    Fixture { language: "go", path: "eval.go", function: "evaluate", source: "package evalorder\nfunc evaluate(input string) { step_one(input); value := step_two(input); step_three(value) }\n" },
    Fixture { language: "java", path: "Eval.java", function: "evaluate", source: "class Eval { static void evaluate(String input) { step_one(input); String value = step_two(input); step_three(value); } }\n" },
    Fixture { language: "javascript", path: "eval.js", function: "evaluate", source: "function evaluate(input) { step_one(input); const value = step_two(input); step_three(value); }\n" },
    Fixture { language: "kotlin", path: "eval.kt", function: "evaluate", source: "fun evaluate(input: String) { step_one(input); val value = step_two(input); step_three(value) }\n" },
    Fixture { language: "lua", path: "eval.lua", function: "evaluate", source: "local function evaluate(input)\n  step_one(input)\n  local value = step_two(input)\n  step_three(value)\nend\n" },
    Fixture { language: "objc", path: "eval.m", function: "evaluate", source: "void evaluate(NSString *input) { step_one(input); NSString *value = step_two(input); step_three(value); }\n" },
    Fixture { language: "perl", path: "eval.pl", function: "evaluate", source: "sub evaluate { my ($input) = @_; step_one($input); my $value = step_two($input); step_three($value); }\n" },
    Fixture { language: "php", path: "eval.php", function: "evaluate", source: "<?php\nfunction evaluate($input) { step_one($input); $value = step_two($input); step_three($value); }\n" },
    Fixture { language: "python", path: "eval.py", function: "evaluate", source: "def evaluate(input):\n    step_one(input)\n    value = step_two(input)\n    step_three(value)\n" },
    Fixture { language: "ruby", path: "eval.rb", function: "evaluate", source: "def evaluate(input)\n  step_one(input)\n  value = step_two(input)\n  step_three(value)\nend\n" },
    Fixture { language: "rust", path: "eval.rs", function: "evaluate", source: "fn evaluate(input: &str) { step_one(input); let value = step_two(input); step_three(value); }\n" },
    Fixture { language: "scala", path: "Eval.scala", function: "evaluate", source: "object Eval { def evaluate(input: String): Unit = { step_one(input); val value = step_two(input); step_three(value) } }\n" },
    Fixture { language: "swift", path: "eval.swift", function: "evaluate", source: "func evaluate(_ input: String) { step_one(input); let value = step_two(input); step_three(value) }\n" },
    Fixture { language: "typescript", path: "eval.ts", function: "evaluate", source: "function evaluate(input: string): void { step_one(input); const value = step_two(input); step_three(value); }\n" },
];

const NESTED_ORDER_FIXTURES: &[Fixture] = &[
    Fixture {
        language: "c",
        path: "nested.c",
        function: "evaluate",
        source: "void evaluate(char *input) { outer(inner(input)); }\n",
    },
    Fixture {
        language: "cpp",
        path: "nested.cpp",
        function: "evaluate",
        source: "void evaluate(const char *input) { outer(inner(input)); }\n",
    },
    Fixture {
        language: "csharp",
        path: "Nested.cs",
        function: "Evaluate",
        source: "class Nested { static void Evaluate(string input) { Outer(Inner(input)); } }\n",
    },
    Fixture {
        language: "dart",
        path: "nested.dart",
        function: "evaluate",
        source: "void evaluate(String input) { outer(inner(input)); }\n",
    },
    Fixture {
        language: "elixir",
        path: "nested.ex",
        function: "evaluate",
        source: "defmodule Nested do\n  def evaluate(input), do: outer(inner(input))\nend\n",
    },
    Fixture {
        language: "erlang",
        path: "nested.erl",
        function: "evaluate",
        source: "-module(nested).\n-export([evaluate/1]).\nevaluate(Input) -> outer(inner(Input)).\n",
    },
    Fixture {
        language: "go",
        path: "nested.go",
        function: "evaluate",
        source: "package nested\nfunc evaluate(input string) { outer(inner(input)) }\n",
    },
    Fixture {
        language: "java",
        path: "Nested.java",
        function: "evaluate",
        source: "class Nested { static void evaluate(String input) { outer(inner(input)); } }\n",
    },
    Fixture {
        language: "javascript",
        path: "nested.js",
        function: "evaluate",
        source: "function evaluate(input) { outer(inner(input)); }\n",
    },
    Fixture {
        language: "kotlin",
        path: "nested.kt",
        function: "evaluate",
        source: "fun evaluate(input: String) { outer(inner(input)) }\n",
    },
    Fixture {
        language: "lua",
        path: "nested.lua",
        function: "evaluate",
        source: "local function evaluate(input)\n  outer(inner(input))\nend\n",
    },
    Fixture {
        language: "objc",
        path: "nested.m",
        function: "evaluate",
        source: "void evaluate(NSString *input) { outer(inner(input)); }\n",
    },
    Fixture {
        language: "perl",
        path: "nested.pl",
        function: "evaluate",
        source: "sub evaluate { my ($input) = @_; outer(inner($input)); }\n",
    },
    Fixture {
        language: "php",
        path: "nested.php",
        function: "evaluate",
        source: "<?php\nfunction evaluate($input) { outer(inner($input)); }\n",
    },
    Fixture {
        language: "python",
        path: "nested.py",
        function: "evaluate",
        source: "def evaluate(input):\n    outer(inner(input))\n",
    },
    Fixture {
        language: "ruby",
        path: "nested.rb",
        function: "evaluate",
        source: "def evaluate(input)\n  outer(inner(input))\nend\n",
    },
    Fixture {
        language: "rust",
        path: "nested.rs",
        function: "evaluate",
        source: "fn evaluate(input: &str) { outer(inner(input)); }\n",
    },
    Fixture {
        language: "scala",
        path: "Nested.scala",
        function: "evaluate",
        source: "object Nested { def evaluate(input: String): Unit = outer(inner(input)) }\n",
    },
    Fixture {
        language: "swift",
        path: "nested.swift",
        function: "evaluate",
        source: "func evaluate(_ input: String) { outer(inner(input)) }\n",
    },
    Fixture {
        language: "typescript",
        path: "nested.ts",
        function: "evaluate",
        source: "function evaluate(input: string): void { outer(inner(input)); }\n",
    },
];

const RETURN_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "return.c", function: "finish", source: "char *finish(char *input) { return input; dead_after_return(input); }\n" },
    Fixture { language: "cpp", path: "return.cpp", function: "finish", source: "const char *finish(const char *input) { return input; dead_after_return(input); }\n" },
    Fixture { language: "csharp", path: "Return.cs", function: "Finish", source: "class ReturnCase { static string Finish(string input) { return input; DeadAfterReturn(input); } }\n" },
    Fixture { language: "dart", path: "return.dart", function: "finish", source: "String finish(String input) { return input; dead_after_return(input); }\n" },
    Fixture { language: "go", path: "return.go", function: "finish", source: "package returnflow\nfunc finish(input string) string { return input; dead_after_return(input) }\n" },
    Fixture { language: "java", path: "ReturnCase.java", function: "finish", source: "class ReturnCase { static String finish(String input) { return input; dead_after_return(input); } }\n" },
    Fixture { language: "javascript", path: "return.js", function: "finish", source: "function finish(input) { return input; dead_after_return(input); }\n" },
    Fixture { language: "kotlin", path: "return.kt", function: "finish", source: "fun finish(input: String): String { return input; dead_after_return(input) }\n" },
    Fixture { language: "lua", path: "return.lua", function: "finish", source: "local function finish(input)\n  do return input end\n  dead_after_return(input)\nend\n" },
    Fixture { language: "objc", path: "return.m", function: "finish", source: "NSString *finish(NSString *input) { return input; dead_after_return(input); }\n" },
    Fixture { language: "perl", path: "return.pl", function: "finish", source: "sub finish { my ($input) = @_; return $input; dead_after_return($input); }\n" },
    Fixture { language: "php", path: "return.php", function: "finish", source: "<?php\nfunction finish($input) { return $input; dead_after_return($input); }\n" },
    Fixture { language: "python", path: "return.py", function: "finish", source: "def finish(input):\n    return input\n    dead_after_return(input)\n" },
    Fixture { language: "ruby", path: "return.rb", function: "finish", source: "def finish(input)\n  return input\n  dead_after_return(input)\nend\n" },
    Fixture { language: "rust", path: "return.rs", function: "finish", source: "fn finish(input: &str) -> &str { return input; dead_after_return(input); }\n" },
    Fixture { language: "scala", path: "ReturnCase.scala", function: "finish", source: "object ReturnCase { def finish(input: String): String = { return input; dead_after_return(input) } }\n" },
    Fixture { language: "swift", path: "return.swift", function: "finish", source: "func finish(_ input: String) -> String { return input; dead_after_return(input) }\n" },
    Fixture { language: "typescript", path: "return.ts", function: "finish", source: "function finish(input: string): string { return input; dead_after_return(input); }\n" },
];

const NO_UNCONDITIONAL_RETURN: &[(&str, &str)] = &[
    (
        "elixir",
        "functions return their final expression; there is no function-return statement",
    ),
    (
        "erlang",
        "functions return their final expression; there is no function-return statement",
    ),
];

const ABRUPT_FIXTURES: &[Fixture] = &[
    Fixture { language: "cpp", path: "throw.cpp", function: "fail", source: "void fail(const char *input) { throw input; dead_after_throw(input); }\n" },
    Fixture { language: "csharp", path: "Throw.cs", function: "Fail", source: "class ThrowCase { static void Fail(string input) { throw new System.Exception(input); DeadAfterThrow(input); } }\n" },
    Fixture { language: "dart", path: "throw.dart", function: "fail", source: "void fail(Object input) { throw input; dead_after_throw(input); }\n" },
    Fixture { language: "erlang", path: "throw.erl", function: "fail", source: "-module(throw_case).\n-export([fail/1]).\nfail(Input) -> erlang:error(Input), dead_after_throw(Input).\n" },
    Fixture { language: "java", path: "ThrowCase.java", function: "fail", source: "class ThrowCase { static void fail(String input) { throw new RuntimeException(input); dead_after_throw(input); } }\n" },
    Fixture { language: "javascript", path: "throw.js", function: "fail", source: "function fail(input) { throw input; dead_after_throw(input); }\n" },
    Fixture { language: "kotlin", path: "throw.kt", function: "fail", source: "fun fail(input: String) { throw RuntimeException(input); dead_after_throw(input) }\n" },
    Fixture { language: "objc", path: "throw.m", function: "fail", source: "void fail(NSException *input) { @throw input; dead_after_throw(input); }\n" },
    Fixture { language: "perl", path: "throw.pl", function: "fail", source: "sub fail { my ($input) = @_; die $input; dead_after_throw($input); }\n" },
    Fixture { language: "php", path: "throw.php", function: "fail", source: "<?php\nfunction fail($input) { throw new Exception($input); dead_after_throw($input); }\n" },
    Fixture { language: "python", path: "throw.py", function: "fail", source: "def fail(input):\n    raise RuntimeError(input)\n    dead_after_throw(input)\n" },
    Fixture { language: "ruby", path: "throw.rb", function: "fail", source: "def fail(input)\n  raise input\n  dead_after_throw(input)\nend\n" },
    Fixture { language: "scala", path: "ThrowCase.scala", function: "fail", source: "object ThrowCase { def fail(input: String): Unit = { throw new RuntimeException(input); dead_after_throw(input) } }\n" },
    Fixture { language: "swift", path: "throw.swift", function: "fail", source: "func fail(_ input: Error) throws { throw input; dead_after_throw(input) }\n" },
    Fixture { language: "typescript", path: "throw.ts", function: "fail", source: "function fail(input: unknown): never { throw input; dead_after_throw(input); }\n" },
];

const NO_GRAMMAR_OWNED_ABRUPT_EXCEPTION: &[(&str, &str)] = &[
    (
        "c",
        "C has no language-level exception construct; termination APIs are library calls",
    ),
    (
        "elixir",
        "raise is a Kernel macro/call identity, not dedicated exception syntax in the grammar",
    ),
    (
        "go",
        "panic is a shadowable predeclared identifier and requires binding-aware intrinsic modeling",
    ),
    (
        "lua",
        "error is a replaceable standard-library function, not a grammar-owned terminator",
    ),
    (
        "rust",
        "panic is a resolvable macro identity, not a grammar-owned terminator",
    ),
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn workspace(fixture: &Fixture) -> Workspace {
    bonsai_testkit::workspace_with(
        vec![adapter_for(fixture.language)],
        &[(fixture.path, fixture.source)],
    )
}

fn find_decl(workspace: &Workspace, name: &str) -> Decl {
    let index = workspace.db().global_index();
    let declaration = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == name)
        .cloned();
    declaration.unwrap_or_else(|| panic!("missing `{name}` declaration"))
}

fn canonical_marker(name: &str) -> Option<&'static str> {
    let normalized = name
        .rsplit(['.', ':', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    match normalized.as_str() {
        "stepone" => Some("step_one"),
        "steptwo" => Some("step_two"),
        "stepthree" => Some("step_three"),
        "deadafterreturn" => Some("dead_after_return"),
        "deadafterthrow" => Some("dead_after_throw"),
        "inner" => Some("inner"),
        "outer" => Some("outer"),
        _ => None,
    }
}

#[test]
fn nested_calls_evaluate_arguments_before_outer_invocation_in_every_language() {
    assert_exact_language_partition(NESTED_ORDER_FIXTURES, &[]);
    let mut failures = BTreeMap::new();
    for fixture in NESTED_ORDER_FIXTURES {
        let workspace = workspace(fixture);
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid nested-call fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let mut calls = Vec::new();
        collect_calls(&decl.flow_events, &mut calls);
        let observed = calls.iter().map(|(_, marker)| *marker).collect::<Vec<_>>();
        if observed != ["inner", "outer"] {
            failures.insert(
                fixture.language,
                format!(
                    "nested evaluation order {observed:?}; events={:#?}",
                    decl.flow_events
                ),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "nested-call evaluation-order regressions:\n{failures:#?}"
    );
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(Span, &'static str)>) {
    for event in events {
        match event {
            FlowEvent::Call { span, name, .. } => {
                if let Some(marker) = canonical_marker(name) {
                    out.push((*span, marker));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls(then_events, out);
                collect_calls(else_events, out);
            }
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                collect_calls(condition_events, out);
                collect_calls(body, out);
                collect_calls(update_events, out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls(body, out);
                collect_calls(catch_events, out);
                collect_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

fn registered_languages() -> BTreeSet<String> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect()
}

fn assert_exact_language_partition(fixtures: &[Fixture], omitted: &[(&str, &str)]) {
    let fixture_languages = fixtures
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fixture_languages.len(),
        fixtures.len(),
        "duplicate language fixture"
    );
    let omitted_languages = omitted
        .iter()
        .map(|(language, rationale)| {
            assert!(
                !rationale.trim().is_empty(),
                "{language}: empty omission rationale"
            );
            (*language).to_string()
        })
        .collect::<BTreeSet<_>>();
    assert!(
        fixture_languages.is_disjoint(&omitted_languages),
        "a language cannot be both tested and omitted"
    );
    assert_eq!(
        fixture_languages
            .union(&omitted_languages)
            .cloned()
            .collect::<BTreeSet<_>>(),
        registered_languages(),
        "every registered language must be tested or explicitly inapplicable"
    );
}

#[test]
fn straight_line_calls_preserve_source_evaluation_order_in_every_language() {
    assert_exact_language_partition(ORDER_FIXTURES, &[]);
    let mut failures = BTreeMap::new();
    for fixture in ORDER_FIXTURES {
        let workspace = workspace(fixture);
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let mut calls = Vec::new();
        collect_calls(&decl.flow_events, &mut calls);
        let observed = calls.iter().map(|(_, marker)| *marker).collect::<Vec<_>>();
        let expected = vec!["step_one", "step_two", "step_three"];
        if observed != expected {
            failures.insert(
                fixture.language,
                format!(
                    "call order {observed:?}, expected {expected:?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        if !calls.windows(2).all(|pair| pair[0].0.start < pair[1].0.start) {
            failures.insert(
                fixture.language,
                format!("call spans are not strictly source ordered: {calls:?}"),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "source-evaluation-order regressions:\n{failures:#?}"
    );
}

fn reachable_blocks(cfg: &bonsai_cfg::Cfg) -> BTreeSet<BasicBlockId> {
    let mut reachable = BTreeSet::new();
    let mut pending = vec![cfg.entry];
    while let Some(block_id) = pending.pop() {
        if !reachable.insert(block_id) {
            continue;
        }
        let block = cfg
            .block(block_id)
            .unwrap_or_else(|| panic!("dangling CFG block {block_id:?}"));
        pending.extend(block.successors.iter().copied());
    }
    reachable
}

#[test]
fn function_return_terminates_control_before_later_calls() {
    assert_exact_language_partition(RETURN_FIXTURES, NO_UNCONDITIONAL_RETURN);
    let mut failures = BTreeMap::new();
    for fixture in RETURN_FIXTURES {
        let workspace = workspace(fixture);
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let mut calls = Vec::new();
        collect_calls(&decl.flow_events, &mut calls);
        let dead_spans = calls
            .iter()
            .filter_map(|(span, marker)| (*marker == "dead_after_return").then_some(*span))
            .collect::<Vec<_>>();
        if dead_spans.len() != 1 {
            failures.insert(
                fixture.language,
                format!(
                    "expected one dead call fact, got {dead_spans:?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        let function = workspace
            .lookup_function(fixture.function)
            .unwrap_or_else(|| panic!("missing function id for {}", fixture.function));
        let cfg = workspace.db().cfg(function);
        if !cfg
            .blocks
            .iter()
            .any(|block| block.terminator == Terminator::Return)
        {
            failures.insert(
                fixture.language,
                format!(
                    "return syntax did not lower to a Return terminator: {:#?}",
                    cfg.blocks
                ),
            );
            continue;
        }
        let reachable = reachable_blocks(&cfg);
        let dead_block = cfg.blocks.iter().find(|block| {
            block
                .events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { span, .. } if dead_spans.contains(span)))
        });
        let Some(dead_block) = dead_block else {
            failures.insert(
                fixture.language,
                format!("dead call was lost between HIR and CFG: {:#?}", cfg.blocks),
            );
            continue;
        };
        if reachable.contains(&dead_block.id)
            || dead_block.synthetic_kind != Some(SyntheticBlockKind::Unreachable)
        {
            failures.insert(
                fixture.language,
                format!("post-return call remains executable in block {dead_block:#?}"),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "function-return termination regressions:\n{failures:#?}"
    );
}

#[test]
fn abrupt_exception_or_panic_terminates_control_before_later_calls() {
    assert_exact_language_partition(ABRUPT_FIXTURES, NO_GRAMMAR_OWNED_ABRUPT_EXCEPTION);
    let mut failures = BTreeMap::new();
    for fixture in ABRUPT_FIXTURES {
        let workspace = workspace(fixture);
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let mut calls = Vec::new();
        collect_calls(&decl.flow_events, &mut calls);
        let dead_spans = calls
            .iter()
            .filter_map(|(span, marker)| (*marker == "dead_after_throw").then_some(*span))
            .collect::<Vec<_>>();
        if dead_spans.len() != 1 {
            failures.insert(
                fixture.language,
                format!(
                    "expected one post-abrupt call fact, got {dead_spans:?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        let function = workspace
            .lookup_function(fixture.function)
            .unwrap_or_else(|| panic!("missing function id for {}", fixture.function));
        let cfg = workspace.db().cfg(function);
        if !cfg
            .blocks
            .iter()
            .any(|block| block.terminator == Terminator::Throw)
        {
            failures.insert(
                fixture.language,
                format!(
                    "abrupt runtime form did not lower to a Throw terminator: {:#?}",
                    cfg.blocks
                ),
            );
            continue;
        }
        let reachable = reachable_blocks(&cfg);
        let dead_block = cfg.blocks.iter().find(|block| {
            block
                .events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { span, .. } if dead_spans.contains(span)))
        });
        let Some(dead_block) = dead_block else {
            failures.insert(
                fixture.language,
                format!("post-abrupt call was lost between HIR and CFG: {:#?}", cfg.blocks),
            );
            continue;
        };
        if reachable.contains(&dead_block.id)
            || dead_block.synthetic_kind != Some(SyntheticBlockKind::Unreachable)
        {
            failures.insert(
                fixture.language,
                format!("post-abrupt call remains executable in block {dead_block:#?}"),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "abrupt exception/panic termination regressions:\n{failures:#?}"
    );
}
