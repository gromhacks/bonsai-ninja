//! Evaluator-style `break` / `continue` conformance.
//!
//! An adapter can emit a terminator token yet still leave following body
//! statements executable. These fixtures prove the complete CFG contract:
//! the terminator exists, the following call is unreachable, and the code
//! after the loop remains reachable through the appropriate loop edge.

use bonsai_cfg::{SyntheticBlockKind, Terminator};
use bonsai_common::{BasicBlockId, Span};
use bonsai_lang_api::{FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const BREAK_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "break.c", function: "break_case", source: "void break_case(void) { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "cpp", path: "break.cpp", function: "break_case", source: "void break_case() { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "csharp", path: "Break.cs", function: "BreakCase", source: "class BreakCaseType { static void BreakCase() { while (Condition()) { BeforeBreak(); break; DeadAfterBreak(); } AfterLoop(); } }\n" },
    Fixture { language: "dart", path: "break.dart", function: "break_case", source: "void break_case() { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "go", path: "break.go", function: "break_case", source: "package loopcontrol\nfunc break_case() { for condition() { before_break(); break; dead_after_break() }; after_loop() }\n" },
    Fixture { language: "java", path: "BreakCase.java", function: "break_case", source: "class BreakCase { static void break_case() { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); } }\n" },
    Fixture { language: "javascript", path: "break.js", function: "break_case", source: "function break_case() { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "kotlin", path: "break.kt", function: "break_case", source: "fun break_case() { while (condition()) { before_break(); break; dead_after_break() }; after_loop() }\n" },
    Fixture { language: "lua", path: "break.lua", function: "break_case", source: "local function break_case()\n  while condition() do\n    before_break()\n    break\n    dead_after_break()\n  end\n  after_loop()\nend\n" },
    Fixture { language: "objc", path: "break.m", function: "break_case", source: "void break_case(void) { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "perl", path: "break.pl", function: "break_case", source: "sub break_case { while (condition()) { before_break(); last; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "php", path: "break.php", function: "break_case", source: "<?php\nfunction break_case() { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "python", path: "break.py", function: "break_case", source: "def break_case():\n    while condition():\n        before_break()\n        break\n        dead_after_break()\n    after_loop()\n" },
    Fixture { language: "ruby", path: "break.rb", function: "break_case", source: "def break_case\n  while condition\n    before_break\n    break\n    dead_after_break\n  end\n  after_loop\nend\n" },
    Fixture { language: "rust", path: "break.rs", function: "break_case", source: "fn break_case() { while condition() { before_break(); break; dead_after_break(); } after_loop(); }\n" },
    Fixture { language: "swift", path: "break.swift", function: "break_case", source: "func break_case() { while condition() { before_break(); break; dead_after_break() }; after_loop() }\n" },
    Fixture { language: "typescript", path: "break.ts", function: "break_case", source: "function break_case(): void { while (condition()) { before_break(); break; dead_after_break(); } after_loop(); }\n" },
];

const CONTINUE_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "continue.c", function: "continue_case", source: "void continue_case(void) { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "cpp", path: "continue.cpp", function: "continue_case", source: "void continue_case() { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "csharp", path: "Continue.cs", function: "ContinueCase", source: "class ContinueCaseType { static void ContinueCase() { while (Condition()) { BeforeContinue(); continue; DeadAfterContinue(); } AfterLoop(); } }\n" },
    Fixture { language: "dart", path: "continue.dart", function: "continue_case", source: "void continue_case() { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "go", path: "continue.go", function: "continue_case", source: "package loopcontrol\nfunc continue_case() { for condition() { before_continue(); continue; dead_after_continue() }; after_loop() }\n" },
    Fixture { language: "java", path: "ContinueCase.java", function: "continue_case", source: "class ContinueCase { static void continue_case() { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); } }\n" },
    Fixture { language: "javascript", path: "continue.js", function: "continue_case", source: "function continue_case() { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "kotlin", path: "continue.kt", function: "continue_case", source: "fun continue_case() { while (condition()) { before_continue(); continue; dead_after_continue() }; after_loop() }\n" },
    Fixture { language: "objc", path: "continue.m", function: "continue_case", source: "void continue_case(void) { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "perl", path: "continue.pl", function: "continue_case", source: "sub continue_case { while (condition()) { before_continue(); next; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "php", path: "continue.php", function: "continue_case", source: "<?php\nfunction continue_case() { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "python", path: "continue.py", function: "continue_case", source: "def continue_case():\n    while condition():\n        before_continue()\n        continue\n        dead_after_continue()\n    after_loop()\n" },
    Fixture { language: "ruby", path: "continue.rb", function: "continue_case", source: "def continue_case\n  while condition\n    before_continue\n    next\n    dead_after_continue\n  end\n  after_loop\nend\n" },
    Fixture { language: "rust", path: "continue.rs", function: "continue_case", source: "fn continue_case() { while condition() { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
    Fixture { language: "swift", path: "continue.swift", function: "continue_case", source: "func continue_case() { while condition() { before_continue(); continue; dead_after_continue() }; after_loop() }\n" },
    Fixture { language: "typescript", path: "continue.ts", function: "continue_case", source: "function continue_case(): void { while (condition()) { before_continue(); continue; dead_after_continue(); } after_loop(); }\n" },
];

const NO_BREAK: &[(&str, &str)] = &[
    (
        "elixir",
        "enumeration is expression-oriented and has no break statement",
    ),
    ("erlang", "recursion/comprehensions have no break statement"),
    (
        "scala",
        "Scala has no native break statement; scala.util.control.Breaks is a library abstraction",
    ),
];

const NO_CONTINUE: &[(&str, &str)] = &[
    (
        "elixir",
        "enumeration is expression-oriented and has no continue statement",
    ),
    ("erlang", "recursion/comprehensions have no continue statement"),
    (
        "lua",
        "the supported Lua grammar has break but no native continue statement",
    ),
    ("scala", "Scala has no native continue statement"),
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
        "deadafterbreak" => Some("dead_after_break"),
        "deadaftercontinue" => Some("dead_after_continue"),
        "afterloop" => Some("after_loop"),
        _ => None,
    }
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
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
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

fn reachable_blocks(cfg: &bonsai_cfg::Cfg) -> BTreeSet<BasicBlockId> {
    let mut reachable = BTreeSet::new();
    let mut pending = vec![cfg.entry];
    while let Some(block_id) = pending.pop() {
        if !reachable.insert(block_id) {
            continue;
        }
        let block = cfg.block(block_id).expect("valid CFG block");
        pending.extend(block.successors.iter().copied());
    }
    reachable
}

fn validate(fixtures: &[Fixture], omitted: &[(&str, &str)], terminator: Terminator, dead: &str) {
    assert_partition(fixtures, omitted);
    let mut failures = BTreeMap::new();
    for fixture in fixtures {
        let workspace = workspace(fixture);
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let function = workspace
            .lookup_function(fixture.function)
            .unwrap_or_else(|| panic!("{}: missing function", fixture.language));
        let global = workspace.db().global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(function.raw()))
            .unwrap_or_else(|| panic!("{}: missing declaration", fixture.language));
        let mut calls = Vec::new();
        collect_calls(&decl.flow_events, &mut calls);
        let dead_spans = calls
            .iter()
            .filter_map(|(span, marker)| (*marker == dead).then_some(*span))
            .collect::<Vec<_>>();
        let after_spans = calls
            .iter()
            .filter_map(|(span, marker)| (*marker == "after_loop").then_some(*span))
            .collect::<Vec<_>>();
        if dead_spans.len() != 1 || after_spans.len() != 1 {
            failures.insert(
                fixture.language,
                format!(
                    "expected exact dead/after calls; calls={calls:?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        let cfg = workspace.db().cfg(function);
        let reachable = reachable_blocks(&cfg);
        let has_terminator = cfg.blocks.iter().any(|block| block.terminator == terminator);
        let dead_block = cfg.blocks.iter().find(|block| {
            block
                .events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { span, .. } if dead_spans.contains(span)))
        });
        let after_block = cfg.blocks.iter().find(|block| {
            block
                .events
                .iter()
                .any(|event| matches!(event, FlowEvent::Call { span, .. } if after_spans.contains(span)))
        });
        let dead_is_unreachable = dead_block.is_some_and(|block| {
            !reachable.contains(&block.id) && block.synthetic_kind == Some(SyntheticBlockKind::Unreachable)
        });
        let after_is_reachable = after_block.is_some_and(|block| reachable.contains(&block.id));
        if !has_terminator || !dead_is_unreachable || !after_is_reachable {
            failures.insert(
                fixture.language,
                format!(
                    "terminator={has_terminator}, dead_unreachable={dead_is_unreachable}, after_reachable={after_is_reachable}; blocks={:#?}",
                    cfg.blocks
                ),
            );
        }
    }
    assert!(failures.is_empty(), "loop-control regressions:\n{failures:#?}");
}

#[test]
fn break_exits_the_body_and_reaches_code_after_the_loop() {
    validate(BREAK_FIXTURES, NO_BREAK, Terminator::Break, "dead_after_break");
}

#[test]
fn continue_restarts_the_loop_and_skips_the_rest_of_the_body() {
    validate(
        CONTINUE_FIXTURES,
        NO_CONTINUE,
        Terminator::Continue,
        "dead_after_continue",
    );
}
