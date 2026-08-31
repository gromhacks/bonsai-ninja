//! Per-language conformance for labeled loop control.
//!
//! Labels are source-language syntax facts. Each applicable adapter must
//! derive them from its Tree-sitter CST and the shared CFG/IDG layers must
//! receive one normalized identity for both the loop and its abrupt exits.

use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter, LoopControlTarget};
use bonsai_workspace::Workspace;
use std::collections::BTreeMap;
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "javascript",
        path: "labels.js",
        function: "labeled",
        source: "function labeled() { outer: while (ready()) { continue outer; break outer; } }\n",
    },
    Fixture {
        language: "typescript",
        path: "labels.ts",
        function: "labeled",
        source: "function labeled(): void { outer: while (ready()) { continue outer; break outer; } }\n",
    },
    Fixture {
        language: "go",
        path: "labels.go",
        function: "labeled",
        source: "package labels\nfunc labeled() { outer: for ready() { continue outer; break outer } }\n",
    },
    Fixture {
        language: "java",
        path: "Labels.java",
        function: "labeled",
        source: "class Labels { static void labeled() { outer: while (ready()) { continue outer; break outer; } } }\n",
    },
    Fixture {
        language: "kotlin",
        path: "Labels.kt",
        function: "labeled",
        source: "fun labeled() { outer@ while (ready()) { continue@outer; break@outer } }\n",
    },
    Fixture {
        language: "rust",
        path: "labels.rs",
        function: "labeled",
        source: "fn labeled() { 'outer: while ready() { continue 'outer; break 'outer; } }\n",
    },
    Fixture {
        language: "dart",
        path: "labels.dart",
        function: "labeled",
        source: "void labeled() { outer: while (ready()) { continue outer; break outer; } }\n",
    },
    Fixture {
        language: "swift",
        path: "labels.swift",
        function: "labeled",
        source: "func labeled() { outer: while ready() { continue outer; break outer } }\n",
    },
    Fixture {
        language: "perl",
        path: "labels.pl",
        function: "labeled",
        source: "sub labeled { outer: while (ready()) { next outer; last outer; } }\n",
    },
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn find_decl(workspace: &Workspace, name: &str) -> Decl {
    let global = workspace.db().global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == name)
        .cloned();
    declaration.unwrap_or_else(|| panic!("missing `{name}` declaration"))
}

fn collect_labels(
    events: &[FlowEvent],
    loops: &mut Vec<Option<String>>,
    breaks: &mut Vec<Option<LoopControlTarget>>,
    continues: &mut Vec<Option<LoopControlTarget>>,
) {
    for event in events {
        match event {
            FlowEvent::Loop { label, body, .. } => {
                loops.push(label.clone());
                collect_labels(body, loops, breaks, continues);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_labels(then_events, loops, breaks, continues);
                collect_labels(else_events, loops, breaks, continues);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_labels(body, loops, breaks, continues);
                collect_labels(catch_events, loops, breaks, continues);
                collect_labels(finally_events, loops, breaks, continues);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_labels(body, loops, breaks, continues);
            }
            FlowEvent::Break { target, .. } => breaks.push(target.clone()),
            FlowEvent::Continue { target, .. } => continues.push(target.clone()),
            _ => {}
        }
    }
}

#[test]
fn applicable_adapters_lower_labeled_loops_and_targets_from_parser_facts() {
    let mut failures = BTreeMap::new();
    for fixture in FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        if !workspace.diagnostics().is_empty() {
            failures.insert(
                fixture.language,
                format!("diagnostics: {:#?}", workspace.diagnostics()),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let (mut loops, mut breaks, mut continues) = (Vec::new(), Vec::new(), Vec::new());
        collect_labels(&decl.flow_events, &mut loops, &mut breaks, &mut continues);
        let expected_loop = Some("outer".to_string());
        let expected_target = Some(LoopControlTarget::Label("outer".to_string()));
        if !loops.contains(&expected_loop)
            || !breaks.contains(&expected_target)
            || !continues.contains(&expected_target)
        {
            failures.insert(
                fixture.language,
                format!("loop labels={loops:?}, break labels={breaks:?}, continue labels={continues:?}"),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "labeled control lowering regressions:\n{failures:#?}"
    );
}

#[test]
fn php_lowers_numeric_loop_levels_from_integer_syntax() {
    let workspace = bonsai_testkit::workspace_with(
        vec![adapter_for("php")],
        &[(
            "levels.php",
            "<?php\nfunction levels($x) { while ($x) { while ($x) { continue 2; break 2; } } }\n",
        )],
    );
    assert!(
        workspace.diagnostics().is_empty(),
        "{:#?}",
        workspace.diagnostics()
    );
    let decl = find_decl(&workspace, "levels");
    let (mut loops, mut breaks, mut continues) = (Vec::new(), Vec::new(), Vec::new());
    collect_labels(&decl.flow_events, &mut loops, &mut breaks, &mut continues);
    let expected = Some(LoopControlTarget::Levels(2));
    assert!(breaks.contains(&expected), "break targets: {breaks:?}");
    assert!(continues.contains(&expected), "continue targets: {continues:?}");
}
