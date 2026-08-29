//! Runtime cleanup-order conformance.
//!
//! `finally`-family constructs execute after their protected body, and
//! language-level `defer` executes at scope exit rather than at its source
//! declaration. The compiler CFG must preserve those evaluator semantics so
//! dataflow cannot observe cleanup writes too early or skip them on return.

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

const FINALLY_FIXTURES: &[Fixture] = &[
    Fixture { language: "csharp", path: "Cleanup.cs", function: "Finish", source: "class Cleanup { static string Finish(string input) { try { BeforeReturn(); return input; } finally { CleanupNow(); } } }\n" },
    Fixture { language: "dart", path: "cleanup.dart", function: "finish", source: "String finish(String input) { try { before_return(); return input; } finally { cleanup_now(); } }\n" },
    Fixture { language: "elixir", path: "cleanup.ex", function: "finish", source: "defmodule Cleanup do\n  def finish(input) do\n    try do\n      before_return()\n      input\n    after\n      cleanup_now()\n    end\n  end\nend\n" },
    Fixture { language: "erlang", path: "cleanup.erl", function: "finish", source: "-module(cleanup).\n-export([finish/1]).\nfinish(Input) -> try before_return(), Input after cleanup_now() end.\n" },
    Fixture { language: "java", path: "Cleanup.java", function: "finish", source: "class Cleanup { static String finish(String input) { try { before_return(); return input; } finally { cleanup_now(); } } }\n" },
    Fixture { language: "javascript", path: "cleanup.js", function: "finish", source: "function finish(input) { try { before_return(); return input; } finally { cleanup_now(); } }\n" },
    Fixture { language: "kotlin", path: "cleanup.kt", function: "finish", source: "fun finish(input: String): String { try { before_return(); return input } finally { cleanup_now() } }\n" },
    Fixture { language: "objc", path: "cleanup.m", function: "finish", source: "NSString *finish(NSString *input) { @try { before_return(); return input; } @finally { cleanup_now(); } }\n" },
    Fixture { language: "php", path: "cleanup.php", function: "finish", source: "<?php\nfunction finish($input) { try { before_return(); return $input; } finally { cleanup_now(); } }\n" },
    Fixture { language: "python", path: "cleanup.py", function: "finish", source: "def finish(input):\n    try:\n        before_return()\n        return input\n    finally:\n        cleanup_now()\n" },
    Fixture { language: "ruby", path: "cleanup.rb", function: "finish", source: "def finish(input)\n  begin\n    before_return\n    return input\n  ensure\n    cleanup_now\n  end\nend\n" },
    Fixture { language: "scala", path: "Cleanup.scala", function: "finish", source: "object Cleanup { def finish(input: String): String = { try { before_return(); return input } finally { cleanup_now() } } }\n" },
    Fixture { language: "typescript", path: "cleanup.ts", function: "finish", source: "function finish(input: string): string { try { before_return(); return input; } finally { cleanup_now(); } }\n" },
];

const NO_FINALLY: &[(&str, &str)] = &[
    ("c", "C has no finally-family construct"),
    ("cpp", "C++ uses RAII destructors rather than finally syntax"),
    ("go", "Go uses defer rather than finally syntax"),
    ("lua", "the supported Lua grammar has no finally-family construct"),
    (
        "perl",
        "the supported Perl grammar has no native finally construct",
    ),
    ("rust", "Rust uses Drop/RAII rather than finally syntax"),
    ("swift", "Swift uses defer rather than finally syntax"),
];

const DEFER_FIXTURES: &[Fixture] = &[
    Fixture {
        language: "go",
        path: "defer.go",
        function: "finish",
        source: "package cleanup\nfunc finish() { defer cleanup_now(); before_return(); return }\n",
    },
    Fixture {
        language: "swift",
        path: "defer.swift",
        function: "finish",
        source: "func finish() { defer { cleanup_now() }; before_return(); return }\n",
    },
];

const NO_DEFER: &[(&str, &str)] = &[
    ("c", "C has no language-level defer construct"),
    ("cpp", "C++ uses RAII destructors rather than defer syntax"),
    ("csharp", "C# uses finally/using rather than defer syntax"),
    ("dart", "Dart uses finally rather than defer syntax"),
    ("elixir", "Elixir uses try/after rather than defer syntax"),
    ("erlang", "Erlang uses try/after rather than defer syntax"),
    (
        "java",
        "Java uses finally/resource scopes rather than defer syntax",
    ),
    ("javascript", "JavaScript uses finally rather than defer syntax"),
    ("kotlin", "Kotlin uses finally/use rather than defer syntax"),
    ("lua", "the supported Lua grammar has no defer construct"),
    (
        "objc",
        "Objective-C uses @finally/autorelease scopes rather than defer syntax",
    ),
    ("perl", "the supported Perl grammar has no defer construct"),
    ("php", "PHP uses finally rather than defer syntax"),
    (
        "python",
        "Python uses finally/context managers rather than defer syntax",
    ),
    ("ruby", "Ruby uses ensure rather than defer syntax"),
    ("rust", "Rust uses Drop/RAII rather than a defer statement"),
    (
        "scala",
        "Scala uses finally/resource abstractions rather than defer syntax",
    ),
    ("typescript", "TypeScript uses finally rather than defer syntax"),
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
        "beforereturn" => Some("before_return"),
        "cleanupnow" => Some("cleanup_now"),
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

fn reachable(cfg: &bonsai_cfg::Cfg, start: BasicBlockId, target: BasicBlockId) -> bool {
    let mut seen = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(block_id) = pending.pop() {
        if block_id == target {
            return true;
        }
        if !seen.insert(block_id) {
            continue;
        }
        let block = cfg.block(block_id).expect("valid CFG block");
        pending.extend(block.successors.iter().copied());
    }
    false
}

fn fixture_cfg(fixture: &Fixture) -> (Workspace, bonsai_common::FuncId) {
    let workspace = bonsai_testkit::workspace_with(
        vec![adapter_for(fixture.language)],
        &[(fixture.path, fixture.source)],
    );
    let diagnostics = workspace.diagnostics();
    assert!(
        diagnostics.is_empty(),
        "{}: valid cleanup fixture emitted diagnostics: {diagnostics:#?}",
        fixture.language
    );
    let function = workspace
        .lookup_function(fixture.function)
        .unwrap_or_else(|| panic!("{}: missing function", fixture.language));
    (workspace, function)
}

fn marker_blocks(
    workspace: &Workspace,
    function: bonsai_common::FuncId,
) -> Result<(bonsai_cfg::Cfg, BasicBlockId, BasicBlockId), String> {
    let global = workspace.db().global_index();
    let decl = global
        .decl_of(bonsai_common::SymbolId::new(function.raw()))
        .expect("function declaration");
    let mut calls = Vec::new();
    collect_calls(&decl.flow_events, &mut calls);
    let before = calls
        .iter()
        .find_map(|(span, marker)| (*marker == "before_return").then_some(*span))
        .ok_or_else(|| {
            format!(
                "before_return call missing; calls={calls:?}; events={:#?}",
                decl.flow_events
            )
        })?;
    let cleanup = calls
        .iter()
        .find_map(|(span, marker)| (*marker == "cleanup_now").then_some(*span))
        .ok_or_else(|| {
            format!(
                "cleanup_now call missing; calls={calls:?}; events={:#?}",
                decl.flow_events
            )
        })?;
    let cfg = (*workspace.db().cfg(function)).clone();
    let block_for = |span| -> Result<BasicBlockId, String> {
        cfg.blocks
            .iter()
            .find(|block| {
                block
                    .events
                    .iter()
                    .any(|event| matches!(event, FlowEvent::Call { span: call, .. } if *call == span))
            })
            .map(|block| block.id)
            .ok_or_else(|| format!("call {span:?} missing from CFG: {:#?}", cfg.blocks))
    };
    let before_block = block_for(before)?;
    let cleanup_block = block_for(cleanup)?;
    Ok((cfg, before_block, cleanup_block))
}

#[test]
fn finally_family_cleanup_runs_after_the_protected_body() {
    assert_partition(FINALLY_FIXTURES, NO_FINALLY);
    let mut failures = BTreeMap::new();
    for fixture in FINALLY_FIXTURES {
        let (workspace, function) = fixture_cfg(fixture);
        let (cfg, before, cleanup) = match marker_blocks(&workspace, function) {
            Ok(markers) => markers,
            Err(error) => {
                failures.insert(fixture.language, error);
                continue;
            }
        };
        if !reachable(&cfg, before, cleanup) {
            failures.insert(
                fixture.language,
                format!("cleanup is not reachable after body: {:#?}", cfg.blocks),
            );
        }
    }
    assert!(failures.is_empty(), "finally-order regressions:\n{failures:#?}");
}

#[test]
fn defer_cleanup_runs_at_scope_exit_not_at_declaration() {
    assert_partition(DEFER_FIXTURES, NO_DEFER);
    let mut failures = BTreeMap::new();
    for fixture in DEFER_FIXTURES {
        let (workspace, function) = fixture_cfg(fixture);
        let (cfg, before, cleanup) = match marker_blocks(&workspace, function) {
            Ok(markers) => markers,
            Err(error) => {
                failures.insert(fixture.language, error);
                continue;
            }
        };
        let correctly_ordered = if before == cleanup {
            let block = cfg.block(before).expect("marker block");
            let markers = block
                .events
                .iter()
                .filter_map(|event| match event {
                    FlowEvent::Call { name, .. } => canonical_marker(name),
                    _ => None,
                })
                .collect::<Vec<_>>();
            markers == ["before_return", "cleanup_now"]
        } else {
            reachable(&cfg, before, cleanup) && !reachable(&cfg, cleanup, before)
        };
        if !correctly_ordered {
            failures.insert(
                fixture.language,
                format!("defer executed before scope exit: {:#?}", cfg.blocks),
            );
        }
    }
    assert!(failures.is_empty(), "defer-order regressions:\n{failures:#?}");
}
