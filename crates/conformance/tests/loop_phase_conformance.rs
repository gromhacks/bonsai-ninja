//! Per-frontend loop phase and runtime-order conformance.
//!
//! Shared IR-only tests cannot prove that a real Tree-sitter adapter
//! recognizes its language's post-test syntax or places condition/update
//! expressions in the correct evaluator phase. Every bundled language is
//! therefore either exercised with valid source or listed explicitly as not
//! having the source-language construct.

use bonsai_cfg::Cfg;
use bonsai_common::{BasicBlockId, Span};
use bonsai_idg::transfer_function_for;
use bonsai_lang_api::{FlowEvent, LanguageAdapter, LoopKind};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const POST_TEST_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "post.c", function: "post_test", source: "void post_test(void) { do { body_call(); } while (condition()); after_call(); }\n" },
    Fixture { language: "cpp", path: "post.cpp", function: "post_test", source: "void post_test() { do { body_call(); } while (condition()); after_call(); }\n" },
    Fixture { language: "csharp", path: "Post.cs", function: "PostTest", source: "class Post { static void PostTest() { do { BodyCall(); } while (Condition()); AfterCall(); } }\n" },
    Fixture { language: "dart", path: "post.dart", function: "post_test", source: "void post_test() { do { body_call(); } while (condition()); after_call(); }\n" },
    Fixture { language: "java", path: "Post.java", function: "post_test", source: "class Post { static void post_test() { do { body_call(); } while (condition()); after_call(); } }\n" },
    Fixture { language: "javascript", path: "post.js", function: "post_test", source: "function post_test() { do { body_call(); } while (condition()); after_call(); }\n" },
    Fixture { language: "kotlin", path: "post.kt", function: "post_test", source: "fun post_test() { do { body_call() } while (condition()); after_call() }\n" },
    Fixture { language: "lua", path: "post.lua", function: "post_test", source: "local function post_test()\n  repeat\n    body_call()\n  until condition()\n  after_call()\nend\n" },
    Fixture { language: "objc", path: "post.m", function: "post_test", source: "void post_test(void) { do { body_call(); } while (condition()); after_call(); }\n" },
    Fixture { language: "perl", path: "post.pl", function: "post_test", source: "sub post_test { do { body_call(); } while condition(); after_call(); }\n" },
    Fixture { language: "php", path: "post.php", function: "post_test", source: "<?php\nfunction post_test() { do { body_call(); } while (condition()); after_call(); }\n" },
    Fixture { language: "ruby", path: "post.rb", function: "post_test", source: "def post_test\n  begin\n    body_call()\n  end while condition()\n  after_call()\nend\n" },
    Fixture { language: "scala", path: "Post.scala", function: "post_test", source: "object Post { def post_test(): Unit = { do { body_call() } while (condition()); after_call() } }\n" },
    Fixture { language: "swift", path: "post.swift", function: "post_test", source: "func post_test() { repeat { body_call() } while condition(); after_call() }\n" },
    Fixture { language: "typescript", path: "post.ts", function: "post_test", source: "function post_test(): void { do { body_call(); } while (condition()); after_call(); }\n" },
];

const NO_POST_TEST_LOOP: &[(&str, &str)] = &[
    ("elixir", "the language has no post-test loop construct"),
    (
        "erlang",
        "iteration is expressed through recursion/comprehensions, not a post-test loop",
    ),
    ("go", "the language has only the for loop form"),
    ("python", "the language has no post-test loop construct"),
    (
        "rust",
        "the language has while/for/loop but no post-test loop construct",
    ),
];

const UPDATE_FIXTURES: &[Fixture] = &[
    Fixture { language: "c", path: "update.c", function: "update_case", source: "void update_case(void) { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "cpp", path: "update.cpp", function: "update_case", source: "void update_case() { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "csharp", path: "Update.cs", function: "UpdateCase", source: "class Update { static void UpdateCase() { for (InitCall(); Condition(); UpdateCall()) { BodyCall(); continue; DeadAfterContinue(); } AfterCall(); } }\n" },
    Fixture { language: "dart", path: "update.dart", function: "update_case", source: "void update_case() { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "go", path: "update.go", function: "update_case", source: "package phases\nfunc update_case() { for init_call(); condition(); update_call() { body_call(); continue; dead_after_continue() }; after_call() }\n" },
    Fixture { language: "java", path: "Update.java", function: "update_case", source: "class Update { static void update_case() { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); } }\n" },
    Fixture { language: "javascript", path: "update.js", function: "update_case", source: "function update_case() { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "objc", path: "update.m", function: "update_case", source: "void update_case(void) { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "perl", path: "update.pl", function: "update_case", source: "sub update_case { for (init_call(); condition(); update_call()) { body_call(); next; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "php", path: "update.php", function: "update_case", source: "<?php\nfunction update_case() { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
    Fixture { language: "typescript", path: "update.ts", function: "update_case", source: "function update_case(): void { for (init_call(); condition(); update_call()) { body_call(); continue; dead_after_continue(); } after_call(); }\n" },
];

const NO_C_STYLE_UPDATE: &[(&str, &str)] = &[
    ("elixir", "the language has no C-style for loop"),
    ("erlang", "the language has no C-style for loop"),
    ("kotlin", "for iterates values and has no update clause"),
    ("lua", "numeric/generic for loops have no C-style update clause"),
    ("python", "for iterates values and has no update clause"),
    ("ruby", "for iterates values and has no update clause"),
    ("rust", "for iterates values and has no update clause"),
    ("scala", "for comprehensions have no C-style update clause"),
    ("swift", "modern Swift has no C-style for loop"),
];

const CONDITIONLESS_FIXTURES: &[Fixture] = &[
    Fixture {
        language: "c",
        path: "forever.c",
        function: "forever",
        source: "void forever(void) { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "cpp",
        path: "forever.cpp",
        function: "forever",
        source: "void forever() { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "csharp",
        path: "Forever.cs",
        function: "Forever",
        source: "class ForeverCase { static void Forever() { for (;;) { BodyCall(); } AfterCall(); } }\n",
    },
    Fixture {
        language: "dart",
        path: "forever.dart",
        function: "forever",
        source: "void forever() { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "go",
        path: "forever.go",
        function: "forever",
        source: "package phases\nfunc forever() { for { body_call() }; after_call() }\n",
    },
    Fixture {
        language: "java",
        path: "Forever.java",
        function: "forever",
        source: "class Forever { static void forever() { for (;;) { body_call(); } after_call(); } }\n",
    },
    Fixture {
        language: "javascript",
        path: "forever.js",
        function: "forever",
        source: "function forever() { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "objc",
        path: "forever.m",
        function: "forever",
        source: "void forever(void) { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "perl",
        path: "forever.pl",
        function: "forever",
        source: "sub forever { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "php",
        path: "forever.php",
        function: "forever",
        source: "<?php\nfunction forever() { for (;;) { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "rust",
        path: "forever.rs",
        function: "forever",
        source: "fn forever() { loop { body_call(); } after_call(); }\n",
    },
    Fixture {
        language: "typescript",
        path: "forever.ts",
        function: "forever",
        source: "function forever(): void { for (;;) { body_call(); } after_call(); }\n",
    },
];

const NO_CONDITIONLESS_LOOP: &[(&str, &str)] = &[
    (
        "elixir",
        "iteration is expression-oriented and has no conditionless loop syntax",
    ),
    ("erlang", "iteration is expressed through recursion"),
    ("kotlin", "the native loop forms require a condition or iterable"),
    ("lua", "the native loop forms require a condition or iterator"),
    ("python", "the native loop forms require a condition or iterable"),
    ("ruby", "unbounded loop is a library block call, not loop syntax"),
    ("scala", "the native while loop requires a condition"),
    ("swift", "the native loop forms require a condition or iterable"),
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

fn assert_partition(fixtures: &[Fixture], omissions: &[(&str, &str)], family: &str) {
    let covered = fixtures
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered.len(), fixtures.len(), "duplicate {family} fixture");
    let omitted = omissions
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
        "every bundled frontend must be tested or explicitly inapplicable for {family}"
    );
}

fn normalized_call_name(name: &str) -> String {
    name.rsplit(['.', ':', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(String, Span)>) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => out.push((normalized_call_name(name), *span)),
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
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => collect_calls(body, out),
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

fn idg_call_names(decl: &bonsai_lang_api::Decl) -> BTreeSet<String> {
    transfer_function_for(decl)
        .call_sites
        .into_iter()
        .map(|site| normalized_call_name(&site.callee_name))
        .collect()
}

fn first_loop(events: &[FlowEvent]) -> Option<&FlowEvent> {
    for event in events {
        match event {
            loop_event @ FlowEvent::Loop { .. } => return Some(loop_event),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(found) = first_loop(then_events).or_else(|| first_loop(else_events)) {
                    return Some(found);
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(found) = first_loop(body) {
                    return Some(found);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(found) = first_loop(body)
                    .or_else(|| first_loop(catch_events))
                    .or_else(|| first_loop(finally_events))
                {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

fn event_block(cfg: &Cfg, span: Span) -> Option<BasicBlockId> {
    cfg.blocks.iter().find_map(|block| {
        block
            .events
            .iter()
            .any(|event| matches!(event, FlowEvent::Call { span: event_span, .. } if *event_span == span))
            .then_some(block.id)
    })
}

fn path_exists(cfg: &Cfg, from: BasicBlockId, to: BasicBlockId, blocked: Option<BasicBlockId>) -> bool {
    let mut seen = BTreeSet::new();
    let mut pending = vec![from];
    while let Some(current) = pending.pop() {
        if Some(current) == blocked || !seen.insert(current) {
            continue;
        }
        if current == to {
            return true;
        }
        pending.extend(
            cfg.block(current)
                .expect("valid CFG block")
                .successors
                .iter()
                .copied(),
        );
    }
    false
}

#[test]
fn every_post_test_frontend_lowers_condition_body_and_runtime_order() {
    assert_partition(POST_TEST_FIXTURES, NO_POST_TEST_LOOP, "post-test loop");
    let mut failures = BTreeMap::new();
    for fixture in POST_TEST_FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let function = workspace
            .lookup_function(fixture.function)
            .unwrap_or_else(|| panic!("{}: missing function {}", fixture.language, fixture.function));
        let global = workspace.db().global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(function.raw()))
            .unwrap_or_else(|| panic!("{}: missing declaration", fixture.language));
        let Some(FlowEvent::Loop {
            loop_kind,
            condition_events,
            body,
            update_events,
            ..
        }) = first_loop(&decl.flow_events)
        else {
            failures.insert(
                fixture.language,
                format!("no loop event: {:#?}", decl.flow_events),
            );
            continue;
        };
        let mut condition_calls = Vec::new();
        let mut body_calls = Vec::new();
        collect_calls(condition_events, &mut condition_calls);
        collect_calls(body, &mut body_calls);
        let condition_span = condition_calls
            .iter()
            .find_map(|(name, span)| (name == "condition").then_some(*span));
        let body_span = body_calls
            .iter()
            .find_map(|(name, span)| (name == "bodycall").then_some(*span));
        if *loop_kind != LoopKind::DoWhile
            || condition_span.is_none()
            || body_span.is_none()
            || !update_events.is_empty()
        {
            failures.insert(
                fixture.language,
                format!(
                    "kind={loop_kind:?}, condition={condition_calls:?}, body={body_calls:?}, update={update_events:#?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        let idg_calls = idg_call_names(decl);
        if !idg_calls.contains("condition") || !idg_calls.contains("bodycall") {
            failures.insert(
                fixture.language,
                format!("IDG dropped a post-test loop phase: {idg_calls:?}"),
            );
            continue;
        }
        let cfg = workspace.db().cfg(function);
        let condition_block = event_block(&cfg, condition_span.expect("checked"));
        let body_block = event_block(&cfg, body_span.expect("checked"));
        let order_is_post_test = condition_block.zip(body_block).is_some_and(|(condition, body)| {
            path_exists(&cfg, cfg.entry, body, Some(condition)) && path_exists(&cfg, body, condition, None)
        });
        if !order_is_post_test {
            failures.insert(
                fixture.language,
                format!("condition/body CFG order is not post-test: {:#?}", cfg.blocks),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "post-test frontend regressions:\n{failures:#?}"
    );
}

#[test]
fn every_c_style_frontend_runs_update_after_continue_before_condition() {
    assert_partition(UPDATE_FIXTURES, NO_C_STYLE_UPDATE, "C-style loop update");
    let mut failures = BTreeMap::new();
    for fixture in UPDATE_FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let function = workspace
            .lookup_function(fixture.function)
            .unwrap_or_else(|| panic!("{}: missing function {}", fixture.language, fixture.function));
        let global = workspace.db().global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(function.raw()))
            .unwrap_or_else(|| panic!("{}: missing declaration", fixture.language));
        let Some(FlowEvent::Loop {
            loop_kind,
            condition_events,
            body,
            update_events,
            ..
        }) = first_loop(&decl.flow_events)
        else {
            failures.insert(
                fixture.language,
                format!("no loop event: {:#?}", decl.flow_events),
            );
            continue;
        };
        let mut condition_calls = Vec::new();
        let mut body_calls = Vec::new();
        let mut update_calls = Vec::new();
        collect_calls(condition_events, &mut condition_calls);
        collect_calls(body, &mut body_calls);
        collect_calls(update_events, &mut update_calls);
        let span_for = |calls: &[(String, Span)], name: &str| {
            calls
                .iter()
                .find_map(|(candidate, span)| (candidate == name).then_some(*span))
        };
        let condition_span = span_for(&condition_calls, "condition");
        let body_span = span_for(&body_calls, "bodycall");
        let update_span = span_for(&update_calls, "updatecall");
        let dead_span = span_for(&body_calls, "deadaftercontinue");
        let mut root_calls = Vec::new();
        collect_calls(&decl.flow_events, &mut root_calls);
        let after_span = span_for(&root_calls, "aftercall");
        if *loop_kind != LoopKind::For
            || condition_span.is_none()
            || body_span.is_none()
            || update_span.is_none()
            || dead_span.is_none()
            || after_span.is_none()
        {
            failures.insert(
                fixture.language,
                format!(
                    "kind={loop_kind:?}, condition={condition_calls:?}, body={body_calls:?}, update={update_calls:?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        let idg_calls = idg_call_names(decl);
        if !["condition", "bodycall", "updatecall"]
            .into_iter()
            .all(|name| idg_calls.contains(name))
            || idg_calls.contains("deadaftercontinue")
        {
            failures.insert(
                fixture.language,
                format!("IDG loop phase/continue facts are wrong: {idg_calls:?}"),
            );
            continue;
        }
        let cfg = workspace.db().cfg(function);
        let blocks = (
            event_block(&cfg, condition_span.expect("checked")),
            event_block(&cfg, body_span.expect("checked")),
            event_block(&cfg, update_span.expect("checked")),
            event_block(&cfg, dead_span.expect("checked")),
            event_block(&cfg, after_span.expect("checked")),
        );
        let correct = if let (Some(condition), Some(body), Some(update), Some(dead), Some(after)) = blocks {
            path_exists(&cfg, cfg.entry, condition, None)
                && path_exists(&cfg, condition, body, None)
                && path_exists(&cfg, body, update, None)
                && path_exists(&cfg, update, condition, None)
                && !path_exists(&cfg, cfg.entry, dead, None)
                && path_exists(&cfg, cfg.entry, after, None)
        } else {
            false
        };
        if !correct {
            failures.insert(
                fixture.language,
                format!("condition/body/update CFG order is wrong: {:#?}", cfg.blocks),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "C-style loop update regressions:\n{failures:#?}"
    );
}

#[test]
fn every_conditionless_frontend_has_no_implicit_false_exit() {
    assert_partition(
        CONDITIONLESS_FIXTURES,
        NO_CONDITIONLESS_LOOP,
        "conditionless loop",
    );
    let mut failures = BTreeMap::new();
    for fixture in CONDITIONLESS_FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let function = workspace
            .lookup_function(fixture.function)
            .unwrap_or_else(|| panic!("{}: missing function {}", fixture.language, fixture.function));
        let global = workspace.db().global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(function.raw()))
            .unwrap_or_else(|| panic!("{}: missing declaration", fixture.language));
        let Some(FlowEvent::Loop {
            loop_kind,
            condition_events,
            update_events,
            body,
            ..
        }) = first_loop(&decl.flow_events)
        else {
            failures.insert(
                fixture.language,
                format!("no loop event: {:#?}", decl.flow_events),
            );
            continue;
        };
        let mut body_calls = Vec::new();
        let mut all_calls = Vec::new();
        collect_calls(body, &mut body_calls);
        collect_calls(&decl.flow_events, &mut all_calls);
        let body_span = body_calls
            .iter()
            .find_map(|(name, span)| (name == "bodycall").then_some(*span));
        let after_span = all_calls
            .iter()
            .find_map(|(name, span)| (name == "aftercall").then_some(*span));
        if *loop_kind != LoopKind::Loop
            || !condition_events.is_empty()
            || !update_events.is_empty()
            || body_span.is_none()
            || after_span.is_none()
        {
            failures.insert(
                fixture.language,
                format!("conditionless loop lowered incorrectly: {:#?}", decl.flow_events),
            );
            continue;
        }
        let idg_calls = idg_call_names(decl);
        if !idg_calls.contains("bodycall") || idg_calls.contains("aftercall") {
            failures.insert(
                fixture.language,
                format!("IDG invented a conditionless-loop exit: {idg_calls:?}"),
            );
            continue;
        }
        let cfg = workspace.db().cfg(function);
        let body_block = event_block(&cfg, body_span.expect("checked"));
        let after_block = event_block(&cfg, after_span.expect("checked"));
        let correct = body_block.zip(after_block).is_some_and(|(body, after)| {
            path_exists(&cfg, cfg.entry, body, None) && !path_exists(&cfg, cfg.entry, after, None)
        });
        if !correct {
            failures.insert(
                fixture.language,
                format!("conditionless loop has an implicit false exit: {:#?}", cfg.blocks),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "conditionless loop regressions:\n{failures:#?}"
    );
}
