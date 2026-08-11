//! Cross-language literal/place ownership contract.
//!
//! Every adapter must classify its own Tree-sitter literal nodes. Shared
//! lowering must not carry a union of source-language tokens or infer value
//! meaning from spelling.

use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
use std::sync::Arc;

fn fixture(language: &str) -> (&'static str, &'static str) {
    match language {
        "c" => (
            "value.c",
            "void probe(int, char*, const char*, int); void f(char *value) { probe(false, value, \"marker\", 7); }",
        ),
        "cpp" => (
            "value.cpp",
            "void probe(bool, const char*, const char*, int); void f(const char *value) { probe(false, value, \"marker\", 7); }",
        ),
        "csharp" => (
            "Value.cs",
            "class Value { void F(string value) { Probe(false, value, \"marker\", 7); } }",
        ),
        "dart" => (
            "value.dart",
            "void f(String value) { probe(false, value, \"marker\", 7); }",
        ),
        "elixir" => (
            "value.ex",
            "defmodule Value do\n  def f(value), do: probe(false, value, \"marker\", 7)\nend\n",
        ),
        "erlang" => ("value.erl", "-module(value).\n-export([f/1]).\nf(Value) -> probe(false, Value, \"marker\", 7).\n"),
        "go" => (
            "value.go",
            "package value\nfunc f(value string) { probe(false, value, \"marker\", 7) }\n",
        ),
        "java" => (
            "Value.java",
            "class Value { void f(String value) { probe(false, value, \"marker\", 7); } }",
        ),
        "javascript" => (
            "value.js",
            "function f(value) { probe(false, value, \"marker\", 7); }",
        ),
        "kotlin" => (
            "Value.kt",
            "fun f(value: String) { probe(false, value, \"marker\", 7) }",
        ),
        "lua" => (
            "value.lua",
            "function f(value) probe(false, value, \"marker\", 7) end",
        ),
        "objc" => (
            "value.m",
            "void probe(bool, NSString*, const char*, int); void f(NSString *value) { probe(false, value, \"marker\", 7); }",
        ),
        "perl" => (
            "Value.pm",
            // Core Perl has no `false` keyword; a bare `false` is a callable
            // or bareword depending on the active pragmas.  Zero is the
            // language's exact false scalar literal.
            "sub f { my ($value) = @_; probe(0, $value, \"marker\", 7); }",
        ),
        "php" => (
            "value.php",
            "<?php function f($value) { probe(false, $value, \"marker\", 7); }",
        ),
        "python" => (
            "value.py",
            "def f(value):\n    probe(False, value, \"marker\", 7)\n",
        ),
        "ruby" => (
            "value.rb",
            "def f(value)\n  probe(false, value, \"marker\", 7)\nend\n",
        ),
        "rust" => (
            "value.rs",
            "fn f(value: String) { probe(false, value, \"marker\", 7); }",
        ),
        "scala" => (
            "Value.scala",
            "object Value { def f(value: String): Unit = probe(false, value, \"marker\", 7) }",
        ),
        "swift" => (
            "Value.swift",
            "func f(_ value: String) { probe(false, value, \"marker\", 7) }",
        ),
        "typescript" => (
            "value.ts",
            "function f(value: string): void { probe(false, value, \"marker\", 7); }",
        ),
        other => panic!("missing literal fixture for {other}"),
    }
}

fn find_probe(events: &[FlowEvent]) -> Option<(bonsai_common::Span, &[bonsai_lang_api::CallArg])> {
    for event in events {
        match event {
            FlowEvent::Call { span, name, args, .. }
                if bonsai_common::short_qualified_tail(name) == "probe" || name == "Probe" =>
            {
                return Some((*span, args));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(call) = find_probe(then_events).or_else(|| find_probe(else_events)) {
                    return Some(call);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(call) = find_probe(body) {
                    return Some(call);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(call) = find_probe(body)
                    .or_else(|| find_probe(catch_events))
                    .or_else(|| find_probe(finally_events))
                {
                    return Some(call);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn every_adapter_distinguishes_literal_from_dynamic_argument() {
    let adapters: Vec<Arc<dyn LanguageAdapter>> = bonsai_adapters::all_adapters();
    assert_eq!(adapters.len(), 20, "fixture must cover every bundled adapter");

    for adapter in adapters {
        let language = adapter.language_id();
        let (path, fixture_source) = fixture(language.as_str());
        let source = if language.as_str() == "php" {
            fixture_source.replacen("<?php", "<?php // bonsai-comment-marker\n", 1)
        } else {
            let prefix = match language.as_str() {
                "elixir" | "perl" | "python" | "ruby" => "#",
                "erlang" => "%",
                "lua" => "--",
                _ => "//",
            };
            format!("{prefix} bonsai-comment-marker\n{fixture_source}")
        };
        let vfs = bonsai_vfs::Vfs::new();
        let file = vfs.write(std::path::Path::new(path), source.as_str());
        let diagnostics = parking_lot::RwLock::new(bonsai_diagnostics::DiagnosticSink::default());
        let index = adapter.extract_declarations(
            file,
            &AdapterContext {
                vfs: &vfs,
                diagnostics: &diagnostics,
                tree_provider: None,
                workspace_root: None,
            },
        );
        let (call_span, args) = index
            .defs
            .iter()
            .find_map(|decl| find_probe(&decl.flow_events))
            .unwrap_or_else(|| panic!("{}: probe call missing", language.as_str()));
        assert_eq!(args.len(), 4, "{}: probe args", language.as_str());
        assert!(
            args[0].place.is_none() && args[0].source_names.is_empty(),
            "{}: false literal became a value place: {:?}",
            language.as_str(),
            args[0]
        );
        assert!(
            args[1].place.is_some() || !args[1].source_names.is_empty(),
            "{}: dynamic parameter lost its value identity: {:?}",
            language.as_str(),
            args[1]
        );
        assert!(
            args[2].place.is_none() && args[2].source_names.is_empty(),
            "{}: string literal became a value place: {:?}",
            language.as_str(),
            args[2]
        );
        assert!(
            args[3].place.is_none() && args[3].source_names.is_empty(),
            "{}: numeric literal became a value place: {:?}",
            language.as_str(),
            args[3]
        );
        for index_value in [0_usize, 2, 3] {
            let fact = bonsai_lang_api::call_argument_value_fact(
                &index.call_argument_values,
                call_span,
                index_value,
            )
            .unwrap_or_else(|| {
                panic!(
                    "{}: literal argument {index_value} has no compiler value fact",
                    language.as_str()
                )
            });
            assert_eq!(
                fact.value_kind,
                Some(bonsai_lang_api::AssignValueKind::Literal),
                "{}: literal argument {index_value} lacks AST literal classification: {fact:?}",
                language.as_str()
            );
        }
        assert_ne!(
            bonsai_lang_api::call_argument_value_fact(&index.call_argument_values, call_span, 1)
                .and_then(|fact| fact.value_kind),
            Some(bonsai_lang_api::AssignValueKind::Literal),
            "{}: dynamic argument classified as a literal",
            language.as_str()
        );
        assert!(
            index
                .strings
                .iter()
                .any(|literal| literal.text.contains("marker")),
            "{}: adapter string inventory missed its parsed literal: {:?}",
            language.as_str(),
            index.strings
        );
        assert!(
            index
                .comments
                .iter()
                .any(|comment| comment.text.contains("bonsai-comment-marker")),
            "{}: adapter comment inventory missed its parsed comment: {:?}",
            language.as_str(),
            index.comments
        );
    }
}
