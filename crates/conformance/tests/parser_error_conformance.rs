//! Parser failure reporting for every bundled grammar.
//!
//! Valid-fixture conformance proves the happy path. These deliberately broken
//! inputs prove the opposite contract: Tree-sitter damage must be visible as
//! exact diagnostics and must never be silently treated as complete code.

use bonsai_lang_api::LanguageAdapter;
use std::collections::BTreeSet;
use std::sync::Arc;

struct BrokenFixture {
    language: &'static str,
    path: &'static str,
    source: &'static str,
}

const FIXTURES: &[BrokenFixture] = &[
    BrokenFixture {
        language: "c",
        path: "broken.c",
        source: "void broken( { if (value {\n",
    },
    BrokenFixture {
        language: "cpp",
        path: "broken.cpp",
        source: "void broken( { if (value {\n",
    },
    BrokenFixture {
        language: "csharp",
        path: "Broken.cs",
        source: "class Broken { void Method( { if (value {\n",
    },
    BrokenFixture {
        language: "dart",
        path: "broken.dart",
        source: "void broken( { if (value {\n",
    },
    BrokenFixture {
        language: "elixir",
        path: "broken.ex",
        source: "defmodule Broken do\n  def broken( do\n    if (\n",
    },
    BrokenFixture {
        language: "erlang",
        path: "broken.erl",
        source: "-module(broken).\nbroken( -> case of .\n",
    },
    BrokenFixture {
        language: "go",
        path: "broken.go",
        source: "package broken\nfunc broken( { if value {\n",
    },
    BrokenFixture {
        language: "java",
        path: "Broken.java",
        source: "class Broken { void method( { if (value {\n",
    },
    BrokenFixture {
        language: "javascript",
        path: "broken.js",
        source: "function broken( { if (value {\n",
    },
    BrokenFixture {
        language: "kotlin",
        path: "broken.kt",
        source: "fun broken( { if (value {\n",
    },
    BrokenFixture {
        language: "lua",
        path: "broken.lua",
        source: "local function broken(\n  if then\n",
    },
    BrokenFixture {
        language: "objc",
        path: "broken.m",
        source: "void broken( { @try { if (value {\n",
    },
    BrokenFixture {
        language: "perl",
        path: "broken.pl",
        source: "sub broken { if ( { call( ;\n",
    },
    BrokenFixture {
        language: "php",
        path: "broken.php",
        source: "<?php function broken( { if ($value {\n",
    },
    BrokenFixture {
        language: "python",
        path: "broken.py",
        source: "def broken(:\n    if (\n",
    },
    BrokenFixture {
        language: "ruby",
        path: "broken.rb",
        source: "def broken(\n  if then\n",
    },
    BrokenFixture {
        language: "rust",
        path: "broken.rs",
        source: "fn broken( { if value {\n",
    },
    BrokenFixture {
        language: "scala",
        path: "Broken.scala",
        source: "object Broken { def method( = if ( {\n",
    },
    BrokenFixture {
        language: "swift",
        path: "broken.swift",
        source: "func broken( { if value {\n",
    },
    BrokenFixture {
        language: "typescript",
        path: "broken.ts",
        source: "function broken(: string { if (value {\n",
    },
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

#[test]
fn every_language_reports_malformed_syntax_as_incomplete() {
    let bundled: BTreeSet<String> = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect();
    let covered: BTreeSet<String> = FIXTURES
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect();
    assert_eq!(
        covered, bundled,
        "broken-syntax fixtures must cover every bundled grammar"
    );
    assert_eq!(covered.len(), FIXTURES.len(), "duplicate broken-syntax fixture");

    let mut failures = Vec::new();
    for fixture in FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        let file = workspace.vfs().all_files()[0];
        let parsed = workspace
            .db()
            .parse(file)
            .expect("damaged syntax still returns a recovery tree");
        if !parsed.tree.root_node().has_error() {
            failures.push(format!(
                "{}: malformed fixture produced an error-free tree",
                fixture.language
            ));
            continue;
        }
        if parsed.diagnostics.is_empty() {
            failures.push(format!(
                "{}: malformed fixture produced no diagnostics",
                fixture.language
            ));
            continue;
        }
        for diagnostic in &parsed.diagnostics {
            if diagnostic.span.file != file
                || diagnostic.span.start > diagnostic.span.end
                || diagnostic.span.end > fixture.source.len() as u64
            {
                failures.push(format!(
                    "{}: invalid diagnostic span {:?}",
                    fixture.language, diagnostic.span
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "parser error conformance failures:\n{}",
        failures.join("\n")
    );
}
