//! R_18 — Default argument value stays clean.
#![allow(unreachable_pub)]
use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_reached, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_r_18(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "R_18"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry).expect("entry indexes");
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_reached(&result, fixture.sink),
        "[R_18/{}] default arg call must not propagate seed; got {:?}",
        fixture.lang,
        result.tainted_calls
    );
}

#[test]
fn r_18_python() {
    run_r_18(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[(
            "a.py",
            "def helper(p='ok'):\n    sink(p)\n\ndef entry(args):\n    helper()\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_javascript() {
    run_r_18(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[(
            "a.js",
            "function helper(p = 'ok') { sink(p); }\nfunction entry(args) { helper(); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_typescript() {
    run_r_18(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[(
            "a.ts",
            "function helper(p: string = 'ok') { sink(p); }\nfunction entry(args: string) { helper(); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_kotlin() {
    run_r_18(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[(
            "a.kt",
            "fun helper(p: String = \"ok\") { sink(p) }\nfun entry(args: String) { helper() }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_scala() {
    run_r_18(LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def helper(p: String = \"ok\"): Unit = sink(p); def entry(args: String): Unit = helper() }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_18_csharp() {
    run_r_18(LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Helper(string p = \"ok\") { Sink(p); } void Entry(string args) { Helper(); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_18_swift() {
    run_r_18(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[(
            "a.swift",
            "func helper(p: String = \"ok\") { sink(p) }\nfunc entry(args: String) { helper() }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_dart() {
    run_r_18(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[(
            "a.dart",
            "void helper([String p = 'ok']) { sink(p); }\nvoid entry(String args) { helper(); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_php() {
    run_r_18(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[(
            "a.php",
            "<?php\nfunction helper($p = 'ok') { sink($p); }\nfunction entry($args) { helper(); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_ruby() {
    run_r_18(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[(
            "a.rb",
            "def helper(p = 'ok')\n  sink(p)\nend\ndef entry(args)\n  helper\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_lua() {
    run_r_18(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[(
            "a.lua",
            "function helper(p)\n  p = p or 'ok'\n  sink(p)\nend\nfunction entry(args)\n  helper()\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_18_perl() {
    run_r_18(LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub helper { my ($p) = @_; $p = 'ok' unless defined $p; sink($p); }\nsub entry { my ($args) = @_; helper(); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_18_elixir() {
    run_r_18(LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def helper(p \\\\ \"ok\") do\n    sink(p)\n  end\n  def entry(args) do\n    helper()\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
