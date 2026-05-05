//! OT_07 — Clean overwrite before sink clears taint.
//!
//! Negative: `x = source; if cond: x = clean1 else: x = clean2; sink(x)`.
//! Both branches assign clean, so the merged state must reach the sink
//! clean. Locks the engine's branch-merge clean-overwrite mitigation.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_text, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_07(fixture: LangFixture, sink_arg: &str) {
    if matches!(
        status(fixture.lang, "OT_07"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_07/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, fixture.sink, sink_arg),
        "[OT_07/{}] clean-overwrite in both branches must clear taint at sink `{}({})`; got {:?}",
        fixture.lang,
        fixture.sink,
        sink_arg,
        result.tainted_calls,
    );
}

#[test]
fn ot_07_python() {
    run_ot_07(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[("a.py", "def entry(args):\n    x = args\n    if cond():\n        x = 'clean1'\n    else:\n        x = 'clean2'\n    sink(x)\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_javascript() {
    run_ot_07(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[("a.js", "function entry(args) { let x = args; if (cond()) { x = 'clean1'; } else { x = 'clean2'; } sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_typescript() {
    run_ot_07(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function entry(args: string) { let x = args; if (cond()) { x = 'clean1'; } else { x = 'clean2'; } sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_java() {
    run_ot_07(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Demo { boolean cond() { return true; } void entry(String args) { String x = args; if (cond()) { x = \"clean1\"; } else { x = \"clean2\"; } sink(x); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_kotlin() {
    run_ot_07(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "fun cond(): Boolean = true\nfun entry(args: String) { var x = args; if (cond()) { x = \"clean1\" } else { x = \"clean2\" }; sink(x) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_scala() {
    run_ot_07(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def cond(): Boolean = true; def entry(args: String): Unit = { var x = args; if (cond()) { x = \"clean1\" } else { x = \"clean2\" }; sink(x) } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_csharp() {
    run_ot_07(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Demo { bool Cond() => true; void Entry(string args) { var x = args; if (Cond()) { x = \"clean1\"; } else { x = \"clean2\"; } Sink(x); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    }, "x");
}

#[test]
fn ot_07_go() {
    run_ot_07(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\nfunc cond() bool { return true }\nfunc entry(args string) { x := args; if cond() { x = \"clean1\" } else { x = \"clean2\" }; sink(x) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_rust() {
    run_ot_07(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "fn cond() -> bool { true }\nfn entry(args: String) { let mut x = args; if cond() { x = String::from(\"clean1\"); } else { x = String::from(\"clean2\"); } sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_c() {
    run_ot_07(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "int cond(void);\nvoid entry(char *args) { char *x = args; if (cond()) x = \"clean1\"; else x = \"clean2\"; sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_cpp() {
    run_ot_07(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "bool cond();\nvoid entry(const char *args) { const char *x = args; if (cond()) x = \"clean1\"; else x = \"clean2\"; sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_objc() {
    run_ot_07(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "BOOL cond(void);\nvoid entry(NSString *args) { NSString *x = args; if (cond()) x = @\"clean1\"; else x = @\"clean2\"; sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_ruby() {
    run_ot_07(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[("a.rb", "def cond; true; end\ndef entry(args)\n  x = args\n  if cond()\n    x = 'clean1'\n  else\n    x = 'clean2'\n  end\n  sink(x)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_php() {
    run_ot_07(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nfunction cond() { return true; }\nfunction entry($args) { $x = $args; if (cond()) { $x = 'clean1'; } else { $x = 'clean2'; } sink($x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "$x");
}

#[test]
fn ot_07_perl() {
    run_ot_07(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub cond { 1 }\nsub entry { my ($args) = @_; my $x = $args; if (cond()) { $x = 'clean1'; } else { $x = 'clean2'; } sink($x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "$x");
}

#[test]
fn ot_07_swift() {
    run_ot_07(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func cond() -> Bool { return true }\nfunc entry(args: String) { var x = args; if cond() { x = \"clean1\" } else { x = \"clean2\" }; sink(x) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_dart() {
    run_ot_07(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "bool cond() => true;\nvoid entry(String args) { var x = args; if (cond()) { x = 'clean1'; } else { x = 'clean2'; } sink(x); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_lua() {
    run_ot_07(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function cond() return true end\nfunction entry(args)\n  local x = args\n  if cond() then x = 'clean1' else x = 'clean2' end\n  sink(x)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_elixir() {
    run_ot_07(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def cond_(), do: true\n  def entry(args) do\n    x = args\n    x = if cond_() do \"clean1\" else \"clean2\" end\n    sink(x)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}

#[test]
fn ot_07_erlang() {
    run_ot_07(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1]).\nentry(Args) -> X = Args, X2 = case cond() of true -> \"clean1\"; _ -> \"clean2\" end, sink(X2).\ncond() -> true.\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    }, "X2");
}

#[test]
fn ot_07_solidity() {
    run_ot_07(LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[("Demo.sol", "contract Demo { function cond() internal pure returns (bool) { return true; } function entry(string memory args) public { string memory x = args; if (cond()) { x = \"clean1\"; } else { x = \"clean2\"; } sink(x); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "x");
}
