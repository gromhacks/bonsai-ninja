//! OT_15 — Constant int/bool args don't promote to taint.
//!
//! Negative: `helper(args, 0)` where the helper sinks its second
//! arg as an int. The constant `0` must not become tainted just
//! because it shares a call site with a tainted arg.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_index, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_15(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "OT_15"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_15/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    // arg 0 (the int constant) MUST stay clean
    assert!(
        !sink_received_arg_index(&result, fixture.sink, 0),
        "[OT_15/{}] sink `{}` arg 0 (constant) MUST stay clean; got {:?}",
        fixture.lang,
        fixture.sink,
        result.tainted_calls,
    );
}

#[test]
fn ot_15_python() {
    run_ot_15(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[("a.py", "def entry(args):\n    sink(0, args)\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_javascript() {
    run_ot_15(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[("a.js", "function entry(args) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_typescript() {
    run_ot_15(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function entry(args: string) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_java() {
    run_ot_15(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[(
            "Demo.java",
            "class Demo { void entry(String args) { sink(0, args); } }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_kotlin() {
    run_ot_15(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "fun entry(args: String) { sink(0, args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_scala() {
    run_ot_15(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[(
            "a.scala",
            "object Demo { def entry(args: String): Unit = sink(0, args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_csharp() {
    run_ot_15(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[(
            "Demo.cs",
            "class Demo { void Entry(string args) { Sink(0, args); } }\n",
        )],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn ot_15_go() {
    run_ot_15(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[(
            "a.go",
            "package main\nfunc entry(args string) { sink(0, args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_rust() {
    run_ot_15(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "fn entry(args: String) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_c() {
    run_ot_15(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "void entry(char *args) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_cpp() {
    run_ot_15(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "void entry(const char *args) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_objc() {
    run_ot_15(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "void entry(NSString *args) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_ruby() {
    run_ot_15(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[("a.rb", "def entry(args)\n  sink(0, args)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_php() {
    run_ot_15(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nfunction entry($args) { sink(0, $args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_perl() {
    run_ot_15(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub entry { my ($args) = @_; sink(0, $args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_swift() {
    run_ot_15(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func entry(args: String) { sink(0, args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_dart() {
    run_ot_15(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "void entry(String args) { sink(0, args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_lua() {
    run_ot_15(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function entry(args)\n  sink(0, args)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_elixir() {
    run_ot_15(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[(
            "a.ex",
            "defmodule Demo do\n  def entry(args) do\n    sink(0, args)\n  end\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_erlang() {
    run_ot_15(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[(
            "demo.erl",
            "-module(demo).\n-export([entry/1]).\nentry(Args) -> sink(0, Args).\n",
        )],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}

#[test]
fn ot_15_solidity() {
    run_ot_15(LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[(
            "Demo.sol",
            "contract Demo { function entry(string memory args) public { sink(0, args); } }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
