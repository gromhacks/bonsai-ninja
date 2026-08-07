//! OT_03 — second-tainted-arg → first-arg backflow.
//!
//! Negative: when the second positional argument receives taint, the
//! first must not. Locks the boundary between args at a single call
//! site so over-taint can't bridge `sink('safe', tainted)` into
//! `sink(tainted, 'safe')`.
//!
//! All 20 languages. Migrated from `over_taint_matrix.rs::
//! over_taint_all_languages_second_tainted_arg_does_not_taint_first_arg`.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_index, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

/// OT_03 has a stronger contract than the generic `run_negative_cell`:
/// it asserts arg-index-1 IS tainted (so the negative arg-0 assertion
/// is meaningful) and arg-index-0 is NOT tainted.
fn run_ot_03(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "OT_03"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_03/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        sink_received_arg_index(&result, fixture.sink, 1),
        "[OT_03/{}] arg 1 of `{}` must be tainted so the negative arg-0 assertion is meaningful; got {:?}",
        fixture.lang,
        fixture.sink,
        result.tainted_calls,
    );
    assert!(
        !sink_received_arg_index(&result, fixture.sink, 0),
        "[OT_03/{}] arg 0 of `{}` must stay clean; got {:?}",
        fixture.lang,
        fixture.sink,
        result.tainted_calls,
    );
}

#[test]
fn ot_03_python() {
    run_ot_03(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[("a.py", "def entry(args):\n    sink('safe', args)\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_javascript() {
    run_ot_03(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[("a.js", "function entry(args) { sink('safe', args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_typescript() {
    run_ot_03(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function entry(args: string) { sink('safe', args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_java() {
    run_ot_03(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[(
            "Demo.java",
            "class Demo { void entry(String args) { sink(\"safe\", args); } }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_kotlin() {
    run_ot_03(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "fun entry(args: String) { sink(\"safe\", args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_scala() {
    run_ot_03(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[(
            "a.scala",
            "object Demo { def entry(args: String): Unit = { sink(\"safe\", args) } }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_csharp() {
    run_ot_03(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[(
            "Demo.cs",
            "class Demo { void Entry(string args) { Sink(\"safe\", args); } }\n",
        )],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn ot_03_go() {
    run_ot_03(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[(
            "a.go",
            "package main\nfunc entry(args string) { sink(\"safe\", args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_rust() {
    run_ot_03(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "fn entry(args: String) { sink(\"safe\", args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_c() {
    run_ot_03(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "void entry(char *args) { sink(\"safe\", args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_cpp() {
    run_ot_03(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[(
            "a.cpp",
            "void entry(const char *args) { sink(\"safe\", args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_objc() {
    run_ot_03(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "void entry(NSString *args) { sink(@\"safe\", args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_ruby() {
    run_ot_03(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[("a.rb", "def entry(args)\n  sink('safe', args)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_php() {
    run_ot_03(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nfunction entry($args) { sink('safe', $args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_perl() {
    run_ot_03(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub entry { my ($args) = @_; sink('safe', $args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_swift() {
    run_ot_03(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func entry(args: String) { sink(\"safe\", args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_dart() {
    run_ot_03(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "void entry(String args) { sink('safe', args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_lua() {
    run_ot_03(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function entry(args)\n  sink('safe', args)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_elixir() {
    run_ot_03(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[(
            "a.ex",
            "defmodule Demo do\n  def entry(args) do\n    sink(\"safe\", args)\n  end\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_03_erlang() {
    run_ot_03(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[(
            "demo.erl",
            "-module(demo).\n-export([entry/1]).\nentry(Args) -> sink(\"safe\", Args).\n",
        )],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}
