//! OT_12 — Unknown call doesn't taint independent later sink.
//!
//! Negative: `unknown_lib_func(args)` is a black-box call that
//! receives tainted input. After it, an independent local `cap = 32`
//! is sinked. The unknown call must NOT pollute the independent
//! local — otherwise every program that passes a tainted value to
//! ANY library function would over-taint the rest of the program.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_text, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_12(fixture: LangFixture, sink_arg: &str) {
    if matches!(
        status(fixture.lang, "OT_12"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_12/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, fixture.sink, sink_arg),
        "[OT_12/{}] unknown call must not taint independent later sink `{}({})`; got {:?}",
        fixture.lang,
        fixture.sink,
        sink_arg,
        result.tainted_calls,
    );
}

#[test]
fn ot_12_python() {
    run_ot_12(
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    unknown_lib_func(args)\n    cap = 32\n    sink(cap)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_javascript() {
    run_ot_12(
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { unknownLibFunc(args); let cap = 32; sink(cap); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_typescript() {
    run_ot_12(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "declare function unknownLibFunc(p: string): void;\nfunction entry(args: string) { unknownLibFunc(args); let cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_java() {
    run_ot_12(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Demo { void entry(String args) { Lib.unknownFunc(args); int cap = 32; sink(cap); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_kotlin() {
    run_ot_12(
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { unknownLibFunc(args); val cap = 32; sink(cap) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_scala() {
    run_ot_12(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def entry(args: String): Unit = { unknownLibFunc(args); val cap = 32; sink(cap) } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_csharp() {
    run_ot_12(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Demo { void Entry(string args) { Lib.UnknownFunc(args); int cap = 32; Sink(cap); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    }, "cap");
}

#[test]
fn ot_12_go() {
    run_ot_12(
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { unknownLibFunc(args); cap := 32; sink(cap) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_rust() {
    run_ot_12(
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { unknown_lib_func(args); let cap = 32; sink(cap); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_c() {
    run_ot_12(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "extern void unknown_lib_func(char *p);\nvoid entry(char *args) { unknown_lib_func(args); int cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_cpp() {
    run_ot_12(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "extern void unknownLibFunc(const char *p);\nvoid entry(const char *args) { unknownLibFunc(args); int cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_objc() {
    run_ot_12(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "extern void unknownLibFunc(NSString *p);\nvoid entry(NSString *args) { unknownLibFunc(args); int cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_ruby() {
    run_ot_12(
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  unknown_lib_func(args)\n  cap = 32\n  sink(cap)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_php() {
    run_ot_12(
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { unknown_lib_func($args); $cap = 32; sink($cap); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "$cap",
    );
}

#[test]
fn ot_12_perl() {
    run_ot_12(
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; unknown_lib_func($args); my $cap = 32; sink($cap); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "$cap",
    );
}

#[test]
fn ot_12_swift() {
    run_ot_12(
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { unknownLibFunc(args); let cap = 32; sink(cap) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_dart() {
    run_ot_12(
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { unknownLibFunc(args); var cap = 32; sink(cap); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_lua() {
    run_ot_12(
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  unknown_lib_func(args)\n  local cap = 32\n  sink(cap)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        "cap",
    );
}

#[test]
fn ot_12_elixir() {
    run_ot_12(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    SomeLib.unknown(args)\n    cap = 32\n    sink(cap)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, "cap");
}

#[test]
fn ot_12_erlang() {
    run_ot_12(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1]).\nentry(Args) -> some_lib:unknown(Args), Cap = 32, sink(Cap).\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    }, "Cap");
}
