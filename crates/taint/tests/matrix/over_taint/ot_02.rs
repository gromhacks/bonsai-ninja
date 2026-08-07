//! OT_02 — Literal containing seed name stays clean.
//!
//! Negative: `x = "user_data"; sink(x)` with seed `user`. The string
//! literal happens to contain the substring "user" but that does NOT
//! make the binding tainted. Locks the engine's "no token-substring
//! promotion" mitigation.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_text, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_02(fixture: LangFixture, sink_arg: &str) {
    if matches!(
        status(fixture.lang, "OT_02"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_02/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, fixture.sink, sink_arg),
        "[OT_02/{}] literal containing seed substring must not taint binding; got {:?}",
        fixture.lang,
        result.tainted_calls,
    );
}

#[test]
fn ot_02_python() {
    run_ot_02(
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[("a.py", "def entry(user):\n    x = 'user_data'\n    sink(x)\n")],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_javascript() {
    run_ot_02(
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[("a.js", "function entry(user) { let x = 'user_data'; sink(x); }\n")],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_typescript() {
    run_ot_02(
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(user: string) { let x = 'user_data'; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_java() {
    run_ot_02(
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String user) { String x = \"user_data\"; sink(x); } }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_kotlin() {
    run_ot_02(
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(user: String) { val x = \"user_data\"; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_scala() {
    run_ot_02(
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(user: String): Unit = { val x = \"user_data\"; sink(x) } }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_csharp() {
    run_ot_02(
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string user) { var x = \"user_data\"; Sink(x); } }\n",
            )],
            entry: "Entry",
            seed: &["user"],
            sink: "Sink",
        },
        "x",
    );
}

#[test]
fn ot_02_go() {
    run_ot_02(
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(user string) { x := \"user_data\"; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_rust() {
    run_ot_02(
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(user: String) { let x = String::from(\"user_data\"); sink(x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_c() {
    run_ot_02(
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "void entry(char *user) { char *x = \"user_data\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_cpp() {
    run_ot_02(
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *user) { const char *x = \"user_data\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_objc() {
    run_ot_02(
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[(
                "a.m",
                "void entry(NSString *user) { NSString *x = @\"user_data\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_ruby() {
    run_ot_02(
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[("a.rb", "def entry(user)\n  x = 'user_data'\n  sink(x)\nend\n")],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_php() {
    run_ot_02(
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($user) { $x = 'user_data'; sink($x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "$x",
    );
}

#[test]
fn ot_02_perl() {
    run_ot_02(
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($user) = @_; my $x = 'user_data'; sink($x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "$x",
    );
}

#[test]
fn ot_02_swift() {
    run_ot_02(
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(user: String) { let x = \"user_data\"; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_dart() {
    run_ot_02(
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String user) { var x = 'user_data'; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_lua() {
    run_ot_02(
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(user)\n  local x = 'user_data'\n  sink(x)\nend\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_elixir() {
    run_ot_02(
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[(
                "a.ex",
                "defmodule Demo do\n  def entry(user) do\n    x = \"user_data\"\n    sink(x)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["user"],
            sink: "sink",
        },
        "x",
    );
}

#[test]
fn ot_02_erlang() {
    run_ot_02(
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[(
                "demo.erl",
                "-module(demo).\n-export([entry/1]).\nentry(User) -> X = \"user_data\", sink(X).\n",
            )],
            entry: "entry",
            seed: &["User"],
            sink: "sink",
        },
        "X",
    );
}
