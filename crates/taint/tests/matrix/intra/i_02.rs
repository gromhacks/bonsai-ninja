//! I_02 — Clean reassignment overwrites taint.
//!
//! Negative: `x = source; x = "clean"; sink(x)` — sink must NOT
//! receive taint because the second assignment overwrote the binding
//! with a clean literal. Locks the engine's clean-overwrite mitigation.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_text, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_i_02(fixture: LangFixture, sink_args: &[&str]) {
    if matches!(
        status(fixture.lang, "I_02"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[I_02/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    for txt in sink_args {
        assert!(
            !sink_received_arg_text(&result, fixture.sink, txt),
            "[I_02/{}] sink `{}({})` MUST stay clean after overwrite; got {:?}",
            fixture.lang,
            fixture.sink,
            txt,
            result.tainted_calls,
        );
    }
}

#[test]
fn i_02_python() {
    run_i_02(
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    x = args\n    x = 'clean'\n    sink(x)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_javascript() {
    run_i_02(
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { let x = args; x = 'clean'; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_typescript() {
    run_i_02(
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { let x = args; x = 'clean'; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_java() {
    run_i_02(
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { String x = args; x = \"clean\"; sink(x); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_kotlin() {
    run_i_02(
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { var x = args; x = \"clean\"; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_scala() {
    run_i_02(
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: String): Unit = { var x = args; x = \"clean\"; sink(x) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_csharp() {
    run_i_02(
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string args) { var x = args; x = \"clean\"; Sink(x); } }\n",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_go() {
    run_i_02(
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { x := args; x = \"clean\"; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_rust() {
    run_i_02(
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { let mut x = args; x = String::from(\"clean\"); sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_c() {
    run_i_02(
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "void entry(char *args) { char *x = args; x = \"clean\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_cpp() {
    run_i_02(
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *args) { const char *x = args; x = \"clean\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_objc() {
    run_i_02(
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[(
                "a.m",
                "void entry(NSString *args) { NSString *x = args; x = @\"clean\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_ruby() {
    run_i_02(
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  x = args\n  x = 'clean'\n  sink(x)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_php() {
    run_i_02(
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $x = $args; $x = 'clean'; sink($x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["$x"],
    );
}

#[test]
fn i_02_perl() {
    run_i_02(
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; my $x = $args; $x = 'clean'; sink($x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["$x"],
    );
}

#[test]
fn i_02_swift() {
    run_i_02(
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { var x = args; x = \"clean\"; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_dart() {
    run_i_02(
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { var x = args; x = 'clean'; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_lua() {
    run_i_02(
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  local x = args\n  x = 'clean'\n  sink(x)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["x"],
    );
}

#[test]
fn i_02_elixir() {
    run_i_02(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    x = args\n    x = \"clean\"\n    sink(x)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["x"]);
}

#[test]
fn i_02_erlang() {
    run_i_02(
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[(
                "demo.erl",
                "-module(demo).\n-export([entry/1]).\nentry(Args) -> X = Args, X2 = \"clean\", sink(X2).\n",
            )],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
        &["X2"],
    );
}
