//! OT_11 — Clean return after consume.
#![allow(unreachable_pub)]
use crate::helpers::{run_negative_cell, LangFixture};
use std::sync::Arc;

#[test]
fn ot_11_python() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[("a.py", "def entry(args):\n    sink('clean')\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_javascript() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[("a.js", "function entry(args) { sink('clean'); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_typescript() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[("a.ts", "function entry(args: string) { sink('clean'); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_java() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { sink(\"clean\"); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_kotlin() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[("a.kt", "fun entry(args: String) { sink(\"clean\") }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_scala() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: String): Unit = sink(\"clean\") }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_csharp() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string args) { Sink(\"clean\"); } }\n",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
    );
}
#[test]
fn ot_11_go() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { sink(\"clean\") }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_rust() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { sink(String::from(\"clean\")); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_c() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[("a.c", "void entry(char *args) { sink(\"clean\"); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_cpp() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[("a.cpp", "void entry(const char *args) { sink(\"clean\"); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_objc() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[("a.m", "void entry(NSString *args) { sink(@\"clean\"); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_ruby() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[("a.rb", "def entry(args)\n  sink('clean')\nend\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_php() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[("a.php", "<?php\nfunction entry($args) { sink('clean'); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_perl() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[("a.pl", "sub entry { my ($args) = @_; sink('clean'); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_swift() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[("a.swift", "func entry(args: String) { sink(\"clean\") }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_dart() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[("a.dart", "void entry(String args) { sink('clean'); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_lua() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[("a.lua", "function entry(args)\n  sink('clean')\nend\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_elixir() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[(
                "a.ex",
                "defmodule Demo do\n  def entry(args) do\n    sink(\"clean\")\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn ot_11_erlang() {
    run_negative_cell(
        "OT_11",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[(
                "demo.erl",
                "-module(demo).\n-export([entry/1]).\nentry(Args) -> sink(\"clean\").\n",
            )],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}
