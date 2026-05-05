//! X_10 — ES↔CJS interop.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_10_python() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[("a.py", "def entry(args):\n    sink(args)\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_javascript() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[("a.js", "function entry(args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_typescript() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[("a.ts", "function entry(args: string) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_java() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_kotlin() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[("a.kt", "fun entry(args: String) { sink(args) }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_scala() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: String): Unit = sink(args) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_csharp() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string args) { Sink(args); } }\n",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
    );
}
#[test]
fn x_10_go() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[("a.go", "package main\nfunc entry(args string) { sink(args) }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_rust() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[("a.rs", "fn entry(args: String) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_c() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[("a.c", "void entry(char *args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_cpp() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[("a.cpp", "void entry(const char *args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_objc() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[("a.m", "void entry(NSString *args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_ruby() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[("a.rb", "def entry(args)\n  sink(args)\nend\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_php() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[("a.php", "<?php\nfunction entry($args) { sink($args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_perl() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[("a.pl", "sub entry { my ($args) = @_; sink($args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_swift() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[("a.swift", "func entry(args: String) { sink(args) }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_dart() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[("a.dart", "void entry(String args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_lua() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[("a.lua", "function entry(args)\n  sink(args)\nend\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_elixir() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[(
                "a.ex",
                "defmodule Demo do\n  def entry(args) do\n    sink(args)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_erlang() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[(
                "demo.erl",
                "-module(demo).\n-export([entry/1]).\nentry(Args) -> sink(Args).\n",
            )],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}
#[test]
fn x_10_solidity() {
    run_positive_cell(
        "X_10",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[(
                "Demo.sol",
                "contract Demo { function entry(string memory args) public { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
