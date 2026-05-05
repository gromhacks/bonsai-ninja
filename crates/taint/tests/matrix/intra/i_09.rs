//! I_09 — Loop body propagation.
//!
//! Positive: tainted variable read inside a loop body; sink in body
//! must receive taint. Validates that intra-CFG loop modeling
//! preserves taint across iterations of the body.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_09_python() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    for i in range(3):\n        sink(args)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_javascript() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { for (let i = 0; i < 3; i++) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_typescript() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { for (let i = 0; i < 3; i++) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_java() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { for (int i = 0; i < 3; i++) { sink(args); } } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_kotlin() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { for (i in 0..2) { sink(args) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_scala() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: String): Unit = { for (i <- 0 until 3) { sink(args) } } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_csharp() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string args) { for (int i = 0; i < 3; i++) { Sink(args); } } }\n",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
    );
}

#[test]
fn i_09_go() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { for i := 0; i < 3; i++ { sink(args) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_rust() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { for _ in 0..3 { sink(&args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_c() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "void entry(char *args) { for (int i = 0; i < 3; i++) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_cpp() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *args) { for (int i = 0; i < 3; i++) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_objc() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[(
                "a.m",
                "void entry(NSString *args) { for (int i = 0; i < 3; i++) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_ruby() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  3.times do\n    sink(args)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_php() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { for ($i = 0; $i < 3; $i++) { sink($args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_perl() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; for (my $i = 0; $i < 3; $i++) { sink($args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_swift() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { for _ in 0..<3 { sink(args) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_dart() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { for (var i = 0; i < 3; i++) { sink(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_lua() {
    run_positive_cell(
        "I_09",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  for i = 1, 3 do\n    sink(args)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_09_elixir() {
    run_positive_cell("I_09", LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    Enum.each(1..3, fn _i -> sink(args) end)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn i_09_erlang() {
    // Erlang lacks classical loops; recursive function call is the
    // idiomatic loop. Adapter doesn't yet model recursion-as-loop;
    // mark deferred until that gap closes.
    run_positive_cell("I_09", LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1, loop/2]).\nentry(Args) -> loop(Args, 3).\nloop(Args, 0) -> ok;\nloop(Args, N) -> sink(Args), loop(Args, N-1).\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}

#[test]
fn i_09_solidity() {
    run_positive_cell("I_09", LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[("Demo.sol", "contract Demo { function entry(string memory args) public { for (uint i = 0; i < 3; i++) { sink(args); } } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
