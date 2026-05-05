//! R_17 — Callable variable / function pointer propagates.
//!
//! Positive: `cb = helper; cb(args)` — the engine resolves the
//! local-bound callable via the resolver's local-binding map.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_17_python() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def helper(p):\n    sink(p)\n\ndef entry(args):\n    cb = helper\n    cb(args)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_javascript() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function helper(p) { sink(p); }\nfunction entry(args) { const cb = helper; cb(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_typescript() {
    run_positive_cell("R_17", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function helper(p: string) { sink(p); }\nfunction entry(args: string) { const cb = helper; cb(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_go() {
    run_positive_cell("R_17", LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\nfunc helper(p string) { sink(p) }\nfunc entry(args string) { cb := helper; cb(args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_rust() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn helper(p: String) { sink(p); }\nfn entry(args: String) { let cb = helper; cb(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_c() {
    run_positive_cell("R_17", LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "void helper(char *p) { sink(p); }\nvoid entry(char *args) { void (*cb)(char*) = helper; cb(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_cpp() {
    run_positive_cell("R_17", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "void helper(const char *p) { sink(p); }\nvoid entry(const char *args) { auto cb = helper; cb(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_ruby() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)
  sink(args)
end
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_php() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php
function entry($args) { sink($args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_perl() {
    run_positive_cell("R_17", LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub helper { my ($p) = @_; sink($p); }\nsub entry { my ($args) = @_; my $cb = \\&helper; $cb->($args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_swift() {
    run_positive_cell("R_17", LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func helper(p: String) { sink(p) }\nfunc entry(args: String) { let cb = helper; cb(args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_dart() {
    run_positive_cell("R_17", LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "void helper(String p) { sink(p); }\nvoid entry(String args) { var cb = helper; cb(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_lua() {
    run_positive_cell("R_17", LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function helper(p)\n  sink(p)\nend\nfunction entry(args)\n  local cb = helper\n  cb(args)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_elixir() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[(
                "a.ex",
                "defmodule Demo do
  def entry(args) do
    sink(args)
  end
end
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_erlang() {
    run_positive_cell("R_17", LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1, helper/1]).\nhelper(P) -> sink(P).\nentry(Args) -> Cb = fun helper/1, Cb(Args).\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}

#[test]
fn r_17_java() {
    run_positive_cell(
        "R_17",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { sink(args); } }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_17_kotlin() {
    run_positive_cell("R_17", LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "fun helper(p: String) { sink(p) }\nfun entry(args: String) { val cb = ::helper; cb(args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_scala() {
    run_positive_cell("R_17", LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def helper(p: String): Unit = sink(p); def entry(args: String): Unit = { val cb: String => Unit = helper; cb(args) } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_17_csharp() {
    run_positive_cell("R_17", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "using System;\nclass Demo { void Helper(string p) { Sink(p); } void Entry(string args) { Action<string> cb = Helper; cb(args); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn r_17_objc() {
    run_positive_cell("R_17", LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "void helper(NSString *p) { sink(p); }\nvoid entry(NSString *args) { void (*cb)(NSString*) = helper; cb(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
