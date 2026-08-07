//! R_02 — Tainted return value reaches caller LHS, then sink.
//!
//! Positive: `helper(p) returns p`. `entry(args) = helper(args); sink(out)`.
//! The return-summary path must mark `out` tainted.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_02_python() {
    run_positive_cell(
        "R_02",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    out = helper(args)\n    sink(out)\n\ndef helper(p):\n    return p\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_02_javascript() {
    run_positive_cell("R_02", LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[("a.js", "function entry(args) { let out = helper(args); sink(out); }\nfunction helper(p) { return p; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_typescript() {
    run_positive_cell("R_02", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function entry(args: string) { let out = helper(args); sink(out); }\nfunction helper(p: string): string { return p; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_java() {
    run_positive_cell("R_02", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Demo { void entry(String args) { String out = helper(args); sink(out); } String helper(String p) { return p; } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_kotlin() {
    run_positive_cell("R_02", LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "fun entry(args: String) { val out = helper(args); sink(out) }\nfun helper(p: String): String = p\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_scala() {
    run_positive_cell("R_02", LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def entry(args: String): Unit = { val out = helper(args); sink(out) }; def helper(p: String): String = p }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_csharp() {
    run_positive_cell("R_02", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Demo { void Entry(string args) { var out_ = Helper(args); Sink(out_); } string Helper(string p) { return p; } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn r_02_go() {
    run_positive_cell("R_02", LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\nfunc entry(args string) { out := helper(args); sink(out) }\nfunc helper(p string) string { return p }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_rust() {
    run_positive_cell("R_02", LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "fn entry(args: String) { let out = helper(args); sink(out); }\nfn helper(p: String) -> String { p }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_c() {
    run_positive_cell("R_02", LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "char *helper(char *p) { return p; }\nvoid entry(char *args) { char *out = helper(args); sink(out); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_cpp() {
    run_positive_cell("R_02", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "const char *helper(const char *p) { return p; }\nvoid entry(const char *args) { const char *out = helper(args); sink(out); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_objc() {
    run_positive_cell("R_02", LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "NSString *helper(NSString *p) { return p; }\nvoid entry(NSString *args) { NSString *out = helper(args); sink(out); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_ruby() {
    run_positive_cell(
        "R_02",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  out = helper(args)\n  sink(out)\nend\ndef helper(p)\n  p\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_02_php() {
    run_positive_cell("R_02", LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nfunction entry($args) { $out = helper($args); sink($out); }\nfunction helper($p) { return $p; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_perl() {
    run_positive_cell("R_02", LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub entry { my ($args) = @_; my $out = helper($args); sink($out); }\nsub helper { my ($p) = @_; return $p; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_swift() {
    run_positive_cell("R_02", LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func entry(args: String) { let out = helper(p: args); sink(out) }\nfunc helper(p: String) -> String { return p }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_dart() {
    run_positive_cell("R_02", LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "void entry(String args) { var out = helper(args); sink(out); }\nString helper(String p) { return p; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_lua() {
    run_positive_cell("R_02", LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function entry(args)\n  local out = helper(args)\n  sink(out)\nend\nfunction helper(p)\n  return p\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_elixir() {
    run_positive_cell("R_02", LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    out = helper(args)\n    sink(out)\n  end\n  def helper(p) do\n    p\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_02_erlang() {
    run_positive_cell("R_02", LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1, helper/1]).\nentry(Args) -> Out = helper(Args), sink(Out).\nhelper(P) -> P.\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}
