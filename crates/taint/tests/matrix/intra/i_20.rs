//! I_20 — Lazy init via if-not assignment.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_20_python() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    x = None\n    if not x:\n        x = args\n    sink(x)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_javascript() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { let x; if (!x) { x = args; } sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_typescript() {
    run_positive_cell("I_20", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function entry(args: string) { let x: string | undefined; if (!x) { x = args; } sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_20_java() {
    run_positive_cell("I_20", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { void entry(String args) { String x = null; if (x == null) { x = args; } sink(x); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_20_kotlin() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { var x: String? = null; if (x == null) { x = args }; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_csharp() {
    run_positive_cell("I_20", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Entry(string args) { string x = null; if (x == null) { x = args; } Sink(x); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn i_20_ruby() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  x = nil\n  if x.nil?\n    x = args\n  end\n  sink(x)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_php() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $x = null; if (!$x) { $x = $args; } sink($x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_swift() {
    run_positive_cell("I_20", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func entry(args: String) { var x: String? = nil; if x == nil { x = args }; sink(x ?? \"\") }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_20_dart() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { String? x; if (x == null) { x = args; } sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_lua() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  local x\n  if not x then\n    x = args\n  end\n  sink(x)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_perl() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; my $x; if (!$x) { $x = $args; } sink($x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_scala() {
    run_positive_cell("I_20", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def entry(args: String): Unit = { var x: String = null; if (x == null) { x = args }; sink(x) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_20_rust() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[("a.rs", "fn entry(args: String) { let x; x = args; sink(x); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_go() {
    run_positive_cell("I_20", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc entry(args string) { var x string; if x == \"\" { x = args }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_20_c() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "void entry(char *args) { char *x = 0; if (!x) x = args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_cpp() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *args) { const char *x = nullptr; if (!x) x = args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_objc() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[(
                "a.m",
                "void entry(NSString *args) { NSString *x = nil; if (!x) x = args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_20_elixir() {
    run_positive_cell("I_20", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def entry(args) do\n    x = if is_nil(nil) do args else \"ok\" end\n    sink(x)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_20_erlang() {
    run_positive_cell(
        "I_20",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[(
                "demo.erl",
                "-module(demo).\n-export([entry/1]).\nentry(Args) -> X = Args, sink(X).\n",
            )],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}
