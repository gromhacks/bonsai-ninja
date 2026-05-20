//! I_19 — Lambda body taint.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_19_python() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    f = lambda x: sink(x)\n    f(args)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_19_javascript() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { const f = x => sink(x); f(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_19_typescript() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { const f = (x: string) => sink(x); f(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_19_ruby() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  f = ->(x) { sink(x) }\n  f.call(args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_19_java() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "import java.util.function.Consumer;\nclass Demo { void entry(String args) { Consumer<String> f = x -> sink(x); f.accept(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_19_dart() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { var f = (String x) { sink(x); }; f(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_cpp() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *args) { auto f = [](const char *x) { sink(x); }; f(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_csharp() {
    run_positive_cell("I_19", LangFixture { lang: "csharp", adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files: &[("Demo.cs", "using System;\nclass Demo { void Entry(string args) { Action<string> f = x => Sink(x); f(args); } }\n")], entry: "Entry", seed: &["args"], sink: "Sink" });
}

#[test]
fn i_19_elixir() {
    run_positive_cell("I_19", LangFixture { lang: "elixir", adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    f = fn x -> sink(x) end\n    f.(args)\n  end\nend\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_19_go() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { f := func(x string) { sink(x) }; f(args) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_kotlin() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { val f = { x: String -> sink(x) }; f(args) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_lua() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  local f = function(x) sink(x) end\n  f(args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_objc() {
    run_positive_cell("I_19", LangFixture { lang: "objc", adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files: &[("a.m", "void entry(NSString *args) { void (^f)(NSString *) = ^(NSString *x) { sink(x); }; f(args); }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_19_perl() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; my $f = sub { my ($x) = @_; sink($x); }; $f->($args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_php() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $f = function($x) { sink($x); }; $f($args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_rust() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { let f = |x| sink(x); f(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_19_scala() {
    run_positive_cell("I_19", LangFixture { lang: "scala", adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files: &[("a.scala", "object Demo { def entry(args: String): Unit = { val f = (x: String) => sink(x); f(args) } }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_19_swift() {
    run_positive_cell(
        "I_19",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { let f = { (x: String) in sink(x) }; f(args) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
