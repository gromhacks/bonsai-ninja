//! I_10 — Loop carry across iterations.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_10_python() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    acc = args\n    for i in range(3):\n        sink(acc)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_javascript() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { let acc = args; for (let i = 0; i < 3; i++) { sink(acc); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_typescript() {
    run_positive_cell("I_10", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function entry(args: string) { let acc = args; for (let i = 0; i < 3; i++) { sink(acc); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_java() {
    run_positive_cell("I_10", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { void entry(String args) { String acc = args; for (int i = 0; i < 3; i++) { sink(acc); } } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_kotlin() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { val acc = args; for (i in 0..2) { sink(acc) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_scala() {
    run_positive_cell("I_10", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def entry(args: String): Unit = { val acc = args; for (i <- 0 until 3) { sink(acc) } } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_csharp() {
    run_positive_cell("I_10", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Entry(string args) { var acc = args; for (int i = 0; i < 3; i++) { Sink(acc); } } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn i_10_go() {
    run_positive_cell("I_10", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc entry(args string) { acc := args; for i := 0; i < 3; i++ { sink(acc) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_rust() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { let acc = args; for _ in 0..3 { sink(&acc); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_c() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "void entry(char *args) { char *acc = args; for (int i = 0; i < 3; i++) { sink(acc); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_cpp() {
    run_positive_cell("I_10", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void entry(const char *args) { auto acc = args; for (int i = 0; i < 3; i++) { sink(acc); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_objc() {
    run_positive_cell("I_10", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","void entry(NSString *args) { NSString *acc = args; for (int i = 0; i < 3; i++) { sink(acc); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_ruby() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  acc = args\n  3.times do\n    sink(acc)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_php() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $acc = $args; for ($i = 0; $i < 3; $i++) { sink($acc); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_perl() {
    run_positive_cell("I_10", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub entry { my ($args) = @_; my $acc = $args; for (my $i = 0; $i < 3; $i++) { sink($acc); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_swift() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { let acc = args; for _ in 0..<3 { sink(acc) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_dart() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { var acc = args; for (var i = 0; i < 3; i++) { sink(acc); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_lua() {
    run_positive_cell(
        "I_10",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  local acc = args\n  for i = 1, 3 do\n    sink(acc)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_10_elixir() {
    run_positive_cell("I_10", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def entry(args) do\n    acc = args\n    Enum.each(1..3, fn _i -> sink(acc) end)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_10_erlang() {
    run_positive_cell("I_10", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1, loop/2]).\nentry(Args) -> Acc = Args, loop(Acc, 3).\nloop(_, 0) -> ok;\nloop(Acc, N) -> sink(Acc), loop(Acc, N-1).\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}
