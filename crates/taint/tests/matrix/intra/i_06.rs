//! I_06 — Ternary / conditional expression — both branches.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_06_python() {
    run_positive_cell(
        "I_06",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):
    x = args
    sink(x)
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_06_javascript() {
    run_positive_cell(
        "I_06",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { let x = args; sink(x); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_06_typescript() {
    run_positive_cell(
        "I_06",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { let x = args; sink(x); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_06_java() {
    run_positive_cell(
        "I_06",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { String x = args; sink(x); } }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_06_csharp() {
    run_positive_cell("I_06", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { bool Cond() => true; void Entry(string args) { string x = Cond() ? args : \"ok\"; Sink(x); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn i_06_go() {
    run_positive_cell("I_06", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc cond() bool { return true }\nfunc entry(args string) { var x string; if cond() { x = args } else { x = \"ok\" }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_c() {
    run_positive_cell(
        "I_06",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "int cond(void);\nvoid entry(char *args) { char *x = cond() ? args : \"ok\"; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_06_cpp() {
    run_positive_cell("I_06", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","bool cond();\nvoid entry(const char *args) { const char *x = cond() ? args : \"ok\"; sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_objc() {
    run_positive_cell("I_06", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","BOOL cond(void);\nvoid entry(NSString *args) { NSString *x = cond() ? args : @\"ok\"; sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_dart() {
    run_positive_cell(
        "I_06",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "bool cond() => true;\nvoid entry(String args) { var x = cond() ? args : 'ok'; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_06_kotlin() {
    run_positive_cell("I_06", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun cond(): Boolean = true\nfun entry(args: String) { val x: String; if (cond()) { x = args } else { x = \"ok\" }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_php() {
    run_positive_cell("I_06", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction cond() { return true; }\nfunction entry($args) { if (cond()) { $x = $args; } else { $x = 'ok'; } sink($x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_ruby() {
    run_positive_cell("I_06", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","def cond; true; end\ndef entry(args)\n  if cond()\n    x = args\n  else\n    x = 'ok'\n  end\n  sink(x)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_perl() {
    run_positive_cell("I_06", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub cond { 1 }\nsub entry { my ($args) = @_; my $x; if (cond()) { $x = $args; } else { $x = 'ok'; } sink($x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_swift() {
    run_positive_cell("I_06", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func cond() -> Bool { return true }\nfunc entry(args: String) { var x: String; if cond() { x = args } else { x = \"ok\" }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_lua() {
    run_positive_cell("I_06", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function cond() return true end\nfunction entry(args)\n  local x\n  if cond() then x = args else x = 'ok' end\n  sink(x)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_scala() {
    run_positive_cell("I_06", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def cond(): Boolean = true; def entry(args: String): Unit = { var x = \"\"; if (cond()) { x = args } else { x = \"ok\" }; sink(x) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_rust() {
    run_positive_cell("I_06", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn cond() -> bool { true }\nfn entry(args: String) { let x; if cond() { x = args; } else { x = String::from(\"ok\"); } sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_elixir() {
    run_positive_cell("I_06", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def cond_(), do: true\n  def entry(args) do\n    x = if cond_() do args else \"ok\" end\n    sink(x)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_06_erlang() {
    run_positive_cell("I_06", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1]).\nentry(Args) -> X = case cond_() of true -> Args; _ -> \"ok\" end, sink(X).\ncond_() -> true.\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}
