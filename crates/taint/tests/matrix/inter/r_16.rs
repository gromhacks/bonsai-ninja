//! R_16 — Mutual recursion converges.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_16_python() {
    run_positive_cell("R_16", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def f(p, n):\n    if n == 0:\n        sink(p)\n    else:\n        g(p, n - 1)\n\ndef g(p, n):\n    f(p, n)\n\ndef entry(args):\n    f(args, 1)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_javascript() {
    run_positive_cell("R_16", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function f(p, n) { if (n === 0) sink(p); else g(p, n - 1); }\nfunction g(p, n) { f(p, n); }\nfunction entry(args) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_go() {
    run_positive_cell("R_16", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc f(p string, n int) { if n == 0 { sink(p) } else { g(p, n-1) } }\nfunc g(p string, n int) { f(p, n) }\nfunc entry(args string) { f(args, 1) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_rust() {
    run_positive_cell("R_16", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn f(p: String, n: i32) { if n == 0 { sink(p); } else { g(p, n - 1); } }\nfn g(p: String, n: i32) { f(p, n); }\nfn entry(args: String) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_typescript() {
    run_positive_cell("R_16", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function f(p: string, n: number) { if (n === 0) sink(p); else g(p, n - 1); }\nfunction g(p: string, n: number) { f(p, n); }\nfunction entry(args: string) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_java() {
    run_positive_cell("R_16", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { void f(String p, int n) { if (n == 0) sink(p); else g(p, n - 1); } void g(String p, int n) { f(p, n); } void entry(String args) { f(args, 1); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_csharp() {
    run_positive_cell("R_16", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void F(string p, int n) { if (n == 0) Sink(p); else G(p, n - 1); } void G(string p, int n) { F(p, n); } void Entry(string args) { F(args, 1); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_16_kotlin() {
    run_positive_cell("R_16", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun f(p: String, n: Int) { if (n == 0) sink(p) else g(p, n - 1) }\nfun g(p: String, n: Int) { f(p, n) }\nfun entry(args: String) { f(args, 1) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_scala() {
    run_positive_cell("R_16", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def f(p: String, n: Int): Unit = if (n == 0) sink(p) else g(p, n - 1); def g(p: String, n: Int): Unit = f(p, n); def entry(args: String): Unit = f(args, 1) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_php() {
    run_positive_cell("R_16", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction f($p, $n) { if ($n == 0) sink($p); else g($p, $n - 1); }\nfunction g($p, $n) { f($p, $n); }\nfunction entry($args) { f($args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_ruby() {
    run_positive_cell("R_16", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","def f(p, n)\n  if n == 0 then sink(p) else g(p, n - 1) end\nend\ndef g(p, n)\n  f(p, n)\nend\ndef entry(args)\n  f(args, 1)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_swift() {
    run_positive_cell("R_16", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func f(p: String, n: Int) { if n == 0 { sink(p) } else { g(p: p, n: n - 1) } }\nfunc g(p: String, n: Int) { f(p: p, n: n) }\nfunc entry(args: String) { f(p: args, n: 1) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_lua() {
    run_positive_cell("R_16", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function f(p, n)\n  if n == 0 then sink(p) else g(p, n - 1) end\nend\nfunction g(p, n)\n  f(p, n)\nend\nfunction entry(args)\n  f(args, 1)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_dart() {
    run_positive_cell("R_16", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","void f(String p, int n) { if (n == 0) sink(p); else g(p, n - 1); }\nvoid g(String p, int n) { f(p, n); }\nvoid entry(String args) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_c() {
    run_positive_cell("R_16", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","void g(char *p, int n);\nvoid f(char *p, int n) { if (n == 0) sink(p); else g(p, n - 1); }\nvoid g(char *p, int n) { f(p, n); }\nvoid entry(char *args) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_cpp() {
    run_positive_cell("R_16", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void g(const char *p, int n);\nvoid f(const char *p, int n) { if (n == 0) sink(p); else g(p, n - 1); }\nvoid g(const char *p, int n) { f(p, n); }\nvoid entry(const char *args) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_objc() {
    run_positive_cell("R_16", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","void g(NSString *p, int n);\nvoid f(NSString *p, int n) { if (n == 0) sink(p); else g(p, n - 1); }\nvoid g(NSString *p, int n) { f(p, n); }\nvoid entry(NSString *args) { f(args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_perl() {
    run_positive_cell("R_16", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub f { my ($p, $n) = @_; if ($n == 0) { sink($p); } else { g($p, $n - 1); } }\nsub g { my ($p, $n) = @_; f($p, $n); }\nsub entry { my ($args) = @_; f($args, 1); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_elixir() {
    run_positive_cell("R_16", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def f(p, 0), do: sink(p)\n  def f(p, n), do: g(p, n - 1)\n  def g(p, n), do: f(p, n)\n  def entry(args), do: f(args, 1)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_16_erlang() {
    run_positive_cell("R_16", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1, f/2, g/2]).\nf(P, 0) -> sink(P);\nf(P, N) -> g(P, N - 1).\ng(P, N) -> f(P, N).\nentry(Args) -> f(Args, 1).\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}
#[test]
fn r_16_solidity() {
    run_positive_cell(
        "R_16",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[(
                "Demo.sol",
                "contract Demo { function entry(string memory args) public { sink(args); } }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
