//! R_15 — Recursive function terminates with taint.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_15_python() {
    run_positive_cell("R_15", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def helper(p, n):\n    if n == 0:\n        sink(p)\n    else:\n        helper(p, n - 1)\n\ndef entry(args):\n    helper(args, 2)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_javascript() {
    run_positive_cell("R_15", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function helper(p, n) { if (n === 0) sink(p); else helper(p, n - 1); }\nfunction entry(args) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_typescript() {
    run_positive_cell("R_15", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function helper(p: string, n: number) { if (n === 0) sink(p); else helper(p, n - 1); }\nfunction entry(args: string) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_java() {
    run_positive_cell("R_15", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { void helper(String p, int n) { if (n == 0) sink(p); else helper(p, n - 1); } void entry(String args) { helper(args, 2); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_csharp() {
    run_positive_cell("R_15", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Helper(string p, int n) { if (n == 0) Sink(p); else Helper(p, n - 1); } void Entry(string args) { Helper(args, 2); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_15_kotlin() {
    run_positive_cell("R_15", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun helper(p: String, n: Int) { if (n == 0) sink(p) else helper(p, n - 1) }\nfun entry(args: String) { helper(args, 2) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_scala() {
    run_positive_cell("R_15", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def helper(p: String, n: Int): Unit = if (n == 0) sink(p) else helper(p, n - 1); def entry(args: String): Unit = helper(args, 2) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_go() {
    run_positive_cell("R_15", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc helper(p string, n int) { if n == 0 { sink(p) } else { helper(p, n-1) } }\nfunc entry(args string) { helper(args, 2) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_rust() {
    run_positive_cell("R_15", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn helper(p: String, n: i32) { if n == 0 { sink(p); } else { helper(p, n - 1); } }\nfn entry(args: String) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_c() {
    run_positive_cell("R_15", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","void helper(char *p, int n) { if (n == 0) sink(p); else helper(p, n - 1); }\nvoid entry(char *args) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_cpp() {
    run_positive_cell("R_15", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void helper(const char *p, int n) { if (n == 0) sink(p); else helper(p, n - 1); }\nvoid entry(const char *args) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_objc() {
    run_positive_cell("R_15", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","void helper(NSString *p, int n) { if (n == 0) sink(p); else helper(p, n - 1); }\nvoid entry(NSString *args) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_ruby() {
    run_positive_cell("R_15", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","def helper(p, n)\n  if n == 0\n    sink(p)\n  else\n    helper(p, n - 1)\n  end\nend\ndef entry(args)\n  helper(args, 2)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_php() {
    run_positive_cell("R_15", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction helper($p, $n) { if ($n == 0) sink($p); else helper($p, $n - 1); }\nfunction entry($args) { helper($args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_perl() {
    run_positive_cell("R_15", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub helper { my ($p, $n) = @_; if ($n == 0) { sink($p); } else { helper($p, $n - 1); } }\nsub entry { my ($args) = @_; helper($args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_swift() {
    run_positive_cell("R_15", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func helper(p: String, n: Int) { if n == 0 { sink(p) } else { helper(p: p, n: n - 1) } }\nfunc entry(args: String) { helper(p: args, n: 2) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_dart() {
    run_positive_cell("R_15", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","void helper(String p, int n) { if (n == 0) { sink(p); } else { helper(p, n - 1); } }\nvoid entry(String args) { helper(args, 2); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_lua() {
    run_positive_cell("R_15", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function helper(p, n)\n  if n == 0 then sink(p) else helper(p, n - 1) end\nend\nfunction entry(args)\n  helper(args, 2)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_elixir() {
    run_positive_cell("R_15", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def helper(p, 0), do: sink(p)\n  def helper(p, n), do: helper(p, n - 1)\n  def entry(args), do: helper(args, 2)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_15_erlang() {
    run_positive_cell("R_15", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1, helper/2]).\nhelper(P, 0) -> sink(P);\nhelper(P, N) -> helper(P, N-1).\nentry(Args) -> helper(Args, 2).\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}
