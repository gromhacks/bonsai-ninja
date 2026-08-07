//! I_08 — Else-branch merge propagates (mirror of I_07).
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_08_python() {
    run_positive_cell("I_08", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def cond(): return False\ndef entry(args):\n    if cond():\n        x = 'ok'\n    else:\n        x = args\n    sink(x)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_javascript() {
    run_positive_cell("I_08", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function cond() { return false; }\nfunction entry(args) { let x; if (cond()) { x = 'ok'; } else { x = args; } sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_typescript() {
    run_positive_cell("I_08", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function cond() { return false; }\nfunction entry(args: string) { let x: string; if (cond()) { x = 'ok'; } else { x = args; } sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_java() {
    run_positive_cell("I_08", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { boolean cond() { return false; } void entry(String args) { String x; if (cond()) { x = \"ok\"; } else { x = args; } sink(x); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_kotlin() {
    run_positive_cell("I_08", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun cond(): Boolean = false\nfun entry(args: String) { val x: String; if (cond()) { x = \"ok\" } else { x = args }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_scala() {
    run_positive_cell("I_08", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def cond(): Boolean = false; def entry(args: String): Unit = { var x = \"\"; if (cond()) { x = \"ok\" } else { x = args }; sink(x) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_csharp() {
    run_positive_cell("I_08", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { bool Cond() => false; void Entry(string args) { string x; if (Cond()) { x = \"ok\"; } else { x = args; } Sink(x); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn i_08_go() {
    run_positive_cell("I_08", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc cond() bool { return false }\nfunc entry(args string) { var x string; if cond() { x = \"ok\" } else { x = args }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_rust() {
    run_positive_cell("I_08", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn cond() -> bool { false }\nfn entry(args: String) { let x; if cond() { x = String::from(\"ok\"); } else { x = args; } sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_c() {
    run_positive_cell("I_08", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","int cond(void);\nvoid entry(char *args) { char *x; if (cond()) x = \"ok\"; else x = args; sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_cpp() {
    run_positive_cell("I_08", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","bool cond();\nvoid entry(const char *args) { const char *x; if (cond()) x = \"ok\"; else x = args; sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_objc() {
    run_positive_cell("I_08", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","BOOL cond(void);\nvoid entry(NSString *args) { NSString *x; if (cond()) x = @\"ok\"; else x = args; sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_ruby() {
    run_positive_cell("I_08", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","def cond; false; end\ndef entry(args)\n  if cond()\n    x = 'ok'\n  else\n    x = args\n  end\n  sink(x)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_php() {
    run_positive_cell("I_08", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction cond() { return false; }\nfunction entry($args) { if (cond()) { $x = 'ok'; } else { $x = $args; } sink($x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_perl() {
    run_positive_cell("I_08", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub cond { 0 }\nsub entry { my ($args) = @_; my $x; if (cond()) { $x = 'ok'; } else { $x = $args; } sink($x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_swift() {
    run_positive_cell("I_08", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func cond() -> Bool { return false }\nfunc entry(args: String) { var x: String; if cond() { x = \"ok\" } else { x = args }; sink(x) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_dart() {
    run_positive_cell("I_08", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","bool cond() => false;\nvoid entry(String args) { var x = ''; if (cond()) { x = 'ok'; } else { x = args; } sink(x); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_lua() {
    run_positive_cell("I_08", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function cond() return false end\nfunction entry(args)\n  local x\n  if cond() then x = 'ok' else x = args end\n  sink(x)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_elixir() {
    run_positive_cell("I_08", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def cond_(), do: false\n  def entry(args) do\n    x = if cond_() do \"ok\" else args end\n    sink(x)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_08_erlang() {
    run_positive_cell("I_08", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1]).\nentry(Args) -> X = case cond_() of true -> \"ok\"; _ -> Args end, sink(X).\ncond_() -> false.\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}
