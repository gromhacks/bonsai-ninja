//! R_09 — Higher-order: pass tainted to callback (named callable).
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_09_python() {
    run_positive_cell("R_09", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def cb(p):\n    sink(p)\n\ndef apply_(f, x):\n    f(x)\n\ndef entry(args):\n    apply_(cb, args)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_09_javascript() {
    run_positive_cell("R_09", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function cb(p) { sink(p); }\nfunction apply_(f, x) { f(x); }\nfunction entry(args) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_09_typescript() {
    run_positive_cell("R_09", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function cb(p: string) { sink(p); }\nfunction apply_(f: (s: string) => void, x: string) { f(x); }\nfunction entry(args: string) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_09_rust() {
    run_positive_cell("R_09", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn cb(p: String) { sink(p); }\nfn apply_(f: fn(String), x: String) { f(x); }\nfn entry(args: String) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_c() {
    run_positive_cell("R_09", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","void cb(char *p) { sink(p); }\nvoid apply_(void (*f)(char *), char *x) { f(x); }\nvoid entry(char *args) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_cpp() {
    run_positive_cell("R_09", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void cb(const char *p) { sink(p); }\nvoid apply_(void (*f)(const char *), const char *x) { f(x); }\nvoid entry(const char *args) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_csharp() {
    run_positive_cell("R_09", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","delegate void Cb(string s);\nclass Demo { void CbFn(string p) { Sink(p); } void Apply(Cb f, string x) { f(x); } void Entry(string args) { Apply(CbFn, args); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}

#[test]
fn r_09_dart() {
    run_positive_cell("R_09", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","void cb(String p) { sink(p); }\nvoid apply_(void Function(String) f, String x) { f(x); }\nvoid entry(String args) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_elixir() {
    run_positive_cell("R_09", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def cb(p) do\n    sink(p)\n  end\n  def apply_(f, x) do\n    f.(x)\n  end\n  def entry(args) do\n    apply_(&cb/1, args)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_erlang() {
    run_positive_cell("R_09", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1, apply_/2, cb/1]).\ncb(P) -> sink(P).\napply_(F, X) -> F(X).\nentry(Args) -> apply_(fun cb/1, Args).\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}

#[test]
fn r_09_go() {
    run_positive_cell("R_09", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc cb(p string) { sink(p) }\nfunc apply_(f func(string), x string) { f(x) }\nfunc entry(args string) { apply_(cb, args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_java() {
    run_positive_cell("R_09", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","import java.util.function.Consumer;\nclass Demo { void cb(String p) { sink(p); } void apply_(Consumer<String> f, String x) { f.accept(x); } void entry(String args) { apply_(this::cb, args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_kotlin() {
    run_positive_cell("R_09", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun cb(p: String) { sink(p) }\nfun apply_(f: (String) -> Unit, x: String) { f(x) }\nfun entry(args: String) { apply_(::cb, args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_lua() {
    run_positive_cell("R_09", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function cb(p)\n  sink(p)\nend\nfunction apply_(f, x)\n  f(x)\nend\nfunction entry(args)\n  apply_(cb, args)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_objc() {
    run_positive_cell("R_09", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","void cb(NSString *p) { sink(p); }\nvoid apply_(void (*f)(NSString *), NSString *x) { f(x); }\nvoid entry(NSString *args) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_perl() {
    run_positive_cell("R_09", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub cb { my ($p) = @_; sink($p); }\nsub apply_ { my ($f, $x) = @_; $f->($x); }\nsub entry { my ($args) = @_; apply_(\\&cb, $args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_php() {
    run_positive_cell("R_09", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction cb($p) { sink($p); }\nfunction apply_($f, $x) { $f($x); }\nfunction entry($args) { apply_('cb', $args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_ruby() {
    run_positive_cell("R_09", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","def cb(p)\n  sink(p)\nend\ndef apply_(f, x)\n  f.call(x)\nend\ndef entry(args)\n  apply_(method(:cb), args)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_scala() {
    run_positive_cell("R_09", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def cb(p: String): Unit = sink(p); def apply_(f: String => Unit, x: String): Unit = f(x); def entry(args: String): Unit = apply_(cb, args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_09_swift() {
    run_positive_cell("R_09", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func cb(_ p: String) { sink(p) }\nfunc apply_(_ f: (String) -> Void, _ x: String) { f(x) }\nfunc entry(args: String) { apply_(cb, args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
