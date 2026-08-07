//! R_10 — Higher-order: callback returns tainted.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_10_python() {
    run_positive_cell(
        "R_10",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def cb(p):\n    return p\n\ndef apply_(f, x):\n    return f(x)\n\ndef entry(args):\n    out = apply_(cb, args)\n    sink(out)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_10_javascript() {
    run_positive_cell("R_10", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function cb(p) { return p; }\nfunction apply_(f, x) { return f(x); }\nfunction entry(args) { let out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_10_typescript() {
    run_positive_cell("R_10", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function cb(p: string): string { return p; }\nfunction apply_(f: (s: string) => string, x: string): string { return f(x); }\nfunction entry(args: string) { let out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_c() {
    run_positive_cell("R_10", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","char *cb(char *p) { return p; }\nchar *apply_(char *(*f)(char *), char *x) { return f(x); }\nvoid entry(char *args) { char *out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_cpp() {
    run_positive_cell("R_10", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","const char *cb(const char *p) { return p; }\nconst char *apply_(const char *(*f)(const char *), const char *x) { return f(x); }\nvoid entry(const char *args) { const char *out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_csharp() {
    run_positive_cell("R_10", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","delegate string Cb(string s);\nclass Demo { string CbFn(string p) { return p; } string apply_(Cb f, string x) { return f(x); } void Entry(string args) { string out_ = apply_(CbFn, args); Sink(out_); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}

#[test]
fn r_10_dart() {
    run_positive_cell("R_10", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","String cb(String p) { return p; }\nString apply_(String Function(String) f, String x) { return f(x); }\nvoid entry(String args) { var out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_elixir() {
    run_positive_cell("R_10", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def cb(p) do\n    p\n  end\n  def apply_(f, x) do\n    f.(x)\n  end\n  def entry(args) do\n    out = apply_(&cb/1, args)\n    sink(out)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_erlang() {
    run_positive_cell("R_10", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1, apply_/2, cb/1]).\ncb(P) -> P.\napply_(F, X) -> F(X).\nentry(Args) -> Out = apply_(fun cb/1, Args), sink(Out).\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}

#[test]
fn r_10_go() {
    run_positive_cell("R_10", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc cb(p string) string { return p }\nfunc apply_(f func(string) string, x string) string { return f(x) }\nfunc entry(args string) { out := apply_(cb, args); sink(out) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_java() {
    run_positive_cell("R_10", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","import java.util.function.Function;\nclass Demo { String cb(String p) { return p; } String apply_(Function<String,String> f, String x) { return f.apply(x); } void entry(String args) { String out = apply_(this::cb, args); sink(out); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_kotlin() {
    run_positive_cell("R_10", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun cb(p: String): String { return p }\nfun apply_(f: (String) -> String, x: String): String { return f(x) }\nfun entry(args: String) { val out = apply_(::cb, args); sink(out) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_lua() {
    run_positive_cell("R_10", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function cb(p)\n  return p\nend\nfunction apply_(f, x)\n  return f(x)\nend\nfunction entry(args)\n  local out = apply_(cb, args)\n  sink(out)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_objc() {
    run_positive_cell("R_10", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","NSString *cb(NSString *p) { return p; }\nNSString *apply_(NSString *(*f)(NSString *), NSString *x) { return f(x); }\nvoid entry(NSString *args) { NSString *out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_perl() {
    run_positive_cell("R_10", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub cb { my ($p) = @_; return $p; }\nsub apply_ { my ($f, $x) = @_; return $f->($x); }\nsub entry { my ($args) = @_; my $out = apply_(\\&cb, $args); sink($out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_php() {
    run_positive_cell("R_10", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction cb($p) { return $p; }\nfunction apply_($f, $x) { return $f($x); }\nfunction entry($args) { $out = apply_('cb', $args); sink($out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_ruby() {
    run_positive_cell("R_10", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","def cb(p)\n  p\nend\ndef apply_(f, x)\n  f.call(x)\nend\ndef entry(args)\n  out = apply_(method(:cb), args)\n  sink(out)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_rust() {
    run_positive_cell("R_10", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn cb(p: String) -> String { p }\nfn apply_(f: fn(String) -> String, x: String) -> String { f(x) }\nfn entry(args: String) { let out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_scala() {
    run_positive_cell("R_10", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def cb(p: String): String = p; def apply_(f: String => String, x: String): String = f(x); def entry(args: String): Unit = { val out = apply_(cb, args); sink(out) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_10_swift() {
    run_positive_cell("R_10", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func cb(_ p: String) -> String { return p }\nfunc apply_(_ f: (String) -> String, _ x: String) -> String { return f(x) }\nfunc entry(args: String) { let out = apply_(cb, args); sink(out) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
