//! R_13 — Multi-return splat to LHS.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_13_go() {
    run_positive_cell("R_13", LangFixture { lang:"go", adapter:Arc::new(bonsai_lang_go::GoAdapter::new()), files:&[("a.go","package main\nfunc helper(p string) (string, string) { return p, \"ok\" }\nfunc entry(args string) { a, b := helper(args); sink(a); _ = b }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_python() {
    run_positive_cell("R_13", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def helper(p):\n    return p, 'ok'\n\ndef entry(args):\n    a, b = helper(args)\n    sink(a)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_rust() {
    run_positive_cell("R_13", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn helper(p: String) -> (String, String) { (p, String::from(\"ok\")) }\nfn entry(args: String) { let (a, b) = helper(args); sink(a); let _ = b; }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_javascript() {
    run_positive_cell("R_13", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function helper(p) { return [p, 'ok']; }\nfunction entry(args) { let [a, b] = helper(args); sink(a); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_typescript() {
    run_positive_cell("R_13", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function helper(p: string): [string, string] { return [p, 'ok']; }\nfunction entry(args: string) { let [a, b] = helper(args); sink(a); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_lua() {
    run_positive_cell("R_13", LangFixture { lang:"lua", adapter:Arc::new(bonsai_lang_lua::LuaAdapter::new()), files:&[("a.lua","function helper(p)\n  return p, 'ok'\nend\nfunction entry(args)\n  local a, b = helper(args)\n  sink(a)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_ruby() {
    run_positive_cell(
        "R_13",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def helper(p)\n  [p, 'ok']\nend\ndef entry(args)\n  a, b = helper(args)\n  sink(a)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_13_swift() {
    run_positive_cell("R_13", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func helper(p: String) -> (String, String) { return (p, \"ok\") }\nfunc entry(args: String) { let (a, _) = helper(p: args); sink(a) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_csharp() {
    run_positive_cell("R_13", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { (string, string) Helper(string p) { return (p, \"ok\"); } void Entry(string args) { var (a, _) = Helper(args); Sink(a); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_13_kotlin() {
    run_positive_cell(
        "R_13",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { sink(args) }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_13_scala() {
    run_positive_cell("R_13", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def helper(p: String): (String, String) = (p, \"ok\"); def entry(args: String): Unit = { val (a, _) = helper(args); sink(a) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_dart() {
    run_positive_cell("R_13", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","String helper(String p) { return p; }\nvoid entry(String args) { var a = helper(args); sink(a); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_elixir() {
    run_positive_cell("R_13", LangFixture { lang:"elixir", adapter:Arc::new(bonsai_lang_elixir::ElixirAdapter::new()), files:&[("a.ex","defmodule Demo do\n  def helper(p), do: {p, \"ok\"}\n  def entry(args) do\n    {a, _b} = helper(args)\n    sink(a)\n  end\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_erlang() {
    run_positive_cell("R_13", LangFixture { lang:"erlang", adapter:Arc::new(bonsai_lang_erlang::ErlangAdapter::new()), files:&[("demo.erl","-module(demo).\n-export([entry/1, helper/1]).\nhelper(P) -> {P, \"ok\"}.\nentry(Args) -> {A, _B} = helper(Args), sink(A).\n")], entry:"entry", seed:&["Args"], sink:"sink" });
}
#[test]
fn r_13_php() {
    run_positive_cell("R_13", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction helper($p) { return [$p, 'ok']; }\nfunction entry($args) { [$a, $b] = helper($args); sink($a); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_13_perl() {
    run_positive_cell("R_13", LangFixture { lang:"perl", adapter:Arc::new(bonsai_lang_perl::PerlAdapter::new()), files:&[("a.pl","sub helper { my ($p) = @_; return ($p, 'ok'); }\nsub entry { my ($args) = @_; my ($a, $b) = helper($args); sink($a); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
