//! R_20 — Keyword args land on named param.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_20_python() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def helper(name=''):\n    sink(name)\n\ndef entry(args):\n    helper(name=args)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_javascript() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function helper({name}) { sink(name); }\nfunction entry(args) { helper({name: args}); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_typescript() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function helper({name}: {name: string}) { sink(name); }\nfunction entry(args: string) { helper({name: args}); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_kotlin() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun helper(name: String) { sink(name) }\nfun entry(args: String) { helper(name = args) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_scala() {
    run_positive_cell("R_20", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def helper(name: String): Unit = sink(name); def entry(args: String): Unit = helper(name = args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_20_csharp() {
    run_positive_cell("R_20", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Helper(string name) { Sink(name); } void Entry(string args) { Helper(name: args); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_20_swift() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func helper(name: String) { sink(name) }\nfunc entry(args: String) { helper(name: args) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_dart() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void helper({required String name}) { sink(name); }\nvoid entry(String args) { helper(name: args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_ruby() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def helper(name:)\n  sink(name)\nend\ndef entry(args)\n  helper(name: args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_20_php() {
    run_positive_cell("R_20", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction helper($name) { sink($name); }\nfunction entry($args) { helper(name: $args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_20_elixir() {
    run_positive_cell(
        "R_20",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[(
                "a.ex",
                "defmodule Demo do\n  def helper(name: name), do: sink(name)\n  def entry(args) do\n    helper(name: args)\n  end\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
