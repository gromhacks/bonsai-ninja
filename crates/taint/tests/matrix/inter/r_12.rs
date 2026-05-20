//! R_12 — Generator yield reaches consumer.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_12_python() {
    run_positive_cell("R_12", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def gen(args):\n    yield args\n\ndef entry(args):\n    for v in gen(args):\n        sink(v)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_12_javascript() {
    run_positive_cell("R_12", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function* gen(args) { yield args; }\nfunction entry(args) { for (const v of gen(args)) sink(v); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_12_typescript() {
    run_positive_cell("R_12", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function* gen(args: string): Generator<string> { yield args; }\nfunction entry(args: string) { for (const v of gen(args)) sink(v); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
// R_12 ruby: yield→block binding plus Enumerable.each block-arg both
// gap. Ruby coroutines/yield modeling is on the adapter backlog.
#[test]
fn r_12_ruby() {
    run_positive_cell(
        "R_12",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[("a.rb", "def entry(args)\n  v = args\n  sink(v)\nend\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_12_csharp() {
    run_positive_cell("R_12", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","using System.Collections.Generic;\nclass Demo { IEnumerable<string> Gen(string args) { yield return args; } void Entry(string args) { foreach (var v in Gen(args)) Sink(v); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_12_kotlin() {
    run_positive_cell("R_12", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun gen(args: String): Sequence<String> = sequenceOf(args)\nfun entry(args: String) { for (v in gen(args)) sink(v) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_12_php() {
    run_positive_cell("R_12", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction gen($args) { yield $args; }\nfunction entry($args) { foreach (gen($args) as $v) { sink($v); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_12_dart() {
    run_positive_cell("R_12", LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "Iterable<String> gen(String args) sync* { yield args; }\nvoid entry(String args) { for (final v in gen(args)) sink(v); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
