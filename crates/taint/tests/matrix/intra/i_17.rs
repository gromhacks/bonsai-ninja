//! I_17 — Switch/case fall-through with tainted scrutinee.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_17_javascript() {
    run_positive_cell("I_17", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function entry(args) { switch (args) { case 'a': sink(args); break; default: sink(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_17_typescript() {
    run_positive_cell("I_17", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function entry(args: string) { switch (args) { case 'a': sink(args); break; default: sink(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_17_java() {
    run_positive_cell("I_17", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { void entry(String args) { switch (args) { case \"a\": sink(args); break; default: sink(args); } } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_17_kotlin() {
    run_positive_cell(
        "I_17",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { when (args) { \"a\" -> sink(args); else -> sink(args) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_17_csharp() {
    run_positive_cell("I_17", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Entry(string args) { switch (args) { case \"a\": Sink(args); break; default: Sink(args); break; } } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn i_17_c() {
    run_positive_cell("I_17", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","void entry(int args) { switch (args) { case 1: sink_int(args); break; default: sink_int(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink_int" });
}
#[test]
fn i_17_cpp() {
    run_positive_cell("I_17", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void entry(int args) { switch (args) { case 1: sink_int(args); break; default: sink_int(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink_int" });
}
#[test]
fn i_17_swift() {
    run_positive_cell(
        "I_17",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { switch args { case \"a\": sink(args); default: sink(args) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_17_dart() {
    run_positive_cell("I_17", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","void entry(String args) { switch (args) { case 'a': sink(args); break; default: sink(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_17_php() {
    run_positive_cell("I_17", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction entry($args) { switch ($args) { case 'a': sink($args); break; default: sink($args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_17_perl() {
    run_positive_cell(
        "I_17",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; if ($args eq 'a') { sink($args); } else { sink($args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_17_objc() {
    run_positive_cell("I_17", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","void entry(int args) { switch (args) { case 1: sink_int(args); break; default: sink_int(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink_int" });
}
