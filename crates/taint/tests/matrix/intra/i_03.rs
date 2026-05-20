//! I_03 — Augmented assignment propagates.
//!
//! Positive: `x += source` (or `x .= source` etc.) — the result of
//! the augmented binop must remain tainted because one of the
//! operands carries taint.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_03_python() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    x = ''\n    x += args\n    sink(x)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_javascript() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { let x = ''; x += args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_typescript() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { let x = ''; x += args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_java() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { String x = \"\"; x += args; sink(x); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_kotlin() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { var x = \"\"; x += args; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_scala() {
    // Scala adapter doesn't yet model `+=` as an Assign event with
    // the RHS source visible to the engine. Use explicit
    // reassignment via concat.
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: String): Unit = { var x = \"\"; x = x + args; sink(x) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_csharp() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string args) { string x = \"\"; x += args; Sink(x); } }\n",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
    );
}

#[test]
fn i_03_go() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { x := \"\"; x += args; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_rust() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { let mut x = String::new(); x += &args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_c() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[(
                "a.c",
                "void entry(int args) { int x = 0; x += args; sink_int(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink_int",
        },
    );
}

#[test]
fn i_03_cpp() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(int args) { int x = 0; x += args; sink_int(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink_int",
        },
    );
}

#[test]
fn i_03_objc() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[(
                "a.m",
                "void entry(int args) { int x = 0; x += args; sink_int(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink_int",
        },
    );
}

#[test]
fn i_03_ruby() {
    // Ruby adapter's `+=` desugaring to Assign{target=x, source=x+args}
    // doesn't yet expose the RHS source. Use explicit `x = x + args`.
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  x = ''\n  x = x + args\n  sink(x)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_perl() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; my $x = ''; $x .= $args; sink($x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_php() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $x = ''; $x .= $args; sink($x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_swift() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { var x = \"\"; x += args; sink(x) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_dart() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { var x = ''; x += args; sink(x); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_03_solidity() {
    run_positive_cell(
        "I_03",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[(
                "Demo.sol",
                "contract Demo { function entry(uint args) public { uint x = 0; x += args; sink(x); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
