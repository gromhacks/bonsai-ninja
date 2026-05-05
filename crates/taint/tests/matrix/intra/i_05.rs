//! I_05 — Destructure from tainted RHS.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_05_javascript() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[("a.js", "function entry(args) { const { v } = args; sink(v); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_typescript() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: {v: string}) { const { v } = args; sink(v); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_rust() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "struct Box { v: String }\nfn entry(args: Box) { let Box { v } = args; sink(v); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_python() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[("a.py", "def entry(args):\n    a, b = args\n    sink(a)\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_dart() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[("a.dart", "void entry(String args) { var v = args; sink(v); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_swift() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: (String, String)) { let (a, _) = args; sink(a) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_kotlin() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: Pair<String, String>) { val (a, _) = args; sink(a) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_scala() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: (String, String)): Unit = { val (a, _) = args; sink(a) } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_csharp() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry((string, string) args) { var (a, _) = args; Sink(a); } }\n",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
    );
}
#[test]
fn i_05_go() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[(
                "a.go",
                "package main\nfunc entry(args string) { v := args; sink(v) }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_lua() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  local v = args\n  sink(v)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_php() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $v = $args; sink($v); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_java() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { String v = args; sink(v); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_cpp() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *args) { auto v = args; sink(v); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_objc() {
    run_positive_cell(
        "I_05",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[(
                "a.m",
                "void entry(NSString *args) { NSString *v = args; sink(v); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_05_ruby() {
    run_positive_cell(
        "I_05",
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
