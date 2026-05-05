//! OT_17 — Variable named like seed but unrelated stays clean.
//!
//! Negative: a different function defines a local with the SAME name
//! as the seed token but which never receives data from the seed.
//! Sink in that function must NOT be tainted just because the
//! identifier happens to match by name.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_reached, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_17(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "OT_17"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_17/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_reached(&result, fixture.sink),
        "[OT_17/{}] independent function with same-name local must NOT taint sink `{}`; got {:?}",
        fixture.lang,
        fixture.sink,
        result.tainted_calls,
    );
}

#[test]
fn ot_17_python() {
    run_ot_17(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[(
            "a.py",
            "def entry(args):\n    pass\n\ndef other():\n    args = 'safe'\n    sink(args)\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_javascript() {
    run_ot_17(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[(
            "a.js",
            "function entry(args) {}\nfunction other() { let args = 'safe'; sink(args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_typescript() {
    run_ot_17(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function entry(args: string): void {}\nfunction other(): void { let args = 'safe'; sink(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_java() {
    run_ot_17(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Demo { void entry(String args) {} void other() { String args = \"safe\"; sink(args); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_kotlin() {
    run_ot_17(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[(
            "a.kt",
            "fun entry(args: String) {}\nfun other() { val args = \"safe\"; sink(args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_scala() {
    run_ot_17(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def entry(args: String): Unit = (); def other(): Unit = { val args = \"safe\"; sink(args) } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_csharp() {
    run_ot_17(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[(
            "Demo.cs",
            "class Demo { void Entry(string args) {} void Other() { var args = \"safe\"; Sink(args); } }\n",
        )],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn ot_17_go() {
    run_ot_17(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[(
            "a.go",
            "package main\nfunc entry(args string) {}\nfunc other() { args := \"safe\"; sink(args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_rust() {
    run_ot_17(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[(
            "a.rs",
            "fn entry(args: String) {}\nfn other() { let args = String::from(\"safe\"); sink(args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_c() {
    run_ot_17(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[(
            "a.c",
            "void entry(char *args) {}\nvoid other() { char *args = \"safe\"; sink(args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_cpp() {
    run_ot_17(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[(
            "a.cpp",
            "void entry(const char *args) {}\nvoid other() { const char *args = \"safe\"; sink(args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_objc() {
    run_ot_17(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[(
            "a.m",
            "void entry(NSString *args) {}\nvoid other() { NSString *args = @\"safe\"; sink(args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_ruby() {
    run_ot_17(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[(
            "a.rb",
            "def entry(args)\nend\ndef other\n  args = 'safe'\n  sink(args)\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_php() {
    run_ot_17(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[(
            "a.php",
            "<?php\nfunction entry($args) {}\nfunction other() { $args = 'safe'; sink($args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_perl() {
    run_ot_17(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[(
            "a.pl",
            "sub entry { my ($args) = @_; }\nsub other { my $args = 'safe'; sink($args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_swift() {
    run_ot_17(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[(
            "a.swift",
            "func entry(args: String) {}\nfunc other() { let args = \"safe\"; sink(args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_dart() {
    run_ot_17(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[(
            "a.dart",
            "void entry(String args) {}\nvoid other() { var args = 'safe'; sink(args); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_lua() {
    run_ot_17(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[(
            "a.lua",
            "function entry(args)\nend\nfunction other()\n  local args = 'safe'\n  sink(args)\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_elixir() {
    run_ot_17(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    :ok\n  end\n  def other() do\n    args = \"safe\"\n    sink(args)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_erlang() {
    run_ot_17(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1, other/0]).\nentry(Args) -> ok.\nother() -> Args = \"safe\", sink(Args).\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}

#[test]
fn ot_17_solidity() {
    run_ot_17(LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[("Demo.sol", "contract Demo { function entry(string memory args) public {} function other() internal { string memory args = \"safe\"; sink(args); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
