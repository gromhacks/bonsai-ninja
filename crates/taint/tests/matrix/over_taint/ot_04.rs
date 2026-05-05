//! OT_04 — Tainted helper param doesn't taint independent sink arg.
//!
//! Negative: helper(c) audits c (so we know taint reaches helper);
//! a separate locally-bound `cap = 32` is then sinked. The
//! independent local must NOT be tainted by virtue of sharing scope
//! with the tainted helper param.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{
    build_db, cfg, func_id_or_none, seed, sink_reached, sink_received_arg_index, LangFixture,
};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_04(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "OT_04"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_04/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        sink_received_arg_index(&result, "audit", 0),
        "[OT_04/{}] helper param must reach audit so the negative is meaningful; got {:?}",
        fixture.lang,
        result.tainted_calls,
    );
    assert!(
        !sink_reached(&result, fixture.sink),
        "[OT_04/{}] tainted helper param must NOT taint independent local sink `{}`; got {:?}",
        fixture.lang,
        fixture.sink,
        result.tainted_calls,
    );
}

#[test]
fn ot_04_python() {
    run_ot_04(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[("a.py", "def entry(args):\n    helper(args)\n\ndef helper(c):\n    audit(c)\n    cap = 32\n    sink(cap)\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_javascript() {
    run_ot_04(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[("a.js", "function entry(args) { helper(args); }\nfunction helper(c) { audit(c); let cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_typescript() {
    run_ot_04(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function entry(args: string) { helper(args); }\nfunction helper(c: string) { audit(c); let cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_java() {
    run_ot_04(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Demo { void entry(String args) { helper(args); } void helper(String c) { audit(c); int cap = 32; sink(cap); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_kotlin() {
    run_ot_04(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "fun entry(args: String) { helper(args) }\nfun helper(c: String) { audit(c); val cap = 32; sink(cap) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_scala() {
    run_ot_04(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def entry(args: String): Unit = helper(args); def helper(c: String): Unit = { audit(c); val cap = 32; sink(cap) } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_csharp() {
    run_ot_04(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Demo { void Entry(string args) { Helper(args); } void Helper(string c) { audit(c); int cap = 32; Sink(cap); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn ot_04_go() {
    run_ot_04(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\nfunc entry(args string) { helper(args) }\nfunc helper(c string) { audit(c); cap := 32; sink(cap) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_rust() {
    run_ot_04(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "fn entry(args: String) { helper(args); }\nfn helper(c: String) { audit(c); let cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_c() {
    run_ot_04(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "void entry(char *args) { helper(args); }\nvoid helper(char *c) { audit(c); int cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_cpp() {
    run_ot_04(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "void entry(const char *args) { helper(args); }\nvoid helper(const char *c) { audit(c); int cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_objc() {
    run_ot_04(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "void entry(NSString *args) { helper(args); }\nvoid helper(NSString *c) { audit(c); int cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_ruby() {
    run_ot_04(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[(
            "a.rb",
            "def entry(args)\n  helper(args)\nend\ndef helper(c)\n  audit(c)\n  cap = 32\n  sink(cap)\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_php() {
    run_ot_04(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nfunction entry($args) { helper($args); }\nfunction helper($c) { audit($c); $cap = 32; sink($cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_perl() {
    run_ot_04(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub entry { my ($args) = @_; helper($args); }\nsub helper { my ($c) = @_; audit($c); my $cap = 32; sink($cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_swift() {
    run_ot_04(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func entry(args: String) { helper(c: args) }\nfunc helper(c: String) { audit(c); let cap = 32; sink(cap) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_dart() {
    run_ot_04(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "void entry(String args) { helper(args); }\nvoid helper(String c) { audit(c); var cap = 32; sink(cap); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_lua() {
    run_ot_04(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function entry(args)\n  helper(args)\nend\nfunction helper(c)\n  audit(c)\n  local cap = 32\n  sink(cap)\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_elixir() {
    run_ot_04(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    helper(args)\n  end\n  def helper(c) do\n    audit(c)\n    cap = 32\n    sink(cap)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_erlang() {
    run_ot_04(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1, helper/1]).\nentry(Args) -> helper(Args).\nhelper(C) -> audit(C), Cap = 32, sink(Cap).\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}

#[test]
fn ot_04_solidity() {
    run_ot_04(LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[("Demo.sol", "contract Demo { function entry(string memory args) public { helper(args); } function helper(string memory c) internal { audit(c); uint cap = 32; sink(cap); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
