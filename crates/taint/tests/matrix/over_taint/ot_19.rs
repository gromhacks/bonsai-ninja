//! OT_19 — Function name with seed substring stays untainted.
//!
//! Negative: a function `users_by_name()` is called with a literal
//! arg. Seed is `user`. The function name happens to contain the
//! seed token but the function's call site is independent of the
//! seed flow. Sink inside the function must NOT be tainted.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_reached, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_19(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "OT_19"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_19/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_reached(&result, fixture.sink),
        "[OT_19/{}] function with seed-substring name must not auto-taint sink `{}`; got {:?}",
        fixture.lang,
        fixture.sink,
        result.tainted_calls,
    );
}

#[test]
fn ot_19_python() {
    run_ot_19(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[(
            "a.py",
            "def users_by_name(p):\n    sink(p)\n\ndef entry(user):\n    users_by_name('admin')\n",
        )],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_javascript() {
    run_ot_19(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[(
            "a.js",
            "function usersByName(p) { sink(p); }\nfunction entry(user) { usersByName('admin'); }\n",
        )],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_typescript() {
    run_ot_19(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "function usersByName(p: string) { sink(p); }\nfunction entry(user: string) { usersByName('admin'); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_java() {
    run_ot_19(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Demo { void usersByName(String p) { sink(p); } void entry(String user) { usersByName(\"admin\"); } }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_kotlin() {
    run_ot_19(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[(
            "a.kt",
            "fun usersByName(p: String) { sink(p) }\nfun entry(user: String) { usersByName(\"admin\") }\n",
        )],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_scala() {
    run_ot_19(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "object Demo { def usersByName(p: String): Unit = sink(p); def entry(user: String): Unit = usersByName(\"admin\") }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_csharp() {
    run_ot_19(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Demo { void UsersByName(string p) { Sink(p); } void Entry(string user) { UsersByName(\"admin\"); } }\n")],
        entry: "Entry",
        seed: &["user"],
        sink: "Sink",
    });
}

#[test]
fn ot_19_go() {
    run_ot_19(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\nfunc usersByName(p string) { sink(p) }\nfunc entry(user string) { usersByName(\"admin\") }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_rust() {
    run_ot_19(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "fn users_by_name(p: String) { sink(p); }\nfn entry(user: String) { users_by_name(String::from(\"admin\")); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_c() {
    run_ot_19(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "void users_by_name(char *p) { sink(p); }\nvoid entry(char *user) { users_by_name(\"admin\"); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_cpp() {
    run_ot_19(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "void usersByName(const char *p) { sink(p); }\nvoid entry(const char *user) { usersByName(\"admin\"); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_objc() {
    run_ot_19(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "void usersByName(NSString *p) { sink(p); }\nvoid entry(NSString *user) { usersByName(@\"admin\"); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_ruby() {
    run_ot_19(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[(
            "a.rb",
            "def users_by_name(p)\n  sink(p)\nend\ndef entry(user)\n  users_by_name('admin')\nend\n",
        )],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_php() {
    run_ot_19(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nfunction users_by_name($p) { sink($p); }\nfunction entry($user) { users_by_name('admin'); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_perl() {
    run_ot_19(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "sub users_by_name { my ($p) = @_; sink($p); }\nsub entry { my ($user) = @_; users_by_name('admin'); }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_swift() {
    run_ot_19(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "func usersByName(p: String) { sink(p) }\nfunc entry(user: String) { usersByName(p: \"admin\") }\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_dart() {
    run_ot_19(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[(
            "a.dart",
            "void usersByName(String p) { sink(p); }\nvoid entry(String user) { usersByName('admin'); }\n",
        )],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_lua() {
    run_ot_19(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[("a.lua", "function users_by_name(p)\n  sink(p)\nend\nfunction entry(user)\n  users_by_name('admin')\nend\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_elixir() {
    run_ot_19(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def users_by_name(p) do\n    sink(p)\n  end\n  def entry(user) do\n    users_by_name(\"admin\")\n  end\nend\n")],
        entry: "entry",
        seed: &["user"],
        sink: "sink",
    });
}

#[test]
fn ot_19_erlang() {
    run_ot_19(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1, users_by_name/1]).\nusers_by_name(P) -> sink(P).\nentry(User) -> users_by_name(\"admin\").\n")],
        entry: "entry",
        seed: &["User"],
        sink: "sink",
    });
}
