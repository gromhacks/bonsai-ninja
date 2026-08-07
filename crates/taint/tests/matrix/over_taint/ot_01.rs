//! OT_01 — Sibling field read stays clean.
//!
//! Negative: `obj.tainted_field = args; sink(obj.clean_field)`.
//! The sink reads a sibling field that was never written, so taint
//! must NOT propagate to it. Locks the field-aware precision boundary
//! so over-taint can't bridge sibling fields.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_text, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_01(fixture: LangFixture, sink_arg_clean: &[&str]) {
    if matches!(
        status(fixture.lang, "OT_01"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_01/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    for clean_text in sink_arg_clean {
        assert!(
            !sink_received_arg_text(&result, fixture.sink, clean_text),
            "[OT_01/{}] sink `{}` arg `{}` (sibling field) MUST stay clean; got {:?}",
            fixture.lang,
            fixture.sink,
            clean_text,
            result.tainted_calls,
        );
    }
}

#[test]
fn ot_01_python() {
    run_ot_01(
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):\n    obj = {}\n    obj['value'] = args\n    sink(obj['other'])\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["obj['other']", "obj.other"],
    );
}

#[test]
fn ot_01_javascript() {
    run_ot_01(
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { let obj = {}; obj.value = args; sink(obj.other); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["obj.other", "obj['other']"],
    );
}

#[test]
fn ot_01_typescript() {
    run_ot_01(
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { let obj: any = {}; obj.value = args; sink(obj.other); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["obj.other", "obj['other']"],
    );
}

#[test]
fn ot_01_java() {
    run_ot_01(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Box { public String value; public String other; }\nclass Demo { void entry(String args) { Box obj = new Box(); obj.value = args; sink(obj.other); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_kotlin() {
    run_ot_01(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "class Box { var value: String? = null; var other: String? = null }\nfun entry(args: String) { val obj = Box(); obj.value = args; sink(obj.other) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_scala() {
    run_ot_01(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "class Box(var value: String, var other: String)\nobject Demo { def entry(args: String): Unit = { val obj = new Box(\"\", \"\"); obj.value = args; sink(obj.other) } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_csharp() {
    run_ot_01(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Box { public string Value; public string Other; }\nclass Demo { void Entry(string args) { var obj = new Box(); obj.Value = args; Sink(obj.Other); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    }, &["obj.Other"]);
}

#[test]
fn ot_01_go() {
    run_ot_01(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\ntype Box struct { Value, Other string }\nfunc entry(args string) { obj := Box{}; obj.Value = args; sink(obj.Other) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.Other"]);
}

#[test]
fn ot_01_rust() {
    run_ot_01(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "struct Box { value: String, other: String }\nfn entry(args: String) { let mut obj = Box { value: String::new(), other: String::new() }; obj.value = args; sink(obj.other); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_c() {
    run_ot_01(LangFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[("a.c", "struct Box { char *value; char *other; };\nvoid entry(char *args) { struct Box obj; obj.value = args; sink(obj.other); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_cpp() {
    run_ot_01(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "struct Box { const char *value; const char *other; };\nvoid entry(const char *args) { Box obj; obj.value = args; sink(obj.other); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_objc() {
    run_ot_01(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "@interface Box : NSObject\n@property NSString *value;\n@property NSString *other;\n@end\nvoid entry(NSString *args) { Box *obj = [[Box alloc] init]; obj.value = args; sink(obj.other); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_ruby() {
    run_ot_01(
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)\n  obj = {}\n  obj[:value] = args\n  sink(obj[:other])\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["obj[:other]", "obj.other"],
    );
}

#[test]
fn ot_01_php() {
    run_ot_01(
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction entry($args) { $obj = []; $obj['value'] = $args; sink($obj['other']); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["$obj['other']"],
    );
}

#[test]
fn ot_01_perl() {
    run_ot_01(
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; my %obj; $obj{value} = $args; sink($obj{other}); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["$obj{other}"],
    );
}

#[test]
fn ot_01_swift() {
    run_ot_01(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "class Box { var value: String = \"\"; var other: String = \"\" }\nfunc entry(args: String) { let obj = Box(); obj.value = args; sink(obj.other) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_dart() {
    run_ot_01(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "class Box { String? value; String? other; }\nvoid entry(String args) { var obj = Box(); obj.value = args; sink(obj.other); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_lua() {
    run_ot_01(
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)\n  local obj = {}\n  obj.value = args\n  sink(obj.other)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        &["obj.other"],
    );
}

#[test]
fn ot_01_elixir() {
    run_ot_01(LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Demo do\n  def entry(args) do\n    obj = %{value: args, other: \"\"}\n    sink(obj.other)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    }, &["obj.other"]);
}

#[test]
fn ot_01_erlang() {
    run_ot_01(LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[("demo.erl", "-module(demo).\n-export([entry/1]).\nentry(Args) -> Obj = #{value => Args, other => \"\"}, sink(maps:get(other, Obj)).\n")],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    }, &["maps:get(other, Obj)"]);
}
