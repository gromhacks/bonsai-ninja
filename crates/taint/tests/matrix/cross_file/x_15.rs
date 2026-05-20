//! X_15 — Module-level shadow: local wins.
//!
//! Positive: a same-name helper exists in another file and routes taint to
//! a decoy sink. The entry file defines the local helper and calls it
//! unqualified. The real sink must receive taint and the decoy sink must
//! stay clean, proving the resolver did not fan out to the imported/module
//! symbol.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_reached};
use bonsai_lang_api::AdapterArc;
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

struct ShadowFixture {
    lang: &'static str,
    adapter: AdapterArc,
    files: &'static [(&'static str, &'static str)],
    entry: &'static str,
    seed: &'static [&'static str],
    sink: &'static str,
    decoy_sink: &'static str,
}

fn run_shadow_cell(fixture: ShadowFixture) {
    match status(fixture.lang, "X_15") {
        Status::NotApplicable => return,
        Status::AdapterDeferred => panic!("X_15/{lang} must not be deferred", lang = fixture.lang),
        Status::Applicable => {}
    }

    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry).unwrap_or_else(|| {
        panic!(
            "[X_15/{lang}] entry `{entry}` should index",
            lang = fixture.lang,
            entry = fixture.entry
        )
    });
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);

    assert!(
        sink_reached(&result, fixture.sink),
        "[X_15/{lang}] local sink `{sink}` MUST receive taint from seed {seed:?}; got {calls:?}",
        lang = fixture.lang,
        sink = fixture.sink,
        seed = fixture.seed,
        calls = result.tainted_calls,
    );
    assert!(
        !sink_reached(&result, fixture.decoy_sink),
        "[X_15/{lang}] decoy sink `{sink}` MUST stay clean; resolver over-approximated shadowed callee; got {calls:?}",
        lang = fixture.lang,
        sink = fixture.decoy_sink,
        calls = result.tainted_calls,
    );
}

#[test]
fn x_15_python() {
    run_shadow_cell(ShadowFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[
            ("helper.py", "def helper(p):\n    decoy_sink(p)\n"),
            (
                "entry.py",
                "from helper import helper\n\ndef helper(p):\n    sink(p)\n\ndef entry(args):\n    helper(args)\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_javascript() {
    run_shadow_cell(ShadowFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[
            ("helper.js", "export function helper(p) { decoy_sink(p); }\n"),
            (
                "entry.js",
                "import './helper.js';\nexport function helper(p) { sink(p); }\nexport function entry(args) { helper(args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_typescript() {
    run_shadow_cell(ShadowFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[
            ("helper.ts", "export function helper(p: string) { decoy_sink(p); }\n"),
            (
                "entry.ts",
                "import './helper';\nexport function helper(p: string) { sink(p); }\nexport function entry(args: string) { helper(args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_java() {
    run_shadow_cell(ShadowFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[
            (
                "util/Helpers.java",
                "package util;\npublic class Helpers { public static void helper(String p) { decoySink(p); } }\n",
            ),
            (
                "Demo.java",
                "import static util.Helpers.helper;\nclass Demo { void entry(String args) { helper(args); } void helper(String p) { sink(p); } }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}

#[test]
fn x_15_kotlin() {
    run_shadow_cell(ShadowFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[
            ("src/util/Helpers.kt", "package util\nfun helper(p: String) { decoySink(p) }\n"),
            (
                "src/Demo.kt",
                "package app\nimport util.helper\nfun helper(p: String) { sink(p) }\nfun entry(args: String) { helper(args) }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}

#[test]
fn x_15_scala() {
    run_shadow_cell(ShadowFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[
            (
                "util/Helpers.scala",
                "package util\nobject Helpers { def helper(p: String): Unit = decoySink(p) }\n",
            ),
            (
                "Demo.scala",
                "import util.Helpers.helper\nobject Demo { def helper(p: String): Unit = sink(p); def entry(args: String): Unit = helper(args) }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}

#[test]
fn x_15_csharp() {
    run_shadow_cell(ShadowFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[
            (
                "Util/Helpers.cs",
                "namespace Util { class Helpers { public static void Helper(string p) { DecoySink(p); } } }\n",
            ),
            (
                "Demo.cs",
                "using static Util.Helpers;\nclass Demo { void Entry(string args) { Helper(args); } void Helper(string p) { Sink(p); } }\n",
            ),
        ],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
        decoy_sink: "DecoySink",
    });
}

#[test]
fn x_15_go() {
    run_shadow_cell(ShadowFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[(
            "entry.go",
            "package main\nfunc entry(args string) { sink(args) }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}

#[test]
fn x_15_rust() {
    run_shadow_cell(ShadowFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("entry.rs", "fn entry(args: String) { sink(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_c() {
    run_shadow_cell(ShadowFixture {
        lang: "c",
        adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
        files: &[
            ("helper.c", "void helper(char *p) { decoy_sink(p); }\n"),
            (
                "entry.c",
                "static void helper(char *p) { sink(p); }\nvoid entry(char *args) { helper(args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_cpp() {
    run_shadow_cell(ShadowFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[
            ("helper.cpp", "void helper(const char *p) { decoy_sink(p); }\n"),
            (
                "entry.cpp",
                "namespace { void helper(const char *p) { sink(p); } }\nvoid entry(const char *args) { helper(args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_objc() {
    run_shadow_cell(ShadowFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[
            ("Helper.m", "void helper(NSString *p) { decoy_sink(p); }\n"),
            (
                "Entry.m",
                "static void helper(NSString *p) { sink(p); }\nvoid entry(NSString *args) { helper(args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_ruby() {
    run_shadow_cell(ShadowFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[
            ("helper.rb", "def helper(p)\n  decoy_sink(p)\nend\n"),
            (
                "entry.rb",
                "require_relative 'helper'\ndef helper(p)\n  sink(p)\nend\ndef entry(args)\n  helper(args)\nend\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_php() {
    run_shadow_cell(ShadowFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[
            (
                "helper.php",
                "<?php\nnamespace Util;\nfunction helper($p) { \\decoy_sink($p); }\n",
            ),
            (
                "entry.php",
                "<?php\nuse function Util\\helper;\nfunction helper($p) { sink($p); }\nfunction entry($args) { helper($args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_perl() {
    run_shadow_cell(ShadowFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[
            (
                "Helper.pm",
                "package Helper;\nsub helper { my ($p) = @_; decoy_sink($p); }\n1;\n",
            ),
            (
                "entry.pl",
                "use Helper;\nsub helper { my ($p) = @_; sink($p); }\nsub entry { my ($args) = @_; helper($args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_swift() {
    run_shadow_cell(ShadowFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("src/Entry.swift", "func entry(args: String) { sink(args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}

#[test]
fn x_15_dart() {
    run_shadow_cell(ShadowFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[
            ("helper.dart", "void helper(String p) { decoySink(p); }\n"),
            (
                "entry.dart",
                "import 'helper.dart';\nvoid helper(String p) { sink(p); }\nvoid entry(String args) { helper(args); }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}

#[test]
fn x_15_lua() {
    run_shadow_cell(ShadowFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[
            ("helper.lua", "function helper(p)\n  decoy_sink(p)\nend\n"),
            (
                "entry.lua",
                "require('helper')\nfunction helper(p)\n  sink(p)\nend\nfunction entry(args)\n  helper(args)\nend\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_elixir() {
    run_shadow_cell(ShadowFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[
            (
                "helper.ex",
                "defmodule Helper do\n  def helper(p) do\n    decoy_sink(p)\n  end\nend\n",
            ),
            (
                "demo.ex",
                "defmodule Demo do\n  import Helper\n  def helper(p) do\n    sink(p)\n  end\n  def entry(args) do\n    helper(args)\n  end\nend\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_erlang() {
    run_shadow_cell(ShadowFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[
            (
                "helper.erl",
                "-module(helper).\n-export([helper/1]).\nhelper(P) -> decoy_sink(P).\n",
            ),
            (
                "demo.erl",
                "-module(demo).\n-import(helper, [helper/1]).\n-export([entry/1, helper/1]).\nhelper(P) -> sink(P).\nentry(Args) -> helper(Args).\n",
            ),
        ],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
        decoy_sink: "decoy_sink",
    });
}

#[test]
fn x_15_solidity() {
    run_shadow_cell(ShadowFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[
            (
                "Helper.sol",
                "contract Helper { function helper(string memory p) public { decoySink(p); } }\n",
            ),
            (
                "Demo.sol",
                "contract Demo { function helper(string memory p) internal { sink(p); } function entry(string memory args) public { helper(args); } }\n",
            ),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
        decoy_sink: "decoySink",
    });
}
