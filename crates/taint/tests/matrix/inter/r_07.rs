//! R_07 — Dotted module call propagates.
//!
//! Positive: `mod.func(args)` propagates taint from caller to
//! callee. Tests the resolver's qualified-name matching across
//! the languages that support module-namespaced calls.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_07_python() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("util.py", "def helper(p):\n    sink(p)\n"),
                ("a.py", "import util\n\ndef entry(args):\n    util.helper(args)\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_javascript() {
    run_positive_cell("R_07", LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[
            ("util.js", "export function helper(p) { sink(p); }\n"),
            ("a.js", "import * as util from './util.js';\nexport function entry(args) { util.helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_07_typescript() {
    run_positive_cell("R_07", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[
            ("util.ts", "export function helper(p: string) { sink(p); }\n"),
            ("a.ts", "import * as util from './util';\nexport function entry(args: string) { util.helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_07_java() {
    run_positive_cell("R_07", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[
            ("Util.java", "package app;\npublic class Util { public static void helper(String p) { Sink.sink(p); } }\n"),
            ("Demo.java", "package app;\npublic class Demo { void entry(String args) { Util.helper(args); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_07_kotlin() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("util.kt", "package util\nfun helper(p: String) { sink(p) }\n"),
                (
                    "a.kt",
                    "import util\nfun entry(args: String) { util.helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_scala() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                (
                    "Util.scala",
                    "package util\nobject Util { def helper(p: String): Unit = sink(p) }\n",
                ),
                (
                    "Demo.scala",
                    "import util.Util\nobject Demo { def entry(args: String): Unit = Util.helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_csharp() {
    run_positive_cell("R_07", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[
            ("Util.cs", "namespace App { public static class Util { public static void Helper(string p) { Sink.SinkFn(p); } } }\n"),
            ("Demo.cs", "using App;\nnamespace App { public class Demo { public void Entry(string args) { Util.Helper(args); } } }\n"),
        ],
        entry: "Entry",
        seed: &["args"],
        sink: "SinkFn",
    });
}

#[test]
fn r_07_go() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[
                (
                    "util/util.go",
                    "package util\nfunc Helper(p string) { sink(p) }\n",
                ),
                (
                    "entry/entry.go",
                    "package entry\nimport \"app/util\"\nfunc Entry(args string) { util.Helper(args) }\n",
                ),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_rust() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("util.rs", "pub fn helper(p: String) { sink(p); }\n"),
                ("a.rs", "fn entry(args: String) { crate::util::helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

// R_07 uses C extern declarations — same fixture as X_01 for plain C
#[test]
fn r_07_c() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                ("util.c", "void helper(char *p) { sink(p); }\n"),
                (
                    "a.c",
                    "extern void helper(char *p);\nvoid entry(char *args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_cpp() {
    run_positive_cell("R_07", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[
            ("util.cpp", "namespace util { void helper(const char *p) { sink(p); } }\n"),
            ("a.cpp", "namespace util { void helper(const char *p); }\nvoid entry(const char *args) { util::helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_07_objc() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("util.m", "void helper(NSString *p) { sink(p); }\n"),
                (
                    "a.m",
                    "extern void helper(NSString *p);\nvoid entry(NSString *args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_ruby() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                (
                    "util.rb",
                    "module Util\n  def self.helper(p)\n    sink(p)\n  end\nend\n",
                ),
                (
                    "a.rb",
                    "require_relative 'util'\n\ndef entry(args)\n  Util.helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_php() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                (
                    "util.php",
                    "<?php\nclass Util { public static function helper($p) { sink($p); } }\n",
                ),
                (
                    "a.php",
                    "<?php\nrequire_once 'util.php';\nfunction entry($args) { Util::helper($args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_perl() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[
                (
                    "Util.pm",
                    "package Util;\nsub helper { my ($p) = @_; sink($p); }\n1;\n",
                ),
                (
                    "a.pl",
                    "use Util;\nsub entry { my ($args) = @_; Util::helper($args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_swift() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                (
                    "Util.swift",
                    "public enum Util { public static func helper(p: String) { sink(p) } }\n",
                ),
                (
                    "Demo.swift",
                    "public func entry(args: String) { Util.helper(p: args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_dart() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("util.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "a.dart",
                    "import 'util.dart' as util;\nvoid entry(String args) { util.helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_lua() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[
                (
                    "util.lua",
                    "local M = {}\nfunction M.helper(p)\n  sink(p)\nend\nreturn M\n",
                ),
                (
                    "a.lua",
                    "local util = require('util')\nfunction entry(args)\n  util.helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_elixir() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[
                (
                    "util.ex",
                    "defmodule Util do\n  def helper(p) do\n    sink(p)\n  end\nend\n",
                ),
                (
                    "a.ex",
                    "defmodule Demo do\n  def entry(args) do\n    Util.helper(args)\n  end\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_erlang() {
    run_positive_cell(
        "R_07",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[
                (
                    "util.erl",
                    "-module(util).\n-export([helper/1]).\nhelper(P) -> sink(P).\n",
                ),
                (
                    "demo.erl",
                    "-module(demo).\n-export([entry/1]).\nentry(Args) -> util:helper(Args).\n",
                ),
            ],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_07_solidity() {
    run_positive_cell("R_07", LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[
            ("Demo.sol", "library Util { function helper(string memory p) internal pure { sink(p); } }\ncontract Demo { function entry(string memory args) public pure { Util.helper(args); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
