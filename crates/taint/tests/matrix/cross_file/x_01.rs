//! X_01 — Direct import + call propagates across files.
//!
//! Positive: file A defines `helper(p) { sink(p) }`. File B imports
//! helper and calls `helper(args)` from `entry`. Sink in file A must
//! receive taint via the cross-file resolver.
//!
//! Per-language fan-out covers the import idioms each language uses.
//! n/a cells (e.g. solidity's pragma-only file model) skip via the
//! applicability table.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_01_python() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("helpers.py", "def helper(p):\n    sink(p)\n"),
                (
                    "entry.py",
                    "from helpers import helper\n\ndef entry(args):\n    helper(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_javascript() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("helpers.js", "export function helper(p) { sink(p); }\n"),
                (
                    "entry.js",
                    "import { helper } from './helpers.js';\nexport function entry(args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_typescript() {
    run_positive_cell("X_01", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[
            ("helpers.ts", "export function helper(p: string) { sink(p); }\n"),
            ("entry.ts", "import { helper } from './helpers';\nexport function entry(args: string) { helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_01_java() {
    run_positive_cell("X_01", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[
            ("Helpers.java", "package app;\npublic class Helpers { public static void helper(String p) { Sink.sink(p); } }\n"),
            ("Entry.java", "package app;\npublic class Entry { public void entry(String args) { Helpers.helper(args); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_01_kotlin() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("helpers.kt", "package app\nfun helper(p: String) { sink(p) }\n"),
                (
                    "entry.kt",
                    "package app\nfun entry(args: String) { helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_scala() {
    run_positive_cell("X_01", LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[
            ("Helpers.scala", "package app\nobject Helpers { def helper(p: String): Unit = sink(p) }\n"),
            ("Entry.scala", "package app\nimport Helpers.helper\nobject Entry { def entry(args: String): Unit = helper(args) }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_01_csharp() {
    run_positive_cell("X_01", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[
            ("Helpers.cs", "namespace App { public static class Helpers { public static void Helper(string p) { Sink.Sink(p); } } }\n"),
            ("Entry.cs", "using App;\nnamespace App { public class Entry { public void EntryFn(string args) { Helpers.Helper(args); } } }\n"),
        ],
        entry: "EntryFn",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn x_01_go() {
    run_positive_cell("X_01", LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[
            ("helpers/helpers.go", "package helpers\nfunc Helper(p string) { sink(p) }\n"),
            ("entry/entry.go", "package entry\nimport \"app/helpers\"\nfunc Entry(args string) { helpers.Helper(args) }\n"),
        ],
        entry: "Entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_01_rust() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("helpers.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::helpers::helper;\npub fn entry(args: String) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_c() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                ("helpers.c", "void helper(char *p) { sink(p); }\n"),
                (
                    "entry.c",
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
fn x_01_cpp() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                ("helpers.cpp", "void helper(const char *p) { sink(p); }\n"),
                (
                    "entry.cpp",
                    "extern void helper(const char *p);\nvoid entry(const char *args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_objc() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("helpers.m", "void helper(NSString *p) { sink(p); }\n"),
                (
                    "entry.m",
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
fn x_01_ruby() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                ("helpers.rb", "def helper(p)\n  sink(p)\nend\n"),
                (
                    "entry.rb",
                    "require_relative 'helpers'\n\ndef entry(args)\n  helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_php() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                ("helpers.php", "<?php\nfunction helper($p) { sink($p); }\n"),
                (
                    "entry.php",
                    "<?php\nrequire_once 'helpers.php';\nfunction entry($args) { helper($args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_perl() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[
                (
                    "Helpers.pm",
                    "package Helpers;\nsub helper { my ($p) = @_; sink($p); }\n1;\n",
                ),
                (
                    "entry.pl",
                    "use Helpers;\nsub entry { my ($args) = @_; Helpers::helper($args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_swift() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                ("Helpers.swift", "public func helper(p: String) { sink(p) }\n"),
                (
                    "Entry.swift",
                    "public func entry(args: String) { helper(p: args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_dart() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("helpers.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
                    "import 'helpers.dart';\nvoid entry(String args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_lua() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[
                (
                    "helpers.lua",
                    "local M = {}\nfunction M.helper(p)\n  sink(p)\nend\nreturn M\n",
                ),
                (
                    "entry.lua",
                    "local helpers = require('helpers')\nfunction entry(args)\n  helpers.helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_elixir() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[
                (
                    "helpers.ex",
                    "defmodule Helpers do\n  def helper(p) do\n    sink(p)\n  end\nend\n",
                ),
                (
                    "entry.ex",
                    "defmodule Entry do\n  def entry(args) do\n    Helpers.helper(args)\n  end\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_erlang() {
    run_positive_cell(
        "X_01",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[
                (
                    "helpers.erl",
                    "-module(helpers).\n-export([helper/1]).\nhelper(P) -> sink(P).\n",
                ),
                (
                    "entry.erl",
                    "-module(entry).\n-export([entry/1]).\nentry(Args) -> helpers:helper(Args).\n",
                ),
            ],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_01_solidity() {
    run_positive_cell("X_01", LangFixture {
        lang: "solidity",
        adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        files: &[
            ("Demo.sol", "contract Demo { function entry(string memory args) public { helper(args); } function helper(string memory p) internal { sink(p); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
