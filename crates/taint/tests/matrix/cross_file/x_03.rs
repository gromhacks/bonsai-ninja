//! X_03 — From-import: `from m import f` propagates.
//!
//! Positive: bare-name call after a from-import resolves to the
//! module's exported function. Tests the resolver's from-import
//! aliasing across languages that have the construct.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_03_python() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("util.py", "def helper(p):\n    sink(p)\n"),
                (
                    "a.py",
                    "from util import helper\n\ndef entry(args):\n    helper(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_javascript() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("util.js", "export function helper(p) { sink(p); }\n"),
                (
                    "a.js",
                    "import { helper } from './util.js';\nexport function entry(args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_typescript() {
    run_positive_cell("X_03", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[
            ("util.ts", "export function helper(p: string) { sink(p); }\n"),
            ("a.ts", "import { helper } from './util';\nexport function entry(args: string) { helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_03_java() {
    run_positive_cell("X_03", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[
            ("Util.java", "package app;\npublic class Util { public static void helper(String p) { Sink.sink(p); } }\n"),
            ("Demo.java", "package app;\nimport static app.Util.helper;\npublic class Demo { void entry(String args) { helper(args); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_03_kotlin() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("util.kt", "package util\nfun helper(p: String) { sink(p) }\n"),
                (
                    "a.kt",
                    "import util.helper\nfun entry(args: String) { helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_scala() {
    run_positive_cell(
        "X_03",
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
                    "import util.Util.helper\nobject Demo { def entry(args: String): Unit = helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_csharp() {
    run_positive_cell("X_03", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[
            ("Util.cs", "namespace App { public static class Util { public static void Helper(string p) { Sink.SinkFn(p); } } }\n"),
            ("Demo.cs", "using static App.Util;\nnamespace App { public class Demo { public void Entry(string args) { Helper(args); } } }\n"),
        ],
        entry: "Entry",
        seed: &["args"],
        sink: "SinkFn",
    });
}

#[test]
fn x_03_go() {
    run_positive_cell(
        "X_03",
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
                    "package entry\nimport . \"app/util\"\nfunc Entry(args string) { Helper(args) }\n",
                ),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_rust() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("util.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::util::helper;\nfn entry(args: String) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_c() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                ("util.c", "void helper(char *p) { sink(p); }\n"),
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
fn x_03_cpp() {
    run_positive_cell("X_03", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[
            ("util.cpp", "namespace util { void helper(const char *p) { sink(p); } }\n"),
            ("entry.cpp", "namespace util { void helper(const char *p); }\nusing util::helper;\nvoid entry(const char *args) { helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_03_objc() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("util.m", "void helper(NSString *p) { sink(p); }\n"),
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
fn x_03_ruby() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                ("util.rb", "def helper(p)\n  sink(p)\nend\n"),
                (
                    "entry.rb",
                    "require_relative 'util'\n\ndef entry(args)\n  helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_php() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                ("util.php", "<?php\nfunction helper($p) { sink($p); }\n"),
                (
                    "entry.php",
                    "<?php\nrequire_once 'util.php';\nfunction entry($args) { helper($args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_perl() {
    run_positive_cell("X_03", LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[
            ("Util.pm", "package Util;\nuse Exporter 'import';\nour @EXPORT_OK = ('helper');\nsub helper { my ($p) = @_; sink($p); }\n1;\n"),
            ("entry.pl", "use Util qw(helper);\nsub entry { my ($args) = @_; helper($args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_03_swift() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                ("src/Util.swift", "public func helper(p: String) { sink(p) }\n"),
                (
                    "src/Entry.swift",
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
fn x_03_dart() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("util.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
                    "import 'util.dart' show helper;\nvoid entry(String args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_lua() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[
                (
                    "util.lua",
                    "local M = {}\nfunction M.helper(p)\n  sink(p)\nend\nreturn M\n",
                ),
                (
                    "entry.lua",
                    "local helper = require('util').helper\nfunction entry(args)\n  helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_elixir() {
    run_positive_cell(
        "X_03",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[
                (
                    "util.ex",
                    "defmodule Util do\n  def helper(p) do\n    sink(p)\n  end\nend\n",
                ),
                (
                    "entry.ex",
                    "defmodule Demo do\n  import Util\n  def entry(args) do\n    helper(args)\n  end\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_03_erlang() {
    run_positive_cell("X_03", LangFixture {
        lang: "erlang",
        adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        files: &[
            ("util.erl", "-module(util).\n-export([helper/1]).\nhelper(P) -> sink(P).\n"),
            ("demo.erl", "-module(demo).\n-import(util, [helper/1]).\n-export([entry/1]).\nentry(Args) -> helper(Args).\n"),
        ],
        entry: "entry",
        seed: &["Args"],
        sink: "sink",
    });
}

#[test]
fn x_03_solidity() {
    run_positive_cell("X_03", LangFixture {
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
