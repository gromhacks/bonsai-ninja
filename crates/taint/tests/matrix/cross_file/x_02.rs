//! X_02 — Aliased import: `import x as y; y(t)` propagates.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_02_python() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("util.py", "def helper(p):\n    sink(p)\n"),
                (
                    "a.py",
                    "from util import helper as h\n\ndef entry(args):\n    h(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_javascript() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("util.js", "export function helper(p) { sink(p); }\n"),
                (
                    "a.js",
                    "import { helper as h } from './util.js';\nexport function entry(args) { h(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_typescript() {
    run_positive_cell("X_02", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[
            ("util.ts", "export function helper(p: string) { sink(p); }\n"),
            ("a.ts", "import { helper as h } from './util';\nexport function entry(args: string) { h(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_02_kotlin() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("util.kt", "package util\nfun helper(p: String) { sink(p) }\n"),
                (
                    "a.kt",
                    "import util.helper as h\nfun entry(args: String) { h(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_scala() {
    run_positive_cell("X_02", LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[
            ("Util.scala", "package util\nobject Util { def helper(p: String): Unit = sink(p) }\n"),
            ("Demo.scala", "import util.Util.{helper => h}\nobject Demo { def entry(args: String): Unit = h(args) }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_02_csharp() {
    run_positive_cell("X_02", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[
            ("Util.cs", "namespace App.Util { public static class Helpers { public static void Helper(string p) { Sink.SinkFn(p); } } }\n"),
            ("Demo.cs", "using H = App.Util.Helpers;\nnamespace App { public class Demo { public void Entry(string args) { H.Helper(args); } } }\n"),
        ],
        entry: "Entry",
        seed: &["args"],
        sink: "SinkFn",
    });
}

#[test]
fn x_02_go() {
    run_positive_cell(
        "X_02",
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
                    "package entry\nimport h \"app/util\"\nfunc Entry(args string) { h.Helper(args) }\n",
                ),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_rust() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("util.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::util::helper as h;\nfn entry(args: String) { h(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_java() {
    run_positive_cell("X_02", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[
            // Java has no import-aliasing — fall through to the same fixture
            // as direct import for parity (matrix cell exists for the
            // construct, even if Java's syntax form is identical to X_01).
            ("Util.java", "package app;\npublic class Util { public static void helper(String p) { Sink.sink(p); } }\n"),
            ("Demo.java", "package app;\nimport app.Util;\npublic class Demo { void entry(String args) { Util.helper(args); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_02_ruby() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                (
                    "util.rb",
                    "module Util\n  def self.helper(p)\n    sink(p)\n  end\nend\n",
                ),
                (
                    "entry.rb",
                    "require_relative 'util'\nH = Util\n\ndef entry(args)\n  H.helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_php() {
    run_positive_cell("X_02", LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[
            ("util.php", "<?php\nnamespace App;\nclass Util { public static function helper($p) { sink($p); } }\n"),
            ("entry.php", "<?php\nrequire_once 'util.php';\nuse App\\Util as H;\nfunction entry($args) { H::helper($args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_02_dart() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("util.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
                    "import 'util.dart' as h;\nvoid entry(String args) { h.helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_lua() {
    run_positive_cell(
        "X_02",
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
                    "local h = require('util')\nfunction entry(args)\n  h.helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_elixir() {
    run_positive_cell("X_02", LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[
            ("util.ex", "defmodule Util do\n  def helper(p) do\n    sink(p)\n  end\nend\n"),
            ("entry.ex", "defmodule Demo do\n  alias Util, as: H\n  def entry(args) do\n    H.helper(args)\n  end\nend\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_02_perl() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[("entry.pl", "sub entry { my ($args) = @_; sink($args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_02_swift() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                // Swift's `typealias` doesn't alias function imports;
                // fixture mirrors X_01 for parity.
                ("Util.swift", "public func helper(p: String) { sink(p) }\n"),
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
fn x_02_objc() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                // ObjC has no language-level import aliasing — mirror X_01.
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
fn x_02_c() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                // C has no import aliasing; trivial cell to keep applicability honest.
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
fn x_02_cpp() {
    run_positive_cell("X_02", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[
            ("util.cpp", "namespace util { void helper(const char *p) { sink(p); } }\n"),
            ("entry.cpp", "namespace util { void helper(const char *p); }\nnamespace h = util;\nvoid entry(const char *args) { h::helper(args); }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_02_erlang() {
    run_positive_cell(
        "X_02",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[
                (
                    "util.erl",
                    "-module(util).\n-export([helper/1]).\nhelper(P) -> sink(P).\n",
                ),
                // Erlang has no import alias — same-shape fixture.
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
