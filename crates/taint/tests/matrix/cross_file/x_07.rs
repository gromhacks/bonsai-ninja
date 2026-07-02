//! X_07 — Wildcard import/load exposes unqualified symbols.
//!
//! Positive: file A defines `helper(p) { sink(p) }`. File B uses the
//! language's unqualified wildcard import/load form and calls
//! `helper(args)` without a namespace qualifier. The resolver must
//! constrain the bare call to the imported module instead of falling
//! back to workspace-wide name matching.
#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_07_cpp() {
    run_positive_cell(
        "X_07",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                ("util.cpp", "namespace util { void helper(const char *p) { sink(p); } }\n"),
                (
                    "entry.cpp",
                    "namespace util { void helper(const char *p); }\nusing namespace util;\nvoid entry(const char *args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_07_csharp() {
    run_positive_cell("X_07", LangFixture {
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
fn x_07_dart() {
    run_positive_cell(
        "X_07",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("util.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
                    "import 'util.dart';\nvoid entry(String args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_07_elixir() {
    run_positive_cell(
        "X_07",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[
                (
                    "util.ex",
                    "defmodule Util do\n  def helper(p), do: sink(p)\nend\n",
                ),
                (
                    "entry.ex",
                    "defmodule Entry do\n  import Util\n  def entry(args), do: helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_07_go() {
    run_positive_cell(
        "X_07",
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
fn x_07_java() {
    run_positive_cell("X_07", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[
            ("Util.java", "package app;\npublic class Util { public static void helper(String p) { sink(p); } }\n"),
            ("Demo.java", "package app;\nimport static app.Util.*;\npublic class Demo { void entry(String args) { helper(args); } }\n"),
        ],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn x_07_kotlin() {
    run_positive_cell(
        "X_07",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("util.kt", "package util\nfun helper(p: String) { sink(p) }\n"),
                (
                    "a.kt",
                    "import util.*\nfun entry(args: String) { helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_07_php() {
    run_positive_cell(
        "X_07",
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
fn x_07_python() {
    run_positive_cell(
        "X_07",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("util.py", "def helper(p):\n    sink(p)\n"),
                (
                    "entry.py",
                    "from util import *\n\ndef entry(args):\n    helper(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_07_ruby() {
    run_positive_cell(
        "X_07",
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
fn x_07_rust() {
    run_positive_cell(
        "X_07",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("util.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::util::*;\npub fn entry(args: String) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_07_scala() {
    run_positive_cell(
        "X_07",
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
                    "import util.Util._\nobject Demo { def entry(args: String): Unit = helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
