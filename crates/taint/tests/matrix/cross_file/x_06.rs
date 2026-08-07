//! X_06 — Namespace import.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_06_c() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[("a.c", "void entry(char *args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_cpp() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                ("util.cpp", "namespace util { void helper(const char *p) { sink(p); } }\n"),
                ("entry.cpp", "namespace util { void helper(const char *p); }\nnamespace u = util;\nvoid entry(const char *args) { u::helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_csharp() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[
                ("Util.cs", "namespace App.Util { public static class Helpers { public static void Helper(string p) { Sink.SinkFn(p); } } }\n"),
                ("Entry.cs", "using U = App.Util.Helpers;\nnamespace App { public class EntryType { public void Entry(string args) { U.Helper(args); } } }\n"),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "SinkFn",
        },
    );
}

#[test]
fn x_06_dart() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("util.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
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
fn x_06_elixir() {
    run_positive_cell(
        "X_06",
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
                    "defmodule Entry do\n  alias Util\n  def entry(args), do: Util.helper(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_erlang() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[(
                "a.erl",
                "-module(a).\n-export([entry/1]).\nentry(Args) -> sink(Args).\n",
            )],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_go() {
    run_positive_cell(
        "X_06",
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
fn x_06_java() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[
                ("Util.java", "package app;\npublic class Util { public static void helper(String p) { sink(p); } }\n"),
                ("Entry.java", "package app;\nimport app.Util;\npublic class Entry { public void entry(String args) { Util.helper(args); } }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_javascript() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("util.js", "export function helper(p) { sink(p); }\n"),
                ("entry.js", "import * as util from './util.js';\nexport function entry(args) { util.helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_kotlin() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                (
                    "util.kt",
                    "package util\nobject Util { fun helper(p: String) { sink(p) } }\n",
                ),
                (
                    "entry.kt",
                    "import util.Util\nfun entry(args: String) { Util.helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_lua() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[("a.lua", "function entry(args)\n  sink(args)\nend\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_objc() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[("a.m", "void entry(NSString *args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_perl() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[("a.pl", "sub entry { my ($args) = @_; sink($args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_php() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                ("util.php", "<?php\nnamespace App;\nclass Util { public static function helper($p) { sink($p); } }\n"),
                ("entry.php", "<?php\nrequire_once 'util.php';\nuse App\\Util;\nfunction entry($args) { Util::helper($args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_python() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("util.py", "def helper(p):\n    sink(p)\n"),
                (
                    "entry.py",
                    "import util\n\ndef entry(args):\n    util.helper(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_ruby() {
    run_positive_cell(
        "X_06",
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
fn x_06_rust() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("util.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::util;\npub fn entry(args: String) { util::helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_scala() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                (
                    "Util.scala",
                    "package util\nobject Util { def helper(p: String): Unit = sink(p) }\n",
                ),
                (
                    "Entry.scala",
                    "import util.Util\nobject Entry { def entry(args: String): Unit = Util.helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_swift() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[("a.swift", "func entry(args: String) { sink(args) }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_06_typescript() {
    run_positive_cell(
        "X_06",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[
                ("util.ts", "export function helper(p: string) { sink(p); }\n"),
                ("entry.ts", "import * as util from './util';\nexport function entry(args: string) { util.helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
