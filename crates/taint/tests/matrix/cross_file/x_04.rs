//! X_04 — Re-export / forwarding chain A -> B -> C.
//!
//! Positive: entry file A calls an exported/forwarded symbol in file B,
//! which delegates to the real helper in file C. The sink in C must
//! receive taint through the cross-file chain.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_04_python() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("leaf.py", "def helper(p):\n    sink(p)\n"),
                (
                    "middle.py",
                    "from leaf import helper\n\ndef exported(p):\n    helper(p)\n",
                ),
                (
                    "entry.py",
                    "from middle import exported\n\ndef entry(args):\n    exported(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_javascript() {
    run_positive_cell("X_04", LangFixture { lang: "javascript", adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files: &[("leaf.js", "export function helper(p) { sink(p); }\n"), ("middle.js", "import { helper } from './leaf.js';\nexport function exported(p) { helper(p); }\n"), ("entry.js", "import { exported } from './middle.js';\nexport function entry(args) { exported(args); }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_typescript() {
    run_positive_cell("X_04", LangFixture { lang: "typescript", adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files: &[("leaf.ts", "export function helper(p: string) { sink(p); }\n"), ("middle.ts", "import { helper } from './leaf';\nexport function exported(p: string) { helper(p); }\n"), ("entry.ts", "import { exported } from './middle';\nexport function entry(args: string) { exported(args); }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_java() {
    run_positive_cell("X_04", LangFixture { lang: "java", adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()), files: &[("Helper.java", "package app;\npublic class Helper { public static void helper(String p) { Sink.sink(p); } }\n"), ("Middle.java", "package app;\npublic class Middle { public static void exported(String p) { Helper.helper(p); } }\n"), ("Entry.java", "package app;\npublic class Entry { public void entry(String args) { Middle.exported(args); } }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_kotlin() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("leaf.kt", "package app\nfun helper(p: String) { sink(p) }\n"),
                (
                    "middle.kt",
                    "package app\nfun exported(p: String) { helper(p) }\n",
                ),
                (
                    "entry.kt",
                    "package app\nfun entry(args: String) { exported(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_scala() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                (
                    "Leaf.scala",
                    "package app\nobject Leaf { def helper(p: String): Unit = sink(p) }\n",
                ),
                (
                    "Middle.scala",
                    "package app\nobject Middle { def exported(p: String): Unit = Leaf.helper(p) }\n",
                ),
                (
                    "Entry.scala",
                    "package app\nobject Entry { def entry(args: String): Unit = Middle.exported(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_csharp() {
    run_positive_cell("X_04", LangFixture { lang: "csharp", adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files: &[("Leaf.cs", "namespace App { public static class Leaf { public static void Helper(string p) { Sink.SinkFn(p); } } }\n"), ("Middle.cs", "namespace App { public static class Middle { public static void Exported(string p) { Leaf.Helper(p); } } }\n"), ("Entry.cs", "namespace App { public class EntryClass { public void Entry(string args) { Middle.Exported(args); } } }\n")], entry: "Entry", seed: &["args"], sink: "SinkFn" });
}

#[test]
fn x_04_go() {
    run_positive_cell("X_04", LangFixture { lang: "go", adapter: Arc::new(bonsai_lang_go::GoAdapter::new()), files: &[("leaf/leaf.go", "package leaf\nfunc Helper(p string) { sink(p) }\n"), ("middle/middle.go", "package middle\nimport \"app/leaf\"\nfunc Exported(p string) { leaf.Helper(p) }\n"), ("entry/entry.go", "package entry\nimport \"app/middle\"\nfunc Entry(args string) { middle.Exported(args) }\n")], entry: "Entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_rust() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("leaf.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "middle.rs",
                    "use crate::leaf::helper;\npub fn exported(p: String) { helper(p); }\n",
                ),
                (
                    "entry.rs",
                    "use crate::middle::exported;\npub fn entry(args: String) { exported(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_c() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                ("leaf.c", "void helper(char *p) { sink(p); }\n"),
                (
                    "middle.c",
                    "extern void helper(char *p);\nvoid exported(char *p) { helper(p); }\n",
                ),
                (
                    "entry.c",
                    "extern void exported(char *p);\nvoid entry(char *args) { exported(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_cpp() {
    run_positive_cell("X_04", LangFixture { lang: "cpp", adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()), files: &[("leaf.cpp", "void helper(const char *p) { sink(p); }\n"), ("middle.cpp", "extern void helper(const char *p);\nvoid exported(const char *p) { helper(p); }\n"), ("entry.cpp", "extern void exported(const char *p);\nvoid entry(const char *args) { exported(args); }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_objc() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("leaf.m", "void helper(NSString *p) { sink(p); }\n"),
                (
                    "middle.m",
                    "extern void helper(NSString *p);\nvoid exported(NSString *p) { helper(p); }\n",
                ),
                (
                    "entry.m",
                    "extern void exported(NSString *p);\nvoid entry(NSString *args) { exported(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_ruby() {
    run_positive_cell("X_04", LangFixture { lang: "ruby", adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files: &[("leaf.rb", "module Leaf\n  def self.helper(p)\n    sink(p)\n  end\nend\n"), ("middle.rb", "require_relative 'leaf'\nmodule Middle\n  def self.exported(p)\n    Leaf.helper(p)\n  end\nend\n"), ("entry.rb", "require_relative 'middle'\ndef entry(args)\n  Middle.exported(args)\nend\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_php() {
    run_positive_cell("X_04", LangFixture { lang: "php", adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()), files: &[("leaf.php", "<?php\nnamespace App;\nclass Leaf { public static function helper($p) { sink($p); } }\n"), ("middle.php", "<?php\nnamespace App;\nclass Middle { public static function exported($p) { Leaf::helper($p); } }\n"), ("entry.php", "<?php\nrequire_once 'middle.php';\nuse App\\Middle;\nfunction entry($args) { Middle::exported($args); }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_perl() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[
                (
                    "Leaf.pm",
                    "package Leaf;\nsub helper { my ($p) = @_; sink($p); }\n1;\n",
                ),
                (
                    "Middle.pm",
                    "package Middle;\nsub exported { my ($p) = @_; Leaf::helper($p); }\n1;\n",
                ),
                (
                    "entry.pl",
                    "package main;\nsub entry { my ($args) = @_; Middle::exported($args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_swift() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                ("src/Leaf.swift", "public func helper(p: String) { sink(p) }\n"),
                (
                    "src/Middle.swift",
                    "public func exported(p: String) { helper(p: p) }\n",
                ),
                (
                    "src/Entry.swift",
                    "public func entry(args: String) { exported(p: args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_dart() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("leaf.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "middle.dart",
                    "import 'leaf.dart';\nvoid exported(String p) { helper(p); }\n",
                ),
                (
                    "entry.dart",
                    "import 'middle.dart';\nvoid entry(String args) { exported(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_lua() {
    run_positive_cell("X_04", LangFixture { lang: "lua", adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()), files: &[("leaf.lua", "local M = {}\nfunction M.helper(p)\n  sink(p)\nend\nreturn M\n"), ("middle.lua", "local leaf = require('leaf')\nlocal M = {}\nfunction M.exported(p)\n  leaf.helper(p)\nend\nreturn M\n"), ("entry.lua", "local middle = require('middle')\nfunction entry(args)\n  middle.exported(args)\nend\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn x_04_elixir() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[
                (
                    "leaf.ex",
                    "defmodule Leaf do\n  def helper(p), do: sink(p)\nend\n",
                ),
                (
                    "middle.ex",
                    "defmodule Middle do\n  def exported(p), do: Leaf.helper(p)\nend\n",
                ),
                (
                    "entry.ex",
                    "defmodule Entry do\n  def entry(args), do: Middle.exported(args)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_04_erlang() {
    run_positive_cell(
        "X_04",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[
                (
                    "leaf.erl",
                    "-module(leaf).\n-export([helper/1]).\nhelper(P) -> sink(P).\n",
                ),
                (
                    "middle.erl",
                    "-module(middle).\n-export([exported/1]).\nexported(P) -> leaf:helper(P).\n",
                ),
                (
                    "entry.erl",
                    "-module(entry).\n-export([entry/1]).\nentry(Args) -> middle:exported(Args).\n",
                ),
            ],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}
