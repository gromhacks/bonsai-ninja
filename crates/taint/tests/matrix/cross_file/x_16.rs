//! X_16 — Multi-file fan-in to same callee.
//!
//! Positive: `entry` and an unrelated sibling live in different files and
//! both call the same helper. The tainted `entry` argument must reach the
//! helper's sink through the cross-file resolver without relying on a
//! single-file placeholder.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_16_python() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("helper.py", "def helper(p):\n    sink(p)\n"),
                (
                    "entry.py",
                    "from helper import helper\n\ndef entry(args):\n    helper(args)\n",
                ),
                (
                    "sibling.py",
                    "from helper import helper\n\ndef sibling(clean):\n    helper(clean)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_javascript() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("helper.js", "export function helper(p) { sink(p); }\n"),
                (
                    "entry.js",
                    "import { helper } from './helper.js';\nexport function entry(args) { helper(args); }\n",
                ),
                (
                    "sibling.js",
                    "import { helper } from './helper.js';\nexport function sibling(clean) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_typescript() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[
                ("helper.ts", "export function helper(p: string) { sink(p); }\n"),
                (
                    "entry.ts",
                    "import { helper } from './helper';\nexport function entry(args: string) { helper(args); }\n",
                ),
                (
                    "sibling.ts",
                    "import { helper } from './helper';\nexport function sibling(clean: string) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_java() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[
                (
                    "Helper.java",
                    "package app;\npublic class Helper { public static void helper(String p) { Sink.sink(p); } }\n",
                ),
                (
                    "Entry.java",
                    "package app;\npublic class Entry { public void entry(String args) { Helper.helper(args); } }\n",
                ),
                (
                    "Sibling.java",
                    "package app;\npublic class Sibling { public void sibling(String clean) { Helper.helper(clean); } }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_kotlin() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                ("helper.kt", "package app\nfun helper(p: String) { sink(p) }\n"),
                (
                    "entry.kt",
                    "package app\nfun entry(args: String) { helper(args) }\n",
                ),
                (
                    "sibling.kt",
                    "package app\nfun sibling(clean: String) { helper(clean) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_scala() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                (
                    "Helper.scala",
                    "package app\nobject Helper { def helper(p: String): Unit = sink(p) }\n",
                ),
                (
                    "Entry.scala",
                    "package app\nobject Entry { def entry(args: String): Unit = Helper.helper(args) }\n",
                ),
                (
                    "Sibling.scala",
                    "package app\nobject Sibling { def sibling(clean: String): Unit = Helper.helper(clean) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_csharp() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[
                (
                    "Helper.cs",
                    "namespace App { public static class Helper { public static void HelperFn(string p) { Sink.SinkFn(p); } } }\n",
                ),
                (
                    "Entry.cs",
                    "namespace App { public class EntryClass { public void Entry(string args) { Helper.HelperFn(args); } } }\n",
                ),
                (
                    "Sibling.cs",
                    "namespace App { public class SiblingClass { public void Sibling(string clean) { Helper.HelperFn(clean); } } }\n",
                ),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "SinkFn",
        },
    );
}

#[test]
fn x_16_go() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[
                (
                    "helper/helper.go",
                    "package helper\nfunc Helper(p string) { sink(p) }\n",
                ),
                (
                    "entry/entry.go",
                    "package entry\nimport \"app/helper\"\nfunc Entry(args string) { helper.Helper(args) }\n",
                ),
                (
                    "sibling/sibling.go",
                    "package sibling\nimport \"app/helper\"\nfunc Sibling(clean string) { helper.Helper(clean) }\n",
                ),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_rust() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("helper.rs", "pub fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::helper::helper;\npub fn entry(args: String) { helper(args); }\n",
                ),
                (
                    "sibling.rs",
                    "use crate::helper::helper;\npub fn sibling(clean: String) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_c() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                ("helper.c", "void helper(char *p) { sink(p); }\n"),
                (
                    "entry.c",
                    "extern void helper(char *p);\nvoid entry(char *args) { helper(args); }\n",
                ),
                (
                    "sibling.c",
                    "extern void helper(char *p);\nvoid sibling(char *clean) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_cpp() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                ("helper.cpp", "void helper(const char *p) { sink(p); }\n"),
                (
                    "entry.cpp",
                    "extern void helper(const char *p);\nvoid entry(const char *args) { helper(args); }\n",
                ),
                (
                    "sibling.cpp",
                    "extern void helper(const char *p);\nvoid sibling(const char *clean) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_objc() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("helper.m", "void helper(NSString *p) { sink(p); }\n"),
                (
                    "entry.m",
                    "extern void helper(NSString *p);\nvoid entry(NSString *args) { helper(args); }\n",
                ),
                (
                    "sibling.m",
                    "extern void helper(NSString *p);\nvoid sibling(NSString *clean) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_ruby() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                ("helper.rb", "def helper(p)\n  sink(p)\nend\n"),
                (
                    "entry.rb",
                    "require_relative 'helper'\n\ndef entry(args)\n  helper(args)\nend\n",
                ),
                (
                    "sibling.rb",
                    "require_relative 'helper'\n\ndef sibling(clean)\n  helper(clean)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_php() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                ("helper.php", "<?php\nfunction helper($p) { sink($p); }\n"),
                (
                    "entry.php",
                    "<?php\nrequire_once 'helper.php';\nfunction entry($args) { helper($args); }\n",
                ),
                (
                    "sibling.php",
                    "<?php\nrequire_once 'helper.php';\nfunction sibling($clean) { helper($clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_perl() {
    run_positive_cell(
        "X_16",
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
                (
                    "sibling.pl",
                    "use Helpers;\nsub sibling { my ($clean) = @_; Helpers::helper($clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_swift() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                ("src/Helper.swift", "public func helper(p: String) { sink(p) }\n"),
                (
                    "src/Entry.swift",
                    "public func entry(args: String) { helper(p: args) }\n",
                ),
                (
                    "src/Sibling.swift",
                    "public func sibling(clean: String) { helper(p: clean) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_dart() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("helper.dart", "void helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
                    "import 'helper.dart';\nvoid entry(String args) { helper(args); }\n",
                ),
                (
                    "sibling.dart",
                    "import 'helper.dart';\nvoid sibling(String clean) { helper(clean); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_lua() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[
                (
                    "helper.lua",
                    "local M = {}\nfunction M.helper(p)\n  sink(p)\nend\nreturn M\n",
                ),
                (
                    "entry.lua",
                    "local helper = require('helper')\nfunction entry(args)\n  helper.helper(args)\nend\n",
                ),
                (
                    "sibling.lua",
                    "local helper = require('helper')\nfunction sibling(clean)\n  helper.helper(clean)\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_elixir() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[
                (
                    "helper.ex",
                    "defmodule Helper do\n  def helper(p) do\n    sink(p)\n  end\nend\n",
                ),
                (
                    "entry.ex",
                    "defmodule Entry do\n  def entry(args) do\n    Helper.helper(args)\n  end\nend\n",
                ),
                (
                    "sibling.ex",
                    "defmodule Sibling do\n  def sibling(clean) do\n    Helper.helper(clean)\n  end\nend\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_erlang() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            files: &[
                (
                    "helper.erl",
                    "-module(helper).\n-export([helper/1]).\nhelper(P) -> sink(P).\n",
                ),
                (
                    "entry.erl",
                    "-module(entry).\n-export([entry/1]).\nentry(Args) -> helper:helper(Args).\n",
                ),
                (
                    "sibling.erl",
                    "-module(sibling).\n-export([sibling/1]).\nsibling(Clean) -> helper:helper(Clean).\n",
                ),
            ],
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_16_solidity() {
    run_positive_cell(
        "X_16",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[
                (
                    "Helper.sol",
                    "pragma solidity ^0.8.0;\ncontract Helper { function helper(string memory p) public { sink(p); } }\n",
                ),
                (
                    "Entry.sol",
                    "pragma solidity ^0.8.0;\nimport './Helper.sol';\ncontract Entry { Helper helperContract; function entry(string memory args) public { helperContract.helper(args); } }\n",
                ),
                (
                    "Sibling.sol",
                    "pragma solidity ^0.8.0;\nimport './Helper.sol';\ncontract Sibling { Helper helperContract; function sibling(string memory clean) public { helperContract.helper(clean); } }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
