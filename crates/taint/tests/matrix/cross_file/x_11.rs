//! X_11 — Visibility crossing.
#![allow(unreachable_pub)]
use crate::helpers::{run_negative_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_11_c() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            files: &[
                ("util.c", "static void helper(char *p) { sink(p); }\n"),
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
fn x_11_cpp() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                ("util.cpp", "static void helper(const char *p) { sink(p); }\n"),
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
fn x_11_csharp() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[
                ("Util.cs", "namespace App { public class Util { private static void Helper(string p) { Sink.SinkFn(p); } } }\n"),
                ("Entry.cs", "namespace App { public class EntryType { public void Entry(string args) { Util.Helper(args); } } }\n"),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "SinkFn",
        },
    );
}

#[test]
fn x_11_dart() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("util.dart", "void _helper(String p) { sink(p); }\n"),
                (
                    "entry.dart",
                    "import 'util.dart' as util;\nvoid entry(String args) { util._helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_elixir() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            files: &[(
                "a.ex",
                "defmodule Demo do\n  def entry(args), do: sink(args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_erlang() {
    run_negative_cell(
        "X_11",
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
fn x_11_go() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[
                (
                    "util/util.go",
                    "package util\nfunc helper(p string) { sink(p) }\n",
                ),
                (
                    "entry/entry.go",
                    "package entry\nimport \"app/util\"\nfunc Entry(args string) { util.helper(args) }\n",
                ),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_java() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[
                ("Util.java", "package app;\npublic class Util { private static void helper(String p) { sink(p); } }\n"),
                ("Entry.java", "package app;\npublic class Entry { public void entry(String args) { Util.helper(args); } }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_javascript() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("hidden.js", "function helper(p) { sink(p); }\n"),
                (
                    "entry.js",
                    "import './hidden.js';\nexport function entry(args) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_kotlin() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                (
                    "Util.kt",
                    "package util\nprivate fun helper(p: String) { sink(p) }\n",
                ),
                (
                    "Entry.kt",
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
fn x_11_lua() {
    run_negative_cell(
        "X_11",
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
fn x_11_objc() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("util.m", "void _helper(NSString *p) { sink(p); }\n"),
                (
                    "entry.m",
                    "extern void _helper(NSString *p);\nvoid entry(NSString *args) { _helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_perl() {
    run_negative_cell(
        "X_11",
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
fn x_11_php() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                ("util.php", "<?php\nnamespace App;\nclass Util { private static function helper($p) { sink($p); } }\n"),
                ("entry.php", "<?php\nrequire_once 'util.php';\nuse App\\Util;\nfunction entry($args) { Util::helper($args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_python() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[("a.py", "def entry(args):\n    sink(args)\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_ruby() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                ("util.rb", "class Util\n  class << self\n    private\n    def helper(p)\n      sink(p)\n    end\n  end\nend\n"),
                ("entry.rb", "require_relative 'util'\n\ndef entry(args)\n  Util.helper(args)\nend\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_rust() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                ("util.rs", "fn helper(p: String) { sink(p); }\n"),
                (
                    "entry.rs",
                    "use crate::util::helper;\npub fn entry(args: String) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_scala() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                ("Util.scala", "package util\nobject Util { private def helper(p: String): Unit = sink(p) }\n"),
                ("Entry.scala", "import util.Util.helper\nobject Entry { def entry(args: String): Unit = helper(args) }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_solidity() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[
                ("Util.sol", "library Util { function helper(string memory p) private { sink(p); } }\n"),
                ("Entry.sol", "import './Util.sol';\ncontract Entry { function entry(string memory args) public { Util.helper(args); } }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_11_swift() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                ("src/Util.swift", "private func helper(p: String) { sink(p) }\n"),
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
fn x_11_typescript() {
    run_negative_cell(
        "X_11",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[
                ("hidden.ts", "function helper(p: string) { sink(p); }\n"),
                (
                    "entry.ts",
                    "import './hidden';\nexport function entry(args: string) { helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
