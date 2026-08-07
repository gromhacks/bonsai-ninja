//! X_14 — Static method on imported class.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_14_c() {
    run_positive_cell(
        "X_14",
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
fn x_14_cpp() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                (
                    "Util.hpp",
                    "class Util { public: static void helper(const char *p) { sink(p); } };\n",
                ),
                (
                    "Entry.cpp",
                    "#include \"Util.hpp\"\nvoid entry(const char *args) { Util::helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_csharp() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[
                ("Util.cs", "namespace App { public class Util { public static void Helper(string p) { Sink.SinkFn(p); } } }\n"),
                ("Entry.cs", "namespace App { public class EntryType { public void Entry(string args) { Util.Helper(args); } } }\n"),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "SinkFn",
        },
    );
}

#[test]
fn x_14_dart() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                (
                    "util.dart",
                    "class Util { static void helper(String p) { sink(p); } }\n",
                ),
                (
                    "entry.dart",
                    "import 'util.dart';\nvoid entry(String args) { Util.helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_elixir() {
    run_positive_cell(
        "X_14",
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
fn x_14_erlang() {
    run_positive_cell(
        "X_14",
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
fn x_14_go() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            files: &[("a.go", "package main\nfunc entry(args string) { sink(args) }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_java() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[
                ("Util.java", "package app;\npublic class Util { public static void helper(String p) { sink(p); } }\n"),
                ("Entry.java", "package app;\npublic class Entry { public void entry(String args) { Util.helper(args); } }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_javascript() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("util.js", "export class Util { static helper(p) { sink(p); } }\n"),
                (
                    "entry.js",
                    "import { Util } from './util.js';\nexport function entry(args) { Util.helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_kotlin() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                (
                    "Util.kt",
                    "package app\nobject Util { fun helper(p: String) { sink(p) } }\n",
                ),
                (
                    "Entry.kt",
                    "package app\nfun entry(args: String) { Util.helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_lua() {
    run_positive_cell(
        "X_14",
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
fn x_14_objc() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("Util.m", "@interface Util : NSObject\n+ (void)helper:(NSString *)p;\n@end\n@implementation Util\n+ (void)helper:(NSString *)p { sink(p); }\n@end\n"),
                ("Entry.m", "@interface Util : NSObject\n+ (void)helper:(NSString *)p;\n@end\nvoid entry(NSString *args) { [Util helper:args]; }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_perl() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[
                (
                    "Util.pm",
                    "package Util;\nsub helper { my ($p) = @_; sink($p); }\n1;\n",
                ),
                (
                    "entry.pl",
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
fn x_14_php() {
    run_positive_cell(
        "X_14",
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
fn x_14_python() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                (
                    "util.py",
                    "class Util:\n    @staticmethod\n    def helper(p):\n        sink(p)\n",
                ),
                (
                    "entry.py",
                    "from util import Util\n\ndef entry(args):\n    Util.helper(args)\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_ruby() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                (
                    "util.rb",
                    "class Util\n  def self.helper(p)\n    sink(p)\n  end\nend\n",
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
fn x_14_rust() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[
                (
                    "util.rs",
                    "pub struct Util;\nimpl Util { pub fn helper(p: String) { sink(p); } }\n",
                ),
                (
                    "entry.rs",
                    "use crate::util::Util;\npub fn entry(args: String) { Util::helper(args); }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_scala() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                (
                    "Util.scala",
                    "package app\nobject Util { def helper(p: String): Unit = sink(p) }\n",
                ),
                (
                    "Entry.scala",
                    "package app\nobject Entry { def entry(args: String): Unit = Util.helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_14_swift() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                (
                    "src/Util.swift",
                    "public class Util { public static func helper(p: String) { sink(p) } }\n",
                ),
                (
                    "src/Entry.swift",
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
fn x_14_typescript() {
    run_positive_cell(
        "X_14",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[
                ("util.ts", "export class Util { static helper(p: string) { sink(p); } }\n"),
                ("entry.ts", "import { Util } from './util';\nexport function entry(args: string) { Util.helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
