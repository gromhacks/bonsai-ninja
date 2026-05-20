//! X_12 — Inheritance across files.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn x_12_c() {
    run_positive_cell(
        "X_12",
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
fn x_12_cpp() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[
                ("Base.hpp", "class Base { public: void helper(const char *p) { sink(p); } };\n"),
                ("Entry.cpp", "#include \"Base.hpp\"\nclass Child : public Base {};\nvoid entry(const char *args) { Child child; child.helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_csharp() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[
                ("Base.cs", "namespace App { public class Base { public void Helper(string p) { Sink.SinkFn(p); } } }\n"),
                ("Entry.cs", "namespace App { public class Child : Base {} public class EntryType { public void Entry(string args) { new Child().Helper(args); } } }\n"),
            ],
            entry: "Entry",
            seed: &["args"],
            sink: "SinkFn",
        },
    );
}

#[test]
fn x_12_dart() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[
                ("base.dart", "class Base { void helper(String p) { sink(p); } }\n"),
                ("entry.dart", "import 'base.dart';\nclass Child extends Base {}\nvoid entry(String args) { Child().helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_elixir() {
    run_positive_cell(
        "X_12",
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
fn x_12_erlang() {
    run_positive_cell(
        "X_12",
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
fn x_12_go() {
    run_positive_cell(
        "X_12",
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
fn x_12_java() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[
                ("Base.java", "package app;\npublic class Base { public void helper(String p) { sink(p); } }\n"),
                ("Entry.java", "package app;\nclass Child extends Base {}\npublic class Entry { public void entry(String args) { new Child().helper(args); } }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_javascript() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[
                ("base.js", "export class Base { helper(p) { sink(p); } }\n"),
                ("entry.js", "import { Base } from './base.js';\nclass Child extends Base {}\nexport function entry(args) { new Child().helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_kotlin() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[
                (
                    "Base.kt",
                    "package app\nopen class Base { fun helper(p: String) { sink(p) } }\n",
                ),
                (
                    "Entry.kt",
                    "package app\nclass Child : Base()\nfun entry(args: String) { Child().helper(args) }\n",
                ),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_lua() {
    run_positive_cell(
        "X_12",
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
fn x_12_objc() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[
                ("Base.m", "@interface Base : NSObject\n- (void)helper:(NSString *)p;\n@end\n@implementation Base\n- (void)helper:(NSString *)p { sink(p); }\n@end\n"),
                ("Entry.m", "@interface Base : NSObject\n- (void)helper:(NSString *)p;\n@end\n@interface Child : Base\n@end\n@implementation Child\n@end\nvoid entry(NSString *args) { Child *obj = [[Child alloc] init]; [obj helper:args]; }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_perl() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[
                ("Base.pm", "package Base;\nsub helper { my ($self, $p) = @_; sink($p); }\n1;\n"),
                ("entry.pl", "use Base;\npackage Child;\nour @ISA = ('Base');\npackage main;\nsub entry { my ($args) = @_; my $obj = bless {}, 'Child'; $obj->helper($args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_php() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[
                ("base.php", "<?php\nnamespace App;\nclass Base { public function helper($p) { sink($p); } }\n"),
                ("entry.php", "<?php\nrequire_once 'base.php';\nuse App\\Base;\nclass Child extends Base {}\nfunction entry($args) { (new Child())->helper($args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_python() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[
                ("base.py", "class Base:\n    def helper(self, p):\n        sink(p)\n"),
                ("entry.py", "from base import Base\n\nclass Child(Base):\n    pass\n\ndef entry(args):\n    Child().helper(args)\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_ruby() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[
                ("base.rb", "class Base\n  def helper(p)\n    sink(p)\n  end\nend\n"),
                ("entry.rb", "require_relative 'base'\nclass Child < Base\nend\ndef entry(args)\n  Child.new.helper(args)\nend\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_rust() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[("a.rs", "fn entry(args: String) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_scala() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[
                ("Base.scala", "package app\nclass Base { def helper(p: String): Unit = sink(p) }\n"),
                ("Entry.scala", "package app\nclass Child extends Base\nobject Entry { def entry(args: String): Unit = new Child().helper(args) }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_solidity() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[
                ("Base.sol", "contract Base { function helper(string memory p) public { sink(p); } }\n"),
                ("Entry.sol", "import './Base.sol';\ncontract Child is Base {}\ncontract Entry { function entry(string memory args) public { Child c; c.helper(args); } }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_swift() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[
                ("src/Base.swift", "public class Base { public func helper(p: String) { sink(p) } }\n"),
                ("src/Entry.swift", "public class Child: Base {}\npublic func entry(args: String) { Child().helper(p: args) }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn x_12_typescript() {
    run_positive_cell(
        "X_12",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[
                ("base.ts", "export class Base { helper(p: string) { sink(p); } }\n"),
                ("entry.ts", "import { Base } from './base';\nclass Child extends Base {}\nexport function entry(args: string) { new Child().helper(args); }\n"),
            ],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
