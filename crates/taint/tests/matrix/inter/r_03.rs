//! R_03 — Method receiver taint propagates.
//!
//! Positive: `obj.method()` where `obj` is tainted; method body
//! sinks `self`. Receiver propagation must carry taint through to
//! the method's `self`/`this` binding.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_03_python() {
    run_positive_cell("R_03", LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[("a.py", "class Box:\n    def method(self):\n        sink(self)\n\ndef entry(args: Box):\n    args.method()\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_javascript() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "class Box { method() { sink(this); } }\nfunction entry(args) { args.method(); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_03_typescript() {
    run_positive_cell("R_03", LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "class Box { method(): void { sink(this); } }\nfunction entry(args: Box) { args.method(); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_java() {
    run_positive_cell("R_03", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Box { void method() { sink(this); } }\nclass Demo { void entry(Box args) { args.method(); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_kotlin() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "class Box { fun method() { sink(this) } }\nfun entry(args: Box) { args.method() }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_03_scala() {
    run_positive_cell("R_03", LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "class Box { def method(): Unit = sink(this) }\nobject Demo { def entry(args: Box): Unit = args.method() }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_csharp() {
    run_positive_cell("R_03", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Box { public void Method() { Sink(this); } }\nclass Demo { void Entry(Box args) { args.Method(); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

// R_03 not applicable to C (no methods) — skipped via applicability table

#[test]
fn r_03_go() {
    run_positive_cell("R_03", LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\ntype Box struct{}\nfunc (b *Box) method() { sink(b) }\nfunc entry(args *Box) { args.method() }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_rust() {
    run_positive_cell("R_03", LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "struct Box;\nimpl Box { fn method(&self) { sink(self); } }\nfn entry(args: Box) { args.method(); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_cpp() {
    run_positive_cell("R_03", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "class Box { public: void method() { sink(this); } };\nvoid entry(Box *args) { args->method(); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_objc() {
    run_positive_cell("R_03", LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "@interface Box : NSObject\n- (void)method;\n@end\n@implementation Box\n- (void)method { sink(self); }\n@end\nvoid entry(Box *args) { [args method]; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_ruby() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "class Box\n  def method\n    sink(self)\n  end\nend\ndef entry(args)\n  args.method\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_03_php() {
    run_positive_cell("R_03", LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nclass Box { public function method() { sink($this); } }\nfunction entry(Box $args) { $args->method(); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_perl() {
    run_positive_cell("R_03", LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "package Box;\nsub method { my ($self) = @_; sink($self); }\npackage main;\nsub entry { my ($args) = @_; $args->method(); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_03_swift() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "class Box { func method() { sink(self) } }\nfunc entry(args: Box) { args.method() }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_03_dart() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "class Box { void method() { sink(this); } }\nvoid entry(Box args) { args.method(); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_03_lua() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function entry(args)
  sink(args)
end
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_03_elixir() {
    run_positive_cell("R_03", LangFixture {
        lang: "elixir",
        adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        files: &[("a.ex", "defmodule Box do\n  def method(self) do\n    sink(self)\n  end\nend\ndefmodule Demo do\n  def entry(args) do\n    Box.method(args)\n  end\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

// R_03 not applicable to Erlang (no methods) — skipped via applicability table

#[test]
fn r_03_solidity() {
    run_positive_cell(
        "R_03",
        LangFixture {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            files: &[(
                "Demo.sol",
                "contract Demo { function entry(string memory args) public { sink(args); } }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
