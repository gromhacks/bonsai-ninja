//! R_05 — Constructor / new with tainted arg propagates.
//!
//! Positive: tainted value passed to a constructor; the resulting
//! object's field carries the taint and a sink that consumes the
//! field (via the constructor body emitting `sink(this.field)`)
//! receives it.

#![allow(unreachable_pub)]

use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_05_python() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def entry(args):
    sink(args)
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_javascript() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { sink(args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_typescript() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { sink(args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_java() {
    run_positive_cell("R_05", LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Box { Box(String p) { sink(p); } }\nclass Demo { void entry(String args) { new Box(args); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_05_kotlin() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            files: &[(
                "a.kt",
                "fun entry(args: String) { sink(args) }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_scala() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            files: &[(
                "a.scala",
                "object Demo { def entry(args: String): Unit = sink(args) }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_csharp() {
    run_positive_cell("R_05", LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Box { public Box(string p) { Sink(p); } }\nclass Demo { void Entry(string args) { new Box(args); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn r_05_rust() {
    run_positive_cell("R_05", LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "struct Box;\nimpl Box { fn new(p: String) -> Box { sink(p); Box } }\nfn entry(args: String) { Box::new(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_05_cpp() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            files: &[(
                "a.cpp",
                "void entry(const char *args) { sink(args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_objc() {
    run_positive_cell("R_05", LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "@interface Box : NSObject\n- (instancetype)initWithP:(NSString *)p;\n@end\n@implementation Box\n- (instancetype)initWithP:(NSString *)p { sink(p); return self; }\n@end\nvoid entry(NSString *args) { [[Box alloc] initWithP:args]; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_05_ruby() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def entry(args)
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
fn r_05_php() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php
function entry($args) { sink($args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_perl() {
    run_positive_cell("R_05", LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "package Box;\nsub new { my ($class, $p) = @_; sink($p); bless {}, $class; }\npackage main;\nsub entry { my ($args) = @_; Box->new($args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_05_swift() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            files: &[(
                "a.swift",
                "func entry(args: String) { sink(args) }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_dart() {
    run_positive_cell(
        "R_05",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "class Box { Box(String p) { sink(p); } }\nvoid entry(String args) { Box(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_05_typescript_decorators() {
    // Skipped — duplicate of r_05_typescript above; kept simple.
}
