//! R_06 — Static / class method propagates.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_06_python() {
    run_positive_cell("R_06", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","class Box:\n    @staticmethod\n    def helper(p):\n        sink(p)\n\ndef entry(args):\n    Box.helper(args)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_java() {
    run_positive_cell("R_06", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Box { static void helper(String p) { sink(p); } }\nclass Demo { void entry(String args) { Box.helper(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_kotlin() {
    run_positive_cell("R_06", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","object Box { fun helper(p: String) { sink(p) } }\nfun entry(args: String) { Box.helper(args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_scala() {
    run_positive_cell("R_06", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Box { def helper(p: String): Unit = sink(p) }\nobject Demo { def entry(args: String): Unit = Box.helper(args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_csharp() {
    run_positive_cell("R_06", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Box { public static void Helper(string p) { Sink(p); } }\nclass Demo { void Entry(string args) { Box.Helper(args); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_06_javascript() {
    run_positive_cell(
        "R_06",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "class Box { static helper(p) { sink(p); } }\nfunction entry(args) { Box.helper(args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_06_typescript() {
    run_positive_cell("R_06", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","class Box { static helper(p: string) { sink(p); } }\nfunction entry(args: string) { Box.helper(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_php() {
    run_positive_cell("R_06", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nclass Box { public static function helper($p) { sink($p); } }\nfunction entry($args) { Box::helper($args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_ruby() {
    run_positive_cell("R_06", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","class Box\n  def self.helper(p)\n    sink(p)\n  end\nend\ndef entry(args)\n  Box.helper(args)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_swift() {
    run_positive_cell("R_06", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","class Box { static func helper(p: String) { sink(p) } }\nfunc entry(args: String) { Box.helper(p: args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_dart() {
    run_positive_cell("R_06", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","class Box { static void helper(String p) { sink(p); } }\nvoid entry(String args) { Box.helper(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_06_cpp() {
    run_positive_cell("R_06", LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "class Box { public: static void helper(const char *p) { sink(p); } };\nvoid entry(const char *args) { Box::helper(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_06_objc() {
    run_positive_cell("R_06", LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "@interface Box : NSObject\n+ (void)helper:(NSString *)p;\n@end\n@implementation Box\n+ (void)helper:(NSString *)p { sink(p); }\n@end\nvoid entry(NSString *args) { [Box helper:args]; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
#[test]
fn r_06_rust() {
    run_positive_cell("R_06", LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[("a.rs", "struct Box;\nimpl Box { fn helper(p: String) { sink(p); } }\nfn entry(args: String) { Box::helper(args); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
