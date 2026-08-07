//! OT_16 — Receiver-only taint doesn't promote to scalar arg.
//!
//! Negative: `obj.method(clean)` where `obj` is tainted but the
//! method's `clean` arg is a literal. The receiver propagation
//! must not auto-taint the scalar arg.

#![allow(unreachable_pub)]

use crate::applicability::{status, Status};
use crate::helpers::{build_db, cfg, func_id_or_none, seed, sink_received_arg_index, LangFixture};
use bonsai_taint::interprocedural_taint;
use std::sync::Arc;

fn run_ot_16(fixture: LangFixture) {
    if matches!(
        status(fixture.lang, "OT_16"),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry)
        .unwrap_or_else(|| panic!("[OT_16/{}] entry `{}` should index", fixture.lang, fixture.entry));
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_received_arg_index(&result, fixture.sink, 0),
        "[OT_16/{}] scalar arg of method on tainted receiver must NOT be auto-tainted; got {:?}",
        fixture.lang,
        result.tainted_calls,
    );
}

#[test]
fn ot_16_python() {
    run_ot_16(LangFixture {
        lang: "python",
        adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
        files: &[("a.py", "class Box:\n    def method(self, x):\n        sink(x)\n\ndef entry(args):\n    args.method('clean')\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_javascript() {
    run_ot_16(LangFixture {
        lang: "javascript",
        adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        files: &[(
            "a.js",
            "class Box { method(x) { sink(x); } }\nfunction entry(args) { args.method('clean'); }\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_typescript() {
    run_ot_16(LangFixture {
        lang: "typescript",
        adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        files: &[("a.ts", "class Box { method(x: string): void { sink(x); } }\nfunction entry(args: Box) { args.method('clean'); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_java() {
    run_ot_16(LangFixture {
        lang: "java",
        adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
        files: &[("Demo.java", "class Box { void method(String x) { sink(x); } }\nclass Demo { void entry(Box args) { args.method(\"clean\"); } }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_kotlin() {
    run_ot_16(LangFixture {
        lang: "kotlin",
        adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        files: &[("a.kt", "class Box { fun method(x: String) { sink(x) } }\nfun entry(args: Box) { args.method(\"clean\") }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_scala() {
    run_ot_16(LangFixture {
        lang: "scala",
        adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        files: &[("a.scala", "class Box { def method(x: String): Unit = sink(x) }\nobject Demo { def entry(args: Box): Unit = args.method(\"clean\") }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_csharp() {
    run_ot_16(LangFixture {
        lang: "csharp",
        adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        files: &[("Demo.cs", "class Box { public void Method(string x) { Sink(x); } }\nclass Demo { void Entry(Box args) { args.Method(\"clean\"); } }\n")],
        entry: "Entry",
        seed: &["args"],
        sink: "Sink",
    });
}

#[test]
fn ot_16_go() {
    run_ot_16(LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\ntype Box struct{}\nfunc (b *Box) method(x string) { sink(x) }\nfunc entry(args *Box) { args.method(\"clean\") }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_rust() {
    run_ot_16(LangFixture {
        lang: "rust",
        adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
        files: &[(
            "a.rs",
            "fn entry(args: String) { let _ = args; sink(\"clean\"); }
",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_cpp() {
    run_ot_16(LangFixture {
        lang: "cpp",
        adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        files: &[("a.cpp", "class Box { public: void method(const char *x) { sink(x); } };\nvoid entry(Box *args) { args->method(\"clean\"); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_objc() {
    run_ot_16(LangFixture {
        lang: "objc",
        adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        files: &[("a.m", "@interface Box : NSObject\n- (void)methodWithX:(NSString *)x;\n@end\n@implementation Box\n- (void)methodWithX:(NSString *)x { sink(x); }\n@end\nvoid entry(Box *args) { [args methodWithX:@\"clean\"]; }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_ruby() {
    run_ot_16(LangFixture {
        lang: "ruby",
        adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        files: &[("a.rb", "class Box\n  def method(x)\n    sink(x)\n  end\nend\ndef entry(args)\n  args.method('clean')\nend\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_php() {
    run_ot_16(LangFixture {
        lang: "php",
        adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
        files: &[("a.php", "<?php\nclass Box { public function method($x) { sink($x); } }\nfunction entry($args) { $args->method('clean'); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_perl() {
    run_ot_16(LangFixture {
        lang: "perl",
        adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        files: &[("a.pl", "package Box;\nsub method { my ($self, $x) = @_; sink($x); }\npackage main;\nsub entry { my ($args) = @_; $args->method('clean'); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_swift() {
    run_ot_16(LangFixture {
        lang: "swift",
        adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        files: &[("a.swift", "class Box { func method(x: String) { sink(x) } }\nfunc entry(args: Box) { args.method(x: \"clean\") }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_dart() {
    run_ot_16(LangFixture {
        lang: "dart",
        adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
        files: &[("a.dart", "class Box { void method(String x) { sink(x); } }\nvoid entry(Box args) { args.method('clean'); }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn ot_16_lua() {
    run_ot_16(LangFixture {
        lang: "lua",
        adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        files: &[(
            "a.lua",
            "local Box = {}\nfunction Box.method(self, x)\n  sink(x)\nend\nfunction entry(args)\n  Box.method(args, 'clean')\nend\n",
        )],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}
