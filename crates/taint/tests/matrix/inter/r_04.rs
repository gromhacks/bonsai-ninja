//! R_04 — Method tainted arg propagates.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_04_python() {
    run_positive_cell("R_04", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","class Box:\n    def method(self, p):\n        sink(p)\n\ndef entry(args):\n    obj = Box()\n    obj.method(args)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_javascript() {
    run_positive_cell("R_04", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","class Box { method(p) { sink(p); } }\nfunction entry(args) { const obj = new Box(); obj.method(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_typescript() {
    run_positive_cell("R_04", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","class Box { method(p: string) { sink(p); } }\nfunction entry(args: string) { const obj = new Box(); obj.method(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_java() {
    run_positive_cell("R_04", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Box { void method(String p) { sink(p); } }\nclass Demo { void entry(String args) { Box obj = new Box(); obj.method(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_kotlin() {
    run_positive_cell("R_04", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","class Box { fun method(p: String) { sink(p) } }\nfun entry(args: String) { val obj = Box(); obj.method(args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_scala() {
    run_positive_cell("R_04", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","class Box { def method(p: String): Unit = sink(p) }\nobject Demo { def entry(args: String): Unit = { val obj = new Box(); obj.method(args) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_csharp() {
    run_positive_cell("R_04", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Box { public void Method(string p) { Sink(p); } }\nclass Demo { void Entry(string args) { var obj = new Box(); obj.Method(args); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}

#[test]
fn r_04_go() {
    run_positive_cell("R_04", LangFixture {
        lang: "go",
        adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
        files: &[("a.go", "package main\ntype Box struct{}\nfunc (b *Box) method(p string) { sink(p) }\nfunc entry(args string) { obj := &Box{}; obj.method(args) }\n")],
        entry: "entry",
        seed: &["args"],
        sink: "sink",
    });
}

#[test]
fn r_04_rust() {
    run_positive_cell(
        "R_04",
        LangFixture {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            files: &[(
                "a.rs",
                "fn entry(args: String) { sink(args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_04_cpp() {
    run_positive_cell("R_04", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","class Box { public: void method(const char *p) { sink(p); } };\nvoid entry(const char *args) { Box obj; obj.method(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_objc() {
    run_positive_cell("R_04", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","@interface Box : NSObject\n- (void)methodWith:(NSString *)p;\n@end\n@implementation Box\n- (void)methodWith:(NSString *)p { sink(p); }\n@end\nvoid entry(NSString *args) { Box *obj = [[Box alloc] init]; [obj methodWith:args]; }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_ruby() {
    run_positive_cell("R_04", LangFixture { lang:"ruby", adapter:Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files:&[("a.rb","class Box\n  def method(p)\n    sink(p)\n  end\nend\ndef entry(args)\n  obj = Box.new\n  obj.method(args)\nend\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_php() {
    run_positive_cell("R_04", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nclass Box { public function method($p) { sink($p); } }\nfunction entry($args) { $obj = new Box(); $obj->method($args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_perl() {
    run_positive_cell(
        "R_04",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub entry { my ($args) = @_; sink($args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_04_swift() {
    run_positive_cell("R_04", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","class Box { func method(p: String) { sink(p) } }\nfunc entry(args: String) { let obj = Box(); obj.method(p: args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_04_dart() {
    run_positive_cell("R_04", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","class Box { void method(String p) { sink(p); } }\nvoid entry(String args) { var obj = Box(); obj.method(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn r_04_lua() {
    run_positive_cell(
        "R_04",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "local Box = {}\nfunction Box.method(self, p)\n  sink(p)\nend\nfunction entry(args)\n  Box.method(Box, args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn r_04_solidity() {
    run_positive_cell("R_04", LangFixture { lang:"solidity", adapter:Arc::new(bonsai_lang_solidity::SolidityAdapter::new()), files:&[("Demo.sol","contract Demo { function entry(string memory args) public { method(args); } function method(string memory p) internal { sink(p); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
