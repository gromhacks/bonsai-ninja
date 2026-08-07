//! I_13 — Try → throw → catch param.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_13_python() {
    run_positive_cell("I_13", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def entry(args):\n    try:\n        raise Exception(args)\n    except Exception as e:\n        sink(e)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_13_javascript() {
    run_positive_cell(
        "I_13",
        LangFixture {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            files: &[(
                "a.js",
                "function entry(args) { try { throw new Error(args); } catch (e) { sink(e); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_13_typescript() {
    run_positive_cell(
        "I_13",
        LangFixture {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            files: &[(
                "a.ts",
                "function entry(args: string) { try { throw new Error(args); } catch (e) { sink(e); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_13_java() {
    run_positive_cell(
        "I_13",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void entry(String args) { sink(args); } }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_13_kotlin() {
    run_positive_cell("I_13", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun entry(args: String) { try { throw RuntimeException(args) } catch (e: Exception) { sink(e) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_13_scala() {
    run_positive_cell("I_13", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def entry(args: String): Unit = { try { throw new RuntimeException(args) } catch { case e: Exception => sink(e) } } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_13_csharp() {
    run_positive_cell(
        "I_13",
        LangFixture {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            files: &[(
                "Demo.cs",
                "class Demo { void Entry(string args) { Sink(args); } }
",
            )],
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
    );
}
#[test]
fn i_13_cpp() {
    run_positive_cell(
        "I_13",
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
fn i_13_objc() {
    run_positive_cell(
        "I_13",
        LangFixture {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            files: &[("a.m", "void entry(NSString *args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn i_13_ruby() {
    run_positive_cell(
        "I_13",
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
fn i_13_php() {
    run_positive_cell("I_13", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction entry($args) { try { throw new Exception($args); } catch (Exception $e) { sink($e); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_13_swift() {
    run_positive_cell(
        "I_13",
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
fn i_13_dart() {
    run_positive_cell(
        "I_13",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { sink(args); }
",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
