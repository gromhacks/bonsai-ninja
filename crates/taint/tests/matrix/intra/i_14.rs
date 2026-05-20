//! I_14 — Catch param propagates further.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn i_14_python() {
    run_positive_cell("I_14", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def entry(args):\n    try:\n        raise Exception(args)\n    except Exception as e:\n        copy = e\n        sink(copy)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_javascript() {
    run_positive_cell("I_14", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function entry(args) { try { throw new Error(args); } catch (e) { const copy = e; sink(copy); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_typescript() {
    run_positive_cell("I_14", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function entry(args: string) { try { throw new Error(args); } catch (e) { const copy = e; sink(copy); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_kotlin() {
    run_positive_cell("I_14", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun entry(args: String) { try { throw RuntimeException(args) } catch (e: Exception) { val copy = e; sink(copy) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_scala() {
    run_positive_cell("I_14", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def entry(args: String): Unit = { try { throw new RuntimeException(args) } catch { case e: Exception => val copy = e; sink(copy) } } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn i_14_php() {
    run_positive_cell("I_14", LangFixture { lang:"php", adapter:Arc::new(bonsai_lang_php::PhpAdapter::new()), files:&[("a.php","<?php\nfunction entry($args) { try { throw new Exception($args); } catch (Exception $e) { $copy = $e; sink($copy); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}

#[test]
fn i_14_cpp() {
    run_positive_cell("I_14", LangFixture { lang: "cpp", adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()), files: &[("a.cpp", "void entry(const char *args) { try { throw args; } catch (const char *e) { const char *copy = e; sink(copy); } }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_14_csharp() {
    run_positive_cell("I_14", LangFixture { lang: "csharp", adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files: &[("Demo.cs", "using System;\nclass Demo { void Entry(string args) { try { throw new Exception(args); } catch (Exception e) { var copy = e; Sink(copy); } } }\n")], entry: "Entry", seed: &["args"], sink: "Sink" });
}

#[test]
fn i_14_dart() {
    run_positive_cell(
        "I_14",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[(
                "a.dart",
                "void entry(String args) { try { throw args; } catch (e) { var copy = e; sink(copy); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}

#[test]
fn i_14_java() {
    run_positive_cell("I_14", LangFixture { lang: "java", adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()), files: &[("Demo.java", "class Demo { void entry(String args) { try { throw new RuntimeException(args); } catch (Exception e) { Object copy = e; sink(copy); } } }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_14_objc() {
    run_positive_cell("I_14", LangFixture { lang: "objc", adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files: &[("a.m", "void entry(NSString *args) { @try { @throw args; } @catch (NSString *e) { NSString *copy = e; sink(copy); } }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_14_ruby() {
    run_positive_cell("I_14", LangFixture { lang: "ruby", adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()), files: &[("a.rb", "def entry(args)\n  begin\n    raise StandardError.new(args)\n  rescue StandardError => e\n    copy = e\n    sink(copy)\n  end\nend\n")], entry: "entry", seed: &["args"], sink: "sink" });
}

#[test]
fn i_14_swift() {
    run_positive_cell("I_14", LangFixture { lang: "swift", adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files: &[("a.swift", "struct BoxError: Error { let value: String }\nfunc entry(args: String) { do { throw BoxError(value: args) } catch let e { let copy = e; sink(copy) } }\n")], entry: "entry", seed: &["args"], sink: "sink" });
}
