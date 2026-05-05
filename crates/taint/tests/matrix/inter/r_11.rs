//! R_11 — Async / await propagates.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_11_python() {
    run_positive_cell("R_11", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","async def helper(p):\n    return p\n\nasync def entry(args):\n    out = await helper(args)\n    sink(out)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_javascript() {
    run_positive_cell("R_11", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","async function helper(p) { return p; }\nasync function entry(args) { const out = await helper(args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_typescript() {
    run_positive_cell("R_11", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","async function helper(p: string) { return p; }\nasync function entry(args: string) { const out = await helper(args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_csharp() {
    run_positive_cell("R_11", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","using System.Threading.Tasks;\nclass Demo { async Task<string> Helper(string p) { return p; } async Task Entry(string args) { var out_ = await Helper(args); Sink(out_); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_11_rust() {
    run_positive_cell("R_11", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","async fn helper(p: String) -> String { p }\nasync fn entry(args: String) { let out = helper(args).await; sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_swift() {
    run_positive_cell("R_11", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func helper(p: String) async -> String { return p }\nfunc entry(args: String) async { let out = await helper(p: args); sink(out) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_kotlin() {
    run_positive_cell("R_11", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","suspend fun helper(p: String): String = p\nsuspend fun entry(args: String) { val out = helper(args); sink(out) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_dart() {
    run_positive_cell("R_11", LangFixture { lang:"dart", adapter:Arc::new(bonsai_lang_dart::DartAdapter::new()), files:&[("a.dart","Future<String> helper(String p) async { return p; }\nFuture<void> entry(String args) async { var out = await helper(args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_11_scala() {
    run_positive_cell("R_11", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def helper(p: String): String = p; def entry(args: String): Unit = { val out = helper(args); sink(out) } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
