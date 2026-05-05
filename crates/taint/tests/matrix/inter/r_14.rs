//! R_14 — Overload dispatch considers all candidates.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_14_java() {
    run_positive_cell("R_14", LangFixture { lang:"java", adapter:Arc::new(bonsai_lang_java::JavaAdapter::new()), files:&[("Demo.java","class Demo { void helper(String p) { sink(p); } void helper(int p) { } void entry(String args) { helper(args); } }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_14_csharp() {
    run_positive_cell("R_14", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Helper(string p) { Sink(p); } void Helper(int p) { } void Entry(string args) { Helper(args); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_14_cpp() {
    run_positive_cell("R_14", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void helper(const char *p) { sink(p); }\nvoid helper(int p) { }\nvoid entry(const char *args) { helper(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_14_kotlin() {
    run_positive_cell("R_14", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun helper(p: String) { sink(p) }\nfun helper(p: Int) { }\nfun entry(args: String) { helper(args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_14_scala() {
    run_positive_cell("R_14", LangFixture { lang:"scala", adapter:Arc::new(bonsai_lang_scala::ScalaAdapter::new()), files:&[("a.scala","object Demo { def helper(p: String): Unit = sink(p); def helper(p: Int): Unit = (); def entry(args: String): Unit = helper(args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_14_swift() {
    run_positive_cell("R_14", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func helper(p: String) { sink(p) }\nfunc helper(p: Int) {}\nfunc entry(args: String) { helper(p: args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
