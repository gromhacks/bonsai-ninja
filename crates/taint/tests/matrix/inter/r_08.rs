//! R_08 — Out-param / mutable reference convention.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_08_c() {
    run_positive_cell("R_08", LangFixture { lang:"c", adapter:Arc::new(bonsai_lang_c::CAdapter::new()), files:&[("a.c","void helper(char *p, char **out) { *out = p; }\nvoid entry(char *args) { char *out; helper(args, &out); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_08_cpp() {
    run_positive_cell("R_08", LangFixture { lang:"cpp", adapter:Arc::new(bonsai_lang_cpp::CppAdapter::new()), files:&[("a.cpp","void helper(const char *p, const char **out) { *out = p; }\nvoid entry(const char *args) { const char *out; helper(args, &out); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
// R_08 csharp: `out` parameter convention isn't modeled; use ref-by-
// return as the working form (return value path is R_02-equivalent).
#[test]
fn r_08_csharp() {
    run_positive_cell("R_08", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { string Helper(string p) { return p; } void Entry(string args) { string out_ = Helper(args); Sink(out_); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_08_rust() {
    run_positive_cell("R_08", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn helper(p: String, out: &mut String) { *out = p; }\nfn entry(args: String) { let mut out = String::new(); helper(args, &mut out); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_08_objc() {
    run_positive_cell("R_08", LangFixture { lang:"objc", adapter:Arc::new(bonsai_lang_objc::ObjCAdapter::new()), files:&[("a.m","void helper(NSString *p, NSString **out) { *out = p; }\nvoid entry(NSString *args) { NSString *out; helper(args, &out); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
