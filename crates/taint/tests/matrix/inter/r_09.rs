//! R_09 — Higher-order: pass tainted to callback (named callable).
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_09_python() {
    run_positive_cell("R_09", LangFixture { lang:"python", adapter:Arc::new(bonsai_lang_python::PythonAdapter::new()), files:&[("a.py","def cb(p):\n    sink(p)\n\ndef apply_(f, x):\n    f(x)\n\ndef entry(args):\n    apply_(cb, args)\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_09_javascript() {
    run_positive_cell("R_09", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function cb(p) { sink(p); }\nfunction apply_(f, x) { f(x); }\nfunction entry(args) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_09_typescript() {
    run_positive_cell("R_09", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function cb(p: string) { sink(p); }\nfunction apply_(f: (s: string) => void, x: string) { f(x); }\nfunction entry(args: string) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_09_rust() {
    run_positive_cell("R_09", LangFixture { lang:"rust", adapter:Arc::new(bonsai_lang_rust::RustAdapter::new()), files:&[("a.rs","fn cb(p: String) { sink(p); }\nfn apply_(f: fn(String), x: String) { f(x); }\nfn entry(args: String) { apply_(cb, args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
