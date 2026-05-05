//! R_10 — Higher-order: callback returns tainted.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_10_python() {
    run_positive_cell(
        "R_10",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def make(args):\n    return args\n\ndef entry(args):\n    out = make(args)\n    sink(out)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_10_javascript() {
    run_positive_cell("R_10", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function make(args) { return args; }\nfunction entry(args) { let out = make(args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_10_typescript() {
    run_positive_cell("R_10", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function make(args: string): string { return args; }\nfunction entry(args: string) { let out = make(args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
