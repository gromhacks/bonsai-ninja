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
                "def cb(p):\n    return p\n\ndef apply_(f, x):\n    return f(x)\n\ndef entry(args):\n    out = apply_(cb, args)\n    sink(out)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_10_javascript() {
    run_positive_cell("R_10", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function cb(p) { return p; }\nfunction apply_(f, x) { return f(x); }\nfunction entry(args) { let out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_10_typescript() {
    run_positive_cell("R_10", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function cb(p: string): string { return p; }\nfunction apply_(f: (s: string) => string, x: string): string { return f(x); }\nfunction entry(args: string) { let out = apply_(cb, args); sink(out); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
