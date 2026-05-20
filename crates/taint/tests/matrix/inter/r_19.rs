//! R_19 — Variadic args carry taint.
#![allow(unreachable_pub)]
use crate::helpers::{run_positive_cell, LangFixture};
use std::sync::Arc;

#[test]
fn r_19_python() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            files: &[(
                "a.py",
                "def helper(*p):\n    for x in p:\n        sink(x)\n\ndef entry(args):\n    helper(args)\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_19_javascript() {
    run_positive_cell("R_19", LangFixture { lang:"javascript", adapter:Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()), files:&[("a.js","function helper(...p) { for (const x of p) sink(x); }\nfunction entry(args) { helper(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_19_typescript() {
    run_positive_cell("R_19", LangFixture { lang:"typescript", adapter:Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()), files:&[("a.ts","function helper(...p: string[]) { for (const x of p) sink(x); }\nfunction entry(args: string) { helper(args); }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_19_java() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            files: &[(
                "Demo.java",
                "class Demo { void helper(String... p) { for (String x : p) sink(x); } void entry(String args) { helper(args); } }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_19_kotlin() {
    run_positive_cell("R_19", LangFixture { lang:"kotlin", adapter:Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), files:&[("a.kt","fun helper(vararg p: String) { for (x in p) sink(x) }\nfun entry(args: String) { helper(args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_19_csharp() {
    run_positive_cell("R_19", LangFixture { lang:"csharp", adapter:Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), files:&[("Demo.cs","class Demo { void Helper(params string[] p) { foreach (var x in p) Sink(x); } void Entry(string args) { Helper(args); } }\n")], entry:"Entry", seed:&["args"], sink:"Sink" });
}
#[test]
fn r_19_php() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            files: &[(
                "a.php",
                "<?php\nfunction helper(...$p) { foreach ($p as $x) { sink($x); } }\nfunction entry($args) { helper($args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_19_swift() {
    run_positive_cell("R_19", LangFixture { lang:"swift", adapter:Arc::new(bonsai_lang_swift::SwiftAdapter::new()), files:&[("a.swift","func helper(p: String...) { for x in p { sink(x) } }\nfunc entry(args: String) { helper(p: args) }\n")], entry:"entry", seed:&["args"], sink:"sink" });
}
#[test]
fn r_19_ruby() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            files: &[(
                "a.rb",
                "def helper(*p)\n  p.each { |x| sink(x) }\nend\ndef entry(args)\n  helper(args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_19_lua() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            files: &[(
                "a.lua",
                "function helper(...)\n  for _, x in ipairs({...}) do sink(x) end\nend\nfunction entry(args)\n  helper(args)\nend\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_19_dart() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            files: &[("a.dart", "void entry(String args) { sink(args); }\n")],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
#[test]
fn r_19_perl() {
    run_positive_cell(
        "R_19",
        LangFixture {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            files: &[(
                "a.pl",
                "sub helper { for my $x (@_) { sink($x); } }\nsub entry { my ($args) = @_; helper($args); }\n",
            )],
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    );
}
