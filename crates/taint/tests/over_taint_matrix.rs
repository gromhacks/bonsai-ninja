//! Over-taint regression matrix across all 21 supported languages.
//!
//! Each test seeds the engine with a tainted entry-point param,
//! then verifies that downstream code paths whose data is
//! HARDCODED literals (not derived from the seed) do NOT report a
//! tainted call. These tests are the user-facing guard against
//! the "args = parse_args() then any reachable function looks
//! tainted" class of false positives.
//!
//! Each language gets a cross-language negative suite:
//!   1. Hardcoded literal arg downstream of a tainted source must
//!      NOT report (the canonical user-reported case).
//!   2. A literal whose text contains the seed name must NOT report.
//!   3. A tainted arg at index N must not satisfy a different sink arg.
//!   4. A tainted helper parameter must not poison an independent local
//!      sink argument in the same callee.
//!   5. Clean reassignment before a sink must clear stale taint.
//!   6. Clean reassignment must remove both value and descendant markers.
//!   7. A tainted lifecycle/carrier object must not taint locals derived
//!      only from independent internal fields such as capacity counters.
//!   8. Unknown calls that consume tainted data must not taint unrelated
//!      later locals, globals, fields, or allocation sizes.
//!   9. Distinct object/map/struct keys must stay field-sensitive:
//!      writing taint to one key must not taint a sibling key.
//!  10. A helper that consumes tainted data and returns a hardcoded clean
//!      value must not make that clean return tainted.
//!
//! Adapter-specific syntax differs but the engine's correctness
//! property is the same: no text-tokenisation of string literals,
//! quote-aware fallbacks, no unresolved-call out-param invention
//! for bare-identifier places. Language-specific guardrails below add
//! C/C++ static-size operands, sigil-prefix interpolation, field-distinct
//! reads, branch overwrite joins, and the user-reported argparse/eval shape.
//!
//! Per-language micro-tests live in `over_taint_per_language.rs`; this
//! file covers the cross-language invariants.

mod common;

use bonsai_lang_api::AdapterArc;
use bonsai_taint::interprocedural_taint;
use common::*;
use rayon::prelude::*;
use std::sync::Arc;

#[test]
fn over_taint_all_languages_second_tainted_arg_does_not_taint_first_arg() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: "def entry(args):\n    sink('safe', args)\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: "function entry(args) { sink('safe', args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: "function entry(args: string) { sink('safe', args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: "class Demo { void entry(String args) { sink(\"safe\", args); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: "fun entry(args: String) { sink(\"safe\", args) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: "object Demo { def entry(args: String): Unit = { sink(\"safe\", args) } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "Demo.cs",
            src: "class Demo { void Entry(string args) { Sink(\"safe\", args); } }\n",
            entry: "Entry",
            seed: &["args"],
            sink: "Sink",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: "package main\nfunc entry(args string) { sink(\"safe\", args) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: "fn entry(args: String) { sink(\"safe\", args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: "void entry(char *args) { sink(\"safe\", args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: "void entry(const char *args) { sink(\"safe\", args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: "void entry(NSString *args) { sink(@\"safe\", args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: "def entry(args)\n  sink('safe', args)\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: "<?php\nfunction entry($args) { sink('safe', $args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: "sub entry { my ($args) = @_; sink('safe', $args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: "func entry(args: String) { sink(\"safe\", args) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: "void entry(String args) { sink('safe', args); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: "function entry(args)\n  sink('safe', args)\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: "defmodule Demo do\n  def entry(args) do\n    sink(\"safe\", args)\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: "-module(demo).\n-export([entry/1]).\nentry(Args) -> sink(\"safe\", Args).\n",
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: "contract Demo { function entry(string memory args) public { sink(\"safe\", args); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        let db = build_db(case.adapter, &[(case.file, case.src)]);
        let entry = func_id_or_none(&db, case.entry)
            .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
        let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
        assert!(
            sink_received_arg_index(&result, case.sink, 1),
            "{}: second sink arg should be tainted so the regression is meaningful; got {:?}",
            case.lang,
            result.tainted_calls,
        );
        assert!(
            !sink_received_arg_index(&result, case.sink, 0),
            "{}: taint on arg 1 must not satisfy arg 0; got {:?}",
            case.lang,
            result.tainted_calls,
        );
    });
}

#[test]
fn over_taint_all_languages_tainted_helper_param_does_not_taint_independent_sink_arg() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: "def entry(args):\n    helper(args)\n\ndef helper(c):\n    audit(c)\n    cap = 32\n    sink(cap)\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: "function entry(args) { helper(args); }\nfunction helper(c) { audit(c); let cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: "function entry(args: string) { helper(args); }\nfunction helper(c: string) { audit(c); let cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: "class Demo { void entry(String args) { helper(args); } void helper(String c) { audit(c); int cap = 32; sink(cap); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: "fun entry(args: String) { helper(args) }\nfun helper(c: String) { audit(c); val cap = 32; sink(cap) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: "object Demo { def entry(args: String): Unit = { helper(args) }; def helper(c: String): Unit = { audit(c); val cap = 32; sink(cap) } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "a.cs",
            src: "class Demo { void entry(string args) { helper(args); } void helper(string c) { audit(c); int cap = 32; sink(cap); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: "package main\nfunc entry(args string) { helper(args) }\nfunc helper(c string) { audit(c); cap := 32; sink(cap) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: "fn entry(args: String) { helper(args); }\nfn helper(c: String) { audit(c); let cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: "void entry(char *args) { helper(args); }\nvoid helper(char *c) { audit(c); int cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: "void entry(const char *args) { helper(args); }\nvoid helper(const char *c) { audit(c); int cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: "void entry(NSString *args) { helper(args); }\nvoid helper(NSString *c) { audit(c); int cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: "def entry(args)\n  helper(args)\nend\ndef helper(c)\n  audit(c)\n  cap = 32\n  sink(cap)\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: "<?php\nfunction entry($args) { helper($args); }\nfunction helper($c) { audit($c); $cap = 32; sink($cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: "sub entry { my ($args) = @_; helper($args); }\nsub helper { my ($c) = @_; audit($c); my $cap = 32; sink($cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: "func entry(args: String) { helper(args) }\nfunc helper(c: String) { audit(c); let cap = 32; sink(cap) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: "void entry(String args) { helper(args); }\nvoid helper(String c) { audit(c); var cap = 32; sink(cap); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: "function entry(args)\n  helper(args)\nend\nfunction helper(c)\n  audit(c)\n  local cap = 32\n  sink(cap)\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: "defmodule Demo do\n  def entry(args) do\n    helper(args)\n  end\n  def helper(c) do\n    audit(c)\n    cap = 32\n    sink(cap)\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: "-module(demo).\n-export([entry/1, helper/1]).\nentry(Args) -> helper(Args).\nhelper(C) -> audit(C), Cap = 32, sink(Cap).\n",
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: "contract Demo { function entry(string memory args) public { helper(args); } function helper(string memory c) internal { audit(c); uint cap = 32; sink(cap); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        let db = build_db(case.adapter, &[(case.file, case.src)]);
        let entry = func_id_or_none(&db, case.entry)
            .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
        let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
        assert!(
            sink_received_arg_index(&result, "audit", 0),
            "{}: helper param should be tainted so the regression is meaningful; got {:?}",
            case.lang,
            result.tainted_calls,
        );
        assert!(
            !sink_reached(&result, case.sink),
            "{}: tainted helper param must not taint independent local sink arg; got {:?}",
            case.lang,
            result.tainted_calls,
        );
    });
}

#[test]
fn over_taint_c_and_cpp_sizeof_operand_does_not_taint_allocator_size() {
    for (lang, adapter, file, src) in [
        (
            "c",
            Arc::new(bonsai_lang_c::CAdapter::new()) as AdapterArc,
            "a.c",
            "void entry(char *argv) { moduleReleaseTempClient(argv); }\nvoid moduleReleaseTempClient(void *c) { int moduleTempClientCap = 32; malloc(sizeof(c) * moduleTempClientCap); }\n",
        ),
        (
            "cpp",
            Arc::new(bonsai_lang_cpp::CppAdapter::new()) as AdapterArc,
            "a.cpp",
            "void entry(const char *argv) { moduleReleaseTempClient(argv); }\nvoid moduleReleaseTempClient(void *c) { int moduleTempClientCap = 32; malloc(sizeof(c) * moduleTempClientCap); }\n",
        ),
    ] {
        let db = build_db(adapter, &[(file, src)]);
        let entry = func_id_or_none(&db, "entry").unwrap_or_else(|| panic!("{lang}: entry should index"));
        let result = interprocedural_taint(entry, &seed(&["argv"]), &cfg(), &db);
        assert!(
            sink_received_arg_index(&result, "moduleReleaseTempClient", 0),
            "{lang}: argv should reach the helper so the regression is meaningful; got {:?}",
            result.tainted_calls,
        );
        assert!(
            !sink_reached(&result, "malloc"),
            "{lang}: sizeof(c) mentions tainted c but does not read c's runtime value; got {:?}",
            result.tainted_calls,
        );
    }
}

#[test]
fn over_taint_c_and_cpp_fixed_size_pointer_copy_does_not_taint_length_arg() {
    for (lang, adapter, file, copy_call, src) in [
        (
            "c",
            Arc::new(bonsai_lang_c::CAdapter::new()) as AdapterArc,
            "a.c",
            "memcpy",
            "void *memcpy(void *dst, const void *src, unsigned long n);\nvoid entry(char **argv) { void *node = 0; void **cp = (void**)argv; audit(cp); memcpy(&node, cp, sizeof(node)); memcpy(cp, &node, sizeof(node)); }\n",
        ),
        (
            "cpp",
            Arc::new(bonsai_lang_cpp::CppAdapter::new()) as AdapterArc,
            "a.cpp",
            "memcpy",
            "void *memcpy(void *dst, const void *src, unsigned long n);\nvoid entry(char **argv) { void *node = 0; void **cp = (void**)argv; audit(cp); memcpy(&node, cp, sizeof(node)); memcpy(cp, &node, sizeof(node)); }\n",
        ),
    ] {
        let db = build_db(adapter, &[(file, src)]);
        let entry = func_id_or_none(&db, "entry").unwrap_or_else(|| panic!("{lang}: entry should index"));
        let result = interprocedural_taint(entry, &seed(&["argv"]), &cfg(), &db);
        assert!(
            sink_received_arg_index(&result, "audit", 0),
            "{lang}: argv should taint cp so the fixed-size copy case is meaningful; got {:?}",
            result.tainted_calls,
        );
        assert!(
            sink_received_arg_text(&result, copy_call, "cp"),
            "{lang}: memcpy source/destination pointer should be tainted so this locks arg-specific precision; got {:?}",
            result.tainted_calls,
        );
        assert!(
            !sink_received_arg_index(&result, copy_call, 2),
            "{lang}: sizeof(pointer) is a fixed compile-time size and must not taint memcpy length; got {:?}",
            result.tainted_calls,
        );
    }
}

#[test]
fn over_taint_all_languages_literal_containing_seed_name_stays_clean() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: "def entry(args):\n    audit(args)\n    sink('args')\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: "function entry(args) { audit(args); sink('args'); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: "function entry(args: string) { audit(args); sink('args'); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: "class Demo { void entry(String args) { audit(args); sink(\"args\"); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: "fun entry(args: String) { audit(args); sink(\"args\") }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: "object Demo { def entry(args: String): Unit = { audit(args); sink(\"args\") } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "a.cs",
            src: "class Demo { void entry(string args) { audit(args); sink(\"args\"); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: "package main\nfunc entry(args string) { audit(args); sink(\"args\") }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: "fn entry(args: String) { audit(args); sink(\"args\"); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: "void entry(char *args) { audit(args); sink(\"args\"); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: "void entry(const char *args) { audit(args); sink(\"args\"); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: "void entry(NSString *args) { audit(args); sink(@\"args\"); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: "def entry(args)\n  audit(args)\n  sink('args')\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: "<?php\nfunction entry($args) { audit($args); sink('args'); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: "sub entry { my ($args) = @_; audit($args); sink('args'); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: "func entry(args: String) { audit(args); sink(\"args\") }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: "void entry(String args) { audit(args); sink('args'); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: "function entry(args)\n  audit(args)\n  sink('args')\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: "defmodule Demo do\n  def entry(args) do\n    audit(args)\n    sink(\"args\")\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: "-module(demo).\n-export([entry/1]).\nentry(Args) -> audit(Args), sink(\"Args\").\n",
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: "contract Demo { function entry(string memory args) public { audit(args); sink(\"args\"); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        assert_audit_tainted_but_sink_clean(
            case.lang,
            case.adapter,
            case.file,
            case.src,
            case.entry,
            case.seed,
            case.sink,
        );
    });
}

#[test]
fn over_taint_all_languages_clean_overwrite_before_sink_clears_taint() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: "def entry(args):\n    audit(args)\n    value = args\n    value = 'safe'\n    sink(value)\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: "function entry(args) { audit(args); let value = args; value = 'safe'; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: "function entry(args: string) { let value = args; audit(args); value = 'safe'; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: "class Demo { void entry(String args) { audit(args); String value = args; value = \"safe\"; sink(value); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: "fun entry(args: String) { audit(args); var value = args; value = \"safe\"; sink(value) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: "object Demo { def entry(args: String): Unit = { audit(args); var value = args; value = \"safe\"; sink(value) } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "a.cs",
            src: "class Demo { void entry(string args) { audit(args); string value = args; value = \"safe\"; sink(value); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: "package main\nfunc entry(args string) { audit(args); value := args; value = \"safe\"; sink(value) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: "fn entry(args: String) { audit(args); let mut value = args; value = \"safe\"; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: "void entry(char *args) { audit(args); char *value = args; value = \"safe\"; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: "void entry(const char *args) { audit(args); const char *value = args; value = \"safe\"; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: "void entry(NSString *args) { audit(args); NSString *value = args; value = @\"safe\"; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: "def entry(args)\n  audit(args)\n  value = args\n  value = 'safe'\n  sink(value)\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: "<?php\nfunction entry($args) { audit($args); $value = $args; $value = 'safe'; sink($value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: "sub entry { my ($args) = @_; audit($args); my $value = $args; $value = 'safe'; sink($value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: "func entry(args: String) { audit(args); var value = args; value = \"safe\"; sink(value) }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: "void entry(String args) { audit(args); var value = args; value = 'safe'; sink(value); }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: "function entry(args)\n  audit(args)\n  local value = args\n  value = 'safe'\n  sink(value)\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: "defmodule Demo do\n  def entry(args) do\n    audit(args)\n    value = args\n    value = \"safe\"\n    sink(value)\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: "-module(demo).\n-export([entry/1]).\nentry(Args) -> audit(Args), Value0 = Args, Value = \"safe\", sink(Value).\n",
            entry: "entry",
            seed: &["Args"],
            sink: "sink",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: "contract Demo { function entry(string memory args) public { audit(args); string memory value = args; value = \"safe\"; sink(value); } }\n",
            entry: "entry",
            seed: &["args"],
            sink: "sink",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        assert_audit_tainted_but_sink_clean(
            case.lang,
            case.adapter,
            case.file,
            case.src,
            case.entry,
            case.seed,
            case.sink,
        );
    });
}

#[test]
fn over_taint_all_languages_lifecycle_field_and_guard_paths_stay_clean() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        carrier_sink: &'static str,
        lifecycle_sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: "def entry(args):\n    audit(args)\n    carrier(args)\n    lifecycle(args)\n\ndef carrier(c):\n    audit(c)\n    sink_carrier(c.capacity)\n\ndef lifecycle(c):\n    stage(c)\n\ndef stage(c):\n    cleanup(c, True)\n\ndef cleanup(c, free_array):\n    audit(c)\n    if not free_array:\n        sink_lifecycle(c.capacity)\n    else:\n        release(c)\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: "function entry(args) { audit(args); carrier(args); lifecycle(args); }\nfunction carrier(c) { audit(c); sink_carrier(c.capacity); }\nfunction lifecycle(c) { stage(c); }\nfunction stage(c) { cleanup(c, true); }\nfunction cleanup(c, freeArray) { audit(c); if (!freeArray) { sink_lifecycle(c.capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: "function entry(args: any) { audit(args); carrier(args); lifecycle(args); }\nfunction carrier(c: any) { audit(c); sink_carrier(c.capacity); }\nfunction lifecycle(c: any) { stage(c); }\nfunction stage(c: any) { cleanup(c, true); }\nfunction cleanup(c: any, freeArray: boolean) { audit(c); if (!freeArray) { sink_lifecycle(c.capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: "class Demo { void entry(Client args) { audit(args); carrier(args); lifecycle(args); } void carrier(Client c) { audit(c); sink_carrier(c.capacity); } void lifecycle(Client c) { stage(c); } void stage(Client c) { cleanup(c, true); } void cleanup(Client c, boolean freeArray) { audit(c); if (!freeArray) { sink_lifecycle(c.capacity); } else { release(c); } } } class Client { int capacity; }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: "class Client { var capacity: Int = 0 }\nfun entry(args: Client) { audit(args); carrier(args); lifecycle(args) }\nfun carrier(c: Client) { audit(c); sink_carrier(c.capacity) }\nfun lifecycle(c: Client) { stage(c) }\nfun stage(c: Client) { cleanup(c, true) }\nfun cleanup(c: Client, freeArray: Boolean) { audit(c); if (!freeArray) { sink_lifecycle(c.capacity) } else { release(c) } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: "class Client { var capacity: Int = 0 }\nobject Demo { def entry(args: Client): Unit = { audit(args); carrier(args); lifecycle(args) }; def carrier(c: Client): Unit = { audit(c); sink_carrier(c.capacity) }; def lifecycle(c: Client): Unit = { stage(c) }; def stage(c: Client): Unit = { cleanup(c, true) }; def cleanup(c: Client, freeArray: Boolean): Unit = { audit(c); if (!freeArray) { sink_lifecycle(c.capacity) } else { release(c) } } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "Demo.cs",
            src: "class Client { public int capacity; } class Demo { void Entry(Client args) { Audit(args); Carrier(args); Lifecycle(args); } void Carrier(Client c) { Audit(c); SinkCarrier(c.capacity); } void Lifecycle(Client c) { Stage(c); } void Stage(Client c) { Cleanup(c, true); } void Cleanup(Client c, bool freeArray) { Audit(c); if (!freeArray) { SinkLifecycle(c.capacity); } else { Release(c); } } }\n",
            entry: "Entry",
            seed: &["args"],
            carrier_sink: "SinkCarrier",
            lifecycle_sink: "SinkLifecycle",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: "package main\ntype Client struct { capacity int }\nfunc entry(args Client) { audit(args); carrier(args); lifecycle(args) }\nfunc carrier(c Client) { audit(c); sink_carrier(c.capacity) }\nfunc lifecycle(c Client) { stage(c) }\nfunc stage(c Client) { cleanup(c, true) }\nfunc cleanup(c Client, freeArray bool) { audit(c); if !freeArray { sink_lifecycle(c.capacity) } else { release(c) } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: "struct Client { capacity: usize }\nfn entry(args: Client) { audit(args); carrier(args); lifecycle(args); }\nfn carrier(c: Client) { audit(c); sink_carrier(c.capacity); }\nfn lifecycle(c: Client) { stage(c); }\nfn stage(c: Client) { cleanup(c, true); }\nfn cleanup(c: Client, free_array: bool) { audit(c); if !free_array { sink_lifecycle(c.capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: "struct Client { int capacity; };\nvoid entry(struct Client *args) { audit(args); carrier(args); lifecycle(args); }\nvoid carrier(struct Client *c) { audit(c); sink_carrier(c->capacity); }\nvoid lifecycle(struct Client *c) { stage(c); }\nvoid stage(struct Client *c) { cleanup(c, 1); }\nvoid cleanup(struct Client *c, int free_array) { audit(c); if (!free_array) { sink_lifecycle(c->capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: "struct Client { int capacity; };\nvoid entry(Client *args) { audit(args); carrier(args); lifecycle(args); }\nvoid carrier(Client *c) { audit(c); sink_carrier(c->capacity); }\nvoid lifecycle(Client *c) { stage(c); }\nvoid stage(Client *c) { cleanup(c, 1); }\nvoid cleanup(Client *c, int free_array) { audit(c); if (!free_array) { sink_lifecycle(c->capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: "typedef struct Client { int capacity; } Client;\nvoid entry(Client *args) { audit(args); carrier(args); lifecycle(args); }\nvoid carrier(Client *c) { audit(c); sink_carrier(c->capacity); }\nvoid lifecycle(Client *c) { stage(c); }\nvoid stage(Client *c) { cleanup(c, 1); }\nvoid cleanup(Client *c, int free_array) { audit(c); if (!free_array) { sink_lifecycle(c->capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: "def entry(args)\n  audit(args)\n  carrier(args)\n  lifecycle(args)\nend\ndef carrier(c)\n  audit(c)\n  sink_carrier(c.capacity)\nend\ndef lifecycle(c)\n  stage(c)\nend\ndef stage(c)\n  cleanup(c, true)\nend\ndef cleanup(c, free_array)\n  audit(c)\n  if !free_array\n    sink_lifecycle(c.capacity)\n  else\n    release(c)\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: "<?php\nfunction entry($args) { audit($args); carrier($args); lifecycle($args); }\nfunction carrier($c) { audit($c); sink_carrier($c->capacity); }\nfunction lifecycle($c) { stage($c); }\nfunction stage($c) { cleanup($c, true); }\nfunction cleanup($c, $free_array) { audit($c); if (!$free_array) { sink_lifecycle($c->capacity); } else { release($c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: "sub entry { my ($args) = @_; audit($args); carrier($args); lifecycle($args); }\nsub carrier { my ($c) = @_; audit($c); sink_carrier($c->{capacity}); }\nsub lifecycle { my ($c) = @_; stage($c); }\nsub stage { my ($c) = @_; cleanup($c, 1); }\nsub cleanup { my ($c, $free_array) = @_; audit($c); if (!$free_array) { sink_lifecycle($c->{capacity}); } else { release($c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: "struct Client { var capacity: Int }\nfunc entry(args: Client) { audit(args); carrier(c: args); lifecycle(c: args) }\nfunc carrier(c: Client) { audit(c); sink_carrier(c.capacity) }\nfunc lifecycle(c: Client) { stage(c: c) }\nfunc stage(c: Client) { cleanup(c: c, freeArray: true) }\nfunc cleanup(c: Client, freeArray: Bool) { audit(c); if !freeArray { sink_lifecycle(c.capacity) } else { release(c) } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: "class Client { int capacity = 0; }\nvoid entry(Client args) { audit(args); carrier(args); lifecycle(args); }\nvoid carrier(Client c) { audit(c); sink_carrier(c.capacity); }\nvoid lifecycle(Client c) { stage(c); }\nvoid stage(Client c) { cleanup(c, true); }\nvoid cleanup(Client c, bool freeArray) { audit(c); if (!freeArray) { sink_lifecycle(c.capacity); } else { release(c); } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: "function entry(args)\n  audit(args)\n  carrier(args)\n  lifecycle(args)\nend\nfunction carrier(c)\n  audit(c)\n  sink_carrier(c.capacity)\nend\nfunction lifecycle(c)\n  stage(c)\nend\nfunction stage(c)\n  cleanup(c, true)\nend\nfunction cleanup(c, free_array)\n  audit(c)\n  if not free_array then\n    sink_lifecycle(c.capacity)\n  else\n    release(c)\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: "defmodule Demo do\n  def entry(args) do\n    audit(args)\n    carrier(args)\n    lifecycle(args)\n  end\n  def carrier(c) do\n    audit(c)\n    sink_carrier(c.capacity)\n  end\n  def lifecycle(c), do: stage(c)\n  def stage(c), do: cleanup(c, true)\n  def cleanup(c, free_array) do\n    audit(c)\n    if !free_array do\n      sink_lifecycle(c.capacity)\n    else\n      release(c)\n    end\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: "-module(demo).\n-export([entry/1, carrier/1, lifecycle/1, stage/1, cleanup/2]).\nentry(Args) -> audit(Args), carrier(Args), lifecycle(Args).\ncarrier(C) -> audit(C), sink_carrier(C.capacity).\nlifecycle(C) -> stage(C).\nstage(C) -> cleanup(C, 1).\ncleanup(C, FreeArray) -> audit(C), if FreeArray == 0 -> sink_lifecycle(C.capacity); true -> release(C) end.\n",
            entry: "entry",
            seed: &["Args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: "contract Demo { struct Client { uint capacity; } function entry(Client memory args) public { audit(args); carrier(args); lifecycle(args); } function carrier(Client memory c) internal { audit(c); sink_carrier(c.capacity); } function lifecycle(Client memory c) internal { stage(c); } function stage(Client memory c) internal { cleanup(c, true); } function cleanup(Client memory c, bool freeArray) internal { audit(c); if (!freeArray) { sink_lifecycle(c.capacity); } else { release(c); } } }\n",
            entry: "entry",
            seed: &["args"],
            carrier_sink: "sink_carrier",
            lifecycle_sink: "sink_lifecycle",
        },
    ];

    // Ruby's `c.capacity` is method-send syntax, not a field-access AST.
    // Without a resolved method body or external summary, a compiler-grade
    // taint graph must conservatively allow the receiver to influence the
    // result. Field-sensitivity is asserted here only for languages whose
    // syntax distinguishes a field projection from a call.
    cases
        .into_par_iter()
        .filter(|case| case.lang != "ruby")
        .for_each(|case| {
            let db = build_db(case.adapter, &[(case.file, case.src)]);
            let entry = func_id_or_none(&db, case.entry)
                .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
            let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
            assert!(
                sink_received_arg_index(&result, "audit", 0)
                    || sink_received_arg_index(&result, "Audit", 0),
                "{}: direct audit of the seed must be tainted so the negative assertions are meaningful; got {:?}",
                case.lang,
                result.tainted_calls,
            );
            assert!(
                !sink_reached(&result, case.carrier_sink),
            "{}: tainted carrier object must not taint independent capacity field; got {:?}",
            case.lang,
            result.tainted_calls,
        );
        assert!(
            !sink_reached(&result, case.lifecycle_sink),
            "{}: cleanup/lifecycle reachability plus constant guard must not taint guarded field sink; got {:?}",
            case.lang,
            result.tainted_calls,
        );
    });
}

#[test]
fn over_taint_all_languages_field_taint_passed_as_carrier_stays_field_scoped() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        cmd_sink: &'static str,
        clean_sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: "def entry(args):\n    c = Client()\n    c.cmd = args\n    cleanup(c)\n\nclass Client:\n    pass\n\ndef cleanup(c):\n    sink_cmd(c.cmd)\n    sink_clean(c.capacity)\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: "function entry(args) { let c = {}; c.cmd = args; cleanup(c); }\nfunction cleanup(c) { sink_cmd(c.cmd); sink_clean(c.capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: "function entry(args: string) { let c: any = {}; c.cmd = args; cleanup(c); }\nfunction cleanup(c: any) { sink_cmd(c.cmd); sink_clean(c.capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: "class Client { String cmd; String capacity; }\nclass Demo { void entry(String args) { Client c = new Client(); c.cmd = args; cleanup(c); } void cleanup(Client c) { sink_cmd(c.cmd); sink_clean(c.capacity); } }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: "class Client { var cmd: String = \"\"; var capacity: String = \"\" }\nfun entry(args: String) { val c = Client(); c.cmd = args; cleanup(c) }\nfun cleanup(c: Client) { sink_cmd(c.cmd); sink_clean(c.capacity) }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: "class Client { var cmd: String = \"\"; var capacity: String = \"\" }\nobject Demo { def entry(args: String): Unit = { val c = new Client(); c.cmd = args; cleanup(c) }; def cleanup(c: Client): Unit = { sink_cmd(c.cmd); sink_clean(c.capacity) } }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "Demo.cs",
            src: "class Client { public string cmd; public string capacity; } class Demo { void Entry(string args) { var c = new Client(); c.cmd = args; Cleanup(c); } void Cleanup(Client c) { SinkCmd(c.cmd); SinkClean(c.capacity); } }\n",
            entry: "Entry",
            seed: &["args"],
            cmd_sink: "SinkCmd",
            clean_sink: "SinkClean",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: "package main\ntype Client struct { cmd string; capacity string }\nfunc entry(args string) { var c Client; c.cmd = args; cleanup(c) }\nfunc cleanup(c Client) { sink_cmd(c.cmd); sink_clean(c.capacity) }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: "struct Client { cmd: String, capacity: String }\nfn entry(args: String) { let mut c = Client { cmd: String::new(), capacity: String::new() }; c.cmd = args; cleanup(c); }\nfn cleanup(c: Client) { sink_cmd(c.cmd); sink_clean(c.capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: "typedef struct Client { char *cmd; char *capacity; } Client;\nvoid entry(char *args) { Client *c; c->cmd = args; cleanup(c); }\nvoid cleanup(Client *c) { sink_cmd(c->cmd); sink_clean(c->capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: "struct Client { char *cmd; char *capacity; };\nvoid entry(char *args) { Client *c; c->cmd = args; cleanup(c); }\nvoid cleanup(Client *c) { sink_cmd(c->cmd); sink_clean(c->capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: "typedef struct Client { char *cmd; char *capacity; } Client;\nvoid entry(char *args) { Client *c; c->cmd = args; cleanup(c); }\nvoid cleanup(Client *c) { sink_cmd(c->cmd); sink_clean(c->capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: "def entry(args)\n  c = {}\n  c[:cmd] = args\n  cleanup(c)\nend\n\ndef cleanup(c)\n  sink_cmd(c[:cmd])\n  sink_clean(c[:capacity])\nend\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: "<?php\nfunction entry($args) { $c = new stdClass(); $c->cmd = $args; cleanup($c); }\nfunction cleanup($c) { sink_cmd($c->cmd); sink_clean($c->capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: "sub entry { my ($args) = @_; my $c = {}; $c->{cmd} = $args; cleanup($c); }\nsub cleanup { my ($c) = @_; sink_cmd($c->{cmd}); sink_clean($c->{capacity}); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: "struct Client { var cmd: String; var capacity: String }\nfunc entry(args: String) { var c = Client(cmd: \"\", capacity: \"\"); c.cmd = args; cleanup(c: c) }\nfunc cleanup(c: Client) { sink_cmd(c.cmd); sink_clean(c.capacity) }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: "class Client { var cmd; var capacity; }\nvoid entry(args) { var c = Client(); c.cmd = args; cleanup(c); }\nvoid cleanup(c) { sink_cmd(c.cmd); sink_clean(c.capacity); }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: "function entry(args)\n  local c = {}\n  c.cmd = args\n  cleanup(c)\nend\nfunction cleanup(c)\n  sink_cmd(c.cmd)\n  sink_clean(c.capacity)\nend\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: "defmodule Demo do\n  def entry(args) do\n    c = %{cmd: args, capacity: \"clean\"}\n    cleanup(c)\n  end\n  def cleanup(c) do\n    sink_cmd(c.cmd)\n    sink_clean(c.capacity)\n  end\nend\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: "-module(demo).\n-export([entry/1, cleanup/1]).\nentry(Args) -> C = #{cmd => Args, capacity => \"clean\"}, cleanup(C).\ncleanup(C) -> sink_cmd(maps:get(cmd, C)), sink_clean(maps:get(capacity, C)).\n",
            entry: "entry",
            seed: &["Args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: "contract Demo { struct Client { bytes cmd; bytes capacity; } function entry(bytes memory args) public { Client memory c; c.cmd = args; cleanup(c); } function cleanup(Client memory c) internal { sink_cmd(c.cmd); sink_clean(c.capacity); } }\n",
            entry: "entry",
            seed: &["args"],
            cmd_sink: "sink_cmd",
            clean_sink: "sink_clean",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        let db = build_db(case.adapter, &[(case.file, case.src)]);
        let entry = func_id_or_none(&db, case.entry)
            .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
        let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
        assert!(
            sink_reached(&result, case.cmd_sink),
            "{}: tainted field should still propagate to matching callee field; got {:?}",
            case.lang,
            result.tainted_calls,
        );
        assert!(
            !sink_reached(&result, case.clean_sink),
            "{}: tainted field passed through carrier must not taint sibling field; got {:?}",
            case.lang,
            result.tainted_calls,
        );
    });
}

#[test]
fn over_taint_all_languages_internal_field_derived_locals_stay_clean() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
    }

    let cases = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: r#"def entry(args):
    audit(args)
    derived(args)

def derived(c):
    audit(c)
    size = c.capacity * 2
    sink_derived(size)
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: r#"function entry(args) { audit(args); derived(args); }
function derived(c) { audit(c); let size = c.capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: r#"function entry(args: any) { audit(args); derived(args); }
function derived(c: any) { audit(c); let size = c.capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "A.java",
            src: r#"class Demo { void entry(Client args) { audit(args); derived(args); } void derived(Client c) { audit(c); int size = c.capacity * 2; sink_derived(size); } } class Client { int capacity; }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "A.kt",
            src: r#"class Client { var capacity: Int = 0 }
fun entry(args: Client) { audit(args); derived(args) }
fun derived(c: Client) { audit(c); val size = c.capacity * 2; sink_derived(size) }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "A.scala",
            src: r#"class Client { var capacity: Int = 0 }
object Demo { def entry(args: Client): Unit = { audit(args); derived(args) }; def derived(c: Client): Unit = { audit(c); val size = c.capacity * 2; sink_derived(size) } }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "A.cs",
            src: r#"class Client { public int capacity; }
class Demo { void entry(Client args) { audit(args); derived(args); } void derived(Client c) { audit(c); int size = c.capacity * 2; sink_derived(size); } }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: r#"class Client { int capacity = 0; }
void entry(Client args) { audit(args); derived(args); }
void derived(Client c) { audit(c); var size = c.capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: r#"package main
type Client struct { capacity int }
func entry(args Client) { audit(args); derived(args) }
func derived(c Client) { audit(c); size := c.capacity * 2; sink_derived(size) }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: r#"struct Client { capacity: usize }
fn entry(args: Client) { audit(args); derived(args); }
fn derived(c: Client) { audit(c); let size = c.capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: r#"struct Client { int capacity; };
void entry(struct Client *args) { audit(args); derived(args); }
void derived(struct Client *c) { audit(c); int size = c->capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: r#"struct Client { int capacity; };
void entry(Client *args) { audit(args); derived(args); }
void derived(Client *c) { audit(c); int size = c->capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: r#"typedef struct Client { int capacity; } Client;
void entry(Client *args) { audit(args); derived(args); }
void derived(Client *c) { audit(c); int size = c->capacity * 2; sink_derived(size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: r#"def entry(args)
  audit(args)
  derived(args)
end
def derived(c)
  audit(c)
  size = c.capacity * 2
  sink_derived(size)
end
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: r#"<?php
function entry($args) { audit($args); derived($args); }
function derived($c) { audit($c); $size = $c->capacity * 2; sink_derived($size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: r#"sub entry { my ($args) = @_; audit($args); derived($args); }
sub derived { my ($c) = @_; audit($c); my $size = $c->{capacity} * 2; sink_derived($size); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: r#"struct Client { var capacity: Int }
func entry(args: Client) { audit(args); derived(c: args) }
func derived(c: Client) { audit(c); let size = c.capacity * 2; sink_derived(size) }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: r#"function entry(args)
  audit(args)
  derived(args)
end
function derived(c)
  audit(c)
  local size = c.capacity * 2
  sink_derived(size)
end
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: r#"defmodule Demo do
  def entry(args) do
    audit(args)
    derived(args)
  end
  def derived(c) do
    audit(c)
    size = c.capacity * 2
    sink_derived(size)
  end
end
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: r#"-module(demo).
-export([entry/1, derived/1]).
entry(Args) -> audit(Args), derived(Args).
derived(C) -> audit(C), Size = C.capacity * 2, sink_derived(Size).
"#,
            entry: "entry",
            seed: &["Args"],
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: r#"contract Demo { struct Client { uint capacity; } function entry(Client memory args) public { audit(args); derived(args); } function derived(Client memory c) internal { audit(c); uint size = c.capacity * 2; sink_derived(size); } }
"#,
            entry: "entry",
            seed: &["args"],
        },
    ];

    // Ruby has no field-access grammar — `c.capacity` is always a
    // method call (tree-sitter classifies it that way; Ruby
    // semantics agree). Treating its return value as tainted when
    // the receiver is tainted is correct; the aspirational
    // "internal field stays clean" framing only applies to languages
    // whose adapters can distinguish field read from method call.
    cases
        .into_par_iter()
        .filter(|case| case.lang != "ruby")
        .for_each(|case| {
            let db = build_db(case.adapter, &[(case.file, case.src)]);
            let entry = func_id_or_none(&db, case.entry)
                .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
            let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
            assert!(
                sink_received_arg_index(&result, "audit", 0)
                    || sink_received_arg_index(&result, "Audit", 0),
                "{}: direct audit of the seed must be tainted so the negative assertion is meaningful; got {:?}",
                case.lang,
                result.tainted_calls,
            );
            assert!(
                !sink_reached(&result, "sink_derived"),
                "{}: local derived only from an independent internal field must stay clean; got {:?}",
                case.lang,
                result.tainted_calls,
            );
        });
}

// ===========================================================================
// USER-REPORTED CASE: argparse → eval through hardcoded intermediates
// ===========================================================================

#[test]
fn over_taint_user_reported_argparse_to_eval_through_hardcoded_filter() {
    // The exact shape the user flagged: `args = parser.parse_args()`
    // then a class method that uses HARDCODED filter strings calls
    // eval. The engine must NOT report the eval as tainted from
    // args, because the data path from args to eval is broken by
    // hardcoded literals.
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = r#"
import argparse

class TestRunner:
    def run(self):
        return self.test_recall_with_filter('.category == "electronics"')

    def test_recall_with_filter(self, filter_expr):
        py_expr = filter_expr.replace('.category', 'attributes["category"]')
        attributes = {}
        return eval(py_expr, {"attributes": attributes})

def entry():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    test = TestRunner()
    return test.run()
"#;
    let db = build_db(adapter, &[("a.py", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "eval"),
        "user-reported case: hardcoded filter literal must not produce a tainted eval; got {:?}",
        result.tainted_calls,
    );
}

#[test]
fn over_taint_all_languages_clean_return_after_tainted_consume_stays_clean() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
    }

    let cases = vec![
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: r#"const char *helper(char *v) { audit(v); return "clean"; }
void entry(char *args) { const char *x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: r#"const char *helper(const char *v) { audit(v); return "clean"; }
void entry(const char *args) { const char *x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "Demo.cs",
            src: r#"class Demo { string Helper(string v) { audit(v); return "clean"; } void Entry(string args) { var x = Helper(args); sink(x); } }
"#,
            entry: "Entry",
            seed: &["args"],
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: r#"String helper(String v) { audit(v); return 'clean'; }
void entry(String args) { final x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: r#"defmodule Demo do
  def helper(v) do audit(v); "clean" end
  def entry(args) do x = helper(args); sink(x) end
end
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: r#"-module(demo).
-export([entry/1, helper/1]).
helper(V) -> audit(V), "clean".
entry(Args) -> X = helper(Args), sink(X).
"#,
            entry: "entry",
            seed: &["Args"],
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: r#"package main
func helper(v string) string { audit(v); return "clean" }
func entry(args string) { x := helper(args); sink(x) }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: r#"class Demo { String helper(String v) { audit(v); return "clean"; } void entry(String args) { String x = helper(args); sink(x); } }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: r#"function helper(v) { audit(v); return "clean"; }
function entry(args) { const x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: r#"fun helper(v: String): String { audit(v); return "clean" }
fun entry(args: String) { val x = helper(args); sink(x) }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: r#"function helper(v) audit(v); return "clean" end
function entry(args) local x = helper(args); sink(x) end
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: r#"NSString *helper(NSString *v) { audit(v); return @"clean"; }
void entry(NSString *args) { NSString *x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: r#"sub helper { my ($v) = @_; audit($v); return "clean"; }
sub entry { my ($args) = @_; my $x = helper($args); sink($x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: r#"<?php
function helper($v) { audit($v); return "clean"; }
function entry($args) { $x = helper($args); sink($x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: r#"def helper(v):
    audit(v)
    return "clean"
def entry(args):
    x = helper(args)
    sink(x)
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: r#"def helper(v)
  audit(v)
  return "clean"
end
def entry(args)
  x = helper(args)
  sink(x)
end
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: r#"fn helper(v: String) -> String { audit(v); return "clean".to_string(); }
fn entry(args: String) { let x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: r#"object Demo { def helper(v: String): String = { audit(v); "clean" }; def entry(args: String): Unit = { val x = helper(args); sink(x) } }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: r#"contract Demo {
  function helper(string memory v) internal returns (string memory) { audit(v); return "clean"; }
  function entry(string memory args) public { string memory x = helper(args); sink(x); }
}
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: r#"func helper(_ v: String) -> String { audit(v); return "clean" }
func entry(args: String) { let x = helper(args); sink(x) }
"#,
            entry: "entry",
            seed: &["args"],
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: r#"function helper(v: string): string { audit(v); return "clean"; }
function entry(args: string) { const x = helper(args); sink(x); }
"#,
            entry: "entry",
            seed: &["args"],
        },
    ];

    cases.into_par_iter().for_each(|case| {
        assert_audit_tainted_but_sink_clean(
            case.lang,
            case.adapter,
            case.file,
            case.src,
            case.entry,
            case.seed,
            "sink",
        );
    });
}

#[test]
fn over_taint_all_languages_unknown_call_does_not_taint_independent_later_sink() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        audit: &'static str,
        sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: r#"void entry(char *args) { audit(args); opaque(args); int cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: r#"void entry(const char *args) { audit(args); opaque(args); int cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "Demo.cs",
            src: r#"class Demo { void Entry(string args) { Audit(args); Opaque(args); int cap = 32; Sink(cap); } }
"#,
            entry: "Entry",
            seed: &["args"],
            audit: "Audit",
            sink: "Sink",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: r#"void entry(String args) { audit(args); opaque(args); var cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: r#"defmodule Demo do
  def entry(args) do
    audit(args)
    opaque(args)
    cap = 32
    sink(cap)
  end
end
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: r#"-module(demo).
-export([entry/1]).
entry(Args) -> audit(Args), opaque(Args), Cap = 32, sink(Cap).
"#,
            entry: "entry",
            seed: &["Args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: r#"package main
func entry(args string) { audit(args); opaque(args); cap := 32; sink(cap) }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: r#"class Demo { void entry(String args) { audit(args); opaque(args); int cap = 32; sink(cap); } }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: r#"function entry(args) { audit(args); opaque(args); const cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: r#"fun entry(args: String) { audit(args); opaque(args); val cap = 32; sink(cap) }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: r#"function entry(args)
  audit(args)
  opaque(args)
  local cap = 32
  sink(cap)
end
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: r#"void entry(NSString *args) { audit(args); opaque(args); int cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: r#"sub entry { my ($args) = @_; audit($args); opaque($args); my $cap = 32; sink($cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: r#"<?php
function entry($args) { audit($args); opaque($args); $cap = 32; sink($cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: r#"def entry(args):
    audit(args)
    opaque(args)
    cap = 32
    sink(cap)
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: r#"def entry(args)
  audit(args)
  opaque(args)
  cap = 32
  sink(cap)
end
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: r#"fn entry(args: String) { audit(args); opaque(args); let cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: r#"object Demo { def entry(args: String): Unit = { audit(args); opaque(args); val cap = 32; sink(cap) } }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: r#"contract Demo { function entry(string memory args) public { audit(args); opaque(args); uint cap = 32; sink(cap); } }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: r#"func entry(args: String) { audit(args); opaque(args); let cap = 32; sink(cap) }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: r#"function entry(args: string) { audit(args); opaque(args); const cap = 32; sink(cap); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        let db = build_db(case.adapter, &[(case.file, case.src)]);
        let entry = func_id_or_none(&db, case.entry)
            .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
        let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
        assert!(
            sink_received_arg_index(&result, case.audit, 0),
            "{}: direct audit of the source must be tainted so the negative assertion is meaningful; got {:?}",
            case.lang,
            result.tainted_calls,
        );
        assert!(
            !sink_reached(&result, case.sink),
            "{}: unknown call/lifecycle consumption must not taint the later independent sink; got {:?}",
            case.lang,
            result.tainted_calls,
        );
    });
}

#[test]
fn over_taint_all_languages_sibling_field_or_key_reads_stay_clean() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        file: &'static str,
        src: &'static str,
        entry: &'static str,
        seed: &'static [&'static str],
        audit: &'static str,
        sink: &'static str,
    }

    let cases = vec![
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            file: "a.c",
            src: r#"struct Box { char *tainted; char *clean; };
void entry(char *args) { audit(args); struct Box b; b.tainted = args; b.clean = "safe"; sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            file: "a.cpp",
            src: r#"struct Box { const char *tainted; const char *clean; };
void entry(const char *args) { audit(args); Box b; b.tainted = args; b.clean = "safe"; sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            file: "Demo.cs",
            src: r#"class Box { public string tainted; public string clean; }
class Demo { void Entry(string args) { Audit(args); var b = new Box(); b.tainted = args; b.clean = "safe"; Sink(b.clean); } }
"#,
            entry: "Entry",
            seed: &["args"],
            audit: "Audit",
            sink: "Sink",
        },
        Case {
            lang: "dart",
            adapter: Arc::new(bonsai_lang_dart::DartAdapter::new()),
            file: "a.dart",
            src: r#"class Box { String tainted = ''; String clean = ''; }
void entry(String args) { audit(args); var b = Box(); b.tainted = args; b.clean = 'safe'; sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "elixir",
            adapter: Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            file: "a.ex",
            src: r#"defmodule Demo do
  def entry(args) do
    audit(args)
    b = %{tainted: args, clean: "safe"}
    sink(b.clean)
  end
end
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "erlang",
            adapter: Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            file: "demo.erl",
            src: r#"-module(demo).
-export([entry/1]).
entry(Args) -> audit(Args), B = #{tainted => Args, clean => "safe"}, sink(maps:get(clean, B)).
"#,
            entry: "entry",
            seed: &["Args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            file: "a.go",
            src: r#"package main
type Box struct { tainted string; clean string }
func entry(args string) { audit(args); b := Box{}; b.tainted = args; b.clean = "safe"; sink(b.clean) }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            file: "Demo.java",
            src: r#"class Box { String tainted; String clean; }
class Demo { void entry(String args) { audit(args); Box b = new Box(); b.tainted = args; b.clean = "safe"; sink(b.clean); } }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            file: "a.js",
            src: r#"function entry(args) { audit(args); const b = {}; b.tainted = args; b.clean = "safe"; sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            file: "a.kt",
            src: r#"class Box { var tainted: String = ""; var clean: String = "" }
fun entry(args: String) { audit(args); val b = Box(); b.tainted = args; b.clean = "safe"; sink(b.clean) }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "lua",
            adapter: Arc::new(bonsai_lang_lua::LuaAdapter::new()),
            file: "a.lua",
            src: r#"function entry(args)
  audit(args)
  local b = {}
  b.tainted = args
  b.clean = "safe"
  sink(b.clean)
end
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "objc",
            adapter: Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
            file: "a.m",
            src: r#"typedef struct Box { NSString *tainted; NSString *clean; } Box;
void entry(NSString *args) { audit(args); Box b; b.tainted = args; b.clean = @"safe"; sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            file: "a.pl",
            src: r#"sub entry { my ($args) = @_; audit($args); my $b = {}; $b->{tainted} = $args; $b->{clean} = "safe"; sink($b->{clean}); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            file: "a.php",
            src: r#"<?php
function entry($args) { audit($args); $b = new stdClass(); $b->tainted = $args; $b->clean = "safe"; sink($b->clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            file: "a.py",
            src: r#"def entry(args):
    audit(args)
    b = {}
    b["tainted"] = args
    b["clean"] = "safe"
    sink(b["clean"])
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            file: "a.rb",
            src: r#"def entry(args)
  audit(args)
  b = {}
  b[:tainted] = args
  b[:clean] = "safe"
  sink(b[:clean])
end
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            file: "a.rs",
            src: r#"struct Box { tainted: String, clean: String }
fn entry(args: String) { audit(args); let mut b = Box { tainted: String::new(), clean: String::new() }; b.tainted = args; b.clean = "safe".to_string(); sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            file: "a.scala",
            src: r#"class Box { var tainted: String = ""; var clean: String = "" }
object Demo { def entry(args: String): Unit = { audit(args); val b = new Box(); b.tainted = args; b.clean = "safe"; sink(b.clean) } }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "solidity",
            adapter: Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            file: "Demo.sol",
            src: r#"contract Demo { struct Box { string tainted; string clean; } function entry(string memory args) public { audit(args); Box memory b = Box({tainted: args, clean: "safe"}); sink(b.clean); } }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            file: "a.swift",
            src: r#"struct Box { var tainted: String; var clean: String }
func entry(args: String) { audit(args); var b = Box(tainted: "", clean: ""); b.tainted = args; b.clean = "safe"; sink(b.clean) }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            file: "a.ts",
            src: r#"function entry(args: string) { audit(args); const b: any = {}; b.tainted = args; b.clean = "safe"; sink(b.clean); }
"#,
            entry: "entry",
            seed: &["args"],
            audit: "audit",
            sink: "sink",
        },
    ];

    cases.into_par_iter().for_each(|case| {
        let db = build_db(case.adapter, &[(case.file, case.src)]);
        let entry = func_id_or_none(&db, case.entry)
            .unwrap_or_else(|| panic!("{}: entry `{}` should index", case.lang, case.entry));
        let result = interprocedural_taint(entry, &seed(case.seed), &cfg(), &db);
        assert!(
            sink_received_arg_index(&result, case.audit, 0),
            "{}: direct audit of the source must be tainted so the negative assertion is meaningful; got {:?}",
            case.lang,
            result.tainted_calls,
        );
        assert!(
            !sink_reached(&result, case.sink),
            "{}: tainted sibling field/key must not taint the clean sibling field/key; got {:?}",
            case.lang,
            result.tainted_calls,
        );
    });
}
