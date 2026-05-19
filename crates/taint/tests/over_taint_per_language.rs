//! Per-language hardcoded-arg negative tests.
//!
//! Each language has the same shape: build a workspace with one
//! file containing a tainted source, an inner helper that takes a
//! HARDCODED literal arg, and a sink. The engine must NOT report
//! the sink as tainted because the data path is broken by the
//! literal.
//!
//! Cross-language invariants are exercised in `over_taint_matrix.rs`;
//! this file covers the per-language smoke tests so language-specific
//! regressions surface in isolation.

mod common;

use bonsai_lang_api::AdapterArc;
use bonsai_taint::interprocedural_taint;
use common::*;
use std::sync::Arc;

// ===========================================================================
// PYTHON
// ===========================================================================

#[test]
fn over_taint_python_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    inner('.category == \"electronics\"')

def inner(filter_expr):
    sink(filter_expr)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "python: hardcoded literal arg must not propagate taint to sink; got {:?}",
        result
            .tainted_calls
            .iter()
            .map(|c| (&c.name, &c.tainted_args))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn over_taint_python_field_distinct_read() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    obj = {}
    obj['value'] = args
    sink(obj['other'])
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, "sink", "obj['other']")
            && !sink_received_arg_text(&result, "sink", "obj.other"),
        "python: field-distinct read must not inherit field taint; got {:?}",
        result.tainted_calls,
    );
}

#[test]
fn over_taint_python_clean_overwrite_both_branches() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let src = "
def entry(args):
    x = args
    if cond():
        x = 'clean1'
    else:
        x = 'clean2'
    sink(x)
";
    let db = build_db(adapter, &[("a.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, "sink", "x"),
        "python: clean-overwrite in both branches must clear taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// JAVASCRIPT
// ===========================================================================

#[test]
fn over_taint_javascript_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let src = "
function entry(args) {
    inner('.category == \"electronics\"');
}

function inner(filterExpr) {
    sink(filterExpr);
}
";
    let db = build_db(adapter, &[("a.js", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "javascript: hardcoded literal arg must not propagate taint to sink; got {:?}",
        result.tainted_calls,
    );
}

#[test]
fn over_taint_javascript_clean_overwrite_both_branches() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    let src = "
function entry(args) {
    let x = args;
    if (cond()) { x = 'clean1'; }
    else { x = 'clean2'; }
    sink(x);
}
";
    let db = build_db(adapter, &[("a.js", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_received_arg_text(&result, "sink", "x"),
        "javascript: clean-overwrite in both branches must clear taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// TYPESCRIPT
// ===========================================================================

#[test]
fn over_taint_typescript_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new());
    let src = "
function entry(args: any) {
    inner('.category == \"electronics\"');
}

function inner(filterExpr: string) {
    sink(filterExpr);
}
";
    let db = build_db(adapter, &[("a.ts", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "typescript: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// JAVA
// ===========================================================================

#[test]
fn over_taint_java_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let src = r#"
class Demo {
    void entry(String args) {
        inner(".category == \"electronics\"");
    }
    void inner(String filter) {
        sink(filter);
    }
}
"#;
    let db = build_db(adapter, &[("Demo.java", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "java: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// KOTLIN
// ===========================================================================

#[test]
fn over_taint_kotlin_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_kotlin::KotlinAdapter::new());
    let src = r#"
fun entry(args: String) {
    inner(".category == \"electronics\"")
}

fun inner(filter: String) {
    sink(filter)
}
"#;
    let db = build_db(adapter, &[("a.kt", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "kotlin: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// SCALA
// ===========================================================================

#[test]
fn over_taint_scala_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_scala::ScalaAdapter::new());
    let src = r#"
object Demo {
  def entry(args: String): Unit = {
    inner(".category == \"electronics\"")
  }
  def inner(filter: String): Unit = {
    sink(filter)
  }
}
"#;
    let db = build_db(adapter, &[("a.scala", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "scala: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// C# (CSHARP)
// ===========================================================================

#[test]
fn over_taint_csharp_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_csharp::CSharpAdapter::new());
    let src = r#"
class Demo {
    void Entry(string args) {
        Inner(".category == \"electronics\"");
    }
    void Inner(string filter) {
        Sink(filter);
    }
}
"#;
    let db = build_db(adapter, &[("Demo.cs", src)]);
    let Some(entry) = func_id_or_none(&db, "Entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "Sink"),
        "csharp: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// GO
// ===========================================================================

#[test]
fn over_taint_go_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_go::GoAdapter::new());
    let src = r#"
package main

func entry(args string) {
    inner(".category == \"electronics\"")
}

func inner(filter string) {
    sink(filter)
}
"#;
    let db = build_db(adapter, &[("a.go", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "go: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// RUST
// ===========================================================================

#[test]
fn over_taint_rust_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_rust::RustAdapter::new());
    let src = r#"
fn entry(args: String) {
    inner(".category == \"electronics\"");
}

fn inner(filter: &str) {
    sink(filter);
}
"#;
    let db = build_db(adapter, &[("a.rs", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "rust: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// C
// ===========================================================================

#[test]
fn over_taint_c_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_c::CAdapter::new());
    let src = r#"
void entry(char *args) {
    inner(".category == \"electronics\"");
}

void inner(const char *filter) {
    sink(filter);
}
"#;
    let db = build_db(adapter, &[("a.c", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "c: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// C++
// ===========================================================================

#[test]
fn over_taint_cpp_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_cpp::CppAdapter::new());
    let src = r#"
void entry(const std::string& args) {
    inner(".category == \"electronics\"");
}

void inner(const std::string& filter) {
    sink(filter);
}
"#;
    let db = build_db(adapter, &[("a.cpp", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "cpp: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// OBJECTIVE-C
// ===========================================================================

#[test]
fn over_taint_objc_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_objc::ObjCAdapter::new());
    let src = r#"
void entry(NSString *args) {
    inner(@".category == \"electronics\"");
}

void inner(NSString *filter) {
    sink(filter);
}
"#;
    let db = build_db(adapter, &[("a.m", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "objc: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// RUBY
// ===========================================================================

#[test]
fn over_taint_ruby_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_ruby::RubyAdapter::new());
    let src = r#"
def entry(args)
    inner('.category == "electronics"')
end

def inner(filter)
    sink(filter)
end
"#;
    let db = build_db(adapter, &[("a.rb", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "ruby: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// PHP
// ===========================================================================

#[test]
fn over_taint_php_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_php::PhpAdapter::new());
    let src = r#"<?php
function entry($args) {
    inner('.category == "electronics"');
}

function inner($filter) {
    sink($filter);
}
"#;
    let db = build_db(adapter, &[("a.php", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "php: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// PERL
// ===========================================================================

#[test]
fn over_taint_perl_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_perl::PerlAdapter::new());
    let src = r#"
sub entry {
    my ($args) = @_;
    inner('.category == "electronics"');
}

sub inner {
    my ($filter) = @_;
    sink($filter);
}
"#;
    let db = build_db(adapter, &[("a.pl", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "perl: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// SWIFT
// ===========================================================================

#[test]
fn over_taint_swift_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let src = r#"
func entry(args: String) {
    inner(filter: ".category == \"electronics\"")
}

func inner(filter: String) {
    sink(filter)
}
"#;
    let db = build_db(adapter, &[("a.swift", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "swift: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

#[test]
fn over_taint_swift_typed_overload_does_not_follow_wrong_candidate() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_swift::SwiftAdapter::new());
    let src = r#"
func helper(p: String) {}
func helper(p: Int) { sink(p) }
func entry(args: String) { helper(p: args) }
"#;
    let db = build_db(adapter, &[("a.swift", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "swift: typed overload dispatch must not propagate String taint into Int overload; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// DART
// ===========================================================================

#[test]
fn over_taint_dart_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_dart::DartAdapter::new());
    let src = r#"
void entry(String args) {
    inner('.category == "electronics"');
}

void inner(String filter) {
    sink(filter);
}
"#;
    let db = build_db(adapter, &[("a.dart", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "dart: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// LUA
// ===========================================================================

#[test]
fn over_taint_lua_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_lua::LuaAdapter::new());
    let src = r#"
function entry(args)
    inner('.category == "electronics"')
end

function inner(filter)
    sink(filter)
end
"#;
    let db = build_db(adapter, &[("a.lua", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "lua: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// ELIXIR
// ===========================================================================

#[test]
fn over_taint_elixir_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let src = r#"
defmodule Demo do
  def entry(args) do
    inner(".category == \"electronics\"")
  end

  def inner(filter) do
    sink(filter)
  end
end
"#;
    let db = build_db(adapter, &[("a.ex", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "elixir: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

#[test]
fn over_taint_elixir_tuple_return_second_element_does_not_taint_first_binding() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_elixir::ElixirAdapter::new());
    let src = r#"
defmodule Demo do
  def helper(p), do: {"ok", p}
  def entry(args) do
    {a, _b} = helper(args)
    sink(a)
  end
end
"#;
    let db = build_db(adapter, &[("a.ex", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "elixir: tuple return element taint must stay positional; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// ERLANG
// ===========================================================================

#[test]
fn over_taint_erlang_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let src = r#"
-module(demo).
-export([entry/1]).

entry(Args) ->
    inner(".category == \"electronics\"").

inner(Filter) ->
    sink(Filter).
"#;
    let db = build_db(adapter, &[("demo.erl", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["Args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "erlang: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}

#[test]
fn over_taint_erlang_tuple_return_second_element_does_not_taint_first_binding() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_erlang::ErlangAdapter::new());
    let src = r#"
-module(demo).
-export([entry/1, helper/1]).

helper(P) -> {"ok", P}.
entry(Args) -> {A, _B} = helper(Args), sink(A).
"#;
    let db = build_db(adapter, &[("demo.erl", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry decl");
    let result = interprocedural_taint(entry, &seed(&["Args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "erlang: tuple return element taint must stay positional; got {:?}",
        result.tainted_calls,
    );
}

// ===========================================================================
// SOLIDITY
// ===========================================================================

#[test]
fn over_taint_solidity_hardcoded_arg_not_tainted() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_solidity::SolidityAdapter::new());
    let src = r#"
contract Demo {
    function entry(string memory args) public {
        inner(".category == \"electronics\"");
    }
    function inner(string memory filter) internal {
        sink(filter);
    }
}
"#;
    let db = build_db(adapter, &[("Demo.sol", src)]);
    let Some(entry) = func_id_or_none(&db, "entry") else {
        return;
    };
    let result = interprocedural_taint(entry, &seed(&["args"]), &cfg(), &db);
    assert!(
        !sink_reached(&result, "sink"),
        "solidity: hardcoded literal arg must not propagate taint; got {:?}",
        result.tainted_calls,
    );
}
