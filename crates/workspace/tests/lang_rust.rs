//! Per-construct tests for the Rust adapter.

#[path = "lang_common.rs"]
mod common;

use bonsai_lang_api::LoopKind;
use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_rust::RustAdapter::new()), "/w/a.rs", src)
}

#[test]
fn fn_item() {
    let w = make("fn foo() {}");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("fn f() { g(); }");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn path_call_preserved() {
    let w = make("fn f() { std::fs::read_to_string(p); }");
    assert!(has_call_containing(&w, "f", "read_to_string"));
}

#[test]
fn method_call() {
    let w = make("fn f(s: &str) { s.to_string(); }");
    assert!(has_call_containing(&w, "f", "to_string"));
}

#[test]
fn macro_invocation_is_a_call() {
    let w = make("fn f() { println!(\"x\"); }");
    assert!(has_call_containing(&w, "f", "println"));
}

#[test]
fn macro_invocation_preserves_bang() {
    let w = make("fn f() { sqlx::query!(\"select 1\"); }");
    assert!(has_call_containing(&w, "f", "sqlx::query!"));
}

#[test]
fn if_expression() {
    let w = make("fn f(x: i32) { if x > 0 { g() } else { h() } }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_expression() {
    let w = make("fn f() { for i in 0..10 { g(i); } }");
    assert!(has_loop_of(&w, "f", LoopKind::For));
}

#[test]
fn while_expression() {
    let w = make("fn f() { while true { break; } }");
    assert!(has_loop_of(&w, "f", LoopKind::While));
}

#[test]
fn loop_expression_is_classified_as_loop() {
    let w = make("fn f() { loop { break; } }");
    // Rust's unconditional `loop { }` has no condition or init/update —
    // the kit's `loop_kinds` slot maps it to `LoopKind::Loop` rather
    // than mis-classifying it as DoWhile.
    assert!(has_loop_of(&w, "f", LoopKind::Loop));
}

#[test]
fn let_is_captured_as_assign() {
    let w = make("fn f() { let x = 1; }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn return_expression() {
    let w = make("fn f() -> i32 { return 1; }");
    assert!(has_return(&w, "f"));
}

#[test]
fn struct_decl() {
    let w = make("struct Widget { x: i32 }");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn enum_decl() {
    let w = make("enum Color { Red, Green }");
    assert!(class_exists(&w, "Color"));
}

#[test]
fn trait_decl() {
    let w = make("trait Greet { fn hi(&self); }");
    assert!(class_exists(&w, "Greet"));
}

#[test]
fn impl_method_is_function() {
    let w = make("struct W; impl W { fn new() -> Self { W } }");
    assert!(function_exists(&w, "new"));
}

#[test]
fn closure_does_not_pollute_outer_flow() {
    let w = make("fn f() { let cb = |x| inner(x); run(cb); }");
    assert!(has_call(&w, "f", "run"));
    assert!(!has_call(&w, "f", "inner"), "closure body leaked into outer flow");
}

#[test]
fn use_declaration_is_import() {
    let w = make("use std::fs;\nfn f() {}");
    assert!(has_import(&w, "std::fs"));
}

#[test]
fn match_as_branch() {
    let w = make("fn f(x: i32) -> i32 { match x { 0 => 1, _ => 2 } }");
    assert!(has_branch(&w, "f"), "match not classified as branch");
}

#[test]
fn throw_equivalent_panic_is_a_macro_call() {
    // Rust has no throw keyword; `panic!` is a macro invocation.
    let w = make("fn f() { panic!(\"bad\"); }");
    assert!(has_call_containing(&w, "f", "panic"));
}

#[test]
fn attribute_is_decorator() {
    let w = make("#[derive(Debug)]\nstruct Foo;");
    assert!(has_decorator(&w, "derive"));
}

#[test]
fn break_and_continue_in_loop() {
    let w = make("fn f() { for i in 0..10 { if i == 0 { continue; } if i == 5 { break; } } }");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn await_in_async() {
    let w = make("async fn f() -> i32 { g().await }\nasync fn g() -> i32 { 1 }");
    assert!(has_await(&w, "f"));
}

#[test]
fn use_alias_captured() {
    let w = make("use std::collections::HashMap as Map;\nfn f() {}");
    assert!(has_import_symbol_alias(&w, "std::collections", "HashMap", "Map"));
}

#[test]
fn use_wildcard_captured() {
    let w = make("use std::io::*;\nfn f() {}");
    assert!(has_wildcard_import(&w, "std::io"));
}

#[test]
fn try_block_as_try() {
    // Nightly/experimental `try { ... }` block. tree-sitter-rust parses it
    // as a dedicated `try_block` node regardless of feature gates.
    let w = make("fn f() { try { g()?; Ok(()) } }\nfn g() -> Result<(), ()> { Ok(()) }");
    assert!(has_try(&w, "f"));
}
