//! Per-construct tests for the C adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_c::CAdapter::new()), "/w/a.c", src)
}

#[test]
fn function_definition() {
    let w = make("int foo(void) { return 0; }");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("void g(void);\nvoid f(void) { g(); }");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn if_else() {
    let w = make("void f(int x) { if (x > 0) a(); else b(); }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("void f(void) { for (int i = 0; i < 10; i++) g(i); }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("void f(void) { while (1) break; }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn do_while_loop() {
    let w = make("void f(void) { do { g(); } while (0); }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn return_stmt() {
    let w = make("int f(void) { return 42; }");
    assert!(has_return(&w, "f"));
}

#[test]
fn assignment() {
    let w = make("void f(void) { int x; x = 1; }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn struct_decl_is_class_like() {
    let w = make("struct Widget { int x; };");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn include_is_import() {
    let w = make("#include <stdio.h>\nint f(void) { return 0; }");
    assert!(has_import(&w, "stdio.h"), "#include not surfaced as import");
}

#[test]
fn break_and_continue() {
    let w =
        make("void f(void) { for (int i = 0; i < 10; ++i) { if (i == 0) continue; if (i == 5) break; } }");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}
