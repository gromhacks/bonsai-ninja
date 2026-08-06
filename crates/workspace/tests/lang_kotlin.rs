//! Per-construct tests for the Kotlin adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()), "/w/A.kt", src)
}

#[test]
fn fun_declaration() {
    let w = make("fun foo() {}");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("fun f() { g() }\nfun g() {}");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn member_call() {
    let w = make("fun f() { list.add(1) }");
    assert!(has_call_containing(&w, "f", "list.add") || has_call(&w, "f", "add"));
}

#[test]
fn if_expression() {
    let w = make("fun f(x: Int): Int { return if (x > 0) 1 else 2 }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("fun f() { for (i in 1..10) { g(i) } }\nfun g(i: Int) {}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("fun f() { while (true) break }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn return_via_jump_expression() {
    let w = make("fun f(x: Int): Int { if (x > 0) return 1 else return 2 }");
    assert!(has_return(&w, "f"));
}

#[test]
fn throw_stmt() {
    let w = make("fun f() { throw RuntimeException(\"x\") }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn class_declaration() {
    let w = make("class Widget(val x: Int)");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn object_declaration_is_class_like() {
    // The tree-sitter-kotlin grammar parses a top-level `object Foo {...}`
    // as an `infix_expression` rather than `object_declaration` — a known
    // grammar quirk. Inside a file with a package declaration, the form
    // lowers correctly as a top-level declaration.
    let w = make("package p\nobject Singleton {\n    fun f() {}\n}\n");
    assert!(class_exists(&w, "Singleton"));
}

#[test]
fn annotation_as_decorator() {
    let w = make("@Deprecated(\"old\")\nfun f() {}");
    assert!(has_decorator(&w, "Deprecated"));
}

#[test]
fn assignment() {
    let w = make("fun f() { var x = 1\nx = 2 }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn import_header() {
    let w = make("package p\nimport kotlin.io.println\nfun f() {}");
    assert!(has_import(&w, "kotlin.io.println"));
}

#[test]
fn do_while_loop() {
    let w = make("fun f() { do { g() } while (true) }\nfun g(){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn when_as_branch() {
    // Kotlin's adapter maps its `when_expression` node to Branch.
    let w = make("fun f(x: Int) { when (x) { 0 -> g(); else -> h() } }\nfun g(){}\nfun h(){}");
    assert!(has_branch(&w, "f"), "when not classified as branch");
}

#[test]
fn try_catch_finally() {
    let w = make(
        "fun f() { try { g() } catch (e: Exception) { h(e) } finally { done() } }\nfun g(){}\nfun h(e: Exception){}\nfun done(){}",
    );
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
    assert!(has_finally(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w = make("fun f() { for (i in 0..10) { if (i == 0) continue; if (i == 5) break } }");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn import_alias() {
    let w = make("package p\nimport kotlin.io.println as p\nfun f() {}");
    assert!(has_import_symbol_alias(&w, "kotlin.io", "println", "p"));
}

#[test]
fn import_wildcard() {
    let w = make("package p\nimport kotlin.collections.*\nfun f() {}");
    assert!(has_wildcard_import(&w, "kotlin.collections"));
}
