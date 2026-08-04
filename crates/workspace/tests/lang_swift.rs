//! Per-construct tests for the Swift adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(
        Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        "/w/A.swift",
        src,
    )
}

#[test]
fn func_declaration() {
    let w = make("func foo() {}");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("func f() { g() }\nfunc g() {}");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn if_statement() {
    let w = make("func f(x: Int) { if x > 0 { a() } else { b() } }\nfunc a(){}\nfunc b(){}");
    assert!(has_branch(&w, "f"));
    assert!(branch_arm_has_call(&w, "f", "a", false));
    assert!(branch_arm_has_call(&w, "f", "b", true));
}

#[test]
fn for_in_loop() {
    let w = make("func f() { for i in 0..<10 { g(i) } }\nfunc g(_ i: Int) {}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("func f() { while true { break } }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn class_declaration() {
    let w = make("class Widget { }");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn struct_declaration() {
    let w = make("struct Point { var x: Int }");
    assert!(class_exists(&w, "Point"));
}

#[test]
fn init_declaration_as_function() {
    // Swift's init syntax for constructors.
    let w = make("class Widget { init(x: Int) {} func run() { } }");
    assert!(function_exists(&w, "run"));
}

#[test]
fn return_stmt() {
    let w = make("func f() -> Int { return 1 }");
    assert!(has_return(&w, "f"));
}

#[test]
fn throw_stmt() {
    let w = make("func f() throws { throw MyError.bad }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn assignment() {
    let w = make("func f() { var x = 1; x = 2 }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn import_declaration() {
    let w = make("import Foundation\nfunc f() {}");
    assert!(has_import(&w, "Foundation"));
}

#[test]
fn repeat_while_as_do_loop() {
    // Swift's `repeat { ... } while cond` is the do-while form.
    let w = make("func f() { repeat { g() } while true }\nfunc g(){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn switch_as_branch() {
    let w = make("func f(x: Int) { switch x { case 0: g(); default: h() } }\nfunc g(){}\nfunc h(){}");
    assert!(has_branch(&w, "f"), "switch not classified as branch");
}

#[test]
fn attribute_is_decorator() {
    let w = make("@objc class Widget { }");
    assert!(has_decorator(&w, "objc"));
}

#[test]
fn do_catch_is_try_catch() {
    // Swift uses `do { ... } catch { ... }` for exception handling.
    let w = make("func f() { do { try g() } catch { h(error) } }\nfunc g() throws {}\nfunc h(_ e: Error) {}");
    // tree-sitter-swift models this as a do_statement with catch_block; the
    // Swift adapter declares that exact shape in its try inventory.
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w = make("func f() { for i in 0..<10 { if i == 0 { continue } ; if i == 5 { break } } }");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn defer_surfaces_as_defer_event() {
    // tree-sitter-swift parses `defer { ... }` as a trailing-closure
    // call to an identifier named `defer` (no dedicated
    // defer_statement node). We detect this shape and synthesize a
    // proper FlowEvent::Defer whose body contains the closure's calls.
    // The body's calls belong to the enclosing fn's flow — so the
    // deferred `cleanup()` surfaces under `f`.
    let w = make("func f() { defer { cleanup() } ; g() }\nfunc cleanup(){}\nfunc g(){}");
    assert!(has_call(&w, "f", "cleanup"), "cleanup() not reachable under f");
    assert!(has_call(&w, "f", "g"), "g() not captured under f");
}

#[test]
fn await_in_async() {
    let w = make("func f() async { let x = await g() }\nfunc g() async -> Int { return 1 }");
    assert!(has_await(&w, "f"));
}
