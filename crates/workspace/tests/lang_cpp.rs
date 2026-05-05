//! Per-construct tests for the C++ adapter.

#[path = "lang_common.rs"]
mod common;

use bonsai_lang_api::{CallKind, FlowEvent};
use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_cpp::CppAdapter::new()), "/w/a.cpp", src)
}

#[test]
fn function_definition() {
    let w = make("int foo() { return 0; }");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("void g();\nvoid f() { g(); }");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn new_expression_is_constructor_call() {
    let w = make("void f(const char *arg) { auto *x = new child(arg); }");
    let d = decl(&w, "f").expect("function f");
    let has_new_child = d.flow_events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                ..
            } if name == "child"
        )
    });
    assert!(
        has_new_child,
        "C++ new_expression should surface as a constructor call: {:?}",
        d.flow_events
    );
}

#[test]
fn if_else() {
    let w = make("void f(int x) { if (x > 0) { a(); } else { b(); } }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("void f() { for (int i = 0; i < 10; ++i) g(i); }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn range_based_for() {
    let w = make("#include <vector>\nvoid f(std::vector<int> v) { for (int x : v) g(x); }");
    // `for_range_loop` is in foreach_kinds.
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("void f() { while (cond()) g(); }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn throw_stmt() {
    let w = make("void f() { throw 1; }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn class_specifier() {
    let w = make("class Widget { int x; };");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn struct_specifier() {
    let w = make("struct Point { int x; };");
    assert!(class_exists(&w, "Point"));
}

#[test]
fn return_stmt() {
    let w = make("int f() { return 42; }");
    assert!(has_return(&w, "f"));
}

#[test]
fn assignment() {
    let w = make("void f() { int x; x = 1; }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn include_is_import() {
    let w = make("#include <vector>\nvoid f() {}");
    assert!(has_import(&w, "vector"), "#include not surfaced as import");
}

#[test]
fn do_while_loop() {
    let w = make("void f() { do { g(); } while (0); }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn try_catch() {
    let w = make(
        "void f() { try { g(); } catch (const std::exception& e) { h(e); } } void g(){} void h(const std::exception& e){}",
    );
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w = make("void f() { for (int i = 0; i < 10; ++i) { if (i == 0) continue; if (i == 5) break; } }");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn using_directive() {
    let w = make("using namespace std;\nvoid f() {}");
    assert!(has_import(&w, "std"));
}

#[test]
fn co_yield_and_co_await() {
    // C++20 coroutines. tree-sitter-cpp has dedicated kinds for each
    // operator: co_yield_statement, co_await_expression, co_return_statement.
    let w = make(
        "#include <coroutine>\ntask<int> f() { co_yield 1; co_await g(); co_return 2; }\ntask<int> g();",
    );
    assert!(has_yield(&w, "f"), "co_yield not surfaced");
    assert!(has_await(&w, "f"), "co_await not surfaced");
    assert!(has_return(&w, "f"), "co_return not surfaced");
}
