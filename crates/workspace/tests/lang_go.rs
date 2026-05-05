//! Per-construct tests for the Go adapter.

#[path = "lang_common.rs"]
mod common;

use bonsai_lang_api::{CallKind, FlowEvent};
use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_go::GoAdapter::new()), "/w/a.go", src)
}

#[test]
fn func_declaration() {
    let w = make("package m\nfunc foo() {}");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn method_declaration() {
    let w = make("package m\ntype T struct{}\nfunc (t *T) run() { t.go_() }\nfunc (t *T) go_() {}");
    assert!(function_exists(&w, "run"));
    assert!(function_exists(&w, "go_"));
}

#[test]
fn direct_call() {
    let w = make("package m\nfunc f() { g() }\nfunc g() {}");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn package_qualified_call() {
    let w = make("package m\nfunc f() { fmt.Println(\"x\") }");
    assert!(has_call_containing(&w, "f", "fmt.Println"));
}

#[test]
fn composite_literal_is_constructor_call_with_keyed_args() {
    let w = make(
        "package m\n\
         type Cookie struct { HttpOnly bool }\n\
         func f() { _ = Cookie{HttpOnly: true} }",
    );
    let d = decl(&w, "f").expect("function f");
    let hit = d.flow_events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Cookie" && args.iter().any(|arg| arg.value_text == "HttpOnly: true")
        )
    });
    assert!(
        hit,
        "Go composite literal should surface as constructor call with keyed args: {:?}",
        d.flow_events
    );
}

#[test]
fn if_branch() {
    let w = make("package m\nfunc f(x int) { if x > 0 { g() } else { h() } }\nfunc g(){}\nfunc h(){}");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("package m\nfunc f() { for i := 0; i < 10; i++ { g(i) } }\nfunc g(i int){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn for_range_loop() {
    let w = make("package m\nfunc f(arr []int) { for _, x := range arr { g(x) } }\nfunc g(x int){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn short_var_declaration() {
    let w = make("package m\nfunc f() { x := 1; _ = x }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn return_stmt() {
    let w = make("package m\nfunc f() int { return 1 }");
    assert!(has_return(&w, "f"));
}

#[test]
fn struct_type_is_class() {
    let w = make("package m\ntype Widget struct { x int }");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn interface_is_class() {
    let w = make("package m\ntype Reader interface { Read() }");
    assert!(class_exists(&w, "Reader"));
}

#[test]
fn import_declaration_is_surfaced() {
    let w = make("package m\nimport \"fmt\"\nfunc f() { fmt.Println(\"x\") }");
    assert!(has_import(&w, "fmt"), "import decl not surfaced");
}

#[test]
fn panic_is_a_call() {
    // Go has no throw keyword — panic() is the idiomatic abort path and
    // surfaces as a regular call event in the flow tree.
    let w = make("package m\nfunc f() { panic(\"x\") }");
    assert!(has_call(&w, "f", "panic"));
}

#[test]
fn switch_as_branch() {
    // Go's switch statement is classified in the generic handler's branch
    // kinds (`switch_statement` / `expression_switch_statement`).
    let w =
        make("package m\nfunc f(x int) { switch x { case 1: g(); default: h() } }\nfunc g(){}\nfunc h(){}");
    assert!(has_branch(&w, "f"), "switch not classified as branch");
}

#[test]
fn defer_statement() {
    let w = make("package m\nfunc f() { defer cleanup() ; g() }\nfunc cleanup(){}\nfunc g(){}");
    assert!(has_defer(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w = make(
        "package m\nfunc f() { for i := 0; i < 10; i++ { if i == 0 { continue } ; if i == 5 { break } } }",
    );
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn import_alias() {
    let w = make("package m\nimport f \"fmt\"\nfunc g() { f.Println(\"x\") }");
    assert!(has_import_alias(&w, "fmt", "f"), "alias not surfaced");
}

#[test]
fn import_dot_is_wildcard() {
    // `import . "fmt"` dumps the package into the file's scope — the
    // closest Go analog to a wildcard import.
    let w = make("package m\nimport . \"fmt\"\nfunc g() { Println(\"x\") }");
    assert!(has_import(&w, "fmt"));
    assert!(has_wildcard_import(&w, "fmt"));
}
