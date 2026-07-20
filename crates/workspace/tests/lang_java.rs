//! Per-construct tests for the Java adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_java::JavaAdapter::new()), "/w/A.java", src)
}

#[test]
fn class_declaration() {
    let w = make("class Widget {}");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn interface_declaration() {
    let w = make("interface Shape { double area(); }");
    assert!(class_exists(&w, "Shape"));
}

#[test]
fn method_declaration() {
    let w = make("class A { void foo() {} }");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn constructor_declaration() {
    let w = make("class A { A() { } A(int x) { } }");
    assert!(ctor_exists(&w, "A"));
}

#[test]
fn method_call() {
    let w = make("class A { void f() { g(); } void g() {} }");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn qualified_call_chain() {
    let w = make("class A { void f() { Runtime.getRuntime().exec(cmd); } }");
    // Java's method_invocation typically captures the rightmost name at minimum.
    assert!(
        has_call_containing(&w, "f", "exec") || has_call(&w, "f", "exec"),
        "expected method invocation on `exec` to be extracted"
    );
}

#[test]
fn if_else() {
    let w = make("class A { void f(int x) { if (x > 0) a(); else b(); } void a(){} void b(){} }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("class A { void f() { for (int i = 0; i < 10; i++) g(i); } void g(int i){} }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn enhanced_for_loop() {
    let w = make("class A { void f(int[] arr) { for (int x : arr) g(x); } void g(int x){} }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("class A { void f() { while (cond()) g(); } boolean cond(){return true;} void g(){} }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn throw_stmt() {
    let w = make("class A { void f() throws Exception { throw new RuntimeException(\"x\"); } }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn annotation_as_decorator() {
    let w = make("class A { @Deprecated void f() {} }");
    assert!(has_decorator(&w, "Deprecated"));
}

#[test]
fn return_stmt() {
    let w = make("class A { int f() { return 42; } }");
    assert!(has_return(&w, "f"));
}

#[test]
fn assignment() {
    let w = make("class A { void f() { int x; x = 1; } }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn import_declaration() {
    let w = make("import java.util.List;\nclass A { }");
    assert!(has_import(&w, "java.util.List"));
}

#[test]
fn do_while_loop() {
    let w = make("class A { void f() { do { g(); } while (true); } void g(){} }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn try_catch_finally() {
    let w = make(
        "class A { void f() { try { g(); } catch (Exception e) { h(e); } finally { done(); } } void g(){} void h(Exception e){} void done(){} }",
    );
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
    assert!(has_finally(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w =
        make("class A { void f() { for (int i=0;i<10;i++) { if (i == 0) continue; if (i == 5) break; } } }");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn import_wildcard() {
    let w = make("import java.util.*;\nclass A { }");
    assert!(has_wildcard_import(&w, "java.util"));
}

#[test]
fn import_static() {
    let w = make("import static java.lang.Math.PI;\nclass A { }");
    assert!(has_import(&w, "java.lang.Math"));
}

#[test]
fn try_with_resources_is_try() {
    // Java's `try (Resource r = ...) { ... }` form is parsed as
    // `try_with_resources_statement`. We surface it under `Try` so
    // consumers see the guarded region; the resource list lives in the
    // body.
    let w = make(
        "class A { void f() throws Exception { try (var s = open()) { use(s); } } Resource open(){return null;} void use(Resource s){} }",
    );
    assert!(has_try(&w, "f"));
}

#[test]
fn qualified_java_21_record_patterns_parse_and_lower_cleanly() {
    let w = make(
        r#"
        class A {
            int switchPattern(Object value) {
                return switch (value) {
                    case pkg.Shape.Point(int x, int y) -> sink(x) + sink(y);
                    default -> 0;
                };
            }

            int instanceofPattern(Object value) {
                if (value instanceof pkg.telemetry.Sample(var count)) {
                    return sink(count);
                }
                return 0;
            }

            int sink(int value) { return value; }
        }
        "#,
    );

    let diagnostics = w.diagnostics();
    assert!(
        diagnostics.is_empty(),
        "qualified record patterns are valid Java 21 syntax: {diagnostics:#?}"
    );
    assert!(has_call(&w, "switchPattern", "sink"));
    assert!(has_call(&w, "instanceofPattern", "sink"));
}

#[test]
fn leading_zero_decimal_floats_parse_cleanly() {
    let w = make("class A { double f() { return 00d + 0012D + 0_0f; } }");
    let diagnostics = w.diagnostics();
    assert!(
        diagnostics.is_empty(),
        "decimal floating suffix determines the radix even with leading zeroes: {diagnostics:#?}"
    );
}
