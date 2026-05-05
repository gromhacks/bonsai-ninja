//! Per-construct tests for the C# adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_csharp::CSharpAdapter::new()), "/w/A.cs", src)
}

#[test]
fn class_declaration() {
    let w = make("class Widget { }");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn interface_declaration() {
    let w = make("interface IShape { double Area(); }");
    assert!(class_exists(&w, "IShape"));
}

#[test]
fn method_declaration() {
    let w = make("class A { void Foo() {} }");
    assert!(function_exists(&w, "Foo"));
}

#[test]
fn method_call() {
    let w = make("class A { void F() { G(); } void G() {} }");
    assert!(has_call(&w, "F", "G"));
}

#[test]
fn qualified_call() {
    let w = make("class A { void F() { Console.WriteLine(\"x\"); } }");
    assert!(has_call_containing(&w, "F", "Console.WriteLine"));
}

#[test]
fn if_else() {
    let w = make("class A { void F(int x) { if (x > 0) A(); else B(); } void A(){} void B(){} }");
    assert!(has_branch(&w, "F"));
}

#[test]
fn for_loop() {
    let w = make("class A { void F() { for (int i = 0; i < 10; i++) G(i); } void G(int i){} }");
    assert!(has_loop(&w, "F"));
}

#[test]
fn foreach_loop() {
    let w = make("class A { void F(int[] a) { foreach (var x in a) G(x); } void G(int x){} }");
    assert!(has_loop(&w, "F"));
}

#[test]
fn while_loop() {
    let w = make("class A { void F() { while (cond()) G(); } bool cond(){return true;} void G(){} }");
    assert!(has_loop(&w, "F"));
}

#[test]
fn throw_stmt() {
    let w = make("class A { void F() { throw new System.Exception(\"x\"); } }");
    assert!(has_throw(&w, "F"));
}

#[test]
fn attribute_as_decorator() {
    let w = make("class A { [Obsolete] void F() {} }");
    assert!(has_decorator(&w, "Obsolete"));
}

#[test]
fn return_stmt() {
    let w = make("class A { int F() { return 42; } }");
    assert!(has_return(&w, "F"));
}

#[test]
fn assignment() {
    let w = make("class A { void F() { int x; x = 1; } }");
    assert!(has_assign(&w, "F", "x"));
}

#[test]
fn using_is_import() {
    let w = make("using System;\nclass A { }");
    assert!(has_import(&w, "System"), "using directive not surfaced");
}

#[test]
fn do_while_loop() {
    let w = make("class A { void F() { do { G(); } while (true); } void G(){} }");
    assert!(has_loop(&w, "F"));
}

#[test]
fn try_catch_finally() {
    let w = make(
        "class A { void F() { try { G(); } catch (System.Exception e) { H(e); } finally { Done(); } } void G(){} void H(System.Exception e){} void Done(){} }",
    );
    assert!(has_try(&w, "F"));
    assert!(has_catch(&w, "F"));
    assert!(has_finally(&w, "F"));
}

#[test]
fn break_and_continue() {
    let w = make(
        "class A { void F() { for (int i = 0; i < 10; i++) { if (i == 0) continue; if (i == 5) break; } } }",
    );
    assert!(has_break(&w, "F"));
    assert!(has_continue(&w, "F"));
}

#[test]
fn await_in_async() {
    let w = make(
        "using System.Threading.Tasks;\nclass A { async Task F() { await G(); } async Task G() { await Task.Delay(1); } }",
    );
    assert!(has_await(&w, "F"));
}

#[test]
fn using_statement_is_using() {
    let w = make(
        "class A { void F() { using (var s = Open()) { Read(s); } } System.IDisposable Open(){return null;} void Read(object s){} }",
    );
    assert!(has_using(&w, "F"));
}

#[test]
fn using_alias() {
    let w = make("using Foo = System.Console;\nclass A { }");
    assert!(has_import(&w, "System.Console"));
}

#[test]
fn yield_return_and_break() {
    let w =
        make("class A { System.Collections.Generic.IEnumerable<int> F() { yield return 1; yield break; } }");
    assert!(has_yield(&w, "F"));
}
