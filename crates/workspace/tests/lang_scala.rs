//! Per-construct tests for the Scala adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(
        Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        "/w/A.scala",
        src,
    )
}

#[test]
fn def_in_object() {
    let w = make("object A { def foo(): Unit = () }");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("object A { def f(): Unit = g(); def g(): Unit = () }");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn qualified_call() {
    let w = make("object A { def f(): Unit = System.out.println(\"x\") }");
    assert!(has_call_containing(&w, "f", "println"));
}

#[test]
fn if_expression() {
    let w = make("object A { def f(x: Int): Int = if (x > 0) 1 else 2 }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_expression() {
    let w = make("object A { def f(): Unit = { for (i <- 1 to 10) println(i) } }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_expression() {
    let w = make("object A { def f(): Unit = { var i = 0; while (i < 10) { i = i + 1 } } }");
    assert!(has_loop(&w, "f"));
}

#[test]
fn class_declaration() {
    let w = make("class Widget(x: Int)");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn object_declaration() {
    let w = make("object Singleton { def f(): Unit = () }");
    assert!(class_exists(&w, "Singleton"));
}

#[test]
fn trait_declaration() {
    let w = make("trait Greet { def hi(): Unit }");
    assert!(class_exists(&w, "Greet"));
}

#[test]
fn throw_stmt() {
    let w = make("object A { def f(): Unit = throw new RuntimeException(\"x\") }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn return_stmt() {
    let w = make("object A { def f(): Int = { return 42 } }");
    assert!(has_return(&w, "f"));
}

#[test]
fn val_binding_is_assign() {
    let w = make("object A { def f(): Unit = { val x = 1; println(x) } }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn import_clause() {
    let w = make("import scala.collection.mutable\nobject A { def f(): Unit = () }");
    assert!(has_import(&w, "scala.collection.mutable"));
}

#[test]
fn match_as_branch() {
    let w = make("object A { def f(x: Int): Int = x match { case 1 => 1; case _ => 0 } }");
    assert!(has_branch(&w, "f"), "match not classified as branch");
}

#[test]
fn annotation_is_decorator() {
    let w = make("object A { @deprecated def f(): Unit = () }");
    assert!(has_decorator(&w, "deprecated"));
}

#[test]
fn try_catch_finally() {
    let w = make(
        "object A { def f(): Unit = try { g() } catch { case e: Exception => h(e) } finally { done() }\n  def g(): Unit = ()\n  def h(e: Exception): Unit = ()\n  def done(): Unit = () }",
    );
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
    assert!(has_finally(&w, "f"));
}

#[test]
fn import_wildcard() {
    // Scala 2: `import x._`, Scala 3: `import x.*`
    let w = make("import scala.collection._\nobject A { def f(): Unit = () }");
    assert!(has_wildcard_import(&w, "scala.collection"));
}

#[test]
fn import_brace_arrow_alias() {
    // Scala rename imports: `import x.{a => b}` captures `b` as alias.
    let w = make("import scala.collection.{mutable => mut}\nobject A { def f(): Unit = () }");
    assert!(has_import_alias(&w, "scala.collection", "mut"));
}
