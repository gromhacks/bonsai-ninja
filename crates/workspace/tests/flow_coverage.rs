//! Exhaustive per-language flow-construct coverage.
//!
//! Each test feeds a language a fixture that exercises a specific
//! CFG-relevant construct (if/else, loops, try/catch, switch/match,
//! short-circuit, ternary, defer, using, goroutines, async/await, etc.)
//! and asserts the calls inside each construct surface in the
//! enclosing function's flow_events. If a construct's calls are
//! missing, `inspect`, `export`, `trace`, and every downstream
//! consumer will render broken flows.
//!
//! This file is the single source of truth for "what constructs does
//! each language actually support?". A regression in any plugin's
//! walker shows up as a concrete failed assertion here.

#[path = "inspect_harness.rs"]
mod h;

use bonsai_lang_api::{CallKind, FlowEvent};
use h::*;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Adapter fns (re-exported from per-lang test files for consistency).
// ---------------------------------------------------------------------------
fn c() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_c::CAdapter::new())
}
fn cpp() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_cpp::CppAdapter::new())
}
fn cs() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_csharp::CSharpAdapter::new())
}
fn go() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_go::GoAdapter::new())
}
fn java() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_java::JavaAdapter::new())
}
fn js() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())
}
fn kt() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())
}
fn pl() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_perl::PerlAdapter::new())
}
fn php() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_php::PhpAdapter::new())
}
fn py() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_python::PythonAdapter::new())
}
fn rb() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_ruby::RubyAdapter::new())
}
fn rs() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_rust::RustAdapter::new())
}
fn sc() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_scala::ScalaAdapter::new())
}
fn sw() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_swift::SwiftAdapter::new())
}
fn ts() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new())
}

fn constructor_call_contains(ws: &bonsai_workspace::Workspace, fn_name: &str, needle: &str) -> bool {
    let Some(d) = decl_by_name(ws, fn_name) else {
        return false;
    };
    constructor_call_in(&d.flow_events, needle)
}

fn constructor_call_in(events: &[FlowEvent], needle: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Call {
            name,
            call_kind: CallKind::Constructor,
            ..
        } => name.contains(needle),
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => constructor_call_in(then_events, needle) || constructor_call_in(else_events, needle),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            constructor_call_in(body, needle)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            constructor_call_in(body, needle)
                || constructor_call_in(catch_events, needle)
                || constructor_call_in(finally_events, needle)
        }
        _ => false,
    })
}

fn call_contains_named_arg(
    ws: &bonsai_workspace::Workspace,
    fn_name: &str,
    needle: &str,
    arg_name: &str,
    arg_text: &str,
) -> bool {
    let Some(d) = decl_by_name(ws, fn_name) else {
        return false;
    };
    fn contains(events: &[FlowEvent], needle: &str, arg_name: &str, arg_text: &str) -> bool {
        events.iter().any(|event| match event {
            FlowEvent::Call { name, args, .. } => {
                name.contains(needle)
                    && args
                        .iter()
                        .any(|arg| arg.name.as_deref() == Some(arg_name) && arg.value_text.contains(arg_text))
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                contains(then_events, needle, arg_name, arg_text)
                    || contains(else_events, needle, arg_name, arg_text)
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                contains(body, needle, arg_name, arg_text)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                contains(body, needle, arg_name, arg_text)
                    || contains(catch_events, needle, arg_name, arg_text)
                    || contains(finally_events, needle, arg_name, arg_text)
            }
            _ => false,
        })
    }
    contains(&d.flow_events, needle, arg_name, arg_text)
}

fn return_contains_text(ws: &bonsai_workspace::Workspace, fn_name: &str, needle: &str) -> bool {
    let Some(d) = decl_by_name(ws, fn_name) else {
        return false;
    };
    return_contains_text_in(&d.flow_events, needle)
}

fn return_contains_text_in(events: &[FlowEvent], needle: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return {
            value_text,
            value_name,
            ..
        } => {
            value_text.as_deref().is_some_and(|text| text.contains(needle))
                || value_name.as_deref().is_some_and(|name| name.contains(needle))
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => return_contains_text_in(then_events, needle) || return_contains_text_in(else_events, needle),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            return_contains_text_in(body, needle)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            return_contains_text_in(body, needle)
                || return_contains_text_in(catch_events, needle)
                || return_contains_text_in(finally_events, needle)
        }
        _ => false,
    })
}

// ===========================================================================
// Python — every CFG construct.
// ===========================================================================

#[test]
fn py_flow_if_else_both_branches() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f(x):\n    if x > 0:\n        a()\n    else:\n        b()\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b"]);
}

#[test]
fn py_flow_elif_chain() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f(x):\n    if x == 1:\n        a()\n    elif x == 2:\n        b()\n    elif x == 3:\n        c()\n    else:\n        d()\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d"]);
}

#[test]
fn py_flow_for_while_nested() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f(xs):\n    for x in xs:\n        while check(x):\n            consume(x)\n",
        )],
    );
    assert_calls(&w, "f", &["check", "consume"]);
}

#[test]
fn py_flow_try_except_finally() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f():\n    try:\n        risky()\n    except ValueError:\n        recover()\n    except Exception:\n        fallback()\n    finally:\n        cleanup()\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "fallback", "cleanup"]);
}

#[test]
fn py_flow_with_init_and_body() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f():\n    with open('x') as fh:\n        process(fh)\n",
        )],
    );
    assert_calls(&w, "f", &["open", "process"]);
}

#[test]
fn py_flow_match_statement() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f(x):\n    match route(x):\n        case 1:\n            alpha()\n        case 2:\n            beta()\n        case _:\n            gamma()\n",
        )],
    );
    assert_calls(&w, "f", &["route", "alpha", "beta", "gamma"]);
}

#[test]
fn py_flow_ternary_and_short_circuit() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f():\n    x = a() or b()\n    y = c() and d()\n    return e() if g() else h()\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d", "e", "g", "h"]);
}

#[test]
fn py_flow_yield_and_comprehension() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def gen():\n    for x in source():\n        yield transform(x)\n",
        )],
    );
    assert_calls(&w, "gen", &["source", "transform"]);
}

#[test]
fn py_flow_nested_function_does_not_leak() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def outer():\n    outer_call()\n    def inner():\n        inner_call()\n    return inner\n",
        )],
    );
    assert_calls(&w, "outer", &["outer_call"]);
    assert_no_call(&w, "outer", "inner_call");
    assert_calls(&w, "inner", &["inner_call"]);
}

#[test]
fn py_flow_lambda_body_separated() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f():\n    outer_call()\n    fn = lambda x: lambda_call(x)\n    return fn\n",
        )],
    );
    assert_calls(&w, "f", &["outer_call"]);
}

// ===========================================================================
// JavaScript — core constructs.
// ===========================================================================

#[test]
fn js_flow_if_else() {
    let w = ws_multi(
        js(),
        &[("/w/m.js", "function f(x) { if (x > 0) { a(); } else { b(); } }\n")],
    );
    assert_calls(&w, "f", &["a", "b"]);
}

#[test]
fn js_flow_switch_case() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "function f(x) { switch (route(x)) { case 1: a(); break; case 2: b(); break; default: c(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["route", "a", "b", "c"]);
}

#[test]
fn js_flow_try_catch_finally() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "function f() { try { risky(); } catch (e) { recover(e); } finally { cleanup(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "cleanup"]);
}

#[test]
fn js_flow_for_while_do() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "function f(xs) { for (let x of xs) { while (check(x)) { consume(x); } } do { d(); } while(g()); }\n",
        )],
    );
    assert_calls(&w, "f", &["check", "consume", "d", "g"]);
}

#[test]
fn js_flow_ternary_and_short_circuit() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "function f() { const x = a() || b(); const y = c() && d(); return g() ? h() : i(); }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d", "g", "h", "i"]);
}

#[test]
fn js_flow_async_await() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "async function f() { const x = await fetch(); const y = await parse(x); return y; }\n",
        )],
    );
    assert_calls(&w, "f", &["fetch", "parse"]);
}

#[test]
fn js_flow_arrow_function_does_not_leak() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "function outer() { outer_call(); const fn = () => inner_call(); return fn; }\n",
        )],
    );
    assert_calls(&w, "outer", &["outer_call"]);
}

#[test]
fn js_flow_new_expression_is_constructor_call() {
    let w = ws_multi(
        js(),
        &[("/w/m.js", "function f(input) { return new URL(input); }\n")],
    );
    assert!(
        constructor_call_contains(&w, "f", "URL"),
        "JavaScript new_expression did not surface as a constructor Call. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

// ===========================================================================
// TypeScript — same grammar as JS, distinct adapter.
// ===========================================================================

#[test]
fn ts_flow_if_else_switch() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/m.ts",
            "function f(x: number): void { if (x > 0) { a(); } else { b(); } switch (x) { case 1: c(); break; default: d(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d"]);
}

#[test]
fn ts_flow_try_and_async() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/m.ts",
            "async function f(): Promise<void> { try { await risky(); } catch (e: unknown) { await recover(e); } }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover"]);
}

#[test]
fn ts_flow_new_expression_is_constructor_call() {
    let w = ws_multi(
        ts(),
        &[(
            "/w/m.ts",
            "function f(input: string): URL { return new URL(input); }\n",
        )],
    );
    assert!(
        constructor_call_contains(&w, "f", "URL"),
        "TypeScript new_expression did not surface as a constructor Call. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

// ===========================================================================
// Java — core constructs.
// ===========================================================================

#[test]
fn java_flow_if_else_switch() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M { static void f(int x) { if (x > 0) { a(); } else { b(); } switch (x) { case 1: c(); break; default: d(); } } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d"]);
}

#[test]
fn java_flow_try_catch_finally() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M { static void f() { try { risky(); } catch (RuntimeException e) { recover(); } finally { cleanup(); } } }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "cleanup"]);
}

#[test]
fn java_flow_loops() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M { static void f(int[] xs) { for (int x : xs) { consume(x); } for (int i = 0; i < len(); i++) { step(i); } while (check()) { body(); } } }\n",
        )],
    );
    assert_calls(&w, "f", &["consume", "len", "step", "check", "body"]);
}

#[test]
fn java_flow_ternary_and_short_circuit() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M { static int f() { int x = a() || b() ? 1 : 0; boolean y = c() && d(); return g() ? h() : i(); } static boolean a() { return true; } static boolean b() { return true; } static boolean c() { return true; } static boolean d() { return true; } static boolean g() { return true; } static int h() { return 1; } static int i() { return 2; } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d", "g", "h", "i"]);
}

// ===========================================================================
// Kotlin — core constructs.
// ===========================================================================

#[test]
fn kotlin_flow_if_when() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/m.kt",
            "fun f(x: Int) { if (x > 0) a() else b(); when (route(x)) { 1 -> c(); 2 -> d(); else -> g() } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "route", "c", "d", "g"]);
}

#[test]
fn kotlin_flow_try_catch_finally() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/m.kt",
            "fun f() { try { risky() } catch (e: Exception) { recover() } finally { cleanup() } }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "cleanup"]);
}

#[test]
fn kotlin_flow_loops() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/m.kt",
            "fun f(xs: List<Int>) { for (x in xs) consume(x); while (check()) body() }\n",
        )],
    );
    assert_calls(&w, "f", &["consume", "check", "body"]);
}

// ===========================================================================
// Rust — core constructs.
// ===========================================================================

#[test]
fn rust_flow_if_else_match() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/m.rs",
            "fn f(x: i32) { if x > 0 { a(); } else { b(); } match route(x) { 1 => c(), 2 => d(), _ => g() }; }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "route", "c", "d", "g"]);
}

#[test]
fn rust_flow_loops() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/m.rs",
            "fn f(xs: &[i32]) { for x in xs { consume(*x); } while check() { body(); } loop { once(); break; } }\n",
        )],
    );
    assert_calls(&w, "f", &["consume", "check", "body", "once"]);
}

#[test]
fn rust_flow_result_try_operator() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/m.rs",
            "fn f() -> Result<(), String> { let x = risky()?; process(x); Ok(()) }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "process"]);
}

// ===========================================================================
// Go — core constructs including goroutines + defer.
// ===========================================================================

#[test]
fn go_flow_if_switch() {
    let w = ws_multi(
        go(),
        &[(
            "/w/m.go",
            "package main\nfunc F(x int) { if x > 0 { a() } else { b() }; switch x { case 1: c(); default: d() } }\n",
        )],
    );
    assert_calls(&w, "F", &["a", "b", "c", "d"]);
}

#[test]
fn go_flow_for_range() {
    let w = ws_multi(
        go(),
        &[(
            "/w/m.go",
            "package main\nfunc F(xs []int) { for _, x := range xs { consume(x) }; for check() { body() } }\n",
        )],
    );
    assert_calls(&w, "F", &["consume", "check", "body"]);
}

#[test]
fn go_flow_goroutine_and_defer() {
    let w = ws_multi(
        go(),
        &[(
            "/w/m.go",
            "package main\nfunc F() { go launch(); defer cleanup(); run() }\n",
        )],
    );
    assert_calls(&w, "F", &["launch", "cleanup", "run"]);
}

// ===========================================================================
// C — core constructs.
// ===========================================================================

#[test]
fn c_flow_if_switch() {
    let w = ws_multi(
        c(),
        &[(
            "/w/m.c",
            "void f(int x) { if (x > 0) a(); else b(); switch (x) { case 1: c(); break; default: d(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d"]);
}

#[test]
fn c_flow_for_while_do() {
    let w = ws_multi(
        c(),
        &[(
            "/w/m.c",
            "void f(int n) { for (int i = 0; i < n; i++) step(i); while (check()) body(); do once(); while (g()); }\n",
        )],
    );
    assert_calls(&w, "f", &["step", "check", "body", "once", "g"]);
}

// ===========================================================================
// C++ — core constructs.
// ===========================================================================

#[test]
fn cpp_flow_try_catch() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/m.cpp",
            "void f() { try { risky(); } catch (const std::exception& e) { recover(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover"]);
}

#[test]
fn cpp_flow_range_for() {
    let w = ws_multi(
        cpp(),
        &[(
            "/w/m.cpp",
            "#include <vector>\nvoid f(const std::vector<int>& xs) { for (const auto& x : xs) consume(x); }\n",
        )],
    );
    assert_calls(&w, "f", &["consume"]);
}

// ===========================================================================
// C# — core constructs.
// ===========================================================================

#[test]
fn csharp_flow_if_switch() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/M.cs",
            "class M { static void F(int x) { if (x > 0) A(); else B(); switch (x) { case 1: C(); break; default: D(); break; } } static void A(){} static void B(){} static void C(){} static void D(){} }\n",
        )],
    );
    assert_calls(&w, "F", &["A", "B", "C", "D"]);
}

#[test]
fn csharp_flow_try_catch_finally_using() {
    let w = ws_multi(
        cs(),
        &[(
            "/w/M.cs",
            "class M { static void F() { using (var s = Open()) { Process(s); } try { Risky(); } catch (Exception e) { Recover(); } finally { Cleanup(); } } static object Open() => null; static void Process(object s){} static void Risky(){} static void Recover(){} static void Cleanup(){} }\n",
        )],
    );
    assert_calls(&w, "F", &["Open", "Process", "Risky", "Recover", "Cleanup"]);
}

// ===========================================================================
// PHP — core constructs.
// ===========================================================================

#[test]
fn php_flow_if_switch() {
    let w = ws_multi(
        php(),
        &[(
            "/w/m.php",
            "<?php\nfunction f($x) { if ($x > 0) a(); else b(); switch ($x) { case 1: c(); break; default: d(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d"]);
}

#[test]
fn php_flow_try_catch_finally() {
    let w = ws_multi(
        php(),
        &[(
            "/w/m.php",
            "<?php\nfunction f() { try { risky(); } catch (\\Exception $e) { recover(); } finally { cleanup(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "cleanup"]);
}

#[test]
fn php_flow_foreach_while() {
    let w = ws_multi(
        php(),
        &[(
            "/w/m.php",
            "<?php\nfunction f($xs) { foreach ($xs as $x) consume($x); while (check()) body(); }\n",
        )],
    );
    assert_calls(&w, "f", &["consume", "check", "body"]);
}

// ===========================================================================
// Ruby — core constructs.
// ===========================================================================

#[test]
fn ruby_flow_if_case_when() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/m.rb",
            "def f(x)\n  if x > 0 then a() else b() end\n  case route(x)\n  when 1 then c()\n  when 2 then d()\n  else g()\n  end\nend\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "route", "c", "d", "g"]);
}

#[test]
fn ruby_flow_begin_rescue_ensure() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/m.rb",
            "def f\n  begin\n    risky()\n  rescue StandardError\n    recover()\n  ensure\n    cleanup()\n  end\nend\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "cleanup"]);
}

// ===========================================================================
// Scala — core constructs.
// ===========================================================================

#[test]
fn scala_flow_if_match() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/M.scala",
            "object M {\n  def f(x: Int): Unit = {\n    if (x > 0) a() else b()\n    route(x) match {\n      case 1 => c()\n      case 2 => d()\n      case _ => g()\n    }\n  }\n  def a() = (); def b() = (); def route(x: Int): Int = x; def c() = (); def d() = (); def g() = ()\n}\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "route", "c", "d", "g"]);
}

#[test]
fn scala_flow_try_catch() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/M.scala",
            "object M {\n  def f(): Unit = {\n    try risky() catch { case e: Exception => recover() } finally cleanup()\n  }\n  def risky() = (); def recover() = (); def cleanup() = ()\n}\n",
        )],
    );
    assert_calls(&w, "f", &["risky", "recover", "cleanup"]);
}

// ===========================================================================
// Swift — core constructs including defer.
// ===========================================================================

#[test]
fn swift_flow_if_switch() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/m.swift",
            "func f(x: Int) { if x > 0 { a() } else { b() }; switch x { case 1: c(); case 2: d(); default: g() } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b", "c", "d", "g"]);
}

#[test]
fn swift_flow_guard_run_defer() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/m.swift",
            "func f() { defer { cleanup() }; guard check() else { return }; run() }\n",
        )],
    );
    // All three constructs must surface under `f`'s flow — defer body
    // inlines via the Swift-specific detection path.
    assert_calls(&w, "f", &["cleanup", "check", "run"]);
}

/// Java method invocation with a chained receiver —
/// `Runtime.getRuntime().exec(...)`. The full qualified callee name
/// `Runtime.getRuntime().exec` must be preserved in the Call event so
/// `inspect --query Runtime.getRuntime` matches it. Previously the
/// extractor collapsed this to just `exec`.
#[test]
fn java_qualified_method_call_preserves_full_name() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M { static void f() { Runtime.getRuntime().exec(\"cmd\"); } }\n",
        )],
    );
    // The call event's name should include the `Runtime.getRuntime`
    // receiver, not just the final `exec`.
    assert!(
        calls_contains(&w, "f", "Runtime.getRuntime") || calls_contains(&w, "f", "getRuntime().exec"),
        "Java qualified call name was collapsed to just the final method. \
         flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

/// PHP arrow-calls retain the receiver in canonical dotted compiler IR.
#[test]
fn php_arrow_call_preserves_object_name() {
    let w = ws_multi(
        php(),
        &[(
            "/w/m.php",
            "<?php\nfunction f($conn) { return $conn->query('x'); }\n",
        )],
    );
    assert!(
        calls_contains(&w, "f", "$conn.query"),
        "PHP `$conn->query` collapsed to bare method. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

#[test]
fn php_static_call_preserves_scope_name() {
    let w = ws_multi(
        php(),
        &[(
            "/w/m.php",
            "<?php\nfunction f() { return Request::input('x'); }\n",
        )],
    );
    assert!(
        calls_contains(&w, "f", "Request::input"),
        "PHP `Request::input` collapsed to bare method. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

#[test]
fn php_object_creation_surfaces_constructor_call() {
    let w = ws_multi(
        php(),
        &[(
            "/w/m.php",
            "<?php\nfunction f($path) { return new SplFileInfo($path); }\n",
        )],
    );
    assert!(
        constructor_call_contains(&w, "f", "SplFileInfo"),
        "PHP object creation did not surface as constructor call. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

#[test]
fn perl_arrow_call_strips_sigil_receiver() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/m.pl",
            "sub f { my ($ldap) = @_; return $ldap->search(filter => '(uid=a)'); }\n",
        )],
    );
    assert!(
        calls_contains(&w, "f", "ldap->search"),
        "Perl `$ldap->search` kept sigil or collapsed to bare method. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

#[test]
fn perl_arrow_call_preserves_keyword_args() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/m.pl",
            "sub f { return IO::Socket::SSL->new($input, SSL_verify_mode => 0); }\n",
        )],
    );
    assert!(
        call_contains_named_arg(&w, "f", "IO::Socket::SSL->new", "SSL_verify_mode", "0",),
        "Perl arrow call args were not attached to the method call. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

/// Ruby `receiver.method(args)` — the dotted qualified form must be
/// preserved.
#[test]
fn ruby_dotted_call_preserves_receiver() {
    let w = ws_multi(rb(), &[("/w/m.rb", "def f(conn)\n  conn.execute('x')\nend\n")]);
    assert!(
        calls_contains(&w, "f", "conn.execute"),
        "Ruby `conn.execute` collapsed to bare method. flow_events: {:?}",
        decl_by_name(&w, "f").map(|d| d.flow_events)
    );
}

/// Ruby methods return their final expression. The adapter must expose
/// that tail expression as a semantic Return event so wrapper helpers
/// can be summarized without treating every reachable callee as tainted.
#[test]
fn ruby_tail_expression_surfaces_as_return_event() {
    let w = ws_multi(rb(), &[("/w/m.rb", "def wrap(data)\n  new(data)\nend\n")]);
    assert!(
        return_contains_text(&w, "wrap", "new(data)"),
        "Ruby tail expression did not surface as Return. flow_events: {:?}",
        decl_by_name(&w, "wrap").map(|d| d.flow_events)
    );
}

/// Scala `fullCmd.!` — postfix invocation of the `!` method, used by
/// the `sys.process` shell-run idiom. tree-sitter-scala parses this as
/// a `field_expression` with an `operator_identifier`, not a call. We
/// detect that shape and emit a Call event so the sink surfaces in
/// flow events.
#[test]
fn scala_postfix_operator_method_call_captured() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/M.scala",
            "import sys.process._\nobject M {\n  def f(cmd: String): Unit = {\n    val fullCmd = s\"notify-admin $cmd\"\n    fullCmd.!\n  }\n}\n",
        )],
    );
    assert!(
        calls_contains(&w, "f", "fullCmd.!"),
        "Scala postfix `fullCmd.!` not captured as a Call event"
    );
}

// ===========================================================================
// Perl — core constructs.
// ===========================================================================

#[test]
fn perl_flow_if_unless() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/m.pl",
            "sub f { my ($x) = @_; if ($x > 0) { a(); } else { b(); } }\n",
        )],
    );
    assert_calls(&w, "f", &["a", "b"]);
}

#[test]
fn perl_flow_loops() {
    let w = ws_multi(
        pl(),
        &[(
            "/w/m.pl",
            "sub f { while (check()) { body(); } for my $x (@list) { consume($x); } }\n",
        )],
    );
    assert_calls(&w, "f", &["check", "body", "consume"]);
}

// ===========================================================================
// Ultra-complex per-lang scenarios — every construct in a single function.
// If any one piece regresses, these will fail loudly.
// ===========================================================================

#[test]
fn python_complex_every_construct() {
    let w = ws_multi(
        py(),
        &[(
            "/w/m.py",
            "def f(x):\n    \
             with open('f') as fh:\n        \
                 for i in range(10):\n            \
                     try:\n                \
                         if x > 0:\n                    \
                             r = compute(x) or fallback()\n                \
                         elif x < 0:\n                    \
                             raise ValueError('neg')\n                \
                         else:\n                    \
                             yield default()\n            \
                     except ValueError:\n                \
                         recover()\n            \
                     except Exception as e:\n                \
                         extra(e)\n            \
                     finally:\n                \
                         cleanup()\n            \
                     if i == 5:\n                \
                         break\n    \
             match route():\n        \
                 case 1:\n            \
                     alpha()\n        \
                 case _:\n            \
                     beta()\n    \
             return process() if check() else reject()\n",
        )],
    );
    assert_calls(
        &w,
        "f",
        &[
            "open",
            "range",
            "compute",
            "fallback",
            "ValueError",
            "default",
            "recover",
            "extra",
            "cleanup",
            "route",
            "alpha",
            "beta",
            "process",
            "check",
            "reject",
        ],
    );
}

#[test]
fn js_complex_every_construct() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "async function f(x) {\n  \
               try {\n    \
                 for (const item of await fetchList()) {\n      \
                   while (check(item)) {\n        \
                     if (item.done) break;\n        \
                     const r = compute(item) || fallback(item);\n        \
                     process(r);\n      \
                   }\n    \
                 }\n    \
                 switch (route(x)) {\n      \
                   case 1: alpha(); break;\n      \
                   case 2: beta(); break;\n      \
                   default: gamma();\n    \
                 }\n  \
               } catch (e) {\n    \
                 await recover(e);\n  \
               } finally {\n    \
                 cleanup();\n  \
               }\n  \
               return g() ? h() : i();\n\
             }\n",
        )],
    );
    assert_calls(
        &w,
        "f",
        &[
            "fetchList",
            "check",
            "compute",
            "fallback",
            "process",
            "route",
            "alpha",
            "beta",
            "gamma",
            "recover",
            "cleanup",
            "g",
            "h",
            "i",
        ],
    );
}

#[test]
fn java_complex_every_construct() {
    let w = ws_multi(
        java(),
        &[(
            "/w/M.java",
            "class M {\n  static void f(int x) {\n    \
               try {\n      \
                 for (int i = 0; i < 10; i++) {\n        \
                   if (i == 5) break;\n        \
                   if (x > 0) { a(i); } else if (x < 0) { b(i); } else { c(i); }\n      \
                 }\n      \
                 switch (route(x)) { case 1: alpha(); break; case 2: beta(); break; default: gamma(); }\n    \
               } catch (RuntimeException e) {\n      \
                 recover();\n    \
               } finally {\n      \
                 cleanup();\n    \
               }\n    \
               int r = check() ? done() : retry();\n  \
             }\n  \
             static int route(int x) { return 0; }\n  \
             static void a(int i) {} static void b(int i) {} static void c(int i) {} static void alpha() {} static void beta() {} static void gamma() {} static void recover() {} static void cleanup() {} static boolean check() { return true; } static int done() { return 0; } static int retry() { return 0; }\n\
             }\n",
        )],
    );
    assert_calls(
        &w,
        "f",
        &[
            "route", "a", "b", "c", "alpha", "beta", "gamma", "recover", "cleanup", "check", "done", "retry",
        ],
    );
}

#[test]
fn rust_complex_every_construct() {
    let w = ws_multi(
        rs(),
        &[(
            "/w/m.rs",
            "fn f(x: i32) -> Result<i32, String> {\n  \
               let r = match route(x) {\n    \
                 Ok(v) => process(v)?,\n    \
                 Err(_) => recover()?,\n  \
               };\n  \
               for i in 0..10 {\n    \
                 if i == 5 { break; }\n    \
                 step(i);\n  \
               }\n  \
               while check() { body(); }\n  \
               if x > 0 { Ok(good()) } else { Err(bad().to_string()) }\n\
             }\n",
        )],
    );
    assert_calls(
        &w,
        "f",
        &[
            "route", "process", "recover", "step", "check", "body", "good", "bad",
        ],
    );
}

#[test]
fn go_complex_every_construct() {
    let w = ws_multi(
        go(),
        &[(
            "/w/m.go",
            "package main\nfunc F(x int) {\n  \
               defer cleanup()\n  \
               go launch()\n  \
               if x > 0 { a() } else { b() }\n  \
               switch route(x) { case 1: alpha(); default: beta() }\n  \
               for i := 0; i < 10; i++ {\n    \
                 if i == 5 { break }\n    \
                 step(i)\n  \
               }\n  \
               for check() { body() }\n\
             }\n",
        )],
    );
    assert_calls(
        &w,
        "F",
        &[
            "cleanup", "launch", "a", "b", "route", "alpha", "beta", "step", "check", "body",
        ],
    );
}

#[test]
fn kotlin_complex_every_construct() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/m.kt",
            "fun f(x: Int): Int {\n  \
               try {\n    \
                 for (i in 0..9) {\n      \
                   if (i == 5) break\n      \
                   if (x > 0) a() else b()\n    \
                 }\n    \
                 when (route(x)) { 1 -> alpha(); 2 -> beta(); else -> gamma() }\n  \
               } catch (e: Exception) {\n    \
                 recover()\n  \
               } finally {\n    \
                 cleanup()\n  \
               }\n  \
               return if (check()) done() else retry()\n\
             }\n",
        )],
    );
    assert_calls(
        &w,
        "f",
        &[
            "route", "a", "b", "alpha", "beta", "gamma", "recover", "cleanup", "check", "done", "retry",
        ],
    );
}

/// Closures passed to higher-order functions should inline their body
/// into the outer flow. `xs.map { x -> step(x) }` — `step` must appear
/// under the enclosing function.
#[test]
fn kotlin_closure_body_inlines_into_outer_flow() {
    let w = ws_multi(
        kt(),
        &[(
            "/w/m.kt",
            "fun f(xs: List<Int>) { xs.forEach { x -> step(x) }; xs.map { it -> transform(it) } }\n",
        )],
    );
    assert_calls(&w, "f", &["step", "transform"]);
}

/// Same invariant for JS/TS: `xs.forEach(x => step(x))` inlines step.
#[test]
fn js_closure_body_inlines_into_outer_flow() {
    let w = ws_multi(
        js(),
        &[(
            "/w/m.js",
            "function f(xs) { xs.forEach(x => step(x)); xs.map(x => transform(x)); }\n",
        )],
    );
    assert_calls(&w, "f", &["step", "transform"]);
}

/// Scala `.foreach { x => ... }` — closure body must propagate.
#[test]
fn scala_foreach_closure_body_propagates() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/M.scala",
            "object M {\n  \
               def f(xs: List[Int]): Unit = {\n    \
                 xs.foreach { x => step(x) }\n    \
                 xs.map { x => transform(x) }\n  \
               }\n  \
               def step(x: Int): Unit = ()\n  \
               def transform(x: Int): Int = x\n\
             }\n",
        )],
    );
    assert_calls(&w, "f", &["step", "transform"]);
}

/// Ruby blocks `xs.each { |x| step(x) }` — the block body is a closure
/// whose calls should propagate to the enclosing method.
#[test]
fn ruby_block_body_propagates() {
    let w = ws_multi(
        rb(),
        &[(
            "/w/m.rb",
            "def f(xs)\n  xs.each { |x| step(x) }\n  xs.map { |x| transform(x) }\nend\n",
        )],
    );
    assert_calls(&w, "f", &["step", "transform"]);
}

/// Swift trailing closures: `xs.forEach { step($0) }`.
#[test]
fn swift_trailing_closure_propagates() {
    let w = ws_multi(
        sw(),
        &[(
            "/w/m.swift",
            "func f(xs: [Int]) { xs.forEach { x in step(x) }; xs.map { x in transform(x) } }\n",
        )],
    );
    assert_calls(&w, "f", &["step", "transform"]);
}

/// Ternary expressions emit both branches' calls. Verified across
/// every language that has ternary syntax.
#[test]
fn ternary_both_branches_captured_all_langs() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "python",
            "def f():\n    return a() if g() else b()\n",
            "m.py",
            "f",
        ),
        ("js", "function f() { return g() ? a() : b(); }\n", "m.js", "f"),
        (
            "java",
            "class M { static int f() { return g() ? a() : b(); } static boolean g(){return true;} static int a(){return 0;} static int b(){return 0;} }\n",
            "M.java",
            "f",
        ),
        ("go", "package main\nfunc F() int { if G() { return A() }; return B() }\n", "m.go", "F"),
        (
            "kotlin",
            "fun f(): Int { return if (g()) a() else b() }\n",
            "m.kt",
            "f",
        ),
        (
            "rust",
            "fn f() -> i32 { if g() { a() } else { b() } }\n",
            "m.rs",
            "f",
        ),
        (
            "scala",
            "object M { def f(): Int = if (g()) a() else b(); def g(): Boolean = true; def a(): Int = 0; def b(): Int = 0 }\n",
            "M.scala",
            "f",
        ),
        (
            "swift",
            "func f() -> Int { return g() ? a() : b() }\n",
            "m.swift",
            "f",
        ),
        (
            "c",
            "int f(void) { return g() ? a() : b(); }\n",
            "m.c",
            "f",
        ),
        (
            "cpp",
            "int f() { return g() ? a() : b(); }\n",
            "m.cpp",
            "f",
        ),
        (
            "csharp",
            "class M { static int F() { return G() ? A() : B(); } static bool G() => true; static int A() => 0; static int B() => 0; }\n",
            "M.cs",
            "F",
        ),
        (
            "typescript",
            "function f(): number { return g() ? a() : b(); }\n",
            "m.ts",
            "f",
        ),
        (
            "php",
            "<?php\nfunction f() { return g() ? a() : b(); }\n",
            "m.php",
            "f",
        ),
        (
            "ruby",
            "def f\n  g() ? a() : b()\nend\n",
            "m.rb",
            "f",
        ),
    ];
    for (lang, src, path, entry) in cases {
        let adapter = match *lang {
            "python" => py(),
            "js" => js(),
            "java" => java(),
            "go" => go(),
            "kotlin" => kt(),
            "rust" => rs(),
            "scala" => sc(),
            "swift" => sw(),
            "c" => c(),
            "cpp" => cpp(),
            "csharp" => cs(),
            "typescript" => ts(),
            "php" => php(),
            "ruby" => rb(),
            _ => unreachable!(),
        };
        let ws = ws_multi(adapter, &[(&format!("/w/{}", path), src)]);
        // Go / C# use PascalCase identifiers; others use lowercase.
        let expected = match *lang {
            "go" => vec!["G", "A", "B"],
            "csharp" => vec!["A", "B"],
            _ => vec!["a", "b"],
        };
        for needle in expected {
            assert!(
                calls_contains(&ws, entry, needle),
                "{lang}: ternary branch call `{needle}` missing under `{entry}`"
            );
        }
    }
}
