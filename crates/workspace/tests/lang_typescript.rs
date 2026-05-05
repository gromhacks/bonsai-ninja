//! Per-construct tests for the TypeScript adapter.

#[path = "lang_common.rs"]
mod common;

use bonsai_lang_api::LoopKind;
use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(
        Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        "/w/a.ts",
        src,
    )
}

#[test]
fn typed_function_declaration() {
    let w = make("function foo(x: number): void { }");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn interface_is_a_declaration() {
    let w = make("interface Shape { area(): number; }");
    assert!(class_exists(&w, "Shape"));
}

#[test]
fn typed_qualified_call() {
    let w = make("function f(): void { child_process.exec(cmd); jwt.decode(t); }");
    assert!(has_call_containing(&w, "f", "child_process.exec"));
    assert!(has_call_containing(&w, "f", "jwt.decode"));
}

#[test]
fn if_branch() {
    let w = make("function f(x: number): void { if (x > 0) { a(); } else { b(); } }");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_of() {
    let w = make("function f(arr: number[]): void { for (const x of arr) { g(x); } }");
    assert!(has_loop_of(&w, "f", LoopKind::ForEach));
}

#[test]
fn while_loop() {
    let w = make("function f(): void { while (true) { break; } }");
    assert!(has_loop_of(&w, "f", LoopKind::While));
}

#[test]
fn throw_stmt() {
    let w = make("function f(): void { throw new Error('x'); }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn class_declaration() {
    let w = make("class Widget { x: number = 0; }");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn decorator_on_class() {
    let w = make("@sealed\nclass Widget { }");
    assert!(has_decorator(&w, "sealed"));
}

#[test]
fn method_in_class() {
    let w = make("class C { run(): void { this.go(); } }");
    assert!(function_exists(&w, "run"));
    assert!(has_call_containing(&w, "run", "this.go"));
}

#[test]
fn param_types_ignored_but_names_captured() {
    let w = make("function f(user_id: string, cb: (x: number) => void): void { cb(1); }");
    let params = params_of(&w, "f");
    assert!(params.contains(&"user_id".to_string()));
    assert!(params.contains(&"cb".to_string()));
}

#[test]
fn decorated_params_capture_binding_names_and_annotations() {
    let w = make(
        "import { Body } from '@nestjs/common';\n\
         class C { save(@Body() req: ProbeReq, @Body('name') name: string): void { sink(req.url, name); } }",
    );
    assert_eq!(params_of(&w, "save"), vec!["req".to_string(), "name".to_string()]);
    let annotations = param_annotations_of(&w, "save");
    assert_eq!(annotations.len(), 2);
    assert!(annotations[0].contains(&"Body".to_string()), "{annotations:?}");
    assert!(annotations[1].contains(&"Body".to_string()), "{annotations:?}");
}

#[test]
fn return_stmt() {
    let w = make("function f(): number { return 1; }");
    assert!(has_return(&w, "f"));
}

#[test]
fn assignment() {
    let w = make("function f(): void { let x = 1; x = 2; }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn import_declaration() {
    let w = make("import { readFile } from \"fs\";\nfunction f(): void {}");
    assert!(has_import(&w, "fs"));
}

#[test]
fn do_while_loop() {
    let w = make("function f(): void { do { g(); } while (true); }\nfunction g(): void {}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn try_catch_finally() {
    let w = make("function f(): void { try { g(); } catch (e) { h(e); } finally { done(); } }");
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
    assert!(has_finally(&w, "f"));
}

#[test]
fn await_in_async() {
    let w = make("async function f(): Promise<number> { const x = await g(); return x; }");
    assert!(has_await(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w = make(
        "function f(): void { for (let i = 0; i < 10; i++) { if (i === 0) continue; if (i === 5) break; } }",
    );
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn import_type_only() {
    let w = make("import type { Widget } from \"./widget\";\nfunction f(): void {}");
    assert!(has_import(&w, "widget"));
}

#[test]
fn import_default_and_named() {
    let w = make("import Fs, { readFile } from \"fs\";\nfunction f(): void {}");
    assert!(has_import(&w, "fs"));
}

#[test]
fn namespace_import_captures_alias() {
    let w = make("import * as fs from \"fs\";\nfunction f(): void {}");
    assert!(has_import_alias(&w, "fs", "fs"));
}

#[test]
fn named_import_renamed_captures_alias() {
    let w = make("import { readFile as read } from \"fs\";\nfunction f(): void {}");
    assert!(has_import_alias(&w, "fs", "read"));
}

#[test]
fn yield_in_generator() {
    let w = make("function* gen(): Generator<number> { yield 1; }");
    assert!(has_yield(&w, "gen"));
}
