//! Per-construct tests for the Python adapter.

#[path = "lang_common.rs"]
mod common;

use bonsai_lang_api::{LoopKind, RefKind};
use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_python::PythonAdapter::new()), "/w/a.py", src)
}

#[test]
fn function_def() {
    let w = make("def foo():\n    pass\n");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn async_function_def() {
    let w = make("async def foo():\n    pass\n");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("def f():\n    g()\n");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn qualified_call() {
    let w = make("def f():\n    os.system('x')\n");
    assert!(has_call_containing(&w, "f", "os.system"));
}

#[test]
fn method_call_on_self() {
    let w = make("class C:\n    def run(self):\n        self.do()\n");
    assert!(has_call_containing(&w, "run", "self.do"));
}

#[test]
fn if_else_branch() {
    let w = make("def f(x):\n    if x:\n        y()\n    else:\n        z()\n");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("def f():\n    for i in [1, 2]:\n        g(i)\n");
    assert!(has_loop_of(&w, "f", LoopKind::For) || has_loop_of(&w, "f", LoopKind::ForEach));
}

#[test]
fn while_loop() {
    let w = make("def f():\n    while True:\n        break\n");
    assert!(has_loop_of(&w, "f", LoopKind::While));
}

#[test]
fn assignment() {
    let w = make("def f():\n    x = 1\n");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn return_stmt() {
    let w = make("def f():\n    return 1\n");
    assert!(has_return(&w, "f"));
}

#[test]
fn raise_is_throw() {
    let w = make("def f():\n    raise ValueError('bad')\n");
    assert!(has_throw(&w, "f"));
}

#[test]
fn class_declaration() {
    let w = make("class Widget:\n    pass\n");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn constructor_method() {
    let w = make("class Widget:\n    def __init__(self, x):\n        self.x = x\n");
    // __init__ should be classified as Constructor.
    assert!(ctor_exists(&w, "__init__"));
}

#[test]
fn decorator_extraction() {
    let w = make("@audited\ndef f():\n    pass\n");
    assert!(has_decorator(&w, "audited"));
}

#[test]
fn attribute_access_is_not_decorator_ref() {
    let w = make("import pickle\n\ndef f(data):\n    return pickle.loads(data)\n");
    assert!(has_call_containing(&w, "f", "pickle.loads"));
    let global = w.db().global_index();
    for file in global.all_files() {
        let Some(index) = global.file_index(file) else {
            continue;
        };
        for reference in &index.refs {
            assert!(
                !(reference.kind == RefKind::Decorator && reference.name == "pickle"),
                "ordinary attribute access must not be reported as a decorator: {reference:?}"
            );
        }
    }
}

#[test]
fn lambda_does_not_pollute_outer_flow() {
    // Lambdas are skipped during flow walking so their internal calls don't
    // appear in the enclosing function's flow events.
    let w = make("def f():\n    cb = lambda x: inner(x)\n    run(cb)\n");
    // Outer: Assign cb + Call run — but NOT `inner`.
    assert!(has_assign(&w, "f", "cb"));
    assert!(has_call(&w, "f", "run"));
    assert!(!has_call(&w, "f", "inner"), "lambda body leaked into outer flow");
}

#[test]
fn param_names_captured() {
    let w = make("def f(user_id, action, cb):\n    cb(user_id)\n");
    let params = params_of(&w, "f");
    assert_eq!(params, vec!["user_id", "action", "cb"]);
}

#[test]
fn fastapi_param_annotations_are_parallel_to_names() {
    let w = make(
        "from typing import Annotated\n\
         from fastapi import Body, Query\n\
         def handle(req: Annotated[ProbeReq, Body()], q: str = Query(...)):\n\
             sink(req.url, q)\n",
    );
    assert_eq!(params_of(&w, "handle"), vec!["req".to_string(), "q".to_string()]);
    let annotations = param_annotations_of(&w, "handle");
    assert_eq!(annotations.len(), 2);
    assert!(annotations[0].contains(&"Body".to_string()), "{annotations:?}");
    assert!(annotations[1].contains(&"Query".to_string()), "{annotations:?}");
}

#[test]
fn nested_branches_extracted() {
    let w = make("def f(x, y):\n    if x:\n        if y:\n            a()\n        else:\n            b()\n");
    assert!(has_branch(&w, "f"));
    assert!(has_call(&w, "f", "a"));
    assert!(has_call(&w, "f", "b"));
}

#[test]
fn import_statement() {
    let w = make("import os\ndef f():\n    os.system('x')\n");
    assert!(has_import(&w, "os"));
}

#[test]
fn from_import_statement() {
    let w = make("from flask import request\ndef f():\n    pass\n");
    assert!(has_import(&w, "flask"));
}

#[test]
fn import_alias_captured() {
    let w = make("import numpy as np\ndef f():\n    pass\n");
    assert!(has_import_alias(&w, "numpy", "np"), "alias not surfaced");
}

#[test]
fn from_import_alias_captured() {
    let w = make("from flask import request as req\ndef f():\n    pass\n");
    assert!(has_import_alias(&w, "flask", "req"));
}

#[test]
fn from_import_star_is_wildcard() {
    let w = make("from os import *\ndef f():\n    pass\n");
    assert!(has_wildcard_import(&w, "os"));
}

#[test]
fn relative_import_surfaces_module() {
    let w = make("from . import helpers\ndef f():\n    pass\n");
    assert!(has_import(&w, "."));
}

#[test]
fn try_except_finally() {
    let w = make("def f():\n    try:\n        g()\n    except ValueError:\n        h()\n    finally:\n        cleanup()\n");
    assert!(has_try(&w, "f"), "try block missing");
    assert!(has_catch(&w, "f"), "except arm missing");
    assert!(has_finally(&w, "f"), "finally block missing");
    assert!(has_call(&w, "f", "g"));
    assert!(has_call(&w, "f", "h"));
    assert!(has_call(&w, "f", "cleanup"));
}

#[test]
fn yield_and_yield_from() {
    let w = make("def gen():\n    yield 1\n    yield from other()\n");
    assert!(has_yield(&w, "gen"));
}

#[test]
fn break_and_continue_in_loop() {
    let w = make("def f():\n    for i in range(10):\n        if i == 0:\n            continue\n        if i == 5:\n            break\n");
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn await_in_async() {
    let w = make("async def f():\n    await g()\n");
    assert!(has_await(&w, "f"));
}

#[test]
fn with_is_using_context() {
    let w = make("def f():\n    with open('x') as fh:\n        read(fh)\n");
    assert!(has_using(&w, "f"));
}
