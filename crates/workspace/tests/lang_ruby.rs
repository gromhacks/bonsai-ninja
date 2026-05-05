//! Per-construct tests for the Ruby adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_ruby::RubyAdapter::new()), "/w/a.rb", src)
}

#[test]
fn def_declaration() {
    let w = make("def foo\nend\n");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call_with_parens() {
    // Ruby's tree-sitter grammar treats bare identifiers without parens as
    // identifiers, not calls. Parens force the call-node form — which is
    // what our flow walker picks up.
    let w = make("def f\n  g()\nend\ndef g\nend\n");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn method_call_with_dot() {
    let w = make("def f(arr)\n  arr.each { |x| g(x) }\nend\ndef g(x) end\n");
    assert!(has_call_containing(&w, "f", "arr.each") || has_call(&w, "f", "each"));
}

#[test]
fn if_else_branch() {
    let w = make("def f(x)\n  if x\n    a()\n  else\n    b()\n  end\nend\ndef a() end\ndef b() end\n");
    assert!(has_branch(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("def f\n  while cond()\n    g()\n  end\nend\ndef cond() true end\ndef g() end\n");
    assert!(has_loop(&w, "f"));
}

#[test]
fn raise_is_a_call() {
    // Ruby's tree-sitter grammar parses `raise` as a regular method call
    // (not a dedicated throw keyword). We surface it as `call raise` — the
    // inspect command still matches it via `inspect raise --kind call`.
    let w = make("def f\n  raise \"bad\"\nend\n");
    assert!(has_call(&w, "f", "raise"));
}

#[test]
fn return_stmt() {
    let w = make("def f\n  return 42\nend\n");
    assert!(has_return(&w, "f"));
}

#[test]
fn class_declaration() {
    let w = make("class Widget\nend\n");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn assignment() {
    let w = make("def f\n  x = 1\nend\n");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn require_is_import() {
    // Ruby's `require "foo"` is surfaced as a top-level call rather than
    // a dedicated import in tree-sitter-ruby — verify it appears as a
    // call so that `inspect require` still surfaces the module hookup.
    let w = make("require \"json\"\ndef f\n  g()\nend\ndef g() end\n");
    let global = w.db().global_index();
    let mut saw_require = false;
    for file in global.all_files() {
        if let Some(idx) = global.file_index(file) {
            for r in &idx.refs {
                if r.name.contains("require") {
                    saw_require = true;
                }
            }
        }
    }
    assert!(saw_require, "require call not surfaced as a ref");
}

#[test]
fn for_each_loop() {
    // Ruby's iterator-style loops look like method calls (arr.each {...}).
    // Block-arg methods should still surface the receiver call.
    let w = make("def f(arr)\n  arr.each { |x| g(x) }\nend\ndef g(x) end\n");
    assert!(has_call_containing(&w, "f", "arr.each") || has_call(&w, "f", "each"));
}

#[test]
fn until_loop() {
    // `until` is while's inverse — grouped in while_kinds via the generic
    // handler's `until` node kind.
    let w = make("def f\n  until cond()\n    g()\n  end\nend\ndef cond() true end\ndef g() end\n");
    assert!(has_loop(&w, "f"), "until not classified as loop");
}

#[test]
fn begin_rescue_ensure() {
    let w = make(
        "def f\n  begin\n    g()\n  rescue StandardError => e\n    h(e)\n  ensure\n    done()\n  end\nend\ndef g() end\ndef h(e) end\ndef done() end\n",
    );
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
    assert!(has_finally(&w, "f"));
}

#[test]
fn yield_in_method() {
    let w = make("def f\n  yield 1\nend\n");
    assert!(has_yield(&w, "f"));
}

#[test]
fn break_and_next_in_while_loop() {
    // Ruby's `break` and `next` inside a `do |x| ... end` block belong to
    // the block, not the enclosing method. A bare `while` loop does
    // surface them in the outer flow.
    let w = make(
        "def f\n  i = 0\n  while i < 10\n    i = i + 1\n    next if i == 1\n    break if i == 5\n  end\nend\n",
    );
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}
