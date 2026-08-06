//! Per-construct tests for the Perl adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_perl::PerlAdapter::new()), "/w/a.pl", src)
}

#[test]
fn sub_declaration() {
    let w = make("sub foo { }\n");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn direct_call() {
    let w = make("sub f { g(); }\nsub g { }\n");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn if_branch() {
    let w = make("sub f { if ($x > 0) { a(); } else { b(); } }\nsub a { }\nsub b { }\n");
    assert!(has_branch(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("sub f { while ($cond) { g(); } }\nsub g { }\n");
    assert!(has_loop(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("sub f { for (my $i = 0; $i < 10; $i++) { g($i); } }\nsub g { }\n");
    assert!(has_loop(&w, "f"));
}

#[test]
fn return_stmt() {
    let w = make("sub f { return 42; }\n");
    assert!(has_return(&w, "f"));
}

#[test]
fn my_binding_is_assign_or_var() {
    // Perl `my $x = 1;` is captured as an assignment-target in the flow.
    // The adapter maps `variable_declaration` into the assignment_kinds
    // set so the walker emits a tagged target.
    let w = make("sub f { my $x = 1; }\n");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn use_statement_is_import() {
    let w = make("use strict;\nsub f { }\n");
    assert!(has_import(&w, "strict"), "use statement not surfaced");
}

#[test]
fn die_is_a_call() {
    // Perl uses `die` for exceptions — surfaced as a regular call in the
    // flow (analogous to Ruby's `raise`).
    let w = make("sub f { die \"bad\"; }\n");
    assert!(has_call(&w, "f", "die"));
}

#[test]
fn last_and_next_are_break_continue() {
    // Perl's `last` = break, `next` = continue.
    let w = make("sub f { for (my $i = 0; $i < 10; $i++) { next if $i == 0; last if $i == 5; } }\n");
    assert!(has_break(&w, "f"), "Perl `last` must lower as Break");
    assert!(has_continue(&w, "f"), "Perl `next` must lower as Continue");
}

#[test]
fn attribute_is_decorator() {
    // Perl's subroutine attributes `sub f :lvalue { ... }` surface as
    // `attribute` nodes.
    let w = make("sub f :lvalue { return 1; }\n");
    assert!(has_decorator(&w, "lvalue"));
}

#[test]
fn try_catch_feature() {
    // Perl 5.34+ `use feature 'try';` enables try/catch. tree-sitter-perl
    // parses it as a dedicated `try_statement`.
    let w = make("use feature 'try';\nsub f { try { g(); } catch ($e) { h($e); } }\nsub g { }\nsub h { }\n");
    assert!(has_try(&w, "f"));
    // Perl's grammar doesn't tag the catch block with a dedicated kind —
    // the fallback in walk_flow_events routes the second block-child into
    // catch_events.
    assert!(has_catch(&w, "f"));
}
