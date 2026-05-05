//! Per-construct tests for the PHP adapter.

#[path = "lang_common.rs"]
mod common;

use common::*;
use std::sync::Arc;

fn make(src: &str) -> bonsai_workspace::Workspace {
    ws(Arc::new(bonsai_lang_php::PhpAdapter::new()), "/w/a.php", src)
}

#[test]
fn function_definition() {
    let w = make("<?php\nfunction foo() {}\n");
    assert!(function_exists(&w, "foo"));
}

#[test]
fn class_declaration() {
    let w = make("<?php\nclass Widget { }");
    assert!(class_exists(&w, "Widget"));
}

#[test]
fn method_in_class() {
    let w = make("<?php\nclass A { public function run() { $this->go(); } public function go() {} }");
    assert!(function_exists(&w, "run"));
}

#[test]
fn direct_call() {
    let w = make("<?php\nfunction f() { g(); } function g() {}");
    assert!(has_call(&w, "f", "g"));
}

#[test]
fn if_else() {
    let w = make("<?php\nfunction f($x) { if ($x > 0) a(); else b(); }\nfunction a(){} function b(){}");
    assert!(has_branch(&w, "f"));
}

#[test]
fn for_loop() {
    let w = make("<?php\nfunction f() { for ($i = 0; $i < 10; $i++) g($i); }\nfunction g($i){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn foreach_loop() {
    let w = make("<?php\nfunction f($arr) { foreach ($arr as $x) g($x); }\nfunction g($x){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn while_loop() {
    let w = make("<?php\nfunction f() { while (cond()) g(); }\nfunction cond(){return true;} function g(){}");
    assert!(has_loop(&w, "f"));
}

#[test]
fn throw_stmt() {
    let w = make("<?php\nfunction f() { throw new Exception('x'); }");
    assert!(has_throw(&w, "f"));
}

#[test]
fn return_stmt() {
    let w = make("<?php\nfunction f() { return 42; }");
    assert!(has_return(&w, "f"));
}

#[test]
fn assignment() {
    let w = make("<?php\nfunction f() { $x = 1; }");
    assert!(has_assign(&w, "f", "x"));
}

#[test]
fn use_statement_is_import() {
    let w = make("<?php\nuse App\\Service;\nfunction f() {}\n");
    assert!(has_import(&w, "App"), "use statement not surfaced");
}

#[test]
fn do_while_loop() {
    let w = make("<?php\nfunction f() { do { g(); } while (true); }\nfunction g(){}\n");
    assert!(has_loop(&w, "f"));
}

#[test]
fn php8_attribute_is_decorator() {
    let w = make("<?php\n#[Deprecated]\nfunction f() {}\n");
    assert!(has_decorator(&w, "Deprecated"));
}

#[test]
fn php8_parameter_attributes_are_annotations() {
    let w = make(
        "<?php\n\
         function handle(#[FromQuery] string $q, #[FromBody] array $body) { sink($q); }\n",
    );
    assert_eq!(
        params_of(&w, "handle"),
        vec!["$q".to_string(), "$body".to_string()]
    );
    let annotations = param_annotations_of(&w, "handle");
    assert_eq!(annotations.len(), 2);
    assert!(
        annotations[0].contains(&"FromQuery".to_string()),
        "{annotations:?}"
    );
    assert!(
        annotations[1].contains(&"FromBody".to_string()),
        "{annotations:?}"
    );
}

#[test]
fn try_catch_finally() {
    let w = make(
        "<?php\nfunction f() { try { g(); } catch (\\Exception $e) { h($e); } finally { done(); } }\nfunction g(){} function h($e){} function done(){}\n",
    );
    assert!(has_try(&w, "f"));
    assert!(has_catch(&w, "f"));
    assert!(has_finally(&w, "f"));
}

#[test]
fn break_and_continue() {
    let w = make(
        "<?php\nfunction f() { for ($i = 0; $i < 10; $i++) { if ($i == 0) continue; if ($i == 5) break; } }\n",
    );
    assert!(has_break(&w, "f"));
    assert!(has_continue(&w, "f"));
}

#[test]
fn use_with_alias() {
    let w = make("<?php\nuse App\\Service as S;\nfunction f() {}\n");
    assert!(has_import_alias(&w, "App\\Service", "S"));
}

#[test]
fn yield_and_yield_from() {
    let w = make("<?php\nfunction gen() { yield 1; yield from other(); }\nfunction other(){}\n");
    assert!(has_yield(&w, "gen"));
}
