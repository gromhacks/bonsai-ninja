//! Per-language inspect search-kind matrix.
//!
//! Every supported language is exercised against every search kind the
//! inspect command dispatches on: decl-name, direct call, qualified /
//! dotted call, string literal, decorator / annotation, variable
//! (assignment target), cross-module chain through the match. Uses the
//! same primitives the CLI's `cmd_inspect` is built on (enumerate chains +
//! flow-event walk) so a failure here means the CLI will mis-render too.

#[path = "lang_common.rs"]
mod common;

use bonsai_lang_api::{AdapterArc, FlowEvent, LanguageRegistry};
use bonsai_workspace::Workspace;
use std::sync::Arc;
// Force the common module to be compiled — the shared helpers are referenced
// transitively from the per-language modules below via `super::`.
#[allow(unused_imports)]
use common as _common;

fn ws_multi(adapter: AdapterArc, files: &[(&str, &str)]) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    for (p, src) in files {
        ws.vfs().write((*p).to_string(), Arc::<str>::from(*src));
    }
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

/// Simulates the inspect command's substring match: case-insensitive
/// `contains` against decl names, call names inside flow events, and
/// string literals.
fn query_hits(ws: &Workspace, query: &str) -> QueryHits {
    let q = query.to_lowercase();
    let global = ws.db().global_index();
    let mut hits = QueryHits::default();
    for file in global.all_files() {
        if let Some(idx) = global.file_index(file) {
            for d in &idx.defs {
                if d.name.to_lowercase().contains(&q) {
                    hits.decl_names.push(d.name.clone());
                }
            }
            for r in &idx.refs {
                if r.name.to_lowercase().contains(&q) {
                    match r.kind {
                        bonsai_lang_api::RefKind::Decorator => {
                            hits.decorator_names.push(r.name.clone());
                        }
                        bonsai_lang_api::RefKind::Call => {
                            hits.top_level_call_names.push(r.name.clone());
                        }
                        _ => hits.refs.push(r.name.clone()),
                    }
                }
            }
            for s in &idx.strings {
                if s.text.to_lowercase().contains(&q) {
                    hits.strings.push(s.text.clone());
                }
            }
            for d in &idx.defs {
                walk_find_calls_and_assigns(&d.flow_events, &q, &d.name, &mut hits);
            }
        }
    }
    hits
}

fn walk_find_calls_and_assigns(events: &[FlowEvent], q: &str, in_fn: &str, hits: &mut QueryHits) {
    for e in events {
        match e {
            FlowEvent::Call { name, .. } => {
                if name.to_lowercase().contains(q) {
                    hits.flow_calls.push((in_fn.to_string(), name.clone()));
                }
            }
            FlowEvent::Assign { target, .. } => {
                if target.to_lowercase().contains(q) {
                    hits.flow_assigns.push((in_fn.to_string(), target.clone()));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_find_calls_and_assigns(then_events, q, in_fn, hits);
                walk_find_calls_and_assigns(else_events, q, in_fn, hits);
            }
            FlowEvent::Loop { body, .. } => {
                walk_find_calls_and_assigns(body, q, in_fn, hits);
            }
            _ => {}
        }
    }
}

#[derive(Default, Debug)]
struct QueryHits {
    decl_names: Vec<String>,
    /// (enclosing_function, callee_name)
    flow_calls: Vec<(String, String)>,
    /// (enclosing_function, assign_target)
    flow_assigns: Vec<(String, String)>,
    top_level_call_names: Vec<String>,
    decorator_names: Vec<String>,
    strings: Vec<String>,
    refs: Vec<String>,
}

impl QueryHits {
    fn has_decl(&self, name: &str) -> bool {
        self.decl_names.iter().any(|n| n == name)
    }
    fn has_flow_call(&self, in_fn: &str, callee: &str) -> bool {
        self.flow_calls
            .iter()
            .any(|(f, c)| f == in_fn && c.contains(callee))
    }
    fn has_string_containing(&self, sub: &str) -> bool {
        self.strings.iter().any(|s| s.contains(sub))
    }
    fn has_decorator(&self, name: &str) -> bool {
        self.decorator_names.iter().any(|n| n.contains(name))
    }
    fn has_flow_assign(&self, in_fn: &str, target: &str) -> bool {
        self.flow_assigns
            .iter()
            .any(|(f, t)| f == in_fn && t.contains(target))
    }
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

mod python {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_python::PythonAdapter::new()),
            &[("/w/a.py", src)],
        )
    }

    #[test]
    fn decl_match_finds_function() {
        let w = ws("def run_admin(): pass\ndef other(): pass\n");
        let h = query_hits(&w, "run_admin");
        assert!(h.has_decl("run_admin"), "decl search missed: {h:?}");
    }

    #[test]
    fn fuzzy_decl_match_substring() {
        let w = ws("def run_admin_command(user_id, cmd): pass\n");
        let h = query_hits(&w, "run_admin");
        assert!(h.has_decl("run_admin_command"), "fuzzy decl missed: {h:?}");
    }

    #[test]
    fn qualified_call_match() {
        let w = ws("def f():\n    os.system('x')\n    jwt.decode(t)\n");
        let h = query_hits(&w, "os.system");
        assert!(h.has_flow_call("f", "os.system"), "os.system missed: {h:?}");
    }

    #[test]
    fn string_match_preserves_literal() {
        let w = ws("def f():\n    q = \"SELECT * FROM users\"\n");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"), "string missed: {h:?}");
    }

    #[test]
    fn decorator_match() {
        let w = ws("@audited\ndef f(): pass\n");
        let h = query_hits(&w, "audited");
        assert!(h.has_decorator("audited"), "decorator missed: {h:?}");
    }

    #[test]
    fn var_match_in_flow() {
        let w = ws("def f():\n    user_id = verify(tok)\n");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "var missed: {h:?}");
    }

    #[test]
    fn cross_file_chain_through_match() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/gate.py".to_string(),
            Arc::<str>::from("from svc import run\ndef main():\n    run(42)\n"),
        );
        w.vfs().write(
            "/w/svc.py".to_string(),
            Arc::<str>::from("def run(id):\n    process(id)\ndef process(id): pass\n"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let trace = w.trace_from("main").expect("trace main");
        let has_run = trace
            .steps
            .iter()
            .any(|s| s.message.contains("Call run") || s.function == "run");
        let has_process = trace
            .steps
            .iter()
            .any(|s| s.message.contains("process") || s.function == "process");
        assert!(has_run, "no `run` step in trace: {:?}", trace.steps);
        assert!(has_process, "no `process` step in trace: {:?}", trace.steps);
    }
}

// ---------------------------------------------------------------------------
// JavaScript
// ---------------------------------------------------------------------------

mod javascript {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            &[("/w/a.js", src)],
        )
    }

    #[test]
    fn decl_and_fuzzy() {
        let w = ws("function handleRequest() {}");
        let h = query_hits(&w, "handle");
        assert!(h.has_decl("handleRequest"));
    }

    #[test]
    fn direct_call() {
        let w = ws("function f() { worker(); }\nfunction worker() {}");
        let h = query_hits(&w, "worker");
        assert!(h.has_flow_call("f", "worker"), "{h:?}");
    }

    #[test]
    fn qualified_call() {
        let w = ws("function f() { child_process.exec(cmd); console.log('x'); }");
        let h = query_hits(&w, "child_process.exec");
        assert!(h.has_flow_call("f", "child_process.exec"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("function f() { const u = \"https://api.example.com\"; }");
        let h = query_hits(&w, "https://");
        assert!(h.has_string_containing("https://"));
    }

    #[test]
    fn assignment_as_var() {
        let w = ws("function f() { user_id = 42; }");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/a.js".to_string(),
            Arc::<str>::from("function main() { worker(); }"),
        );
        w.vfs()
            .write("/w/b.js".to_string(), Arc::<str>::from("function worker() {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace main");
        assert!(
            t.steps.iter().any(|s| s.function == "worker"),
            "no worker step: {:?}",
            t.steps
        );
    }

    #[test]
    fn class_decorator_stage3() {
        // TC39 stage-3 class decorator syntax.
        let w = ws("@sealed\nclass Widget { }");
        let h = query_hits(&w, "sealed");
        assert!(h.has_decorator("sealed"), "expected @sealed decorator: {h:?}");
    }
}

// ---------------------------------------------------------------------------
// TypeScript
// ---------------------------------------------------------------------------

mod typescript {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            &[("/w/a.ts", src)],
        )
    }

    #[test]
    fn decl_and_interface() {
        let w = ws("interface Foo { bar(): void; }\nfunction fetchFoo(): void {}");
        let h = query_hits(&w, "foo");
        assert!(h.has_decl("Foo") || h.has_decl("fetchFoo"), "{h:?}");
    }

    #[test]
    fn direct_call() {
        let w = ws("function f(): void { worker(); }\nfunction worker(): void {}");
        let h = query_hits(&w, "worker");
        assert!(h.has_flow_call("f", "worker"));
    }

    #[test]
    fn qualified_call_with_types() {
        let w = ws("function f(): void { jwt.decode(tok); }");
        let h = query_hits(&w, "jwt.decode");
        assert!(h.has_flow_call("f", "jwt.decode"));
    }

    #[test]
    fn decorator() {
        let w = ws("@sealed\nclass Widget { }");
        let h = query_hits(&w, "sealed");
        assert!(h.has_decorator("sealed"));
    }

    #[test]
    fn string_literal() {
        let w = ws("function f(): void { const q: string = \"SELECT * FROM users\"; }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_as_var() {
        let w = ws("function f(): void { user_id = 42; }");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/a.ts".to_string(),
            Arc::<str>::from("function main(): void { worker(); }"),
        );
        w.vfs().write(
            "/w/b.ts".to_string(),
            Arc::<str>::from("function worker(): void {}"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

mod rust {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_rust::RustAdapter::new()),
            &[("/w/a.rs", src)],
        )
    }

    #[test]
    fn decl_by_name() {
        let w = ws("fn process_order() {}");
        let h = query_hits(&w, "process");
        assert!(h.has_decl("process_order"));
    }

    #[test]
    fn direct_call() {
        let w = ws("fn f() { g(); }\nfn g() {}");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn path_call_preserved() {
        let w = ws("fn f() { std::fs::read_to_string(p); }");
        let h = query_hits(&w, "read_to_string");
        assert!(h.has_flow_call("f", "read_to_string"), "{h:?}");
    }

    #[test]
    fn macro_call() {
        let w = ws("fn f() { println!(\"hi\"); }");
        let h = query_hits(&w, "println");
        assert!(h.has_flow_call("f", "println"));
    }

    #[test]
    fn string_literal() {
        let w = ws("fn f() { let q = \"SELECT id FROM t\"; }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn let_binding_matched_as_var() {
        let w = ws("fn f() { let user_id = 1; }");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_rust::RustAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs()
            .write("/w/a.rs".to_string(), Arc::<str>::from("fn main() { helper(); }"));
        w.vfs()
            .write("/w/b.rs".to_string(), Arc::<str>::from("pub fn helper() {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "helper"));
    }

    #[test]
    fn attribute_item_as_decorator() {
        let w = ws("#[derive(Debug)]\nstruct Foo { x: i32 }");
        let h = query_hits(&w, "derive");
        assert!(
            h.has_decorator("derive"),
            "expected #[derive] as decorator: {h:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

mod go {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(Arc::new(bonsai_lang_go::GoAdapter::new()), &[("/w/a.go", src)])
    }

    #[test]
    fn decl_and_struct() {
        let w = ws("package m\ntype Widget struct{}\nfunc ProcessItem() {}\n");
        let h = query_hits(&w, "Widget");
        assert!(h.has_decl("Widget"));
        let h2 = query_hits(&w, "Process");
        assert!(h2.has_decl("ProcessItem"));
    }

    #[test]
    fn direct_call() {
        let w = ws("package m\nfunc f() { g() }\nfunc g() {}\n");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn package_qualified_call() {
        let w = ws("package m\nfunc f() { fmt.Println(\"x\") }\n");
        let h = query_hits(&w, "fmt.Println");
        assert!(h.has_flow_call("f", "fmt.Println"));
    }

    #[test]
    fn string_literal() {
        let w = ws("package m\nfunc f() { q := \"SELECT id FROM t\"; _ = q }\n");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn short_var_decl_as_var() {
        let w = ws("package m\nfunc f() { user_id := 1; _ = user_id }\n");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_go::GoAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/a.go".to_string(),
            Arc::<str>::from("package main\nfunc main() { worker() }\n"),
        );
        w.vfs().write(
            "/w/b.go".to_string(),
            Arc::<str>::from("package main\nfunc worker() {}\n"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

mod java {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_java::JavaAdapter::new()),
            &[("/w/A.java", src)],
        )
    }

    #[test]
    fn class_and_method() {
        let w = ws("class AccountService { void process() {} }");
        let h = query_hits(&w, "Account");
        assert!(h.has_decl("AccountService"));
    }

    #[test]
    fn direct_call() {
        let w = ws("class A { void f() { g(); } void g() {} }");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn annotation_as_decorator() {
        let w = ws("class A { @Deprecated void f() {} }");
        let h = query_hits(&w, "Deprecated");
        assert!(h.has_decorator("Deprecated"));
    }

    #[test]
    fn method_invocation() {
        let w = ws("class A { void f() { Runtime.getRuntime().exec(cmd); } }");
        let h = query_hits(&w, "exec");
        assert!(!h.flow_calls.is_empty(), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("class A { void f() { String q = \"SELECT * FROM users\"; } }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("class A { int userId; void f() { userId = 42; } }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("f", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/Main.java".to_string(),
            Arc::<str>::from("public class Main { public static void main() { Helper.worker(); } }"),
        );
        w.vfs().write(
            "/w/Helper.java".to_string(),
            Arc::<str>::from("public class Helper { public static void worker() {} }"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Kotlin
// ---------------------------------------------------------------------------

mod kotlin {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            &[("/w/A.kt", src)],
        )
    }

    #[test]
    fn fun_decl() {
        let w = ws("fun process_request() {}");
        let h = query_hits(&w, "process");
        assert!(h.has_decl("process_request"));
    }

    #[test]
    fn direct_call() {
        let w = ws("fun f() { g() }\nfun g() {}");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn decl_and_navigation_call() {
        let w = ws("fun f() { list.add(1) }");
        let h = query_hits(&w, "list.add");
        assert!(h.has_flow_call("f", "list.add"), "{h:?}");
    }

    #[test]
    fn annotation() {
        let w = ws("@Deprecated(\"old\") fun f() {}");
        let h = query_hits(&w, "Deprecated");
        assert!(h.has_decorator("Deprecated"));
    }

    #[test]
    fn string_literal() {
        let w = ws("fun f() { val q = \"SELECT id FROM t\" }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("fun f() { var userId = 0; userId = 42 }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("f", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/Main.kt".to_string(),
            Arc::<str>::from("fun main() { worker() }"),
        );
        w.vfs()
            .write("/w/W.kt".to_string(), Arc::<str>::from("fun worker() {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Scala
// ---------------------------------------------------------------------------

mod scala {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            &[("/w/A.scala", src)],
        )
    }

    #[test]
    fn object_and_method() {
        let w = ws("object Svc { def process(): Unit = () }");
        let h = query_hits(&w, "process");
        assert!(h.has_decl("process"));
    }

    #[test]
    fn direct_call() {
        let w = ws("object A { def f(): Unit = g(); def g(): Unit = () }");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn qualified_call() {
        let w = ws("object A { def f(): Unit = System.out.println(\"x\") }");
        let h = query_hits(&w, "println");
        assert!(h.has_flow_call("f", "println"));
    }

    #[test]
    fn string_literal() {
        let w = ws("object A { def f(): Unit = { val q = \"SELECT id FROM t\"; () } }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("object A { var userId = 0; def f(): Unit = { userId = 42 } }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("f", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_scala::ScalaAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/Main.scala".to_string(),
            Arc::<str>::from("object Main { def main(args: Array[String]): Unit = worker() }"),
        );
        w.vfs().write(
            "/w/W.scala".to_string(),
            Arc::<str>::from("object W { def worker(): Unit = () }"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }

    #[test]
    fn annotation_as_decorator() {
        let w = ws("object A { @deprecated def f(): Unit = () }");
        let h = query_hits(&w, "deprecated");
        assert!(h.has_decorator("deprecated"), "expected @deprecated: {h:?}");
    }
}

// ---------------------------------------------------------------------------
// Swift
// ---------------------------------------------------------------------------

mod swift {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            &[("/w/A.swift", src)],
        )
    }

    #[test]
    fn func_and_class() {
        let w = ws("class Widget { }\nfunc run() {}");
        let h = query_hits(&w, "Widget");
        assert!(h.has_decl("Widget"));
        let h2 = query_hits(&w, "run");
        assert!(h2.has_decl("run"));
    }

    #[test]
    fn call_inside_fn() {
        let w = ws("func f() { g() }\nfunc g() {}");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"), "{h:?}");
    }

    #[test]
    fn qualified_member_call() {
        let w = ws("func f() { list.append(1) }");
        let h = query_hits(&w, "list.append");
        assert!(h.has_flow_call("f", "list.append"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("func f() { let q = \"SELECT id FROM t\"; _ = q }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("var userId = 0\nfunc f() { userId = 42 }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("f", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_swift::SwiftAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/Main.swift".to_string(),
            Arc::<str>::from("func main() { worker() }"),
        );
        w.vfs()
            .write("/w/W.swift".to_string(), Arc::<str>::from("func worker() {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }

    #[test]
    fn attribute_as_decorator() {
        let w = ws("@objc class Widget { }");
        let h = query_hits(&w, "objc");
        assert!(h.has_decorator("objc"), "expected @objc attribute: {h:?}");
    }
}

// ---------------------------------------------------------------------------
// C
// ---------------------------------------------------------------------------

mod c {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(Arc::new(bonsai_lang_c::CAdapter::new()), &[("/w/a.c", src)])
    }

    #[test]
    fn function_definition() {
        let w = ws("int process_request(int x) { return x; }");
        let h = query_hits(&w, "process");
        assert!(h.has_decl("process_request"));
    }

    #[test]
    fn libc_call() {
        let w = ws("#include <stdio.h>\nvoid f(void) { printf(\"x\"); }");
        let h = query_hits(&w, "printf");
        assert!(h.has_flow_call("f", "printf"));
    }

    #[test]
    fn struct_member_call() {
        let w = ws("struct V { void (*run)(void); };\nvoid f(struct V *v) { v->run(); }");
        let h = query_hits(&w, "run");
        assert!(h.has_flow_call("f", "run"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("void f(void) { const char *q = \"SELECT id FROM t\"; (void)q; }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("void f(void) { int user_id = 0; user_id = 42; (void)user_id; }");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_c::CAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.c".to_string(),
            Arc::<str>::from("extern void worker(void);\nint main(void) { worker(); return 0; }"),
        );
        w.vfs()
            .write("/w/b.c".to_string(), Arc::<str>::from("void worker(void) {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// C++
// ---------------------------------------------------------------------------

mod cpp {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(Arc::new(bonsai_lang_cpp::CppAdapter::new()), &[("/w/a.cpp", src)])
    }

    #[test]
    fn class_and_method() {
        let w = ws("class Widget { public: int x() { return 1; } };");
        let h = query_hits(&w, "Widget");
        assert!(h.has_decl("Widget"));
    }

    #[test]
    fn direct_call() {
        let w = ws("void g();\nvoid f() { g(); }");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn scoped_call() {
        let w = ws("namespace ns { void g(); }\nvoid f() { ns::g(); }");
        let h = query_hits(&w, "ns::g");
        assert!(
            h.has_flow_call("f", "ns::g") || h.has_flow_call("f", "g"),
            "{h:?}"
        );
    }

    #[test]
    fn string_literal() {
        let w = ws("#include <string>\nvoid f() { auto q = \"SELECT name FROM t\"; (void)q; }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"), "{h:?}");
    }

    #[test]
    fn assignment_var() {
        let w = ws("void f() { int userId = 0; userId = 42; (void)userId; }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("f", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_cpp::CppAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.cpp".to_string(),
            Arc::<str>::from("void worker();\nint main() { worker(); return 0; }"),
        );
        w.vfs()
            .write("/w/b.cpp".to_string(), Arc::<str>::from("void worker() {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }

    #[test]
    fn attribute_declaration_as_decorator() {
        let w = ws("[[nodiscard]] int compute() { return 1; }");
        let h = query_hits(&w, "nodiscard");
        assert!(h.has_decorator("nodiscard"), "expected [[nodiscard]]: {h:?}");
    }
}

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

mod csharp {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            &[("/w/A.cs", src)],
        )
    }

    #[test]
    fn class_method_and_attribute() {
        let w = ws("class A { [Obsolete] void Foo() { Console.WriteLine(\"x\"); } }");
        let h = query_hits(&w, "Foo");
        assert!(h.has_decl("Foo"));
        let h2 = query_hits(&w, "Obsolete");
        assert!(h2.has_decorator("Obsolete"));
        let h3 = query_hits(&w, "Console.WriteLine");
        assert!(h3.has_flow_call("Foo", "Console.WriteLine"), "{h3:?}");
    }

    #[test]
    fn direct_call() {
        let w = ws("class A { void F() { G(); } void G() {} }");
        let h = query_hits(&w, "G");
        assert!(h.has_flow_call("F", "G"));
    }

    #[test]
    fn string_literal() {
        let w = ws("class A { void F() { string q = \"SELECT id FROM t\"; } }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("class A { int userId; void F() { userId = 42; } }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("F", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_csharp::CSharpAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/M.cs".to_string(),
            Arc::<str>::from("class M { static void Main() { H.Worker(); } }"),
        );
        w.vfs().write(
            "/w/H.cs".to_string(),
            Arc::<str>::from("class H { public static void Worker() {} }"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("Main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "Worker"));
    }
}

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

mod php {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(Arc::new(bonsai_lang_php::PhpAdapter::new()), &[("/w/a.php", src)])
    }

    #[test]
    fn function_and_string_literal() {
        let w = ws("<?php\nfunction run_admin() { $q = \"SELECT * FROM u\"; return $q; }");
        let h = query_hits(&w, "run_admin");
        assert!(h.has_decl("run_admin"));
        let h2 = query_hits(&w, "SELECT");
        assert!(h2.has_string_containing("SELECT"));
    }

    #[test]
    fn direct_call() {
        let w = ws("<?php\nfunction f() { g(); }\nfunction g() {}\n");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn qualified_method_call() {
        let w = ws("<?php\nfunction f($svc) { $svc->run(); }");
        let h = query_hits(&w, "run");
        assert!(h.has_flow_call("f", "run"), "{h:?}");
    }

    #[test]
    fn assignment_var() {
        let w = ws("<?php\nfunction f() { $user_id = 42; return $user_id; }");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.php".to_string(),
            Arc::<str>::from("<?php\nfunction main() { worker(); }"),
        );
        w.vfs().write(
            "/w/w.php".to_string(),
            Arc::<str>::from("<?php\nfunction worker() {}"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }

    #[test]
    fn php8_attribute_as_decorator() {
        let w = ws("<?php\n#[Deprecated]\nfunction f() {}\n");
        let h = query_hits(&w, "Deprecated");
        assert!(h.has_decorator("Deprecated"), "expected #[Deprecated]: {h:?}");
    }
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

mod ruby {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            &[("/w/a.rb", src)],
        )
    }

    #[test]
    fn def_and_qualified_method_call() {
        let w = ws("def f(arr)\n  arr.each { |x| puts(x) }\nend\n");
        let h = query_hits(&w, "arr.each");
        assert!(h.has_flow_call("f", "arr.each"), "{h:?}");
    }

    #[test]
    fn class_decl() {
        let w = ws("class Widget\nend\n");
        let h = query_hits(&w, "Widget");
        assert!(h.has_decl("Widget"));
    }

    #[test]
    fn direct_call_with_parens() {
        let w = ws("def f\n  g()\nend\ndef g\nend\n");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn string_literal() {
        let w = ws("def f\n  q = \"SELECT id FROM t\"\nend\n");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("def f\n  user_id = 42\n  user_id\nend\n");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_ruby::RubyAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.rb".to_string(),
            Arc::<str>::from("def main\n  worker()\nend\n"),
        );
        w.vfs().write(
            "/w/w.rb".to_string(),
            Arc::<str>::from("def worker\n  puts 1\nend\n"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Perl
// ---------------------------------------------------------------------------

mod perl {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            &[("/w/a.pl", src)],
        )
    }

    #[test]
    fn sub_and_call() {
        let w = ws("sub run_admin { exec_cmd(); }\nsub exec_cmd { }\n");
        let h = query_hits(&w, "run_admin");
        assert!(h.has_decl("run_admin"));
        let h2 = query_hits(&w, "exec_cmd");
        assert!(h2.has_flow_call("run_admin", "exec_cmd"), "{h2:?}");
    }

    #[test]
    fn qualified_call() {
        let w = ws("sub f { Module::run(); }\n");
        let h = query_hits(&w, "run");
        assert!(h.has_flow_call("f", "run"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("sub f { my $q = \"SELECT id FROM t\"; return $q; }\n");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_perl::PerlAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.pl".to_string(),
            Arc::<str>::from("sub main { worker(); }\n"),
        );
        w.vfs()
            .write("/w/w.pl".to_string(), Arc::<str>::from("sub worker { }\n"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }

    #[test]
    fn my_binding_as_var() {
        // Perl's `my $x = ...` parses as an assignment_expression whose
        // `left` is a variable_declaration; the target text contains the
        // sigil + name, so fuzzy-substring matching on the bare name hits.
        let w = ws("sub f { my $user_id = 42; return $user_id; }\n");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }
}

// ---------------------------------------------------------------------------
// Dart
// ---------------------------------------------------------------------------

mod dart {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_dart::DartAdapter::new()),
            &[("/w/a.dart", src)],
        )
    }

    #[test]
    fn function_and_class() {
        let w = ws("class Widget { }\nvoid run() {}");
        let h = query_hits(&w, "Widget");
        assert!(h.has_decl("Widget"));
        let h2 = query_hits(&w, "run");
        assert!(h2.has_decl("run"));
    }

    #[test]
    fn direct_call() {
        let w = ws("void f() { g(); }\nvoid g() {}");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"), "{h:?}");
    }

    #[test]
    fn member_call() {
        let w = ws("void f(List<int> xs) { xs.add(1); }");
        let h = query_hits(&w, "xs.add");
        assert!(h.has_flow_call("f", "xs.add"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("void f() { var q = \"SELECT id FROM t\"; }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("void f() { var userId = 42; }");
        let h = query_hits(&w, "userId");
        assert!(h.has_flow_assign("f", "userId"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_dart::DartAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.dart".to_string(),
            Arc::<str>::from("void main() { worker(); }"),
        );
        w.vfs()
            .write("/w/w.dart".to_string(), Arc::<str>::from("void worker() {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Objective-C
// ---------------------------------------------------------------------------

mod objc {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(Arc::new(bonsai_lang_objc::ObjCAdapter::new()), &[("/w/a.m", src)])
    }

    #[test]
    fn function_definition() {
        let w = ws("void runAdmin(NSString *token) { NSLog(@\"%@\", token); }");
        let h = query_hits(&w, "runAdmin");
        assert!(h.has_decl("runAdmin"));
    }

    #[test]
    fn bracket_message_send() {
        let w = ws("void f(NSMutableArray *a) { [a addObject:@\"x\"]; }");
        let h = query_hits(&w, "addObject");
        assert!(!h.flow_calls.is_empty(), "{h:?}");
    }

    #[test]
    fn nslog_call() {
        let w = ws("void f(void) { NSLog(@\"hi\"); }");
        let h = query_hits(&w, "NSLog");
        assert!(h.has_flow_call("f", "NSLog"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("void f(void) { NSString *q = @\"SELECT id FROM t\"; (void)q; }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn assignment_var() {
        let w = ws("void f(void) { int user_id = 42; (void)user_id; }");
        let h = query_hits(&w, "user_id");
        assert!(h.has_flow_assign("f", "user_id"), "{h:?}");
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_objc::ObjCAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.m".to_string(),
            Arc::<str>::from("extern void worker(void);\nint main(void) { worker(); return 0; }"),
        );
        w.vfs()
            .write("/w/w.m".to_string(), Arc::<str>::from("void worker(void) {}"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Lua
// ---------------------------------------------------------------------------

mod lua {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(Arc::new(bonsai_lang_lua::LuaAdapter::new()), &[("/w/a.lua", src)])
    }

    #[test]
    fn function_declaration() {
        let w = ws("function runAdmin(t) os.execute(t) end");
        let h = query_hits(&w, "runAdmin");
        assert!(h.has_decl("runAdmin"));
    }

    #[test]
    fn direct_call() {
        let w = ws("function f() g() end\nfunction g() end");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn qualified_call() {
        let w = ws("function f() os.execute('x') end");
        let h = query_hits(&w, "os.execute");
        assert!(h.has_flow_call("f", "os.execute"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("function f() local q = \"SELECT id FROM t\"; return q end");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_lua::LuaAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.lua".to_string(),
            Arc::<str>::from("function main() worker() end"),
        );
        w.vfs()
            .write("/w/w.lua".to_string(), Arc::<str>::from("function worker() end"));
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Elixir
// ---------------------------------------------------------------------------

mod elixir {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
            &[("/w/a.ex", src)],
        )
    }

    #[test]
    fn def_and_defp() {
        let w = ws("defmodule A do\ndef foo, do: :ok\ndefp bar, do: :ok\nend");
        let h = query_hits(&w, "foo");
        assert!(h.has_decl("foo"));
        let h2 = query_hits(&w, "bar");
        assert!(h2.has_decl("bar"));
    }

    #[test]
    fn direct_call() {
        let w = ws("defmodule A do\ndef f do\n  g()\nend\ndef g do\n  :ok\nend\nend");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"), "{h:?}");
    }

    #[test]
    fn module_qualified_call() {
        let w = ws("defmodule A do\ndef f do\n  IO.puts(\"x\")\nend\nend");
        let h = query_hits(&w, "IO.puts");
        assert!(h.has_flow_call("f", "IO.puts"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("defmodule A do\ndef f do\n  q = \"SELECT id FROM t\"\n  q\nend\nend");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_elixir::ElixirAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.ex".to_string(),
            Arc::<str>::from("defmodule M do\ndef main do\n  W.worker()\nend\nend\n"),
        );
        w.vfs().write(
            "/w/w.ex".to_string(),
            Arc::<str>::from("defmodule W do\ndef worker do\n  :ok\nend\nend\n"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}

// ---------------------------------------------------------------------------
// Erlang
// ---------------------------------------------------------------------------

mod erlang {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
            &[("/w/a.erl", src)],
        )
    }

    #[test]
    fn function_clause() {
        let w = ws("-module(a).\n-export([run_admin/0]).\nrun_admin() -> ok.\n");
        let h = query_hits(&w, "run_admin");
        assert!(h.has_decl("run_admin"));
    }

    #[test]
    fn direct_call() {
        let w = ws("-module(a).\nf() -> g().\ng() -> ok.\n");
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn module_qualified_call() {
        let w = ws("-module(a).\nf() -> io:format(\"x\").\n");
        let h = query_hits(&w, "io:format");
        assert!(h.has_flow_call("f", "io:format"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("-module(a).\nf() -> Q = \"SELECT id FROM t\", Q.\n");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_erlang::ErlangAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.erl".to_string(),
            Arc::<str>::from("-module(main).\nmain() -> worker:run().\n"),
        );
        w.vfs().write(
            "/w/worker.erl".to_string(),
            Arc::<str>::from("-module(worker).\n-export([run/0]).\nrun() -> ok.\n"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "run"));
    }
}

// ---------------------------------------------------------------------------
// Solidity
// ---------------------------------------------------------------------------

mod solidity {
    use super::*;

    fn ws(src: &str) -> Workspace {
        ws_multi(
            Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
            &[("/w/a.sol", src)],
        )
    }

    #[test]
    fn function_and_contract() {
        let w = ws("pragma solidity ^0.8.0;\ncontract Widget { function run() public {} }");
        let h = query_hits(&w, "run");
        assert!(h.has_decl("run"));
    }

    #[test]
    fn direct_call() {
        let w = ws(
            "pragma solidity ^0.8.0;\ncontract A { function f() public { g(); } function g() internal {} }",
        );
        let h = query_hits(&w, "g");
        assert!(h.has_flow_call("f", "g"));
    }

    #[test]
    fn member_call() {
        let w = ws("pragma solidity ^0.8.0;\ncontract A { function f(address x) public { x.call(\"\"); } }");
        let h = query_hits(&w, "x.call");
        assert!(h.has_flow_call("f", "x.call"), "{h:?}");
    }

    #[test]
    fn string_literal() {
        let w = ws("pragma solidity ^0.8.0;\ncontract A { function f() public pure returns (string memory) { return \"SELECT id FROM t\"; } }");
        let h = query_hits(&w, "SELECT");
        assert!(h.has_string_containing("SELECT"));
    }

    #[test]
    fn cross_file_flow() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_solidity::SolidityAdapter::new()));
        let w = Workspace::new(registry);
        w.vfs().write(
            "/w/main.sol".to_string(),
            Arc::<str>::from("pragma solidity ^0.8.0;\nimport \"./w.sol\";\ncontract M { function main() public { W.worker(); } }"),
        );
        w.vfs().write(
            "/w/w.sol".to_string(),
            Arc::<str>::from("pragma solidity ^0.8.0;\ncontract W { function worker() public pure {} }"),
        );
        for f in w.vfs().all_files() {
            let _ = w.db().decl_index(f);
        }
        let t = w.trace_from("main").expect("trace");
        assert!(t.steps.iter().any(|s| s.function == "worker"));
    }
}
