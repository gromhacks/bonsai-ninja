//! Flow-event extraction behavior that the inspect / export / trace
//! commands all depend on. Tests run across multiple languages to ensure
//! the grammar-driven walker produces consistent facts regardless of
//! syntax.

use bonsai_lang_api::{AdapterArc, CallKind, DeclKind, FlowEvent, LanguageRegistry, RefKind};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn ws_with(adapter: AdapterArc, files: &[(&str, &str)]) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    for (path, text) in files {
        ws.vfs().write((*path).to_string(), Arc::<str>::from(*text));
    }
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

fn call_names_in_fn(ws: &Workspace, fn_name: &str) -> Vec<String> {
    let global = ws.db().global_index();
    let mut out = Vec::new();
    for file in global.all_files() {
        for d in global.decls_in(file) {
            if d.name == fn_name {
                walk(&d.flow_events, &mut out);
            }
        }
    }
    out
}

fn walk(events: &[FlowEvent], out: &mut Vec<String>) {
    for e in events {
        match e {
            FlowEvent::Call { name, .. } => out.push(name.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk(then_events, out);
                walk(else_events, out);
            }
            FlowEvent::Loop { body, .. } => walk(body, out),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Qualified-call preservation
// ---------------------------------------------------------------------------

#[test]
fn python_preserves_qualified_call_names() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[("/w/a.py", "def f():\n    os.system('x')\n    jwt.decode(t)\n")],
    );
    let calls = call_names_in_fn(&ws, "f");
    assert!(
        calls.iter().any(|c| c == "os.system"),
        "expected os.system in {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "jwt.decode"),
        "expected jwt.decode in {calls:?}"
    );
}

#[test]
fn javascript_preserves_dotted_calls() {
    let ws = ws_with(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        &[(
            "/w/a.js",
            "function f() { console.log('x'); child_process.exec(cmd); }",
        )],
    );
    let calls = call_names_in_fn(&ws, "f");
    assert!(calls.iter().any(|c| c.contains("console.log")), "got {calls:?}");
    assert!(
        calls.iter().any(|c| c.contains("child_process.exec")),
        "got {calls:?}"
    );
}

#[test]
fn rust_preserves_path_calls() {
    let ws = ws_with(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[(
            "/w/a.rs",
            "fn f() { std::process::Command::new(\"x\"); std::fs::read_to_string(p); }",
        )],
    );
    let calls = call_names_in_fn(&ws, "f");
    assert!(
        calls.iter().any(|c| c.contains("read_to_string")),
        "got {calls:?}"
    );
}

#[test]
fn java_preserves_method_chains() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[(
            "/w/A.java",
            "class A { void f() { Runtime.getRuntime().exec(cmd); Files.write(path); } }",
        )],
    );
    let calls = call_names_in_fn(&ws, "f");
    // Java's method_invocation picks the rightmost name so chain syntax
    // like `Runtime.getRuntime()` surfaces as either the full text or the
    // rightmost method.
    assert!(!calls.is_empty(), "no calls extracted: {calls:?}");
    assert!(
        calls.iter().any(|c| c.contains("exec") || c.contains("write")),
        "got {calls:?}"
    );
}

#[test]
fn java_and_scala_constructor_expressions_emit_constructor_calls() {
    let java = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[(
            "/w/A.java",
            "class A { void f(String input) { new File(input); } } class File { File(Object... args) {} }",
        )],
    );
    let scala = ws_with(
        Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        &[(
            "/w/A.scala",
            "object A { def f(input: String): Unit = { new File(input) } } class File(args: Any*)",
        )],
    );

    for (label, ws) in [("java", java), ("scala", scala)] {
        let global = ws.db().global_index();
        let decl = global
            .find_by_name("f")
            .iter()
            .find_map(|s| global.decl_of(*s).cloned())
            .unwrap_or_else(|| panic!("{label}: f found"));
        let ok = decl.flow_events.iter().any(|e| {
            matches!(
                e,
                FlowEvent::Call {
                    name,
                    call_kind: CallKind::Constructor,
                    ..
                } if name == "File"
            )
        });
        assert!(
            ok,
            "{label}: expected File constructor call in {:?}",
            decl.flow_events
        );
    }
}

// ---------------------------------------------------------------------------
// Control-flow structure: branches, loops, assigns
// ---------------------------------------------------------------------------

#[test]
fn python_branch_events_emitted() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/a.py",
            "def f(x):\n    if x > 0:\n        g()\n    else:\n        h()\n",
        )],
    );
    let global = ws.db().global_index();
    let decl = global
        .find_by_name("f")
        .iter()
        .find_map(|s| global.decl_of(*s).cloned())
        .expect("f found");
    let has_branch = decl
        .flow_events
        .iter()
        .any(|e| matches!(e, FlowEvent::Branch { .. }));
    assert!(has_branch, "expected a Branch event in {:?}", decl.flow_events);
}

#[test]
fn rust_loop_events_emitted() {
    let ws = ws_with(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[("/w/a.rs", "fn f() { for i in 0..10 { g(i); } }")],
    );
    let global = ws.db().global_index();
    let decl = global
        .find_by_name("f")
        .iter()
        .find_map(|s| global.decl_of(*s).cloned())
        .expect("f found");
    let has_loop = decl
        .flow_events
        .iter()
        .any(|e| matches!(e, FlowEvent::Loop { .. }));
    assert!(has_loop, "expected Loop in {:?}", decl.flow_events);
}

#[test]
fn python_assign_events_record_source_name() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[("/w/a.py", "def f():\n    cb = existing\n    run(cb)\n")],
    );
    let global = ws.db().global_index();
    let decl = global
        .find_by_name("f")
        .iter()
        .find_map(|s| global.decl_of(*s).cloned())
        .expect("f found");
    let ok = decl.flow_events.iter().any(|e| {
        matches!(
            e,
            FlowEvent::Assign { target, source_name: Some(src), ..  }
                if target == "cb" && src == "existing"
        )
    });
    assert!(ok, "expected cb=existing Assign in {:?}", decl.flow_events);
}

// ---------------------------------------------------------------------------
// Decorator / annotation extraction
// ---------------------------------------------------------------------------

#[test]
fn python_decorator_is_extracted_as_ref() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[("/w/a.py", "@audited\ndef f(): pass\n")],
    );
    let global = ws.db().global_index();
    let mut hit = false;
    for file in global.all_files() {
        let idx = global.file_index(file).expect("idx");
        for r in &idx.refs {
            if r.kind == RefKind::Decorator && r.name.contains("audited") {
                hit = true;
            }
        }
    }
    assert!(hit, "expected decorator @audited to be extracted as a ref");
}

#[test]
fn java_annotation_is_extracted_as_decorator_ref() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[("/w/A.java", "class A { @Deprecated void f() {} }")],
    );
    let global = ws.db().global_index();
    let mut hit = false;
    for file in global.all_files() {
        let idx = global.file_index(file).expect("idx");
        for r in &idx.refs {
            if r.kind == RefKind::Decorator && r.name.contains("Deprecated") {
                hit = true;
            }
        }
    }
    assert!(hit, "expected @Deprecated annotation to be extracted");
}

// ---------------------------------------------------------------------------
// String classification
// ---------------------------------------------------------------------------

#[test]
fn python_strings_are_classified() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/a.py",
            "def f():\n    q = \"SELECT * FROM users\"\n    u = \"https://example.com\"\n    p = \"/etc/passwd\"\n",
        )],
    );
    let global = ws.db().global_index();
    let mut cats: Vec<String> = Vec::new();
    for file in global.all_files() {
        let idx = global.file_index(file).expect("idx");
        for s in &idx.strings {
            cats.push(format!("{:?}", s.category).to_lowercase());
        }
    }
    assert!(cats.contains(&"sql".to_string()), "no SQL: {cats:?}");
    assert!(cats.contains(&"url".to_string()), "no URL: {cats:?}");
}

// ---------------------------------------------------------------------------
// Class + constructor routing for lookup_function
// ---------------------------------------------------------------------------

#[test]
fn class_name_routes_to_constructor_for_lookup() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/a.py",
            "class Widget:\n    def __init__(self, x):\n        self.x = x\n\ndef main():\n    Widget(1)\n",
        )],
    );
    // Inspecting "Widget" should resolve to its __init__ via
    // Workspace::lookup_function (Class → Constructor routing).
    let found = ws.lookup_function("Widget");
    assert!(
        found.is_some(),
        "expected lookup_function(Widget) to route to __init__"
    );
}

#[test]
fn class_name_lookup_rejects_duplicate_constructor_candidates() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/a.py",
            "class Widget:\n    def __init__(self):\n        pass\n    def __init__(self, x):\n        self.x = x\n",
        )],
    );
    assert!(
        ws.lookup_function("Widget").is_none(),
        "class-name constructor routing must not choose one duplicate/overloaded constructor arbitrarily"
    );
}

// ---------------------------------------------------------------------------
// Params are captured for callback resolution
// ---------------------------------------------------------------------------

#[test]
fn params_captured_for_higher_order_resolution() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/a.py",
            "def driver(cb):\n    cb(1)\n\ndef target(x):\n    pass\n\ndef main():\n    driver(target)\n",
        )],
    );
    let global = ws.db().global_index();
    let driver = global
        .find_by_name("driver")
        .iter()
        .find_map(|s| global.decl_of(*s).cloned())
        .expect("driver found");
    assert_eq!(driver.params, vec!["cb".to_string()], "params captured");
}

#[test]
fn go_repeated_parameter_names_share_type_but_not_slot() {
    let ws = ws_with(
        Arc::new(bonsai_lang_go::GoAdapter::new()),
        &[(
            "/w/a.go",
            "package main\nfunc makeJoiner() func(string, string) string { return func(acc, tok string) string { return tok } }\n",
        )],
    );
    let global = ws.db().global_index();
    let lambda = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name.starts_with("<lambda@"))
        .cloned()
        .expect("go function literal should be indexed");
    assert_eq!(
        lambda.params,
        vec!["acc".to_string(), "tok".to_string()],
        "Go grouped params `acc, tok string` must produce one slot per name"
    );
}

// ---------------------------------------------------------------------------
// Regression: multiple chains per target
// ---------------------------------------------------------------------------

#[test]
fn multiple_paths_to_same_sink_produce_distinct_chains() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/a.py",
            "def sink(): pass\n\
             def a(): sink()\n\
             def b(): sink()\n\
             def main():\n    a()\n    b()\n",
        )],
    );
    // Walk trace from main; it should reach sink via both a() and b().
    let trace = ws.trace_from("main").expect("trace main");
    let sink_calls = trace
        .steps
        .iter()
        .filter(|s| s.message.contains("Call sink"))
        .count();
    assert!(
        sink_calls >= 2,
        "expected at least 2 Call sink steps, got {sink_calls}"
    );
}

// ---------------------------------------------------------------------------
// All 14 adapters extract at least function decls + at least one call
// ---------------------------------------------------------------------------

#[test]
fn every_language_extracts_calls() {
    struct Case {
        lang: &'static str,
        adapter: AdapterArc,
        path: &'static str,
        src: &'static str,
        fn_name: &'static str,
    }
    let cases: Vec<Case> = vec![
        Case {
            lang: "python",
            adapter: Arc::new(bonsai_lang_python::PythonAdapter::new()),
            path: "/w/a.py",
            src: "def f():\n    g()\n",
            fn_name: "f",
        },
        Case {
            lang: "javascript",
            adapter: Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
            path: "/w/a.js",
            src: "function f() { g(); }",
            fn_name: "f",
        },
        Case {
            lang: "typescript",
            adapter: Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
            path: "/w/a.ts",
            src: "function f(): void { g(); }",
            fn_name: "f",
        },
        Case {
            lang: "rust",
            adapter: Arc::new(bonsai_lang_rust::RustAdapter::new()),
            path: "/w/a.rs",
            src: "fn f() { g(); }",
            fn_name: "f",
        },
        Case {
            lang: "go",
            adapter: Arc::new(bonsai_lang_go::GoAdapter::new()),
            path: "/w/a.go",
            src: "package m\nfunc f() { g() }\n",
            fn_name: "f",
        },
        Case {
            lang: "java",
            adapter: Arc::new(bonsai_lang_java::JavaAdapter::new()),
            path: "/w/A.java",
            src: "class A { void f() { g(); } void g() {} }",
            fn_name: "f",
        },
        Case {
            lang: "kotlin",
            adapter: Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
            path: "/w/A.kt",
            src: "fun f() { g() }\nfun g() {}",
            fn_name: "f",
        },
        Case {
            lang: "scala",
            adapter: Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
            path: "/w/A.scala",
            src: "object A { def f(): Unit = g(); def g(): Unit = () }",
            fn_name: "f",
        },
        Case {
            lang: "swift",
            adapter: Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
            path: "/w/A.swift",
            src: "func f() { g() }\nfunc g() {}",
            fn_name: "f",
        },
        Case {
            lang: "c",
            adapter: Arc::new(bonsai_lang_c::CAdapter::new()),
            path: "/w/a.c",
            src: "void g(void);\nvoid f(void) { g(); }",
            fn_name: "f",
        },
        Case {
            lang: "cpp",
            adapter: Arc::new(bonsai_lang_cpp::CppAdapter::new()),
            path: "/w/a.cpp",
            src: "void g();\nvoid f() { g(); }",
            fn_name: "f",
        },
        Case {
            lang: "csharp",
            adapter: Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
            path: "/w/A.cs",
            src: "class A { void F() { G(); } void G() {} }",
            fn_name: "F",
        },
        Case {
            lang: "php",
            adapter: Arc::new(bonsai_lang_php::PhpAdapter::new()),
            path: "/w/a.php",
            src: "<?php function f() { g(); } function g() {}",
            fn_name: "f",
        },
        Case {
            lang: "perl",
            adapter: Arc::new(bonsai_lang_perl::PerlAdapter::new()),
            path: "/w/a.pl",
            src: "sub f { g(); }\nsub g { }",
            fn_name: "f",
        },
        Case {
            lang: "ruby",
            adapter: Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
            path: "/w/a.rb",
            src: "def f\n  g()\nend\ndef g\nend\n",
            fn_name: "f",
        },
    ];
    for case in cases {
        let ws = ws_with(case.adapter, &[(case.path, case.src)]);
        let calls = call_names_in_fn(&ws, case.fn_name);
        assert!(
            calls
                .iter()
                .any(|c| c == "g" || c.ends_with('g') || c == "G" || c.ends_with('G')),
            "{}: expected a call to g/G inside {}, got {:?}",
            case.lang,
            case.fn_name,
            calls
        );

        // Also ensure the decl_kind for the function is set.
        let global = ws.db().global_index();
        let d = global
            .find_by_name(case.fn_name)
            .iter()
            .filter_map(|s| global.decl_of(*s).cloned())
            .find(|d| {
                matches!(
                    d.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
            });
        assert!(
            d.is_some(),
            "{}: no function/method decl for {}",
            case.lang,
            case.fn_name
        );
    }
}
