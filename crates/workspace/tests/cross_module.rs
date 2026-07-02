//! Cross-file / cross-module trace integration tests.
//!
//! These are the tests that prove the analyzer does what the README
//! promises: simulate execution flow across files for every supported
//! language, statically. Each language gets a 2- or 3-file fixture and we
//! assert the trace visits the callee in a *different* file.

use bonsai_callgraph::{collect_callable_targets, EdgeKind};
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_trace::TraceStepKind;
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn ws_with(adapter: AdapterArc, files: &[(&str, &str)]) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    for (path, text) in files {
        ws.vfs().write((*path).to_string(), Arc::<str>::from(*text));
    }
    // Prime the global index.
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

fn assert_cross_file_trace(ws: &Workspace, entry: &str, callee: &str, expected_file_fragment: &str) {
    let trace = ws
        .trace_from(entry)
        .unwrap_or_else(|e| panic!("trace_from({entry}) failed: {e:?}"));
    // The trace must contain a Call step to `callee`, followed by an
    // EnterFunction step whose file is in a different file from entry's.
    let call_idx = trace
        .steps
        .iter()
        .position(|s| s.kind == TraceStepKind::Call && s.message.contains(callee))
        .unwrap_or_else(|| {
            panic!(
                "no Call step matching {callee}; steps={:#?}",
                trace
                    .steps
                    .iter()
                    .map(|s| (s.kind, s.message.clone(), s.file.clone()))
                    .collect::<Vec<_>>()
            )
        });
    let enter_idx = trace
        .steps
        .iter()
        .skip(call_idx + 1)
        .position(|s| s.kind == TraceStepKind::EnterFunction)
        .unwrap_or_else(|| {
            panic!(
                "no EnterFunction after Call {callee}; steps={:#?}",
                trace
                    .steps
                    .iter()
                    .map(|s| (s.kind, s.message.clone(), s.file.clone()))
                    .collect::<Vec<_>>()
            )
        })
        + call_idx
        + 1;
    let entered_file = &trace.steps[enter_idx].file;
    assert!(
        entered_file.contains(expected_file_fragment),
        "expected cross-file entry in {expected_file_fragment}, got {entered_file}"
    );
}

fn assert_unresolved_call_marked_incomplete(ws: &Workspace, entry: &str, call_name: &str) {
    let trace = ws
        .trace_from(entry)
        .unwrap_or_else(|e| panic!("trace_from({entry}) failed: {e:?}"));
    let diagnostic_step = trace
        .steps
        .iter()
        .find(|s| s.kind == TraceStepKind::Diagnostic && s.message.contains(call_name))
        .unwrap_or_else(|| {
            panic!(
                "trace should render unresolved call {call_name} as diagnostic metadata; steps={:#?}",
                trace.steps
            )
        });
    assert_eq!(
        diagnostic_step.precision,
        bonsai_common::Precision::Exact,
        "unresolved call diagnostics are exact metadata, not call-flow evidence; step={diagnostic_step:#?}"
    );
    assert!(
        !trace
            .steps
            .iter()
            .any(|s| s.kind == TraceStepKind::Call && s.message.contains(call_name)),
        "unresolved calls must not be emitted as call evidence; steps={:#?}",
        trace.steps
    );
    assert!(
        !trace.steps.iter().any(|s| {
            s.kind == TraceStepKind::EnterFunction
                && s.message
                    .contains(call_name.rsplit('.').next().unwrap_or(call_name))
                && s.function != entry
        }),
        "unresolved call must not be expanded to a broad callee; steps={:#?}",
        trace.steps
    );
    assert!(
        !trace.summary.analysis_complete,
        "unresolved call must mark trace incomplete; summary={:#?}",
        trace.summary
    );
    let expected = format!("unresolved-call:{call_name}");
    assert!(
        trace
            .summary
            .analysis_incomplete_reasons
            .iter()
            .any(|reason| reason == &expected),
        "trace should explain unresolved call {call_name}; summary={:#?}",
        trace.summary
    );
    assert!(
        trace.summary.truncation_reasons.is_empty(),
        "unresolved calls are semantic incompleteness, not budget truncation; summary={:#?}",
        trace.summary
    );
    assert!(
        trace
            .paths
            .iter()
            .all(|path| !matches!(path.terminated_by, bonsai_trace::PathTermination::DepthLimit)),
        "unresolved calls must not masquerade as depth limits; paths={:#?}",
        trace.paths
    );
}

#[test]
fn rust_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[
            ("/w/main.rs", "mod worker;\nfn main() { worker::helper(); }"),
            ("/w/worker.rs", "pub fn helper() {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "helper", "worker.rs");
}

#[test]
fn python_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[
            (
                "/w/app.py",
                "from worker import worker\n\ndef main():\n    worker()\n",
            ),
            ("/w/worker.py", "def worker():\n    pass\n"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "worker.py");
}

#[test]
fn python_trace_assignment_steps_preserve_source_evidence_and_exit_header_span() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/app.py",
            concat!(
                "def entry():\n",
                "    token = request.args.get(\"token\")\n",
                "    cursor = conn.cursor()\n",
                "    return token\n",
            ),
        )],
    );

    let trace = ws.trace_from("entry").expect("trace_from entry");
    let token_assigns: Vec<_> = trace
        .steps
        .iter()
        .filter(|step| step.kind == TraceStepKind::Assign && step.message.starts_with("Assign token"))
        .map(|step| step.message.as_str())
        .collect();
    assert!(
        token_assigns.contains(&"Assign token = request.args.get(\"token\")"),
        "call-result assignment must name its RHS call; assigns={token_assigns:#?}"
    );
    assert!(
        token_assigns.contains(&"Assign token = request.args.token"),
        "projected source assignment must stay distinguishable; assigns={token_assigns:#?}"
    );
    assert!(
        trace.steps.iter().any(|step| {
            step.kind == TraceStepKind::Assign && step.message == "Assign cursor = conn.cursor()"
        }),
        "no-arg call assignments must render with parentheses; steps={:#?}",
        trace.steps
    );

    let exit = trace
        .steps
        .iter()
        .find(|step| step.kind == TraceStepKind::Return && step.message == "Exit entry")
        .unwrap_or_else(|| panic!("missing synthetic Exit entry step; steps={:#?}", trace.steps));
    assert_eq!(
        exit.span.start_line, 1,
        "synthetic function exit should point at the function header, not the first body line"
    );
    assert_eq!(exit.code.trim(), "def entry():");
}

#[test]
fn javascript_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        &[
            (
                "/w/app.js",
                "import { worker } from './w.js';\nfunction main() { worker(); }",
            ),
            ("/w/w.js", "export function worker() {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.js");
}

#[test]
fn javascript_receiver_callback_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        &[(
            "/w/app.js",
            "function entry(items) { items.forEach(cb); }\n\
             function cb(item) { sink(item); }\n\
             function sink(x) {}\n",
        )],
    );
    let trace = ws.trace_from("entry").expect("trace_from entry");
    let global = ws.db().global_index();
    let entry = collect_callable_targets(&global, "entry")[0];
    let cb = collect_callable_targets(&global, "cb")[0];
    let graph = ws.resolved_call_graph();
    assert!(
        graph
            .callees_of(entry)
            .any(|edge| edge.to == cb && edge.kind == EdgeKind::Indirect),
        "resolved call graph did not include entry -> cb receiver-callback edge"
    );
    assert!(
        trace
            .steps
            .iter()
            .any(|s| s.kind == TraceStepKind::EnterFunction && s.message.contains("cb")),
        "receiver callback `cb` was not expanded; steps={:#?}",
        trace.steps
    );
    assert!(
        trace
            .steps
            .iter()
            .any(|s| s.kind == TraceStepKind::Call && s.message.contains("sink")),
        "callback body did not reach sink; steps={:#?}",
        trace.steps
    );
}

#[test]
fn java_inherited_receiver_method_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[(
            "/w/App.java",
            "class Base { void sink(String value) { audit(value); } }\n\
             class Child extends Base {}\n\
             class App { void entry(String input) { Child child = new Child(); child.sink(input); } }\n",
        )],
    );
    let trace = ws.trace_from("entry").expect("trace_from entry");
    let global = ws.db().global_index();
    let entry = collect_callable_targets(&global, "entry")[0];
    let sink = collect_callable_targets(&global, "sink")[0];
    let graph = ws.resolved_call_graph();
    assert!(
        graph
            .callees_of(entry)
            .any(|edge| edge.to == sink && edge.kind == EdgeKind::Direct),
        "resolved call graph did not include inherited receiver edge entry -> Base.sink"
    );
    assert!(
        trace
            .steps
            .iter()
            .any(|s| s.kind == TraceStepKind::EnterFunction && s.message.contains("sink")),
        "inherited Base.sink was not expanded from Child receiver; steps={:#?}",
        trace.steps
    );
}

#[test]
fn javascript_imported_export_const_lambda_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        &[
            (
                "/w/app.js",
                "import { flow } from './wrapper.js';\n\
                 function entry(token) { flow(token); }\n",
            ),
            (
                "/w/wrapper.js",
                "export const flow = (value) => { sink(value); };\n\
                 function sink(x) {}\n",
            ),
        ],
    );
    let trace = ws.trace_from("entry").expect("trace_from entry");
    assert!(
        trace
            .steps
            .iter()
            .any(|s| s.kind == TraceStepKind::EnterFunction && s.message.contains("flow")),
        "exported const lambda `flow` was not expanded; steps={:#?}",
        trace.steps
    );
    assert!(
        trace
            .steps
            .iter()
            .any(|s| s.kind == TraceStepKind::Call && s.message.contains("sink")),
        "exported const lambda body did not reach sink; steps={:#?}",
        trace.steps
    );
}

#[test]
fn typescript_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        &[
            (
                "/w/app.ts",
                "import { worker } from './w';\nfunction main(): void { worker(); }",
            ),
            ("/w/w.ts", "export function worker(): void {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.ts");
}

#[test]
fn go_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_go::GoAdapter::new()),
        &[
            ("/w/main.go", "package main\nfunc main() { worker() }\n"),
            ("/w/w.go", "package main\nfunc worker() {}\n"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.go");
}

#[test]
fn java_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[
            (
                "/w/Main.java",
                "public class Main { public static void main() { Helper.worker(); } }",
            ),
            (
                "/w/Helper.java",
                "public class Helper { public static void worker() {} }",
            ),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "Helper.java");
}

#[test]
fn java_receiver_type_dispatch_prefers_service_bean_method() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[
            (
                "/w/Controller.java",
                "public class Controller {\n\
                   private UserService svc;\n\
                   public void handle(String token) { svc.process(token); }\n\
                 }\n",
            ),
            (
                "/w/UserService.java",
                "public class UserService {\n\
                   public void process(String token) { sink(token); }\n\
                   public void sink(String value) {}\n\
                 }\n",
            ),
            (
                "/w/AuditService.java",
                "public class AuditService {\n\
                   public void process(String token) { audit(token); }\n\
                   public void audit(String value) {}\n\
                 }\n",
            ),
        ],
    );
    let trace = ws.trace_from("handle").expect("trace_from handle");
    assert!(
        trace.steps.iter().any(|s| s.kind == TraceStepKind::EnterFunction
            && s.message.contains("process")
            && s.file.ends_with("UserService.java")),
        "receiver-typed service call did not enter UserService.process; steps={:#?}",
        trace.steps
    );
    assert!(
        !trace.steps.iter().any(|s| s.kind == TraceStepKind::EnterFunction
            && s.message.contains("process")
            && s.file.ends_with("AuditService.java")),
        "receiver-typed service call should not dispatch to AuditService.process; steps={:#?}",
        trace.steps
    );
}

#[test]
fn java_receiver_type_dispatch_prefers_caller_package_when_class_names_collide() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[
            (
                "/w/aaa/Service.java",
                "package aaa;\n\
                 class Service {\n\
                   void process(String token) { wrong(token); }\n\
                   void wrong(String value) {}\n\
                 }\n",
            ),
            (
                "/w/app/Controller.java",
                "package app;\n\
                 class Controller {\n\
                   private Service svc;\n\
                   void handle(String token) { svc.process(token); }\n\
                 }\n",
            ),
            (
                "/w/app/Service.java",
                "package app;\n\
                 class Service {\n\
                   void process(String token) { right(token); }\n\
                   void right(String value) {}\n\
                 }\n",
            ),
        ],
    );
    let trace = ws.trace_from("handle").expect("trace_from handle");
    assert!(
        trace.steps.iter().any(|s| {
            s.kind == TraceStepKind::EnterFunction
                && s.message.contains("process")
                && s.file.ends_with("app/Service.java")
        }),
        "receiver dispatch did not enter app.Service.process; steps={:#?}",
        trace.steps
    );
    assert!(
        !trace.steps.iter().any(|s| {
            s.kind == TraceStepKind::EnterFunction
                && s.message.contains("process")
                && s.file.ends_with("aaa/Service.java")
        }),
        "receiver dispatch should not choose lexically-first aaa.Service.process; steps={:#?}",
        trace.steps
    );
}

#[test]
fn java_callgraph_receiver_type_from_constructor_prefers_caller_package() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[
            (
                "/w/aaa/Service.java",
                "package aaa;\n\
                 class Service {\n\
                   void process(String token) { wrong(token); }\n\
                   void wrong(String value) {}\n\
                 }\n",
            ),
            (
                "/w/app/Controller.java",
                "package app;\n\
                 class Controller {\n\
                   void handle(String token) {\n\
                     Service svc = new Service();\n\
                     svc.process(token);\n\
                   }\n\
                 }\n",
            ),
            (
                "/w/app/Service.java",
                "package app;\n\
                 class Service {\n\
                   void process(String token) { right(token); }\n\
                   void right(String value) {}\n\
                 }\n",
            ),
        ],
    );
    let global = ws.db().global_index();
    let handle = collect_callable_targets(&global, "handle")[0];
    let process_in = |suffix: &str| {
        global
            .all_files()
            .flat_map(|file| global.decls_in(file).iter().cloned())
            .find(|decl| {
                decl.name == "process"
                    && global
                        .declaring_file(decl.symbol)
                        .and_then(|file| ws.db().vfs().path(file).ok())
                        .is_some_and(|path| path.to_string_lossy().ends_with(suffix))
            })
            .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
            .unwrap_or_else(|| panic!("missing process in {suffix}"))
    };
    let right = process_in("app/Service.java");
    let wrong = process_in("aaa/Service.java");
    let graph = ws.resolved_call_graph();
    let callees: Vec<_> = graph.callees_of(handle).map(|edge| edge.to).collect();
    assert!(
        callees.contains(&right),
        "callgraph did not resolve svc.process to app.Service.process; callees={callees:?}"
    );
    assert!(
        !callees.contains(&wrong),
        "callgraph should not choose lexically-first aaa.Service.process; callees={callees:?}"
    );
}

#[test]
fn java_super_dispatch_is_shared_by_trace_and_callgraph() {
    let ws = ws_with(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[
            (
                "/w/app/Base.java",
                "package app;\n\
                 class Base {\n\
                   void process(String token) { sink(token); }\n\
                   void sink(String value) {}\n\
                 }\n",
            ),
            (
                "/w/app/Child.java",
                "package app;\n\
                 class Child extends Base {\n\
                   void handle(String token) { super.process(token); }\n\
                 }\n",
            ),
        ],
    );
    let trace = ws.trace_from("handle").expect("trace_from handle");
    assert!(
        trace.steps.iter().any(|step| {
            step.kind == TraceStepKind::EnterFunction
                && step.message.contains("process")
                && step.file.ends_with("Base.java")
        }),
        "trace must dispatch super.process to Base.process; steps={:#?}",
        trace.steps
    );

    let global = ws.db().global_index();
    let handle = collect_callable_targets(&global, "handle")[0];
    let base_process = global
        .all_files()
        .flat_map(|file| global.decls_in(file).iter())
        .find(|decl| {
            decl.name == "process"
                && global
                    .declaring_file(decl.symbol)
                    .and_then(|file| ws.db().vfs().path(file).ok())
                    .is_some_and(|path| path.to_string_lossy().ends_with("Base.java"))
        })
        .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
        .expect("Base.process");
    let graph = ws.resolved_call_graph();
    assert!(
        graph.callees_of(handle).any(|edge| edge.to == base_process),
        "resolved callgraph must include handle -> Base.process"
    );
}

#[test]
fn python_constructor_receiver_dispatch_is_shared_by_trace_and_callgraph() {
    let ws = ws_with(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[(
            "/w/app.py",
            concat!(
                "class Runner:\n",
                "    def execute(self, value):\n",
                "        sink(value)\n",
                "    def sink(self, value):\n",
                "        pass\n",
                "\n",
                "class Loader:\n",
                "    def load(self, value):\n",
                "        runner = Runner()\n",
                "        return runner.execute(value)\n",
                "\n",
                "def load_model(value):\n",
                "    loader = Loader()\n",
                "    return loader.load(value)\n",
            ),
        )],
    );
    let trace = ws.trace_from("load_model").expect("trace_from load_model");
    assert!(
        trace
            .steps
            .iter()
            .any(|step| { step.kind == TraceStepKind::EnterFunction && step.message.contains("execute") }),
        "trace must dispatch loader.load()/runner.execute() through constructor-bound receivers; steps={:#?}",
        trace.steps
    );

    let global = ws.db().global_index();
    let load_model = collect_callable_targets(&global, "load_model")[0];
    let load = global
        .all_files()
        .flat_map(|file| global.decls_in(file).iter())
        .find(|decl| {
            decl.name == "load"
                && decl.parent.is_some_and(|parent| {
                    global
                        .decl_of(parent)
                        .is_some_and(|parent_decl| parent_decl.name == "Loader")
                })
        })
        .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
        .expect("Loader.load");
    let execute = global
        .all_files()
        .flat_map(|file| global.decls_in(file).iter())
        .find(|decl| {
            decl.name == "execute"
                && decl.parent.is_some_and(|parent| {
                    global
                        .decl_of(parent)
                        .is_some_and(|parent_decl| parent_decl.name == "Runner")
                })
        })
        .map(|decl| bonsai_common::FuncId::new(decl.symbol.raw()))
        .expect("Runner.execute");
    let graph = ws.resolved_call_graph();
    assert!(
        graph.callees_of(load_model).any(|edge| edge.to == load),
        "resolved callgraph must include load_model -> Loader.load"
    );
    assert!(
        graph.callees_of(load).any(|edge| edge.to == execute),
        "resolved callgraph must include Loader.load -> Runner.execute"
    );
}

#[test]
fn c_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_c::CAdapter::new()),
        &[
            (
                "/w/main.c",
                "extern void worker(void);\nint main(void) { worker(); return 0; }",
            ),
            ("/w/w.c", "void worker(void) {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.c");
}

#[test]
fn cpp_extern_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        &[
            ("/w/main.cpp", "void worker();\nint main() { worker(); }"),
            ("/w/w.cpp", "void worker() {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.cpp");
}

#[test]
fn csharp_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        &[
            ("/w/Main.cs", "class M { static void Main() { H.Worker(); } }"),
            ("/w/H.cs", "class H { public static void Worker() {} }"),
        ],
    );
    assert_cross_file_trace(&ws, "Main", "Worker", "H.cs");
}

#[test]
fn kotlin_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        &[
            ("/w/Main.kt", "package app\nfun main() { worker() }"),
            ("/w/W.kt", "package app\nfun worker() {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "W.kt");
}

#[test]
fn scala_unresolved_cross_object_trace_is_marked_incomplete() {
    let ws = ws_with(
        Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        &[
            (
                "/w/Main.scala",
                "object Main { def main(args: Array[String]): Unit = worker() }",
            ),
            ("/w/W.scala", "object W { def worker(): Unit = () }"),
        ],
    );
    assert_unresolved_call_marked_incomplete(&ws, "main", "worker");
}

#[test]
fn swift_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        &[
            ("/w/Main.swift", "func main() { worker() }"),
            ("/w/W.swift", "func worker() {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "W.swift");
}

#[test]
fn php_unresolved_cross_file_trace_is_marked_incomplete() {
    let ws = ws_with(
        Arc::new(bonsai_lang_php::PhpAdapter::new()),
        &[
            (
                "/w/main.php",
                "<?php require \"w.php\"; function main() { worker(); }",
            ),
            ("/w/w.php", "<?php function worker() {}"),
        ],
    );
    assert_unresolved_call_marked_incomplete(&ws, "main", "worker");
}

#[test]
fn ruby_require_relative_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        &[
            ("/w/main.rb", "require_relative 'w'\ndef main\n  worker()\nend\n"),
            ("/w/w.rb", "def worker\n  puts 1\nend\n"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.rb");
}

#[test]
fn perl_require_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        &[
            ("/w/main.pl", "require './w.pl';\nsub main { worker(); }"),
            ("/w/w.pl", "sub worker { }"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.pl");
}

#[test]
fn dart_import_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_dart::DartAdapter::new()),
        &[
            ("/w/main.dart", "import 'w.dart';\nvoid main() { worker(); }"),
            ("/w/w.dart", "void worker() {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.dart");
}

#[test]
fn objc_extern_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        &[
            (
                "/w/main.m",
                "extern void worker(void);\nint main(void) { worker(); return 0; }",
            ),
            ("/w/w.m", "void worker(void) {}"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.m");
}

#[test]
fn lua_unresolved_cross_file_trace_is_marked_incomplete() {
    let ws = ws_with(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        &[
            ("/w/main.lua", "dofile('w.lua')\nfunction main() worker() end"),
            ("/w/w.lua", "function worker() end"),
        ],
    );
    assert_unresolved_call_marked_incomplete(&ws, "main", "worker");
}

#[test]
fn elixir_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        &[
            (
                "/w/main.ex",
                "defmodule M do\ndef main do\n  W.worker()\nend\nend\n",
            ),
            ("/w/w.ex", "defmodule W do\ndef worker do\n  :ok\nend\nend\n"),
        ],
    );
    assert_cross_file_trace(&ws, "main", "worker", "w.ex");
}

#[test]
fn erlang_cross_file_trace() {
    let ws = ws_with(
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        &[
            (
                "/w/main.erl",
                "-module(main).\n-export([main/0]).\nmain() -> worker:run().\n",
            ),
            (
                "/w/worker.erl",
                "-module(worker).\n-export([run/0]).\nrun() -> ok.\n",
            ),
        ],
    );
    assert_cross_file_trace(&ws, "main", "run", "worker.erl");
}

#[test]
fn solidity_unresolved_contract_static_call_is_marked_incomplete() {
    let ws = ws_with(
        Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        &[
            (
                "/w/main.sol",
                "pragma solidity ^0.8.0;\nimport \"./w.sol\";\ncontract M { function main() public { W.worker(); } }",
            ),
            (
                "/w/w.sol",
                "pragma solidity ^0.8.0;\ncontract W { function worker() public pure {} }",
            ),
        ],
    );
    assert_unresolved_call_marked_incomplete(&ws, "main", "W.worker");
}
