use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_cpp::CppAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("m.cpp", "int main() { return 0; }")]
    );
}

#[test]
fn qualified_parameter_types_are_preserved_beside_short_dispatch_aliases() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("qualified.cpp"),
        r#"
namespace alpha { struct Packet {}; }
namespace beta { struct Packet {}; }
struct Packet {};
void from_alpha(const alpha::Packet& value) { consume(value); }
void from_beta(const beta::Packet& value) { consume(value); }
void local_only(const Packet& value) { consume(value); }
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let types = |name: &str| {
        index
            .defs
            .iter()
            .find(|decl| decl.name == name)
            .map(|decl| {
                decl.type_aliases
                    .iter()
                    .filter(|alias| alias.name == "value")
                    .map(|alias| alias.type_name.as_str())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| panic!("missing {name}"))
    };

    assert_eq!(types("from_alpha"), ["Packet", "alpha::Packet"]);
    assert_eq!(types("from_beta"), ["Packet", "beta::Packet"]);
    assert_eq!(types("local_only"), ["Packet"]);
}

#[test]
fn complete_literal_return_helpers_fail_closed_on_dynamic_or_fallthrough_paths() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("selectors.cpp"),
        "const char *closed(const char *key) {\n\
           if (key[0] == 'a') return \"alpha\";\n\
           if (key[0] == 'b') return \"beta\";\n\
           return \"fallback\";\n\
         }\n\
         const char *dynamic(const char *key) { if (key[0]) return \"fixed\"; return key; }\n\
         const char *fallthrough(const char *key) { if (key[0]) return \"fixed\"; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let fact_owner = |name: &str| {
        let decl = index.defs.iter().find(|decl| decl.name == name).expect("helper");
        index.finite_literal_selections.iter().any(|fact| {
            decl.span.start <= fact.selection_span.start && fact.selection_span.end <= decl.span.end
        })
    };

    assert!(fact_owner("closed"));
    assert!(!fact_owner("dynamic"));
    assert!(!fact_owner("fallthrough"));
}

#[test]
fn qualified_base_uses_the_current_qualified_identifier_cst() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("qualified.cpp"),
        "namespace outer { class Base {}; }\nclass Child : public outer::Base {};\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let child = index
        .defs
        .iter()
        .find(|decl| decl.name == "Child")
        .expect("qualified derived class declaration");

    assert_eq!(child.bases, ["Base"]);
}

#[test]
fn declared_type_and_binding_may_have_the_same_spelling() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("typed.cpp"),
        "namespace web { struct request { int body; }; }\n\
         void handle(const web::request& request) { auto payload = request.body; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let handle = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handler declaration");

    assert!(handle
        .type_aliases
        .iter()
        .any(|alias| alias.name == "request" && alias.type_name == "request"));
}

#[test]
fn lambda_parameter_types_belong_to_the_lambda_scope_only() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("lambda_types.cpp"),
        r#"
namespace crow { struct request { int body; }; }
void register_route(int req) {
    consume([&](const crow::request& req) {
        auto payload = req.body;
        sink(payload);
    });
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let outer = index
        .defs
        .iter()
        .find(|decl| decl.name == "register_route")
        .expect("outer declaration");
    let callback = index
        .defs
        .iter()
        .find(|decl| decl.span.start > outer.span.start && decl.params == ["req"])
        .expect("lambda declaration");

    assert!(callback
        .type_aliases
        .iter()
        .any(|alias| { alias.name == "req" && alias.type_name == "crow::request" }));
    assert!(
        outer
            .type_aliases
            .iter()
            .all(|alias| alias.name != "req" || alias.type_name != "crow::request"),
        "a nested callback parameter type must not leak into the outer function: {:#?}",
        outer.type_aliases
    );
}

#[test]
fn cpp_call_arguments_use_ast_value_kinds_not_identifier_spelling() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, AssignValueKind, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("values.cpp"),
        "void emit(const char*, const char*, bool, void*);\n\
         void run(const char *USER_VALUE) { emit(\"literal\", USER_VALUE, true, nullptr); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let kind = |argument_index| {
        index
            .call_argument_values
            .iter()
            .find(|fact| fact.argument_index == argument_index)
            .and_then(|fact| fact.value_kind)
    };

    assert_eq!(kind(0), Some(AssignValueKind::Literal));
    assert_eq!(kind(1), None, "ALL_CAPS is still a dynamic parameter");
    assert_eq!(kind(2), Some(AssignValueKind::Literal));
    assert_eq!(kind(3), Some(AssignValueKind::Literal));
}

#[test]
fn stream_extraction_lowers_each_destination_as_an_exact_operator_writeback() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, ArgumentPassingMode, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("stream.cpp"),
        r#"
#include <iostream>
#include <string>

struct Reader {
    Reader& operator>>(std::string& value);
};

struct ValueShifter {
    ValueShifter operator>>(const int& amount) const;
};

enum class Mode { One = 1 };

void read(Reader& input, ValueShifter& shifter, Mode mode, int amount) {
    std::string first, second;
    input >> first >> second;
    int shifted = 8 >> amount;
    int enum_shifted = static_cast<int>(mode) >> amount;
    ValueShifter copied = shifter >> amount;
    std::cin >> first;
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let read = index
        .defs
        .iter()
        .find(|decl| decl.name == "read")
        .expect("read declaration");
    let calls = read
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call {
                name,
                receiver,
                call_kind,
                args,
                ..
            } if name == ">>" => Some((receiver, call_kind, args)),
            _ => None,
        })
        .collect::<Vec<_>>();

    let proven = calls
        .iter()
        .filter(|(receiver, _, _)| receiver.as_deref() == Some("input"))
        .collect::<Vec<_>>();
    assert_eq!(
        proven.len(),
        2,
        "each compiler-proven chained extraction must be retained: {calls:#?}"
    );
    let destinations = proven
        .iter()
        .map(|(_, _, args)| args[0].place.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(destinations, vec![Some("first"), Some("second")]);
    assert!(proven.iter().all(|(_, kind, args)| {
        **kind == bonsai_lang_api::CallKind::Operator
            && args[0].passing_mode == ArgumentPassingMode::WriteBack
    }));

    let unproven = calls
        .iter()
        .filter(|(receiver, _, _)| receiver.as_deref() != Some("input"))
        .collect::<Vec<_>>();
    assert_eq!(
        unproven.len(),
        4,
        "numeric, enum, value-operator, and external-type shifts stay generic: {calls:#?}"
    );
    assert!(unproven.iter().all(|(_, kind, args)| {
        **kind == bonsai_lang_api::CallKind::Operator
            && args.len() == 1
            && args
                .iter()
                .all(|argument| argument.passing_mode == ArgumentPassingMode::Value)
    }));
    let generic_left_operands = unproven
        .iter()
        .filter_map(|(receiver, _, _)| receiver.as_deref())
        .collect::<Vec<_>>();
    assert!(generic_left_operands.contains(&"8"));
    assert!(generic_left_operands
        .iter()
        .any(|operand| operand.contains("mode")));
    assert!(generic_left_operands.contains(&"shifter"));
    assert!(generic_left_operands.contains(&"std::cin"));
}

#[test]
fn reference_declarator_call_result_binds_the_declared_name() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("reference.cpp"),
        r#"
#include <string>

struct Repository {
    const std::string& cmd() const;
};

void execute(const std::string& value);

void run(const Repository& repo) {
    const std::string& c = repo.cmd();
    execute(c);
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: None,
                source_call: Some(source_call),
                source_call_args,
                source_names,
                ..
            } if target == "c"
                && bonsai_common::short_qualified_tail(source_call) == "cmd"
                && source_call_args.is_empty()
                && source_names == &["repo"]
        )),
        "a reference declarator must unwrap to its identifier and retain the exact call-result and receiver binding: {:#?}",
        run.flow_events
    );
    assert!(
        !run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, .. }
                if matches!(target.as_str(), "Repository" | "repo" | "cmd")
        )),
        "type, initializer receiver, and callee identifiers must not become assignment targets: {:#?}",
        run.flow_events
    );
}

#[test]
fn same_type_brace_copy_is_not_lowered_as_one_positional_field() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("copies.cpp"),
        r#"
struct Envelope { int kind; const char* cmd; };

void use(Envelope env, int kind, const char* cmd) {
    Envelope valid{env};
    Envelope built{kind, cmd};
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let use_decl = index
        .defs
        .iter()
        .find(|decl| decl.name == "use")
        .expect("use declaration");

    assert!(use_decl.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign {
            target,
            source_names,
            ..
        } if target == "valid" && source_names == &["env"]
    )));
    assert!(
        !use_decl.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::AggregateAssign { target, .. } if target == "valid"
        )),
        "same-type direct-list initialization copies the complete object: {:#?}",
        use_decl.flow_events
    );
    assert!(
        use_decl.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::AggregateAssign { target, value_flow, .. }
                if target == "built" && value_flow.tuple_items.len() == 2
        )),
        "a real positional aggregate initializer must remain field-precise: {:#?}",
        use_decl.flow_events
    );
}

#[test]
fn template_arguments_do_not_change_callable_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("templates.cpp"),
        r#"
template <typename T> T convert(int value) { return T{value}; }

void use(int value) {
    convert<long>(value);
    ns::factory<Item>(value);
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let use_decl = index
        .defs
        .iter()
        .find(|decl| decl.name == "use")
        .expect("use declaration");
    let calls = use_decl
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(calls.contains(&"convert"), "calls={calls:#?}");
    assert!(calls.contains(&"ns::factory"), "calls={calls:#?}");
    assert!(
        calls
            .iter()
            .all(|name| !name.contains('<') && !name.contains('>')),
        "parsed template arguments select a specialization, not a different declaration identity: {calls:#?}"
    );
}

#[test]
fn private_template_instantiation_refines_generic_receiver_from_exact_type_arguments() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("private_template.cpp"),
        r#"
#include <string>
#include <vector>
using Names = std::vector<std::string>;
template <typename Container>
static Container collect(const std::string& value) {
    Container out;
    out.push_back(value);
    return out;
}
Names use(const std::string& value) { return collect<Names>(value); }
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let collect = index
        .defs
        .iter()
        .find(|decl| decl.name == "collect")
        .expect("collect declaration");
    assert!(
        collect
            .type_aliases
            .iter()
            .any(|alias| { alias.name == "out" && alias.type_name == "std::vector<std::string>" }),
        "the only possible TU-private specialization is an exact compiler type fact: {:#?}",
        collect.type_aliases
    );
    assert_eq!(collect.return_type.as_deref(), Some("std::vector<std::string>"));
}

#[test]
fn mixed_private_template_instantiations_fail_closed() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("mixed_template.cpp"),
        r#"
struct Left { void push_back(int); };
struct Right { void push_back(int); };
template <typename Container>
static Container collect(int value) {
    Container out;
    out.push_back(value);
    return out;
}
Left left(int value) { return collect<Left>(value); }
Right right(int value) { return collect<Right>(value); }
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let collect = index
        .defs
        .iter()
        .find(|decl| decl.name == "collect")
        .expect("collect declaration");
    assert_eq!(collect.return_type.as_deref(), Some("Container"));
    assert!(
        collect
            .type_aliases
            .iter()
            .filter(|alias| alias.name == "out")
            .all(|alias| alias.type_name == "Container"),
        "a shared generic body must not borrow one incompatible instantiation's receiver type: {:#?}",
        collect.type_aliases
    );
}

#[test]
fn structured_binding_retains_each_call_result_position() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{kit::SYNTHETIC_TUPLE_RESULT_PREFIX, AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("structured.cpp"),
        r#"
#include <tuple>
void use(int input) {
    auto [value, size] = std::make_tuple(input, 1);
    consume(value);
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let use_decl = index
        .defs
        .iter()
        .find(|decl| decl.name == "use")
        .expect("use declaration");
    for (target, position) in [("value", 0), ("size", 1)] {
        assert!(
            use_decl.flow_events.iter().any(|event| matches!(
                event,
                FlowEvent::Assign {
                    target: actual,
                    source_call: Some(call),
                    source_names,
                    ..
                } if actual == target
                    && call == "std::make_tuple"
                    && source_names == &[format!("{SYNTHETIC_TUPLE_RESULT_PREFIX}{position}")]
            )),
            "structured binding {target} must retain its parsed tuple position: {:#?}",
            use_decl.flow_events
        );
    }
}

#[test]
fn switch_break_exits_the_switch_without_terminating_the_function() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("switch.cpp"),
        r#"
void use(int input, int kind) {
    int routed = 0;
    switch (kind) {
        case 1: routed = input; break; consume_unreachable(input);
        default: routed = input; break;
    }
    consume_after_switch(routed);
}
"#,
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let use_decl = index
        .defs
        .iter()
        .find(|decl| decl.name == "use")
        .expect("use declaration");
    fn contains_call(events: &[FlowEvent], wanted: &str) -> bool {
        events.iter().any(|event| match event {
            FlowEvent::Call { name, .. } => name == wanted,
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => contains_call(then_events, wanted) || contains_call(else_events, wanted),
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                contains_call(body, wanted)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                contains_call(body, wanted)
                    || contains_call(catch_events, wanted)
                    || contains_call(finally_events, wanted)
            }
            _ => false,
        })
    }
    assert!(contains_call(&use_decl.flow_events, "consume_after_switch"));
    assert!(!contains_call(&use_decl.flow_events, "consume_unreachable"));
}

/// Drift guard for the semantic-identity contract
/// (`docs/contributing/design-patterns.mdx::Semantic Resolution Always`). The C++
/// adapter must:
///
/// - emit `Decl.qualified_name = Some("<file_stem>.<name>")` for
///   every function — never `None`;
/// - emit `Decl.module_path = ["<file_stem>"]`;
/// - mark `static` free functions AND functions inside an anonymous
///   namespace as `Visibility::Private` so the resolver's per-file
///   filter prevents cross-TU collisions.
#[test]
fn cpp_adapter_marks_static_and_anonymous_ns_private() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, Visibility};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("vendor.cpp"),
        "static void error(const char *msg) {}\n\
         namespace { void helper(int x) {} }\n\
         namespace net { namespace transport { void fetch(int x) {} } }\n\
         void exposed(int x) {}\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let by_name = |name: &str| {
        idx.defs
            .iter()
            .find(|d| d.name == name)
            .unwrap_or_else(|| panic!("expected decl {name} present"))
    };

    let error_decl = by_name("error");
    assert_eq!(
        error_decl.qualified_name.as_deref(),
        Some("vendor.error"),
        "qualified_name must be file-stem-prefixed"
    );
    assert_eq!(
        error_decl.module_path.segments,
        vec!["vendor".to_string()],
        "module_path is the file stem when no namespace applies"
    );
    assert!(
        matches!(error_decl.visibility, Visibility::Private),
        "static C++ functions must be Visibility::Private"
    );

    let helper_decl = by_name("helper");
    assert!(
        matches!(helper_decl.visibility, Visibility::Private),
        "anonymous-namespace C++ functions must be Visibility::Private"
    );

    let fetch_decl = by_name("fetch");
    assert_eq!(
        fetch_decl.qualified_name.as_deref(),
        Some("vendor.net.transport.fetch"),
        "named namespace ancestry must remain part of the callable identity"
    );
    assert_eq!(
        fetch_decl.module_path.segments,
        vec!["vendor", "net", "transport"],
        "module path must retain file ownership and exact named namespaces"
    );

    let exposed_decl = by_name("exposed");
    assert!(
        matches!(exposed_decl.visibility, Visibility::Public),
        "non-static, non-anonymous-ns C++ functions are visible"
    );
}

#[test]
fn cpp_adapter_uses_ast_class_identity_for_constructors_and_return_fields() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, DeclKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("model.cpp"),
        "struct Model {\n\
             explicit Model(int value) : value_(value) {}\n\
             const int& value() const { return value_; }\n\
             int value_;\n\
         };\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);

    let constructor = idx
        .defs
        .iter()
        .find(|decl| decl.name == "Model" && decl.params == ["value"])
        .expect("constructor declaration");
    assert_eq!(constructor.kind, DeclKind::Constructor);
    assert!(
        constructor
            .receiver_field_writes
            .iter()
            .any(|write| write.target == "this.value_" && write.source_param_indices == [0]),
        "initializer-list field write must remain an AST fact: {constructor:#?}"
    );

    let accessor = idx
        .defs
        .iter()
        .find(|decl| decl.name == "value" && decl.params.is_empty())
        .expect("accessor declaration");
    assert!(
        accessor.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Return { value_flow, .. }
                if value_flow.place.as_deref() == Some("this.value_")
        )),
        "field return must be lowered from the return-expression CST: {accessor:#?}"
    );
}

#[test]
fn cpp_adapter_lowers_direct_initialization_as_a_constructor_call() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("direct.cpp"),
        "struct Model { explicit Model(int value) {} };\n\
         int build(int value) { Model model(std::move(value)); return 0; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let build = idx
        .defs
        .iter()
        .find(|decl| decl.name == "build")
        .expect("build declaration");
    assert!(
        build.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Model"
                && args.len() == 1
                && args[0].place.is_none()
                && args[0].source_names.iter().any(|source| source == "value")
        )),
        "direct initialization must retain its grammar-owned constructor boundary: {build:#?}"
    );
}

#[test]
fn cpp_adapter_disambiguates_value_direct_initialization_from_local_prototypes() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("direct_ambiguous.cpp"),
        "struct Input {};\n\
         struct Archive { explicit Archive(Input& value) {} };\n\
         int restore(Input& blob) { Input in(blob); Archive ar(in); return 0; }\n\
         using ExternalType = int;\n\
         void declarations() { void helper(ExternalType); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let restore = idx
        .defs
        .iter()
        .find(|decl| decl.name == "restore")
        .expect("restore declaration");
    for (constructor, source) in [("Input", "blob"), ("Archive", "in")] {
        assert!(
            restore.flow_events.iter().any(|event| matches!(
                event,
                FlowEvent::Call {
                    name,
                    call_kind: CallKind::Constructor,
                    args,
                    ..
                } if name == constructor
                    && args.iter().any(|arg| arg.source_names.iter().any(|name| name == source))
            )),
            "lexically bound value must prove {constructor} direct initialization: {restore:#?}"
        );
    }
    let declarations = idx
        .defs
        .iter()
        .find(|decl| decl.name == "declarations")
        .expect("declarations function");
    assert!(
        declarations.flow_events.iter().all(|event| !matches!(
            event,
            FlowEvent::Call {
                call_kind: CallKind::Constructor,
                ..
            }
        )),
        "a block-local function prototype must not become a constructor call: {declarations:#?}"
    );
}

#[test]
fn cpp_adapter_lowers_base_initializer_as_a_constructor_call() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, DeclKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("base.cpp"),
        "struct Base { explicit Base(int value) {} };\n\
         struct Model : Base { explicit Model(int value) : Base(value) {} };\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let model = idx
        .defs
        .iter()
        .find(|decl| decl.name == "Model" && decl.kind == DeclKind::Constructor)
        .expect("Model constructor");
    assert!(
        model.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                call_kind: CallKind::Constructor,
                args,
                ..
            } if name == "Base"
                && args.len() == 1
                && args[0].place.as_deref() == Some("value")
        )),
        "base initializer must retain its grammar-owned constructor boundary: {model:#?}"
    );
}

#[test]
fn cpp_adapter_preserves_positional_aggregate_syntax_facts() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let header = vfs.write(
        std::path::Path::new("envelope.hpp"),
        "struct Envelope { int kind; const char *cmd; const char *user; };\n",
    );
    let source = vfs.write(
        std::path::Path::new("app.cpp"),
        "int main(int argc, char **argv) { std::string raw = argv[1]; Envelope env{0, raw.size(), raw}; return 0; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };

    let header_idx = adapter.extract_declarations(header, &ctx);
    assert_eq!(
        header_idx.aggregate_layouts,
        vec![bonsai_lang_api::AggregateLayout {
            type_name: "Envelope".to_string(),
            fields: vec!["kind".to_string(), "cmd".to_string(), "user".to_string()],
        }]
    );

    let source_idx = adapter.extract_declarations(source, &ctx);
    let main = source_idx
        .defs
        .iter()
        .find(|decl| decl.name == "main")
        .expect("main declaration");
    assert!(
        main.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::AggregateAssign {
                target,
                type_name: Some(type_name),
                value_flow,
                ..
            } if target == "env" && type_name == "Envelope" && value_flow.tuple_items.len() == 3
        )),
        "aggregate initializer must remain ordered AST data: {main:#?}"
    );
}

#[test]
fn cpp_compound_predicate_guard_requires_complete_static_membership_and_configuration() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let source = r#"#include <set>
#include <string>
static const std::set<std::string> TRUSTED = {"api.example", "hooks.example"};
static bool accepted(const std::string& value, std::string& token) {
  if (value.rfind("https://", 0) != 0) return false;
  auto rest = value.substr(8);
  token = rest.substr(0, rest.find('/'));
  return TRUSTED.count(token) > 0;
}
void fetch(void *client, const std::string& value) {
  std::string token;
  if (!accepted(value, token)) return;
  curl_easy_setopt(client, CURLOPT_URL, value.c_str());
  curl_easy_setopt(client, CURLOPT_FOLLOWLOCATION, 0L);
}
"#;
    let adapter = bonsai_lang_cpp::CppAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("guard.cpp"), source);
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| {
            fact.capability == "terminal-predicate.compound-static-allowlist"
                && fact
                    .evidence
                    .contains(&"guarded-argument:2=predicate-argument:0".to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "missing compound C++ predicate fact: {:#?}",
                index.compiler_guards
            )
        });
    for required in [
        "predicate-complete:true",
        "finite-static-string-membership:true",
        "prefix-call:rfind",
        "prefix-value:string:https://",
        "prefix-position:number:0",
        "prefix-remainder-call:substr",
        "membership-call:count",
        "membership-token-boundary:true",
        "membership-subject-derived-from-prefix:true",
        "related-call:curl_easy_setopt:argument:0=guarded-argument:0",
        "related-call:curl_easy_setopt:argument:1=place:CURLOPT_FOLLOWLOCATION",
        "related-call:curl_easy_setopt:argument:2=number:0",
    ] {
        assert!(
            fact.evidence.iter().any(|evidence| evidence == required),
            "missing {required}: {fact:#?}"
        );
    }
}
