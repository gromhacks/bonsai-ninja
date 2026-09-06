use bonsai_diagnostics::DiagnosticSink;
use bonsai_lang_api::{AdapterContext, DeclIndex, FlowEvent, LanguageAdapter, Visibility};
use bonsai_vfs::Vfs;
use parking_lot::RwLock;

fn index(source: &str) -> DeclIndex {
    let vfs = Vfs::new();
    let file = vfs.write(std::path::Path::new("identity.cpp"), source);
    let diagnostics = RwLock::new(DiagnosticSink::default());
    bonsai_lang_cpp::CppAdapter::new().extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    )
}

#[test]
fn equal_class_names_keep_their_exact_bases_and_namespace_owners() {
    let facts = index(
        r#"
struct BaseA {}; struct BaseB {};
namespace alpha { struct Node : BaseA { int left; }; }
namespace beta { struct Node : BaseB { int right; }; }
namespace gamma { struct Node { int data; }; }
"#,
    );
    let mut nodes = facts
        .defs
        .iter()
        .filter(|decl| decl.name == "Node")
        .collect::<Vec<_>>();
    nodes.sort_by_key(|decl| decl.span.start);
    assert_eq!(nodes.len(), 3, "{:#?}", facts.defs);
    assert_eq!(nodes[0].bases, ["BaseA"]);
    assert_eq!(nodes[1].bases, ["BaseB"], "{nodes:#?}");
    assert!(nodes[2].bases.is_empty(), "{nodes:#?}");
    for (node, owner) in nodes.into_iter().zip(["alpha", "beta", "gamma"]) {
        assert!(
            node.qualified_name
                .as_deref()
                .is_some_and(|name| name.ends_with(&format!("{owner}.Node"))),
            "{node:#?}"
        );
    }
}

#[test]
fn static_function_does_not_make_a_same_named_other_owner_private() {
    let facts = index(
        r#"
namespace alpha { static void action() {} }
namespace beta { void action() {} }
"#,
    );
    let mut actions = facts
        .defs
        .iter()
        .filter(|decl| decl.name == "action")
        .collect::<Vec<_>>();
    actions.sort_by_key(|decl| decl.span.start);
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].visibility, Visibility::Private);
    assert_eq!(actions[1].visibility, Visibility::Public, "{actions:#?}");
}

#[test]
fn a_distinct_qualified_wrapper_is_not_whole_object_copy_initialization() {
    let facts = index(
        r#"
namespace alpha { struct Envelope { const char *data; }; }
namespace beta { struct Envelope { alpha::Envelope wrapped; }; }
void run(alpha::Envelope source) {
  beta::Envelope wrapper{source};
  consume(wrapper.wrapped.data);
}
"#,
    );
    let function = facts.defs.iter().find(|decl| decl.name == "run").unwrap();
    assert!(
        function
            .flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::AggregateAssign { target, .. } if target == "wrapper")),
        "distinct aggregate initialization was erased: {function:#?}"
    );
}
