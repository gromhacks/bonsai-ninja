use bonsai_lang_api::{DeclKind, LanguageAdapter};
use std::sync::Arc;

fn declaration_index(source: &'static str) -> bonsai_lang_api::DeclIndex {
    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let workspace = bonsai_testkit::workspace_with(vec![adapter], &[("Types.java", source)]);
    let file = *workspace.db().vfs().all_files().first().expect("fixture file");
    workspace
        .db()
        .decl_index(file)
        .expect("Java declaration index")
        .as_ref()
        .clone()
}

#[test]
fn class_like_syntax_preserves_java_declaration_taxonomy() {
    let index = declaration_index(
        r#"
interface Service {}
@interface Marker {}
enum State { READY }
record Item(String name) {}
class Impl implements Service {}
"#,
    );

    for (name, expected) in [
        ("Service", DeclKind::Interface),
        ("Marker", DeclKind::Interface),
        ("State", DeclKind::Enum),
        ("Item", DeclKind::Class),
        ("Impl", DeclKind::Class),
    ] {
        let declaration = index
            .defs
            .iter()
            .find(|declaration| declaration.name == name)
            .unwrap_or_else(|| panic!("missing declaration {name}"));
        assert_eq!(
            declaration.kind, expected,
            "{name} must be classified from its Tree-sitter declaration node"
        );
    }
}

#[test]
fn anonymous_class_methods_do_not_belong_to_enclosing_interface() {
    let index = declaration_index(
        r#"
public interface Tracer {
    Tracer NOOP = new Tracer() {
        @Override public void startTrace() {}
        @Override public void stopTrace() {}
    };

    void startTrace();
    void stopTrace();
}
"#,
    );

    let tracer = index
        .defs
        .iter()
        .find(|declaration| declaration.name == "Tracer")
        .expect("Tracer interface");
    assert_eq!(tracer.kind, DeclKind::Interface);

    let mut owned_methods = index
        .defs
        .iter()
        .filter(|declaration| declaration.parent == Some(tracer.symbol))
        .map(|declaration| declaration.name.as_str())
        .collect::<Vec<_>>();
    owned_methods.sort_unstable();
    assert_eq!(owned_methods, ["startTrace", "stopTrace"]);
    assert!(index
        .defs
        .iter()
        .filter(|declaration| declaration.parent == Some(tracer.symbol))
        .all(|declaration| declaration
            .qualified_name
            .as_deref()
            .is_some_and(|name| name.contains("Tracer."))));

    let anonymous_methods = index
        .defs
        .iter()
        .filter(|declaration| {
            declaration.parent.is_none()
                && declaration.kind == DeclKind::Method
                && matches!(declaration.name.as_str(), "startTrace" | "stopTrace")
        })
        .count();
    assert_eq!(anonymous_methods, 2);
}

#[test]
fn nested_types_and_members_preserve_the_complete_lexical_identity() {
    let index = declaration_index(
        r#"
package org.example;

public interface HttpServerTransport {
    interface Dispatcher {
        void dispatchRequest(String request);
    }
}
"#,
    );

    let outer = index
        .defs
        .iter()
        .find(|declaration| declaration.name == "HttpServerTransport")
        .expect("outer interface");
    let dispatcher = index
        .defs
        .iter()
        .find(|declaration| declaration.name == "Dispatcher")
        .expect("nested interface");
    let dispatch = index
        .defs
        .iter()
        .find(|declaration| declaration.name == "dispatchRequest")
        .expect("nested interface method");

    assert_eq!(dispatcher.parent, Some(outer.symbol));
    assert_eq!(dispatch.parent, Some(dispatcher.symbol));
    assert_eq!(
        dispatcher.qualified_name.as_deref(),
        Some("org.example.HttpServerTransport.Dispatcher")
    );
    assert_eq!(
        dispatch.qualified_name.as_deref(),
        Some("org.example.HttpServerTransport.Dispatcher.dispatchRequest")
    );
}

#[test]
fn method_local_types_do_not_become_members_of_the_enclosing_class() {
    let index = declaration_index(
        r#"
package org.example;

class Factory {
    Object create() {
        class Local {
            Object build() { return new Object(); }
        }
        return new Local().build();
    }
}
"#,
    );

    let factory = index
        .defs
        .iter()
        .find(|declaration| declaration.name == "Factory")
        .expect("Factory class");
    let local = index
        .defs
        .iter()
        .find(|declaration| declaration.name == "Local")
        .expect("method-local class");

    assert_ne!(local.parent, Some(factory.symbol));
    assert_eq!(
        local.qualified_name.as_deref(),
        Some("org.example.Local"),
        "a method-local type is not a member named Factory.Local"
    );
}
