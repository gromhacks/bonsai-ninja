use bonsai_diagnostics::DiagnosticSink;
use bonsai_lang_api::{AdapterContext, LanguageAdapter};
use bonsai_vfs::Vfs;
use parking_lot::RwLock;

#[test]
fn pointer_typedef_parameter_keeps_the_sdk_type_and_binding() {
    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("mqtt.c"),
        "#include \"core_mqtt.h\"\n\
         static bool on_event(MQTTContext_t *ctx, MQTTDeserializedInfo_t *decoded) {\n\
           consume(decoded->pPublishInfo->pPayload); return true;\n\
         }\n",
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
    let callback = index
        .defs
        .iter()
        .find(|decl| decl.name == "on_event")
        .expect("callback declaration");

    assert_eq!(callback.params, ["ctx", "decoded"]);
    assert!(
        callback
            .type_aliases
            .iter()
            .any(|alias| alias.name == "decoded" && alias.type_name == "MQTTDeserializedInfo_t"),
        "the C adapter must retain the declared SDK typedef through the pointer declarator: {:?}",
        callback.type_aliases
    );
}

#[test]
fn same_parameter_name_with_an_application_type_stays_distinct() {
    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("local.c"),
        "typedef struct { const char *payload; } LocalEvent;\n\
         static void helper(LocalEvent *decoded) { consume(decoded->payload); }\n",
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
    let helper = index
        .defs
        .iter()
        .find(|decl| decl.name == "helper")
        .expect("helper declaration");

    assert!(helper
        .type_aliases
        .iter()
        .any(|alias| alias.name == "decoded" && alias.type_name == "LocalEvent"));
    assert!(helper
        .type_aliases
        .iter()
        .all(|alias| alias.type_name != "MQTTDeserializedInfo_t"));
}

#[test]
fn pointer_and_size_callback_signature_keeps_each_exact_parameter_type() {
    let adapter = bonsai_lang_c::CAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("callback.c"),
        "#include <stddef.h>\n\
         struct transport_context;\n\
         static void deliver(struct transport_context *context, char *bytes, size_t length) {\n\
           consume(bytes, length);\n\
         }\n",
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
    let callback = index
        .defs
        .iter()
        .find(|decl| decl.name == "deliver")
        .expect("callback declaration");

    assert_eq!(callback.params, ["context", "bytes", "length"]);
    for (binding, expected) in [
        ("context", "struct transport_context"),
        ("bytes", "char"),
        ("length", "size_t"),
    ] {
        assert!(
            callback
                .type_aliases
                .iter()
                .any(|alias| alias.name == binding && alias.type_name == expected),
            "missing {binding}: {expected} in {:?}",
            callback.type_aliases
        );
    }
}
