use bonsai_lang_api::LanguageRegistry;
use bonsai_lang_c::CAdapter;
use bonsai_lang_cpp::CppAdapter;
use bonsai_lang_objc::ObjCAdapter;
use bonsai_workspace::{Workspace, WorkspaceOpenOptions};
use std::sync::Arc;

fn c_family_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(CAdapter::new()));
    registry.register(Arc::new(CppAdapter::new()));
    registry.register(Arc::new(ObjCAdapter::new()));
    registry
}

#[test]
fn included_object_macro_recovers_cpp_declaration_without_changing_spans() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::create_dir_all(root.path().join("include")).expect("include dir");
    std::fs::create_dir_all(root.path().join("src")).expect("source dir");
    std::fs::write(
        root.path().join("include/api.h"),
        "#ifdef _WIN32\n#define PUBLIC_API extern \"C\" __declspec(dllexport)\n#else\n#define PUBLIC_API extern \"C\" __attribute__((visibility(\"default\")))\n#endif\n",
    )
    .expect("header");
    std::fs::write(
        root.path().join("src/main.cpp"),
        "#include \"api.h\"\nPUBLIC_API int exported(const char *value) { return value ? 1 : 0; }\n",
    )
    .expect("translation unit");

    let workspace = Workspace::open_with_options(
        root.path(),
        c_family_registry(),
        WorkspaceOpenOptions::parse_only(),
    )
    .expect("workspace");
    assert!(
        workspace.diagnostics().is_empty(),
        "valid preprocessed C++ must parse cleanly"
    );

    let global = workspace.db().global_index();
    let declaration = global
        .find_by_name("exported")
        .iter()
        .find_map(|symbol| global.decl_of(*symbol))
        .expect("exported declaration");
    assert_eq!(declaration.return_type.as_deref(), Some("int"));
    let source = workspace
        .vfs()
        .snapshot(declaration.span.file)
        .expect("source snapshot");
    let declaration_start = source.text.find("int exported").expect("declaration text");
    assert_eq!(declaration.span.start as usize, declaration_start);
    assert!(source.text[..declaration_start].contains("PUBLIC_API"));
}

#[test]
fn ambiguous_h_extension_uses_concrete_tree_damage_to_select_cpp() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("generic.h"),
        "template <typename T> struct Box { T value; };\n",
    )
    .expect("C++ header");

    let workspace = Workspace::open_with_options(
        root.path(),
        c_family_registry(),
        WorkspaceOpenOptions::parse_only(),
    )
    .expect("workspace");
    let file = workspace.vfs().all_files()[0];
    assert_eq!(
        workspace
            .db()
            .adapter_for(file)
            .expect("adapter")
            .language_id()
            .as_str(),
        "cpp"
    );
    assert!(workspace.diagnostics().is_empty());
}

#[test]
fn ambiguous_h_extension_prefers_c_when_both_grammars_are_clean() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(root.path().join("plain.h"), "struct item { int value; };\n").expect("C header");

    let workspace = Workspace::open_with_options(
        root.path(),
        c_family_registry(),
        WorkspaceOpenOptions::parse_only(),
    )
    .expect("workspace");
    let file = workspace.vfs().all_files()[0];
    assert_eq!(
        workspace
            .db()
            .adapter_for(file)
            .expect("adapter")
            .language_id()
            .as_str(),
        "c"
    );
    assert!(workspace.diagnostics().is_empty());
}

#[test]
fn ambiguous_h_extension_uses_concrete_tree_damage_to_select_objc() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("Widget.h"),
        "@interface Widget : NSObject\n- (void)render:(NSString *)value;\n@end\n",
    )
    .expect("Objective-C header");

    let workspace = Workspace::open_with_options(
        root.path(),
        c_family_registry(),
        WorkspaceOpenOptions::parse_only(),
    )
    .expect("workspace");
    let file = workspace.vfs().all_files()[0];
    assert_eq!(
        workspace
            .db()
            .adapter_for(file)
            .expect("adapter")
            .language_id()
            .as_str(),
        "objc"
    );
    assert!(workspace.diagnostics().is_empty());
}
