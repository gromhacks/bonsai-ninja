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
fn ambiguous_h_extension_uses_grammar_owned_syntax_to_select_cpp() {
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
fn cplusplus_grammar_proof_ignores_objective_c_spelling_in_documentation() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("documented.h"),
        "/// `@interface` is mentioned as documentation, not syntax.\ntemplate <typename T> struct Box { T value; };\n",
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
fn ambiguous_h_extension_uses_cpp_uniform_construction_as_language_proof() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("construction.h"),
        "struct item { int value; };\nstatic inline item make(void) { return item { 1 }; }\n",
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
fn c_compound_literal_does_not_prove_cpp_ownership() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("compound.h"),
        "typedef struct { int value; } item;\nstatic inline item make(void) { return (item) { 1 }; }\n",
    )
    .expect("C header");

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
fn c_compatible_header_stays_c_when_superset_grammars_have_fewer_errors() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("generated_enum.h"),
        "typedef enum {\n#define ITEM(name) name,\n#include \"items.h\"\n#undef ITEM\n} item_kind;\n",
    )
    .expect("C header");
    std::fs::write(root.path().join("items.h"), "ITEM(first)\nITEM(second)\n").expect("item list");

    let workspace = Workspace::open_with_options(
        root.path(),
        c_family_registry(),
        WorkspaceOpenOptions::parse_only(),
    )
    .expect("workspace");
    let file = workspace
        .vfs()
        .all_files()
        .into_iter()
        .find(|file| {
            workspace
                .vfs()
                .path(*file)
                .is_ok_and(|path| path.ends_with("generated_enum.h"))
        })
        .expect("generated header");
    assert_eq!(
        workspace
            .db()
            .adapter_for(file)
            .expect("adapter")
            .language_id()
            .as_str(),
        "c"
    );
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

#[test]
fn objective_c_grammar_proof_outranks_damage_for_ambiguous_header() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("DamagedWidget.h"),
        "@interface DamagedWidget : NSObject\n- (void)render:(NSString *)value;\n@end\nBROKEN_TRAILING_MACRO(\n",
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
        "objc",
        "grammar-owned @interface syntax proves Objective-C even when unrelated damage remains"
    );
}

#[test]
fn objective_c_header_recovers_branch_free_preprocessor_wrapper() {
    let root = tempfile::tempdir().expect("temp workspace");
    std::fs::write(
        root.path().join("ImageCache.h"),
        "#if TARGET_OS_IOS\n@protocol ImageCache <NSObject>\n- (void)addImage:(UIImage *)image;\n@end\n#endif\n",
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
    assert!(
        workspace.diagnostics().is_empty(),
        "branch-free preprocessing must not hide valid Objective-C declarations: {:#?}",
        workspace.diagnostics()
    );
}
