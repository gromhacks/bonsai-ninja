use super::*;

#[test]
fn bundled_registry_includes_every_supported_adapter() {
    assert_eq!(all_adapters().len(), 20);
    let registry = all_languages_registry();
    assert!(registry.adapter_for_extension("py").is_some());
    assert!(registry.adapter_for_extension("ts").is_some());
    let header_candidates = registry.adapters_for_extension("h");
    assert_eq!(
        header_candidates
            .iter()
            .map(|adapter| adapter.language_id().as_str())
            .collect::<Vec<_>>(),
        vec!["c", "cpp", "objc"],
        "ambiguous compiler headers must preserve every grammar in deterministic order"
    );
}

#[test]
fn ecmascript_frontends_own_minified_path_classification() {
    let registry = all_languages_registry();
    for path in [
        "public/vendor.min.js",
        "public/vendor-min.jsx",
        "assets/runtime.min.mjs",
        "src/client-min.ts",
        "src/client.min.tsx",
    ] {
        assert_eq!(
            registry.source_file_representation(std::path::Path::new(path)),
            Some(bonsai_lang_api::SourceFileRepresentation::Minified),
            "{path}"
        );
    }
    for path in ["src/app.js", "src/app.ts", "src/app.min.py"] {
        assert_eq!(
            registry.source_file_representation(std::path::Path::new(path)),
            Some(bonsai_lang_api::SourceFileRepresentation::Maintained),
            "{path}"
        );
    }
}
