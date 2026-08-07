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
