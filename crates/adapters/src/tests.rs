use super::*;

#[test]
fn bundled_registry_includes_every_supported_adapter() {
    assert_eq!(all_adapters().len(), 21);
    let registry = all_languages_registry();
    assert!(registry.adapter_for_extension("py").is_some());
    assert!(registry.adapter_for_extension("ts").is_some());
    assert!(registry.adapter_for_extension("sol").is_some());
}
