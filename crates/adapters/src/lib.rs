//! Bundled language adapter registration for SDK consumers.
//!
//! Core crates intentionally do not depend on concrete `lang_*`
//! crates. This crate is the opt-in convenience layer for frontends
//! that want the same supported-language set as the CLI.

use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use std::sync::Arc;

#[must_use]
pub fn all_adapters() -> Vec<AdapterArc> {
    vec![
        Arc::new(bonsai_lang_c::CAdapter::new()),
        Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        Arc::new(bonsai_lang_go::GoAdapter::new()),
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        Arc::new(bonsai_lang_php::PhpAdapter::new()),
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        Arc::new(bonsai_lang_ruby::RubyAdapter::new()),
        Arc::new(bonsai_lang_dart::DartAdapter::new()),
        Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
    ]
}

#[must_use]
pub fn all_languages_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    for adapter in all_adapters() {
        registry.register(adapter);
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_registry_includes_every_supported_adapter() {
        assert_eq!(all_adapters().len(), 21);
        let registry = all_languages_registry();
        assert!(registry.adapter_for_extension("py").is_some());
        assert!(registry.adapter_for_extension("ts").is_some());
        assert!(registry.adapter_for_extension("sol").is_some());
    }
}
