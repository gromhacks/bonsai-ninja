use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_lang_ruby::RubyAdapter;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("guard.rb".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(RubyAdapter::new()));
    AnalyzerDb::new(vfs, registry)
        .decl_index(file)
        .expect("Ruby declaration index")
}

#[test]
fn terminal_compound_static_allowlist_retains_exact_syntax_evidence() {
    let index = index(
        r#"class Gateway
  APPROVED = %w[api.example hooks.example].freeze

  def self.fetch(input)
    endpoint = Endpoint.parse(input) rescue nil
    return "" unless endpoint.is_a?(Endpoint::Secure) && APPROVED.include?(endpoint.server)

    Client.start(endpoint.server, endpoint.port, encrypted: true)
  end
end
"#,
    );
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| fact.capability == "terminal-predicate.compound-static-allowlist")
        .unwrap_or_else(|| panic!("missing compiler guard: {:#?}", index.compiler_guards));
    for expected in [
        "guarded-argument:0=predicate-component:server",
        "predicate-complete:true",
        "finite-static-string-membership:true",
        "parser-call:Endpoint.parse",
        "type-predicate-call:is_a?",
        "type-predicate-value:place:Endpoint::Secure",
        "membership-call:include?",
        "membership-component:server",
        "guarded-named-argument:2:encrypted=boolean:true",
    ] {
        assert!(
            fact.evidence.iter().any(|evidence| evidence == expected),
            "missing {expected}: {fact:#?}"
        );
    }
}

#[test]
fn mutable_or_dynamic_collection_does_not_claim_complete_guard() {
    let index = index(
        r#"class Gateway
  APPROVED = configured_hosts

  def self.fetch(input)
    endpoint = Endpoint.parse(input) rescue nil
    return "" unless endpoint.is_a?(Endpoint::Secure) && APPROVED.include?(endpoint.server)
    Client.start(endpoint.server, endpoint.port, encrypted: true)
  end
end
"#,
    );
    assert!(
        index.compiler_guards.is_empty(),
        "dynamic collection must fail closed: {:#?}",
        index.compiler_guards
    );
}
