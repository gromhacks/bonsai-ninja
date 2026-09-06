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
fn nested_if_does_not_inherit_an_enclosing_unless_polarity() {
    use bonsai_lang_api::BranchConditionPolarity;
    let source = "def choose(value, enabled)\n  unless enabled\n    if value == 'allowed'\n      consume(value)\n    end\n  end\nend\n";
    let index = index(source);
    for (condition, expected) in [
        ("enabled", BranchConditionPolarity::Negated),
        ("value == 'allowed'", BranchConditionPolarity::Positive),
    ] {
        let fact = index
            .branch_conditions
            .iter()
            .find(|fact| {
                &source[fact.condition_span.start as usize..fact.condition_span.end as usize] == condition
            })
            .unwrap_or_else(|| panic!("missing condition {condition}: {:#?}", index.branch_conditions));
        assert_eq!(fact.polarity, expected, "{condition}");
    }
}

#[test]
fn unless_negates_the_complete_boolean_condition_once() {
    use bonsai_lang_api::{BranchConditionPolarity, ConditionExpressionFact};
    let index = index("def choose(value)\n  return unless first(value) && second(value)\n  return unless !third(value)\nend\n");
    assert_eq!(index.branch_conditions.len(), 2);
    assert!(matches!(index.branch_conditions[0].expression.as_ref(),
        Some(ConditionExpressionFact::Not { operand, .. })
            if matches!(operand.as_ref(), ConditionExpressionFact::All { operands, .. } if operands.len() == 2)));
    assert_eq!(
        index.branch_conditions[1].polarity,
        BranchConditionPolarity::Positive
    );
    assert!(matches!(index.branch_conditions[1].expression.as_ref(),
        Some(ConditionExpressionFact::Not { operand, .. })
            if matches!(operand.as_ref(), ConditionExpressionFact::Not { .. })));
}

#[test]
fn compound_guard_requires_dominance_unchanged_values_and_lexical_identity() {
    let source = "class Gateway\n  APPROVED = %w[api.example hooks.example].freeze\n  def self.fetch(input, enabled)\n    endpoint = Endpoint.parse(input) rescue nil\n    return \"\" unless endpoint.is_a?(Endpoint::Secure) && APPROVED.include?(endpoint.server)\n    Client.start(endpoint.server, endpoint.port, encrypted: true)\n  end\nend\n";
    let parser = "    endpoint = Endpoint.parse(input) rescue nil\n";
    let guard =
        "    return \"\" unless endpoint.is_a?(Endpoint::Secure) && APPROVED.include?(endpoint.server)\n";
    let cases = [
        (
            "conditional guard",
            source.replace(guard, &format!("    if enabled\n{guard}    end\n")),
        ),
        (
            "conditional parser",
            source.replace(parser, &format!("    if enabled\n{parser}    end\n")),
        ),
        (
            "mutated component",
            source.replace(guard, &format!("{guard}    endpoint.server = input\n")),
        ),
        (
            "replaced parsed value",
            source.replace(guard, &format!("{guard}    endpoint = other_endpoint(input)\n")),
        ),
        (
            "mutated string element",
            source.replace(
                "  def self.fetch",
                "  APPROVED.first.replace(ENV['HOST'])\n  def self.fetch",
            ),
        ),
        (
            "escaped collection",
            source.replace("  def self.fetch", "  configure(APPROVED)\n  def self.fetch"),
        ),
        (
            "reassigned constant",
            source.replace(
                "  def self.fetch",
                "  APPROVED = configured_hosts\n  def self.fetch",
            ),
        ),
        (
            "interpolated collection",
            source.replace(
                "%w[api.example hooks.example]",
                "%W[api.#{ENV['HOST']} hooks.example]",
            ),
        ),
        (
            "unrelated lexical constant",
            source.replace("  APPROVED = %w[api.example hooks.example].freeze\n", "")
                + "class Other\n  APPROVED = %w[api.example hooks.example].freeze\nend\n",
        ),
        (
            "local parser provider",
            source.to_string() + "class Endpoint\n  def self.parse(value)\n    value\n  end\nend\n",
        ),
    ];
    let failures = cases
        .into_iter()
        .filter_map(|(label, source)| {
            let facts = index(&source).compiler_guards.clone();
            (!facts.is_empty()).then_some((label, facts))
        })
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "unproven guards must fail closed: {failures:#?}"
    );
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
