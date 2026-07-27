use super::*;

#[test]
fn match_attribution_recovers_outer_java_method_after_nested_lambda() {
    let source = r#"
class Example {
    void method() {
        Runnable callback = () -> { consume("inside"); };
        consume("after");
    }
}
"#;
    let registry = std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new());
    registry.register(std::sync::Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs()
        .write("Example.java".to_string(), std::sync::Arc::<str>::from(source));
    let file = ws.vfs().all_files()[0];
    let _ = ws.db().decl_index(file);
    let start = source.find("consume(\"after\")").expect("outer call") as u64;
    let hit = RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: "java.test.sink".to_string(),
        language: "java".to_string(),
        file: "Example.java".to_string(),
        line: 5,
        column: 9,
        span: Span::new(file, start, start + "consume(\"after\")".len() as u64),
        match_text: "consume".to_string(),
        enclosing_fn: None,
    };

    let func = func_id_for_match(&ws, &hit).expect("outer method attribution");
    let global = ws.compiler_linkage_index();
    assert_eq!(
        global
            .decl_of(SymbolId::new(func.raw()))
            .expect("attributed declaration")
            .name,
        "method"
    );
}
