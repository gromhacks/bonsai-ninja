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

#[test]
fn match_attribution_owns_calls_inside_recovered_c_preprocessor_predicate() {
    let source = r#"int process(int first, int second, int tail, int value) {
#ifdef FIRST_SHAPE
    if (first ||
#else
    if (second ||
#endif
        tail) {
        consume(value);
    }
    return value;
}
int unrelated(
"#;
    let registry = std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new());
    registry.register(std::sync::Arc::new(bonsai_lang_c::CAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs()
        .write("unit.c".to_string(), std::sync::Arc::<str>::from(source));
    let file = ws.vfs().all_files()[0];
    let _ = ws.db().decl_index(file);
    let start = source.find("consume(value)").expect("call") as u64;
    let hit = RuleMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: "c.test.sink".to_string(),
        language: "c".to_string(),
        file: "unit.c".to_string(),
        line: 7,
        column: 9,
        span: Span::new(file, start, start + "consume(value)".len() as u64),
        match_text: "consume".to_string(),
        enclosing_fn: None,
    };

    let attributed = [&hit]
        .into_iter()
        .filter_map(|matched| func_id_for_match(&ws, matched))
        .collect::<Vec<_>>();
    assert_eq!(
        attributed.len(),
        1,
        "a compiler-owned recovered call must not contribute an unattributed sink match"
    );
    let global = ws.compiler_linkage_index();
    assert_eq!(
        global
            .decl_of(SymbolId::new(attributed[0].raw()))
            .expect("attributed declaration")
            .name,
        "process"
    );
}
