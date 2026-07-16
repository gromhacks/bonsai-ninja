use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn elvis_assignment_preserves_exact_rhs_call_site() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "app.php".to_string(),
        Arc::<str>::from("<?php function handle() { $raw = readline(\"cmd: \") ?: \"\"; }"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");
    let (assignment_span, value_kind) = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .and_then(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                FlowEvent::Assign {
                    span,
                    target,
                    value_kind,
                    ..
                } if target == "$raw" => Some((*span, *value_kind)),
                _ => None,
            })
        })
        .expect("raw assignment flow event");
    assert_eq!(
        value_kind,
        Some(bonsai_lang_api::AssignValueKind::Compound),
        "an AST-indexed nested call is not a literal overwrite"
    );
    let fact = index
        .assignment_values
        .iter()
        .find(|fact| fact.assignment_span == assignment_span)
        .expect("exact RHS syntax fact for raw assignment");
    assert_eq!(fact.call_sites.len(), 1, "assignment fact: {fact:?}");
    assert!(
        fact.value_span.start <= fact.call_sites[0].start && fact.call_sites[0].end <= fact.value_span.end,
        "RHS must contain its call site: {fact:?}"
    );
}
