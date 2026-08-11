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
    let handle = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");
    let (assignment_span, value_kind) = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                span,
                target,
                value_kind,
                ..
            } if target == "$raw" => Some((*span, *value_kind)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("raw assignment flow event: {:#?}", handle.flow_events));
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

#[test]
fn scoped_self_call_retains_its_parsed_receiver_and_enclosing_type() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "pipeline.php".to_string(),
        Arc::<str>::from(
            "<?php class Pipeline {\n\
             public static function tokenize($value) { return $value; }\n\
             public static function orchestrate($value) { return self::tokenize($value); }\n\
             }",
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");
    let orchestrate = index
        .defs
        .iter()
        .find(|decl| decl.name == "orchestrate")
        .expect("orchestrate declaration");
    let call = orchestrate
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                ..
            } if name == "self::tokenize" => Some((receiver, receiver_types)),
            _ => None,
        })
        .expect("self::tokenize call");

    assert_eq!(call.0.as_deref(), Some("self"));
    assert_eq!(call.1, &["Pipeline"]);
}

#[test]
fn static_subscript_assignment_preserves_the_exact_projected_source() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "app.php".to_string(),
        Arc::<str>::from("<?php function handle() { $user = $_GET['cmd']; }"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");
    let handle = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle declaration");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_names, .. }
                if target == "$user"
                    && source_names.iter().any(|source| source == "$_GET.cmd")
        )),
        "PHP static subscripts must lower as field-sensitive places: {:#?}",
        handle.flow_events
    );
}

#[test]
fn append_assignment_writes_the_parsed_aggregate_place() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "app.php".to_string(),
        Arc::<str>::from("<?php function collect($value) { $items = []; $items[] = $value; return $items; }"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");
    let collect = index
        .defs
        .iter()
        .find(|decl| decl.name == "collect")
        .expect("collect declaration");

    assert!(
        collect.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, source_names, .. }
                if target == "$items" && source_names.iter().any(|source| source == "$value")
        )),
        "PHP append syntax must mutate the parsed aggregate place: {:#?}",
        collect.flow_events
    );
}

#[test]
fn sigil_variable_wrappers_do_not_emit_unsigiled_child_reads() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "app.php".to_string(),
        Arc::<str>::from("<?php function grow($c) { $size = $c->capacity * 2; }"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");
    let grow = index
        .defs
        .iter()
        .find(|decl| decl.name == "grow")
        .expect("grow declaration");
    let sources = grow
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target, source_names, ..
            } if target == "$size" => Some(source_names),
            _ => None,
        })
        .expect("size assignment");

    assert!(sources.iter().any(|source| source == "$c.capacity"));
    assert!(sources.iter().all(|source| source != "c"), "sources={sources:?}");
}
