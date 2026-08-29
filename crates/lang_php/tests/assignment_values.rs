use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry, StringCompositionPart};
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
fn concatenation_emits_complete_ordered_string_composition_facts() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "paths.php".to_string(),
        Arc::<str>::from(
            "<?php final class Store { private const ROOT = '/srv/assets'; function read($name) { $path = realpath(self::ROOT . '/' . $this->ctx->name); check($path, $path . '/'); $sum = $name + 1; } }",
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");

    assert!(
        index.string_compositions.iter().any(|composition| {
            composition.target.is_none()
                && composition.parts
                    == [
                        StringCompositionPart::Place {
                            place: "ROOT".to_string(),
                        },
                        StringCompositionPart::Literal {
                            value: "/".to_string(),
                        },
                        StringCompositionPart::Place {
                            place: "$this.ctx.name".to_string(),
                        },
                    ]
        }),
        "nested canonicalizer input must retain exact ordered operands: {:#?}",
        index.string_compositions
    );
    assert!(
        index.string_compositions.iter().any(|composition| {
            composition.target.is_none()
                && composition.parts
                    == [
                        StringCompositionPart::Place {
                            place: "$path".to_string(),
                        },
                        StringCompositionPart::Literal {
                            value: "/".to_string(),
                        },
                    ]
        }),
        "call-argument concatenation must retain its exact expression span: {:#?}",
        index.string_compositions
    );
    assert!(
        index
            .string_compositions
            .iter()
            .all(|composition| composition.target.as_deref() != Some("$sum")),
        "numeric addition is not PHP string concatenation: {:#?}",
        index.string_compositions
    );
    let constant = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("ROOT"))
        .expect("class constant value fact");
    assert!(constant.target_is_immutable, "{constant:?}");
    assert!(constant.target_owner.is_some(), "{constant:?}");
    assert_eq!(
        constant.static_value,
        Some(bonsai_lang_api::StaticScalarValue::String(
            "/srv/assets".to_string()
        )),
        "{constant:?}"
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
fn static_server_subscripts_preserve_exact_client_and_process_keys() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "app.php".to_string(),
        Arc::<str>::from(
            "<?php function handle() { $host = $_SERVER['HTTP_HOST']; $software = $_SERVER['SERVER_SOFTWARE']; }",
        ),
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

    let assigned_sources = |target: &str| {
        handle.flow_events.iter().find_map(|event| match event {
            FlowEvent::Assign {
                target: actual,
                source_names,
                ..
            } if actual == target => Some(source_names.clone()),
            _ => None,
        })
    };
    let host = assigned_sources("$host").expect("host assignment sources");
    let software = assigned_sources("$software").expect("software assignment sources");
    assert!(
        host.iter().any(|source| source == "$_SERVER.HTTP_HOST"),
        "{host:?}"
    );
    assert!(
        software.iter().any(|source| source == "$_SERVER.SERVER_SOFTWARE"),
        "{software:?}"
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

#[test]
fn nested_configuration_arrays_retain_exact_static_field_paths() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "tls.php".to_string(),
        Arc::<str>::from(
            "<?php function configure($timeout) { return stream_context_create(['ssl' => ['verify_peer' => false, 'check_name' => TRUE, 'fallback' => NULL, 'protocol' => 'tls', 'timeout' => $timeout]]); }",
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("PHP declaration index");
    let options = index
        .call_argument_values
        .iter()
        .find(|fact| fact.argument_index == 0 && !fact.exact_static_aggregate_fields.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "missing exact PHP options aggregate: {:#?}",
                index.call_argument_values
            )
        });

    assert!(
        options.exact_static_aggregate_fields.iter().any(|field| {
            field.path.iter().map(String::as_str).eq(["ssl", "verify_peer"])
                && field.value == bonsai_lang_api::StaticScalarValue::Boolean(false)
        }),
        "nested exact boolean option missing: {options:#?}"
    );
    for (path, expected) in [
        (
            ["ssl", "check_name"],
            bonsai_lang_api::StaticScalarValue::Boolean(true),
        ),
        (["ssl", "fallback"], bonsai_lang_api::StaticScalarValue::Null),
        (
            ["ssl", "protocol"],
            bonsai_lang_api::StaticScalarValue::String("tls".to_string()),
        ),
    ] {
        assert!(
            options
                .exact_static_aggregate_fields
                .iter()
                .any(|field| { field.path.iter().map(String::as_str).eq(path) && field.value == expected }),
            "nested exact PHP scalar {path:?} missing: {options:#?}"
        );
    }
    assert!(
        options.exact_static_aggregate_fields.iter().all(|field| !field
            .path
            .iter()
            .map(String::as_str)
            .eq(["ssl", "timeout"])),
        "a dynamic sibling must remain unknown rather than becoming a static value: {options:#?}"
    );
}
