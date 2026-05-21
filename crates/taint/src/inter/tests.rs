//! Unit tests for the interprocedural taint engine — exercise the full
//! resolver-driven propagation path on real multi-file workspaces, not
//! synthetic fact records. This catches alias-map bugs, missing
//! resolver hops, and budget-exhaustion edge cases that synthetic
//! fact-level tests would miss.

use super::*;
use bonsai_common::{FileId, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_resolve::resolve_callable;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn python_ws_one_file(source: &str) -> AnalyzerDb {
    python_ws_multi(&[("main.py", source)])
}

/// Build a multi-file Python workspace. Files appear in the
/// workspace in the order given.
fn python_ws_multi(files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    // Pre-warm so global_index() reflects every decl.
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn javascript_ws_multi(files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn rust_ws_multi(files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_rust::RustAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn perl_ws_one_file(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.pl".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_perl::PerlAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

/// Find a function decl by name and return its FuncId.
fn func_id_of(db: &AnalyzerDb, name: &str) -> FuncId {
    let global = db.global_index();
    let matches = resolve_callable(&global, name);
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{name}`, got {}",
        matches.len()
    );
    matches[0]
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn config(sanitizers: &[&str]) -> InterTaintConfig {
    InterTaintConfig {
        sanitizers: seed(sanitizers),
        budget: 512,
        intra_worklist_cap: None,
        ..Default::default()
    }
}

#[test]
fn default_inter_taint_config_is_semantic_only() {
    assert_eq!(
        InterTaintConfig::default().max_edge_precision,
        Some(Precision::Narrowed),
        "taint defaults must cap public flow evidence at the semantic precision ceiling",
    );
}

fn arg(index: u64, text: &str, place: Option<&str>) -> bonsai_lang_api::CallArg {
    bonsai_lang_api::CallArg {
        span: Span::new(FileId::new(0), index, index + 1),
        name: None,
        place: place.map(str::to_string),
        source_names: Vec::new(),
        value_text: text.to_string(),
    }
}

fn summary_decl(flow_events: Vec<FlowEvent>, has_implicit_returns: bool) -> Decl {
    let span = Span::new(FileId::new(0), 0, 10);
    Decl {
        symbol: SymbolId::new(1),
        kind: DeclKind::Function,
        name: "helper".to_string(),
        qualified_name: None,
        module_path: ModulePath::default(),
        span,
        name_span: span,
        visibility: bonsai_lang_api::Visibility::Public,
        parent: None,
        body_span: Some(span),
        flow_events,
        has_implicit_returns,
        params: vec!["input".to_string()],
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
    }
}

#[test]
fn terminal_assign_return_taint_requires_adapter_implicit_return_fact() {
    let flow_events = vec![FlowEvent::Assign {
        span: Span::new(FileId::new(0), 1, 2),
        target: "out".to_string(),
        source_name: Some("input".to_string()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: false,
        value_kind: None,
    }];

    let explicit_only = compute_function_summary(&summary_decl(flow_events.clone(), false));
    assert!(
        explicit_only.returns_taint_of.is_empty(),
        "ordinary languages must not treat a terminal assignment as an implicit return"
    );

    let implicit_tail = compute_function_summary(&summary_decl(flow_events, true));
    assert_eq!(
        implicit_tail.returns_taint_of,
        vec![0],
        "tail-expression languages can propagate taint through terminal expression evidence"
    );
}

#[test]
fn clean_output_call_overwrite_only_clears_when_value_inputs_are_clean() {
    let mut state = seed(&["buf"]);
    let config = InterTaintConfig {
        clean_output_overwrites: vec![CleanOutputOverwrite {
            callee: "clean_copy".to_string(),
            output_arg_index: 0,
            value_start_arg_index: 2,
        }],
        ..config(&[])
    };
    let clean_args = vec![
        arg(0, "buf", Some("buf")),
        arg(1, "64", None),
        arg(2, "\"clean\"", None),
    ];
    apply_clean_output_call_overwrite("clean_copy", &clean_args, &mut state, &config);
    assert!(
            !state.contains("buf"),
            "configured clean-output call with only clean value inputs should overwrite stale buf taint: {state:?}"
        );

    let mut state = seed(&["buf", "input"]);
    let tainted_args = vec![
        arg(0, "buf", Some("buf")),
        arg(1, "64", None),
        arg(2, "\"%s\"", None),
        arg(3, "input", None),
    ];
    apply_clean_output_call_overwrite("clean_copy", &tainted_args, &mut state, &config);
    assert!(
        state.contains("buf"),
        "configured clean-output call with tainted value input must not clear output taint: {state:?}"
    );
}

#[test]
fn call_arg_taint_uses_adapter_source_names_for_interpolation_operands() {
    let state = seed(&["$c"]);
    assert!(arg_text_is_tainted("$c", &state));
    assert!(
        !arg_text_is_tainted("\"prefix $c suffix\"", &state),
        "raw string text is not parsed for interpolation by the engine"
    );
    let mut interpolated = arg(0, "\"prefix $c suffix\"", None);
    interpolated.source_names = vec!["$c".to_string()];
    assert!(call_arg_is_tainted(&interpolated, &state));
    assert!(
        !arg_text_is_tainted("$cap", &state),
        "$c must not taint a distinct sigil variable whose name only shares a prefix"
    );
    let mut different = arg(1, "\"prefix $cap suffix\"", None);
    different.source_names = vec!["$cap".to_string()];
    assert!(!call_arg_is_tainted(&different, &state));
}

#[test]
fn assignment_rhs_field_reads_do_not_match_sibling_fields() {
    let state = seed(&["data.user"]);

    assert!(
        assignment_rhs_is_tainted("data[\"user\"]", &state),
        "exact field read must match the same tainted field"
    );
    assert!(
        !assignment_rhs_is_tainted("data[\"cmd\"]", &state),
        "tainted sibling field must not taint a different field read"
    );

    let span = Span::new(FileId::new(0), 0, 1);
    assert!(
        !assignment_source_names_any_tainted(&["data".to_string()], span, None, None, &state,),
        "bare carrier source names without RHS text must not inherit sibling field taint"
    );
}

#[test]
fn configured_sanitizer_call_does_not_clear_reference_prefixes_in_inter_transfer() {
    let span = Span::new(FileId::new(0), 0, 1);
    let event = FlowEvent::Call {
        span,
        name: "clean".to_string(),
        receiver: None,
        call_kind: bonsai_lang_api::CallKind::Function,
        receiver_types: Vec::new(),
        args: vec![bonsai_lang_api::CallArg {
            span,
            name: None,
            value_text: "&mut cmd".to_string(),
            place: Some("cmd".to_string()),
            source_names: Vec::new(),
        }],
    };
    let mut state = seed(&["cmd"]);
    apply_event_transfer(&event, &mut state, &config(&["clean"]), None, None);
    assert!(
        state.contains("cmd"),
        "configured sanitizer names must not clear taint during propagation"
    );
}

fn first_call_span(db: &AnalyzerDb, func: FuncId, callee: &str) -> Span {
    let global = db.global_index();
    let decl = global.decl_of(SymbolId::new(func.raw())).expect("function decl");
    find_call_span(&decl.flow_events, callee).expect("call span")
}

fn find_call_span(events: &[FlowEvent], callee: &str) -> Option<Span> {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } if name == callee => return Some(*span),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(span) =
                    find_call_span(then_events, callee).or_else(|| find_call_span(else_events, callee))
                {
                    return Some(span);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(span) = find_call_span(body, callee) {
                    return Some(span);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(span) = find_call_span(body, callee)
                    .or_else(|| find_call_span(catch_events, callee))
                    .or_else(|| find_call_span(finally_events, callee))
                {
                    return Some(span);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn direct_call_propagates_arg_taint_to_callee_param() {
    let src = "
def sink(data):
    os_system(data)

def entry(user_input):
    sink(user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(!result.saturated);
    // We should see one call record: entry → sink with user_input
    // tainting sink's `data` param.
    let prop = result
        .call_records
        .iter()
        .find(|c| c.caller == entry && c.callee == sink)
        .expect("entry → sink propagation must be recorded");
    assert!(
        prop.tainted_args
            .iter()
            .any(|a| a.param_name == "data" && a.value_text == "user_input"),
        "expected tainted user_input → sink's data param; got {:?}",
        prop.tainted_args,
    );
    assert_eq!(prop.edge_kind, EdgeKind::Direct);
    assert_eq!(prop.edge_precision, Precision::Narrowed);
}

#[test]
fn direct_call_preserves_explicit_descendant_taint_for_callee_fields() {
    let caller_state = seed(&["env.*"]);
    let mut callee_seed = TokenSet::default();
    bind_param_taint(&mut callee_seed, "param", "env", &caller_state);
    assert!(
            !callee_seed.contains("param") && callee_seed.contains("param.*"),
            "explicit descendant taint must survive param binding without promoting the whole carrier; seed: {callee_seed:?}"
        );
}

#[test]
fn direct_call_maps_concrete_descendant_taint_without_sibling_wildcard() {
    let caller_state = seed(&["env.cmd"]);
    let mut callee_seed = TokenSet::default();
    bind_param_taint(&mut callee_seed, "param", "env", &caller_state);
    assert!(
        callee_seed.contains("param.cmd"),
        "concrete descendant taint must map to the matching callee field; seed: {callee_seed:?}"
    );
    assert!(
        !callee_seed.contains("param") && !callee_seed.contains("param.*"),
        "concrete descendant taint must not promote the whole callee carrier; seed: {callee_seed:?}"
    );
    assert!(
        !arg_text_is_tainted("param.capacity", &callee_seed),
        "a mapped field must not taint sibling fields; seed: {callee_seed:?}"
    );
}

#[test]
fn named_constructor_field_initializer_taints_only_that_field() {
    let mut state = seed(&["raw"]);
    let args = vec!["{ kind: Kind.Run, cmd: raw, length: raw.length }".to_string()];
    assert!(apply_named_field_arg_taint("envelope", &args, &mut state));
    assert!(
        arg_text_is_tainted("envelope.cmd", &state),
        "field initializer `cmd: raw` must taint envelope.cmd; state: {state:?}"
    );
    assert!(
        !arg_text_is_tainted("envelope.kind", &state),
        "field initializer `cmd: raw` must not taint sibling envelope.kind; state: {state:?}"
    );
}

#[test]
fn compound_arg_token_fallback_keeps_standalone_value_next_to_qualified_access() {
    let state = seed(&["raw"]);
    assert!(
        arg_text_is_tainted("{ cmd: raw, length: raw.length }", &state),
        "standalone raw value must be seen even when raw.length also appears"
    );
    assert!(
        !arg_text_is_tainted("{ length: raw.length }", &state),
        "qualified raw.length alone must not be promoted to raw value taint"
    );
}

#[test]
fn assignment_guard_preserves_direct_carrier_taint_next_to_qualified_access() {
    let mut state = seed(&["value"]);
    let event = FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 1, 10),
        target: "upper".to_string(),
        source_name: None,
        source_call: Some("value.toUpperCase".to_string()),
        source_call_args: Vec::new(),
        source_names: vec![
            "toUpperCase".to_string(),
            "value".to_string(),
            "value.toUpperCase".to_string(),
        ],
        declares_new_binding: false,
        value_kind: None,
    };
    apply_event_transfer(&event, &mut state, &InterTaintConfig::default(), None, None);
    assert!(
        arg_text_is_tainted("upper", &state),
        "directly tainted carrier `value` must survive the qualified-read guard; state={state:?}"
    );
}

#[test]
fn assignment_guard_preserves_direct_sigil_alias_source() {
    let mut state = seed(&["$_GET.*", "_GET.*"]);
    let event = FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 1, 10),
        target: "$user".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["$_GET".to_string(), "$_GET.cmd".to_string(), "_GET".to_string()],
        declares_new_binding: false,
        value_kind: None,
    };
    apply_event_transfer(&event, &mut state, &InterTaintConfig::default(), None, None);
    assert!(
            arg_text_is_tainted("$user", &state),
            "direct `_GET` source must taint `$user` even when qualified `$_GET.cmd` is also present; state={state:?}"
        );
}

#[test]
fn assignment_guard_rejects_direct_carrier_field_read() {
    let mut state = seed(&["c"]);
    let event = FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 1, 10),
        target: "size".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["c".to_string(), "c.capacity".to_string(), "capacity".to_string()],
        declares_new_binding: false,
        value_kind: None,
    };
    apply_event_transfer(&event, &mut state, &InterTaintConfig::default(), None, None);
    assert!(
        !arg_text_is_tainted("size", &state),
        "direct taint on carrier c must not taint independent field-derived size; state={state:?}"
    );
}

#[test]
fn assignment_guard_still_rejects_sibling_field_promotion() {
    let mut state = seed(&["data.value"]);
    let event = FlowEvent::Assign {
        span: Span::new(FileId::INVALID, 1, 10),
        target: "out".to_string(),
        source_name: None,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec!["data".to_string(), "data.other".to_string()],
        declares_new_binding: false,
        value_kind: None,
    };
    apply_event_transfer(&event, &mut state, &InterTaintConfig::default(), None, None);
    assert!(
        !arg_text_is_tainted("out", &state),
        "taint on data.value must not promote through sibling read data.other; state={state:?}"
    );
}

#[test]
fn sizeof_qualified_member_operand_is_value_free_for_taint() {
    let state = seed(&["it.node", "it.*", "node"]);
    assert!(
        !arg_text_is_tainted("sizeof(it->node)", &state),
        "sizeof(member) must not read the member value for taint"
    );
    assert!(
        !arg_text_is_tainted("sizeof(it->node) + FIXED_PAD", &state),
        "sizeof(member) inside a size expression must not preserve member taint"
    );
    assert!(
        !arg_text_is_tainted("sizeof *cp", &seed(&["cp"])),
        "sizeof unary pointer operand must not read the pointer value"
    );
    assert!(
        !arg_text_is_tainted("sizeof(void*) * it->node", &seed(&["it.*"])),
        "value-free size expressions must not promote wildcard carrier taint into metadata fields"
    );
    assert!(
        arg_text_is_tainted("sizeof(void*) * it->node", &seed(&["it.node"])),
        "explicit field taint should still be honored even when sizeof appears in the expression"
    );
}

#[test]
fn receiver_method_projection_handles_unicode_boundaries() {
    let state = seed(&["schema"]);
    assert!(
        !arg_text_is_tainted(
            r#"expect(result.error.issues[0].message).toBe("קטן מדי: הקבוצה")"#,
            &state
        ),
        "unicode string text before a call must not panic or invent receiver taint"
    );
    assert!(
        !arg_text_is_tainted(r#"requests.Request("PUT", data="ööö".encode())"#, &state),
        "multibyte text inside call expressions must keep byte slicing on char boundaries"
    );
}

#[test]
fn branch_clean_overwrite_removes_prebranch_taint_before_sink_call() {
    let src = r#"
import os

def entry(cond):
    x = os.environ["CMD"]
    if cond:
        x = "clean-then"
    else:
        x = "clean-else"
    os_system(x)
"#;
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["x", "os.environ", "environ"]), &config(&[]), &db);
    assert!(
        result.tainted_calls.iter().all(|call| call.name != "os_system"),
        "sink call after clean overwrite in both branches must not be tainted: {:#?}",
        result.tainted_calls
    );
}

#[test]
fn source_call_name_seed_matches_exact_or_tail_only() {
    assert!(source_call_name_is_seeded("rl.question", &seed(&["rl.question"])));
    assert!(source_call_name_is_seeded("rl.question", &seed(&["question"])));
    assert!(
        !source_call_name_is_seeded("rl.question", &seed(&["rl"])),
        "tainted receiver/carrier alone must not make a source-call return tainted"
    );
}

#[test]
fn clean_arg_does_not_propagate_taint() {
    let src = "
def sink(data):
    os_system(data)

def entry(user_input):
    clean_value = 42
    sink(clean_value)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    // entry → sink propagation should NOT be recorded because
    // clean_value is not tainted.
    let leaked = result
        .call_records
        .iter()
        .any(|c| c.caller == entry && c.callee == sink);
    assert!(
        !leaked,
        "false-path detection: clean arg must not propagate taint",
    );
}

// The previous version of this test asserted that `type(receiver)`
// suppresses receiver-taint propagation through the engine's
// hard-coded `type` builtin filter. That filter was removed
// because it embedded a Python library/API name in the engine
// (taint-engine-spec.mdx non-negotiable). The conservative
// direction is over-approximation; any future precise solution
// should be driven by an adapter fact (`returns_metadata_only`
// on `CallEvent`) rather than a string match here.

#[test]
fn unresolved_call_return_does_not_parse_receiver_from_callee_text() {
    let state = seed(&["receiver"]);
    assert!(!unresolved_call_return_is_tainted("receiver.get_cmd", &state));
    assert!(!unresolved_call_return_is_tainted(
        "Repository._new_runner",
        &state
    ));
    assert!(!unresolved_call_return_is_tainted(
        "type(receiver)._new_runner",
        &state
    ));
}

#[test]
fn call_site_receives_taint_rejects_static_helper_return_from_receiver_seed() {
    let src = "
class Repository:
    @classmethod
    def new_runner(klass):
        return 'runner'

    def entry(receiver):
        runner = Repository.new_runner()
        os_system(runner)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let span = first_call_span(&db, entry, "os_system");
    assert!(
        !call_site_receives_taint(entry, span, &seed(&["receiver"]), &config(&[]), &db),
        "receiver taint must not leak through unrelated class/static helper returns"
    );
}

#[test]
fn call_site_receives_taint_rejects_clean_sink_in_reachable_callee() {
    let src = "
def safe():
    os_system('constant')

def entry(user_input):
    safe()
";
    let db = python_ws_one_file(src);
    let safe = func_id_of(&db, "safe");
    let span = first_call_span(&db, safe, "os_system");
    assert!(
        !call_site_receives_taint(safe, span, &seed(&["user_input"]), &config(&[]), &db),
        "clean constant sink arg must not be treated as tainted"
    );
}

#[test]
fn call_site_receives_taint_accepts_compound_tainted_sink_arg() {
    let src = "
def entry(user_input):
    os_system('prefix ' + user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let span = first_call_span(&db, entry, "os_system");
    assert!(
        call_site_receives_taint(entry, span, &seed(&["user_input"]), &config(&[]), &db),
        "compound sink arg containing a tainted identifier must be detected"
    );
}

#[test]
fn unresolved_call_assignment_with_source_operands_preserves_taint() {
    let assign_span = Span::new(FileId::INVALID, 1, 10);
    let sink_span = Span::new(FileId::INVALID, 20, 30);
    let events = vec![
        FlowEvent::Assign {
            span: assign_span,
            target: "full_cmd".to_string(),
            source_name: None,
            source_call: Some("format".to_string()),
            source_call_args: Vec::new(),
            source_names: vec!["cmd".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: sink_span,
            name: "os_system".to_string(),
            receiver: None,
            call_kind: bonsai_lang_api::CallKind::Function,
            receiver_types: Vec::new(),
            args: vec![bonsai_lang_api::CallArg {
                span: sink_span,
                name: None,
                place: None,
                source_names: Vec::new(),
                value_text: "full_cmd".to_string(),
            }],
        },
    ];
    let db = python_ws_one_file("def placeholder():\n    pass\n");
    let config = config(&[]);
    let aliases = AHashMap::new();
    let alias_targets = AHashMap::new();
    let local_bindings = AHashMap::new();
    let const_bindings = AHashMap::new();
    let ctx = SinkWalkCtx {
        sink_span,
        config: &config,
        db: &db,
        aliases: &aliases,
        alias_targets: &alias_targets,
        local_bindings: &local_bindings,
        const_bindings: &const_bindings,
        caller: func_id_of(&db, "placeholder"),
    };
    let (_, found) = walk_events_for_sink(
        &events,
        seed(&["cmd"]),
        &ctx,
        &parking_lot::RwLock::new(AHashMap::new()),
    );
    assert!(
        found,
        "unresolved formatter-style assignment must use source_names before evaluating the sink"
    );
}

#[test]
fn configured_source_output_arg_introduces_taint_after_clean_initialization() {
    let init_span = Span::new(FileId::INVALID, 1, 10);
    let source_assign_span = Span::new(FileId::INVALID, 11, 20);
    let source_call_span = Span::new(FileId::INVALID, 21, 30);
    let envelope_span = Span::new(FileId::INVALID, 31, 40);
    let sink_span = Span::new(FileId::INVALID, 41, 50);
    let events = vec![
        FlowEvent::Assign {
            span: init_span,
            target: "raw".to_string(),
            source_name: None,
            source_call: Some("String::new".to_string()),
            source_call_args: Vec::new(),
            source_names: vec!["String".to_string(), "new".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Assign {
            span: source_assign_span,
            target: "_".to_string(),
            source_name: None,
            source_call: Some("stdin.lock().read_line".to_string()),
            source_call_args: vec!["&mut raw".to_string()],
            source_names: vec!["raw".to_string(), "stdin.lock().read_line".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: source_call_span,
            name: "stdin.lock().read_line".to_string(),
            receiver: Some("stdin.lock()".to_string()),
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Method,
            args: vec![arg(21, "&mut raw", Some("raw"))],
        },
        FlowEvent::Assign {
            span: envelope_span,
            target: "envelope".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["raw.trim".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Call {
            span: sink_span,
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![arg(41, "envelope", Some("envelope"))],
        },
    ];
    let db = python_ws_one_file("def placeholder():\n    pass\n");
    let config = InterTaintConfig {
        source_output_args: vec![SourceOutputArgs {
            callee: "read_line".to_string(),
            output_arg_indices: vec![0],
        }],
        ..config(&[])
    };
    let aliases = AHashMap::new();
    let alias_targets = AHashMap::new();
    let local_bindings = AHashMap::new();
    let const_bindings = AHashMap::new();
    let ctx = SinkWalkCtx {
        sink_span,
        config: &config,
        db: &db,
        aliases: &aliases,
        alias_targets: &alias_targets,
        local_bindings: &local_bindings,
        const_bindings: &const_bindings,
        caller: func_id_of(&db, "placeholder"),
    };
    let (_, found) = walk_events_for_sink(
        &events,
        TokenSet::default(),
        &ctx,
        &parking_lot::RwLock::new(AHashMap::new()),
    );
    assert!(
        found,
        "configured source-output calls must introduce taint at the call site, after earlier clean initializers"
    );
}

#[test]
fn configured_output_arg_flow_taints_later_buffer_consumer() {
    let format_span = Span::new(FileId::INVALID, 11, 20);
    let sink_span = Span::new(FileId::INVALID, 21, 30);
    let events = vec![
        FlowEvent::Call {
            span: format_span,
            name: "sprintf".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![
                arg(11, "buf", Some("buf")),
                arg(12, "\"echo %s\"", None),
                arg(13, "user", Some("user")),
            ],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "system".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![arg(21, "buf", Some("buf"))],
        },
    ];
    let db = python_ws_one_file("def placeholder():\n    pass\n");
    let config = InterTaintConfig {
        output_arg_flows: vec![OutputArgFlow {
            callee: "sprintf".to_string(),
            output_arg_index: 0,
            value_start_arg_index: Some(1),
            value_arg_indices: Vec::new(),
        }],
        ..config(&[])
    };
    let aliases = AHashMap::new();
    let alias_targets = AHashMap::new();
    let local_bindings = AHashMap::new();
    let const_bindings = AHashMap::new();
    let ctx = SinkWalkCtx {
        sink_span,
        config: &config,
        db: &db,
        aliases: &aliases,
        alias_targets: &alias_targets,
        local_bindings: &local_bindings,
        const_bindings: &const_bindings,
        caller: func_id_of(&db, "placeholder"),
    };
    let (_, found) = walk_events_for_sink(
        &events,
        seed(&["user"]),
        &ctx,
        &parking_lot::RwLock::new(AHashMap::new()),
    );
    assert!(
        found,
        "configured output-arg flow should taint the formatted buffer"
    );
}

#[test]
fn unconfigured_output_arg_flow_does_not_taint_later_buffer_consumer() {
    let format_span = Span::new(FileId::INVALID, 11, 20);
    let sink_span = Span::new(FileId::INVALID, 21, 30);
    let events = vec![
        FlowEvent::Call {
            span: format_span,
            name: "sprintf".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![
                arg(11, "buf", Some("buf")),
                arg(12, "\"echo %s\"", None),
                arg(13, "user", Some("user")),
            ],
        },
        FlowEvent::Call {
            span: sink_span,
            name: "system".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: vec![arg(21, "buf", Some("buf"))],
        },
    ];
    let db = python_ws_one_file("def placeholder():\n    pass\n");
    let config = config(&[]);
    let aliases = AHashMap::new();
    let alias_targets = AHashMap::new();
    let local_bindings = AHashMap::new();
    let const_bindings = AHashMap::new();
    let ctx = SinkWalkCtx {
        sink_span,
        config: &config,
        db: &db,
        aliases: &aliases,
        alias_targets: &alias_targets,
        local_bindings: &local_bindings,
        const_bindings: &const_bindings,
        caller: func_id_of(&db, "placeholder"),
    };
    let (_, found) = walk_events_for_sink(
        &events,
        seed(&["user"]),
        &ctx,
        &parking_lot::RwLock::new(AHashMap::new()),
    );
    assert!(
        !found,
        "unconfigured calls must not get hidden output-arg propagation"
    );
}

#[test]
fn compound_non_call_assignment_rhs_preserves_taint() {
    let src = r#"
sub entry {
    my ($input) = @_;
    my $raw = $input;
    $raw = defined $raw ? $raw : '';
    sink($raw);
}

sub sink {
    my ($cmd) = @_;
    system($cmd);
}
"#;
    let db = perl_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["$input"]), &config(&[]), &db);
    assert!(
            result
                .tainted_calls
                .iter()
                .any(|call| call.name == "system"
                    && call.tainted_args.iter().any(|arg| arg.value_text == "$cmd")),
            "ternary self-assignment should preserve taint through Perl defined/defaulting flow: {:?}",
            result.tainted_calls
        );
}

#[test]
fn field_read_return_summary_maps_descendant_taint_to_scalar_return() {
    let src = r#"
sub wrap {
    my ($envelope) = @_;
    my $cmd = $envelope->{cmd};
    return wantarray ? ($cmd) : $cmd;
}
"#;
    let db = perl_ws_one_file(src);
    let wrap = func_id_of(&db, "wrap");
    let summary = function_summary(&db, wrap);
    assert!(
        summary.returns_descendant_taint_of.contains(&0),
        "returning a field read from param0 should summarize descendant taint: {summary:?}"
    );
}

#[test]
fn call_assignment_applies_descendant_return_summary_as_scalar_value() {
    let src = r#"
sub wrap {
    my ($envelope) = @_;
    my $cmd = $envelope->{cmd};
    return wantarray ? ($cmd) : $cmd;
}

sub entry {
    my ($envelope) = @_;
    my $cmd = wrap($envelope);
    system($cmd);
}
"#;
    let db = perl_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let wrap = func_id_of(&db, "wrap");
    let summary = function_summary(&db, wrap);
    assert!(
        summary.returns_descendant_taint_of.contains(&0),
        "test setup expected wrap descendant return summary: {summary:?}"
    );
    let result = interprocedural_taint(entry, &seed(&["$envelope.*", "envelope.*"]), &config(&[]), &db);
    assert!(
            result
                .tainted_calls
                .iter()
                .any(|call| call.name == "system"
                    && call.tainted_args.iter().any(|arg| arg.value_text == "$cmd")),
            "call assignment from descendant-returning helper should taint scalar target: {:?}",
            result.tainted_calls
        );
}

#[test]
fn call_site_receives_taint_ignores_identifier_inside_string_literal() {
    let src = "
def entry(cmd):
    os_system('cmd')
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let span = first_call_span(&db, entry, "os_system");
    assert!(
        !call_site_receives_taint(entry, span, &seed(&["cmd"]), &config(&[]), &db),
        "a string literal containing a tainted variable name is not value taint"
    );
}

#[test]
fn call_site_receives_taint_detects_string_interpolation() {
    let src = "
def entry(cmd):
    os_system(f'notify {cmd}')
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let span = first_call_span(&db, entry, "os_system");
    assert!(
        call_site_receives_taint(entry, span, &seed(&["cmd"]), &config(&[]), &db),
        "string interpolation containing a tainted variable is value taint"
    );
}

#[test]
fn call_site_receives_taint_rejects_sink_after_clean_reassignment() {
    let src = "
def run(cmd):
    cmd = 'constant'
    os_system(cmd)
";
    let db = python_ws_one_file(src);
    let run = func_id_of(&db, "run");
    let span = first_call_span(&db, run, "os_system");
    assert!(
        !call_site_receives_taint(run, span, &seed(&["cmd"]), &config(&[]), &db),
        "semantic reassignment to a clean value must clear stale param taint"
    );
}

#[test]
fn chained_call_propagates_through_two_hops() {
    // entry → middle → sink — taint must reach sink via middle.
    let src = "
def sink(payload):
    os_system(payload)

def middle(forwarded):
    sink(forwarded)

def entry(user_input):
    middle(user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let middle = func_id_of(&db, "middle");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    // Two call records: entry→middle and middle→sink.
    assert!(result
        .call_records
        .iter()
        .any(|c| c.caller == entry && c.callee == middle));
    assert!(result
        .call_records
        .iter()
        .any(|c| c.caller == middle && c.callee == sink));
}

#[test]
fn configured_sanitizer_in_caller_still_propagates() {
    // Sanitizer names are metadata only. The call result remains
    // tainted when the callee returns tainted input.
    let src = "
def sink(data):
    os_system(data)

def sanitize(x):
    return x

def entry(user_input):
    clean = sanitize(user_input)
    sink(clean)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&["sanitize"]), &db);
    let sink_prop = result
        .call_records
        .iter()
        .find(|c| c.caller == entry && c.callee == sink);
    assert!(
        sink_prop.is_some(),
        "configured sanitizer names must not block propagation to sink",
    );
}

#[test]
fn positional_arg_maps_to_correct_param() {
    // sink(first, second) with tainted value in position 1 only —
    // must taint `second`, not `first`.
    let src = "
def sink(first, second):
    os_system(second)

def entry(user_input):
    clean = 0
    sink(clean, user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    let prop = result
        .call_records
        .iter()
        .find(|c| c.caller == entry && c.callee == sink)
        .expect("entry→sink must be recorded");
    // Should taint only `second` (index 1).
    let tainted_params: Vec<&str> = prop.tainted_args.iter().map(|a| a.param_name.as_str()).collect();
    assert_eq!(
        tainted_params,
        vec!["second"],
        "only position-1 arg should taint — got {tainted_params:?}",
    );
}

#[test]
fn implicit_method_receiver_slot_does_not_shift_tainted_argument_to_receiver() {
    let src = "
class Runner:
    def execute(self, cmd):
        os_system(cmd)

def entry(user_input):
    runner = Runner()
    runner.execute(user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let execute = func_id_of(&db, "execute");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    let prop = result
        .call_records
        .iter()
        .find(|c| c.caller == entry && c.callee == execute)
        .expect("entry→execute must be recorded");
    let tainted_params: Vec<&str> = prop.tainted_args.iter().map(|a| a.param_name.as_str()).collect();
    assert_eq!(
            tainted_params,
            vec!["cmd"],
            "adapter-declared receiver param must be skipped for implicit method-call args; got {tainted_params:?}",
        );
}

#[test]
fn unresolved_callee_does_not_propagate() {
    // Call to an external name that doesn't exist in the
    // workspace — resolver returns zero candidates, so no
    // propagation record.
    let src = "
def entry(user_input):
    external_unknown(user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(result.call_records.is_empty());
    assert_eq!(result.precision, Precision::Exact);
}

#[test]
fn unresolved_out_param_side_effect_does_not_propagate() {
    let src = "
def entry(user_input):
    buf = ''
    external_fill(buf, user_input)
    os_system(buf)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert_eq!(
        result.precision,
        Precision::Exact,
        "opaque out-param side effects must not degrade or invent flow"
    );
    assert!(
        !result
            .tainted_calls
            .iter()
            .any(|call| call.name == "os_system"
                && call.tainted_args.iter().any(|arg| arg.value_text == "buf")),
        "opaque side effect should not taint the later sink arg: {:?}",
        result.tainted_calls
    );
}

#[test]
fn multi_candidate_callee_does_not_propagate() {
    let db = python_ws_multi(&[
        (
            "main.py",
            "
def entry(user_input):
    run(user_input)
",
        ),
        (
            "a.py",
            "
def run(a):
    os_system(a)
",
        ),
        (
            "b.py",
            "
def run(a):
    os_system(a)
",
        ),
    ]);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(
        result.call_records.is_empty(),
        "ambiguous `run` must not produce call records; got {:?}",
        result.call_records,
    );
    assert_eq!(
        result.precision,
        Precision::Exact,
        "ambiguous callee must not degrade precision by guessing",
    );
}

#[test]
fn recursion_terminates_via_seen_cache() {
    // Direct self-recursion: foo calls itself. Without the seen
    // cache this would loop forever.
    let src = "
def foo(x):
    foo(x)

def entry(user_input):
    foo(user_input)
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(!result.saturated);
    // pairs_analyzed should be small (entry once, foo once) —
    // definitely less than the budget.
    assert!(result.pairs_analyzed < 10);
}

#[test]
fn cross_module_propagation_through_import() {
    // Two files, cross-module call. The resolver lets the taint
    // flow from main.py's entry into sink_service.py's sink.
    let sink_src = "
def sink(payload):
    os_system(payload)
";
    let main_src = "
from sink_service import sink

def entry(user_input):
    sink(user_input)
";
    let db = python_ws_multi(&[("sink_service.py", sink_src), ("main.py", main_src)]);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(
        result
            .call_records
            .iter()
            .any(|c| c.caller == entry && c.callee == sink),
        "cross-module propagation must work — got call records: {:?}",
        result
            .call_records
            .iter()
            .map(|c| (c.caller, c.callee))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn cross_module_alias_rewrite_resolves_to_original() {
    // `from sink_service import sink as run_it; run_it(tainted)`
    // — the alias map in main.py must rewrite `run_it` → `sink`
    // before resolving.
    let sink_src = "
def sink(payload):
    os_system(payload)
";
    let main_src = "
from sink_service import sink as run_it

def entry(user_input):
    run_it(user_input)
";
    let db = python_ws_multi(&[("sink_service.py", sink_src), ("main.py", main_src)]);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(
        result
            .call_records
            .iter()
            .any(|c| c.caller == entry && c.callee == sink),
        "alias `run_it` → `sink` must resolve through the alias map",
    );
}

#[test]
fn import_qualified_candidate_does_not_retry_bare_tail() {
    let db = python_ws_one_file(
        r#"
import fmt as fmt

class fmt:
    pass

def Println(value):
    sink(value)

def entry(value):
    pass
"#,
    );
    let entry = func_id_of(&db, "entry");
    let aliases = AHashMap::from_iter([("fmt".to_string(), "fmt".to_string())]);
    let alias_targets = AHashMap::from_iter([(
        "fmt".to_string(),
        AliasTarget::Namespace {
            module: "fmt".to_string(),
        },
    )]);

    let candidates = resolve_call_candidates_with_caller(
        "fmt:Println",
        &aliases,
        &alias_targets,
        &AHashMap::new(),
        &db,
        entry,
        &InterTaintConfig::default(),
    );

    assert!(
        candidates.is_empty(),
        "fmt:Println must resolve through the fmt import target or remain unresolved; \
         retrying bare Println fabricates a taint edge to the local function"
    );
}

#[test]
fn commonjs_default_require_callable_module_exports_function_resolves() {
    let db = javascript_ws_multi(&[
        (
            "src/controller.js",
            r#"const render = require("./view");
function handle(el, html) {
  return render(el, html);
}
"#,
        ),
        (
            "src/view.js",
            r#"module.exports = function render(el, html) {
  el.innerHTML = html;
};
"#,
        ),
    ]);
    let handle = func_id_of(&db, "handle");
    let default_export = func_id_of(&db, "default");
    let global = db.global_index();
    let decl = global
        .decl_of(SymbolId::new(handle.raw()))
        .expect("handle decl")
        .clone();
    let file = global
        .declaring_file(SymbolId::new(handle.raw()))
        .expect("handle file");
    let aliases = alias_map_for_file(&db.imports_for(file));
    let alias_targets = alias_targets_for_decl(&db.imports_for(file), &decl);
    let local_bindings = bonsai_callgraph::collect_local_callable_bindings_with_aliases(
        &decl.flow_events,
        &global,
        &decl,
        &alias_targets,
    );

    let candidates = resolve_call_candidates_with_caller(
        "render",
        &aliases,
        &alias_targets,
        &local_bindings,
        &db,
        handle,
        &InterTaintConfig::default(),
    );

    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.func == default_export),
        "CommonJS default callable require must resolve to module.exports function; \
         aliases={aliases:?} alias_targets={alias_targets:?} candidates={candidates:?}"
    );
}

#[test]
fn rust_imported_instance_and_static_methods_propagate_into_impl_body() {
    let db = rust_ws_multi(&[
        (
            "util.rs",
            r#"pub struct Util;
impl Util {
    pub fn helper(&self, p: String) { sink(p); }
    pub fn static_helper(p: String) { sink(p); }
}
"#,
        ),
        (
            "entry.rs",
            r#"use crate::util::Util;
pub fn entry(args: String) {
    let u = Util;
    u.helper(args);
    Util::static_helper(args);
}
"#,
        ),
    ]);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &config(&[]), &db);

    assert!(
        result
            .tainted_calls
            .iter()
            .any(|call| call.name == "sink" && call.tainted_args.iter().any(|arg| arg.value_text == "p")),
        "Rust imported impl methods must propagate taint into the impl body; got {:#?}",
        result.tainted_calls
    );
}

#[test]
fn unqualified_local_function_shadows_import_alias_in_legacy_inter_resolver() {
    let db = python_ws_multi(&[
        ("helper.py", "def helper(p):\n    decoy_sink(p)\n"),
        (
            "entry.py",
            "from helper import helper\n\ndef helper(p):\n    sink(p)\n\ndef entry(args):\n    helper(args)\n",
        ),
    ]);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &config(&[]), &db);

    assert!(
        result
            .tainted_calls
            .iter()
            .any(|call| call.name == "sink" && call.tainted_args.iter().any(|arg| arg.value_text == "p")),
        "local helper should receive taint; got {:#?}",
        result.tainted_calls
    );
    assert!(
        !result.tainted_calls.iter().any(|call| call.name == "decoy_sink"),
        "imported decoy helper must not receive taint when shadowed locally; got {:#?}",
        result.tainted_calls
    );
}

#[test]
fn budget_cap_is_honored() {
    // Ten-hop chain with budget=3 — worklist should stop early
    // and report saturated=true.
    let mut src = String::new();
    for i in 0..10 {
        src.push_str(&format!("def hop{i}(x):\n    hop{next}(x)\n\n", next = i + 1));
    }
    // Final hop doesn't call anything so the chain terminates
    // naturally if the budget permits.
    src.push_str("def hop10(x):\n    pass\n\n");
    src.push_str("def entry(user_input):\n    hop0(user_input)\n");
    let db = python_ws_one_file(&src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(
        entry,
        &seed(&["user_input"]),
        &InterTaintConfig {
            sanitizers: TokenSet::default(),
            budget: 3,
            intra_worklist_cap: None,
            ..Default::default()
        },
        &db,
    );
    assert!(
        result.saturated,
        "budget=3 on an 11-function chain must hit the cap",
    );
    assert!(
        matches!(result.precision, Precision::Exact | Precision::Narrowed),
        "budget chunking is an execution limit, not a resolver-imprecision source: {:?}",
        result.precision
    );
    assert!(result.pairs_analyzed <= 3);
    assert!(
        result.continuation.is_some(),
        "saturated runs must carry a continuation instead of dropping the pending work item"
    );
}

#[test]
fn budgeted_run_can_resume_to_completion() {
    let mut src = String::new();
    for i in 0..10 {
        src.push_str(&format!("def hop{i}(x):\n    hop{next}(x)\n\n", next = i + 1));
    }
    src.push_str("def hop10(x):\n    sink(x)\n\n");
    src.push_str("def sink(x):\n    pass\n\n");
    src.push_str("def entry(user_input):\n    hop0(user_input)\n");
    let db = python_ws_one_file(&src);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: 3,
        intra_worklist_cap: None,
        ..Default::default()
    };
    let caches = InterTaintCaches::default();
    let result =
        interprocedural_taint_to_completion_with_caches(entry, &seed(&["user_input"]), &config, &db, &caches);
    assert!(!result.saturated);
    assert!(result.continuation.is_none());
    assert!(
        result.call_records.iter().any(|record| record.callee == sink),
        "resumed run must reach the final sink instead of stopping at the first budget chunk",
    );
    assert!(
        matches!(result.precision, Precision::Exact | Precision::Narrowed),
        "resuming must not leave a stale unknown/over-approximate precision marker: {:?}",
        result.precision
    );
}

#[test]
fn to_completion_has_no_hidden_pair_ceiling() {
    let mut src = String::new();
    for i in 0..40 {
        src.push_str(&format!("def hop{i}(x):\n    hop{next}(x)\n\n", next = i + 1));
    }
    src.push_str("def hop40(x):\n    sink(x)\n\n");
    src.push_str("def sink(x):\n    pass\n\n");
    src.push_str("def entry(user_input):\n    hop0(user_input)\n");
    let db = python_ws_one_file(&src);
    let entry = func_id_of(&db, "entry");
    let sink = func_id_of(&db, "sink");
    let config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: 3,
        intra_worklist_cap: None,
        ..Default::default()
    };
    let caches = InterTaintCaches::default();
    let result =
        interprocedural_taint_to_completion_with_caches(entry, &seed(&["user_input"]), &config, &db, &caches);
    assert!(!result.saturated);
    assert!(result.continuation.is_none());
    assert!(
        result.pairs_analyzed > config.budget * 8,
        "to-completion must keep resuming beyond the old hidden budget*8 ceiling"
    );
    assert!(
        result.call_records.iter().any(|record| record.callee == sink),
        "to-completion must reach sinks beyond the old hidden pair ceiling",
    );
}

#[test]
fn function_without_matching_param_doesnt_crash() {
    // sink takes zero args; entry still calls it. Edge case —
    // we record a propagation with zero tainted_args.
    let src = "
def sink():
    os_system('hardcoded')

def entry(user_input):
    sink()
";
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let _sink = func_id_of(&db, "sink");
    let result = interprocedural_taint(entry, &seed(&["user_input"]), &config(&[]), &db);
    assert!(!result.saturated);
    // No propagation because the call has no args at all.
    assert!(result.call_records.is_empty());
}

#[test]
fn try_body_throws_tainted_via_assigned_then_raised() {
    // `e = ValueError(cmd); raise e` — the catch param `e` should
    // be tainted because the throw value name `e` was bound from
    // a tainted RHS just before the raise. Pre-fix the helper
    // only checked the static taint set, missing the assignment
    // before the throw.
    let span = Span::new(FileId::new(0), 0, 1);
    let body = vec![
        FlowEvent::Assign {
            span,
            target: "e".to_string(),
            source_name: Some("cmd".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["cmd".to_string()],
            declares_new_binding: false,
            value_kind: None,
        },
        FlowEvent::Throw {
            span,
            value_name: Some("e".to_string()),
            thrown_type: None,
        },
    ];
    let state = seed(&["cmd"]);
    assert!(
        try_body_throws_tainted(&body, &state),
        "tainted value reassigned then raised must be observed by the catch-param seeding"
    );
}

#[test]
fn try_body_throws_tainted_clean_throw_with_clean_state() {
    // No taint anywhere — must NOT report.
    let span = Span::new(FileId::new(0), 0, 1);
    let body = vec![FlowEvent::Throw {
        span,
        value_name: Some("e".to_string()),
        thrown_type: None,
    }];
    assert!(
        !try_body_throws_tainted(&body, &TokenSet::default()),
        "empty state must produce no catch-param tainting"
    );
}

#[test]
fn try_body_throws_tainted_compound_throw_conservative() {
    // `raise ValueError(tainted)` — adapter emits Throw{value_name: None}
    // but state holds `tainted`. Conservative: report as tainted to
    // preserve recall.
    let span = Span::new(FileId::new(0), 0, 1);
    let body = vec![FlowEvent::Throw {
        span,
        value_name: None,
        thrown_type: None,
    }];
    let state = seed(&["tainted"]);
    assert!(
        try_body_throws_tainted(&body, &state),
        "compound throw with non-empty state must conservatively report tainted"
    );
}

#[test]
fn standalone_engine_tracks_multi_hop_object_field_flow_no_rulepack() {
    // Engine-only multi-hop: source `req` flows through
    // copy() (returns object whose .value field carries the
    // taint), then buildQuery() (concatenates obj.value into
    // a SQL string), then db.query(). No rulepack, no
    // source_bearing_functions hack — pure dataflow graph
    // built from adapter facts + interprocedural worklist.
    // This is the "fully procedural" baseline the engine must
    // hold up regardless of the security layer.
    let src = "
def copy(user):
    return {'value': user}

def build_query(obj):
    return 'SELECT * FROM users WHERE name = ' + obj['value']

def handler(req):
    data = copy(req)
    q = build_query(data)
    db_query(q)

def db_query(q):
    pass
";
    let db = python_ws_one_file(src);
    let handler = func_id_of(&db, "handler");
    let db_query = func_id_of(&db, "db_query");
    let result = interprocedural_taint(handler, &seed(&["req"]), &config(&[]), &db);
    // Cross-function propagation: the taint of req must reach
    // db_query through copy + build_query without any
    // rulepack seeding.
    assert!(
        result.call_records.iter().any(|r| r.callee == db_query),
        "engine must report a cross-function record into db_query \
             from a tainted-req entry; got {} records",
        result.call_records.len(),
    );
    // The chain must be at least 3 hops (handler → copy +
    // build_query → db_query) — i.e. multiple call records,
    // not just one direct edge.
    assert!(
        result.call_records.len() >= 2,
        "multi-hop object-field flow should produce >= 2 \
             call records; got {}",
        result.call_records.len(),
    );
}

#[test]
fn empty_seed_with_yield_event_produces_no_propagation() {
    // Engine invariant: empty seed → no propagation records.
    // Confirm Yield handler does not invent taint.
    let src = "
def gen():
    yield 1
    yield 2

def main():
    for x in gen():
        sink(x)
";
    let db = python_ws_one_file(src);
    let main = func_id_of(&db, "main");
    let result = interprocedural_taint(main, &TokenSet::default(), &config(&[]), &db);
    assert!(
        result.call_records.is_empty(),
        "Yield/Await/comprehension handlers must not invent taint on empty seed; got {:?}",
        result.call_records
    );
}

#[test]
fn constructor_named_arg_taints_only_matching_receiver_field() {
    let src = r#"
class Repository:
    def __init__(self, data, who="anon"):
        self._data = data
        self.who = who

    def persist(self):
        cmd = self._data["cmd"]
        sink_cmd(cmd)
        sink_who(self.who)

def entry(valid, user):
    repo = Repository(valid, who=user)
    repo.persist()
"#;
    let db = python_ws_one_file(src);
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["user"]), &config(&[]), &db);

    assert!(
        result.tainted_calls.iter().any(|call| call.name == "sink_who"),
        "constructor named arg should taint the matching receiver field: {:?}",
        result.tainted_calls
    );
    assert!(
        result.tainted_calls.iter().all(|call| call.name != "sink_cmd"),
        "constructor named arg must not taint unrelated data field: {:?}",
        result.tainted_calls
    );
}

fn receiver_allows_name_fallback(
    receiver: &str,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> bool {
    let receiver = normalise_qualified_text(receiver);
    let receiver = receiver.trim();
    if receiver.is_empty() {
        return false;
    }
    if receiver
        .chars()
        .any(|ch| matches!(ch, '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\'' | '`') || ch.is_whitespace())
    {
        return false;
    }
    let head = receiver
        .split(&['.', ':', '\\', '('][..])
        .next()
        .unwrap_or(receiver);
    aliases.contains_key(head) || alias_targets.contains_key(head)
}

#[test]
fn expression_receiver_does_not_fall_back_to_bare_method_name() {
    let aliases = AHashMap::new();
    let alias_targets = AHashMap::new();

    assert!(
        !receiver_allows_name_fallback("pkg.Command(\"sh\")", &aliases, &alias_targets),
        "expression receivers must not resolve through the bare tail `Run`"
    );
    assert!(
        !receiver_allows_name_fallback("Runtime", &aliases, &alias_targets),
        "class-looking receivers are not semantic evidence by themselves"
    );
    assert!(
        !receiver_allows_name_fallback("Repository.wrap(envelope)", &aliases, &alias_targets),
        "factory receivers must resolve through semantic return-type evidence, not the bare tail"
    );

    let db = python_ws_one_file(
        r#"
def Run(value):
    sink(value)

def entry(args):
    pkg.Command("sh").Run(args)
"#,
    );
    let entry = func_id_of(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["args"]), &config(&[]), &db);
    assert!(
        result.call_records.iter().all(|record| {
            let global = db.global_index();
            global
                .decl_of(SymbolId::new(record.callee.raw()))
                .is_none_or(|decl| decl.name != "Run")
        }),
        "expression receiver must not fabricate an edge to a same-named top-level `Run`"
    );
}
