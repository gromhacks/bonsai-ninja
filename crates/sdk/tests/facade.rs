use std::path::PathBuf;
use std::sync::Mutex;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn python_micro() -> PathBuf {
    repo_root().join("examples/python/micro")
}

fn temp_python_micro(name: &str) -> PathBuf {
    let dst = std::env::temp_dir().join(format!("bonsai-sdk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    copy_dir(&python_micro(), &dst);
    dst
}

fn tempdir(name: &str) -> PathBuf {
    let dst = std::env::temp_dir().join(format!(
        "bonsai-sdk-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dst).expect("create tempdir");
    dst
}

fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("create temp fixture dir");
    for entry in std::fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name();
        if name == ".bonsai" {
            continue;
        }
        let target = dst.join(name);
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            std::fs::copy(&path, &target).expect("copy fixture file");
        }
    }
}

fn sdk() -> bonsai_sdk::Bonsai {
    bonsai_sdk::Bonsai::new()
        .with_rulepack(repo_root().join("security-patterns"))
        .expect("rulepack")
}

#[test]
fn facade_indexes_and_exposes_workspace_basics() {
    let root = temp_python_micro("cache");
    let project = sdk().index(&root).expect("index");

    assert!(project.stats().files > 0);
    assert!(project.diagnostics().is_empty());
    assert!(project.rulepack().is_some());
    assert!(project.rulepack_root().is_some());
    let stats = project.cache().stats().expect("cache stats after index");
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "SDK index should stay structural unless full prewarm/cache rebuild is requested"
    );
    project.cache().rebuild_dataflow().expect("rebuild dataflow");
    assert!(project.load_dataflow_sidecar().expect("load sidecar") > 0);
    let stats = project.cache().stats().expect("cache stats");
    assert!(stats.bonsai_dir_exists);
    assert!(
        stats.dataflow_sidecar_exists,
        "explicit cache rebuild should write the legacy SDK dataflow sidecar"
    );
    assert!(
        !stats.dataflow_factstore_sidecar_exists,
        "cache rebuild should not imply the streaming full-prewarm factstore path"
    );
    project.cache().clear_dataflow_only().expect("clear dataflow");
    let stats = project.cache().stats().expect("cache stats after clear");
    assert!(!stats.dataflow_sidecar_exists);
    assert!(!stats.dataflow_factstore_sidecar_exists);
    project.cache().rebuild_dataflow().expect("rebuild dataflow");
    assert!(
        project
            .cache()
            .stats()
            .expect("cache stats after rebuild")
            .dataflow_sidecar_exists
    );
    project
        .export()
        .warm_default_json_cache()
        .expect("warm default export cache");
    let stats = project.cache().stats().expect("cache stats after export warm");
    assert!(
        stats.export_sidecar_exists,
        "warming the default export cache must write the sidecar"
    );
    let export_json = std::fs::read_to_string(&stats.export_sidecar).expect("read export sidecar");
    let parsed: serde_json::Value = serde_json::from_str(&export_json).expect("export sidecar JSON parses");
    assert!(
        parsed.get("taint_graph").is_some(),
        "export sidecar should contain native export JSON"
    );
    let root_cache = sdk().cache(&root);
    assert!(root_cache.stats().expect("root cache stats").bonsai_dir_exists);
    root_cache.clear_all().expect("root cache clear all");
    assert!(
        !root_cache
            .stats()
            .expect("root cache stats after clear")
            .bonsai_dir_exists
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_index_with_progress_reports_workspace_lifecycle() {
    let root = temp_python_micro("progress");
    let events = Mutex::new(Vec::new());
    let project = sdk()
        .index_with_progress(&root, |event| {
            events.lock().expect("events lock").push(event);
        })
        .expect("index with progress");

    assert!(project.stats().files > 0);
    let events = events.into_inner().expect("events lock");
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::IngestStarted));
    let parsed_files = events
        .iter()
        .find_map(|event| match event {
            bonsai_sdk::WorkspaceOpenEvent::ParseStarted { files } => Some(*files),
            _ => None,
        })
        .expect("parse started event");
    assert_eq!(parsed_files, project.stats().files);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::ParseFileIndexed))
            .count(),
        parsed_files
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmStarted { .. }
                | bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmFinished
                | bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmStarted
                | bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmFinished
                | bonsai_sdk::WorkspaceOpenEvent::FlowIdsPrewarmStarted
                | bonsai_sdk::WorkspaceOpenEvent::FlowIdsPrewarmFinished
        )),
        "index_with_progress should report structural indexing only by default"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_full_prewarm_with_progress_reports_analysis_prewarm() {
    let root = temp_python_micro("progress-full-prewarm");
    let events = Mutex::new(Vec::new());
    let project = sdk()
        .open_with_options_and_progress(&root, bonsai_sdk::OpenOptions::full_prewarm(), |event| {
            events.lock().expect("events lock").push(event);
        })
        .expect("full prewarm with progress");

    assert!(project.stats().files > 0);
    let events = events.into_inner().expect("events lock");
    assert!(events.iter().any(|event| matches!(
        event,
        bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmStarted { .. }
    )));
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmFinished));
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmStarted));
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmFinished));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_hot_reloads_saved_source_changes() {
    let root = tempdir("hot-reload");
    let app = root.join("app.py");
    std::fs::write(&app, "def old_name():\n    pass\n").expect("write initial source");
    let project = bonsai_sdk::Bonsai::new().index(&root).expect("index");

    let names = |project: &bonsai_sdk::Project| -> Vec<String> {
        project
            .browse()
            .defs(Default::default())
            .expect("defs")
            .into_iter()
            .map(|def| def.name)
            .collect()
    };
    assert!(names(&project).contains(&"old_name".to_string()));

    std::fs::write(&app, "def new_name():\n    pass\n").expect("modify source");
    let after_modify = names(&project);
    assert!(after_modify.contains(&"new_name".to_string()));
    assert!(!after_modify.contains(&"old_name".to_string()));

    let extra = root.join("extra.py");
    std::fs::write(&extra, "def added_name():\n    pass\n").expect("add source");
    let after_add = names(&project);
    assert!(after_add.contains(&"added_name".to_string()));

    std::fs::remove_file(&extra).expect("remove source");
    let after_remove = names(&project);
    assert!(!after_remove.contains(&"added_name".to_string()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_browse_dump_export_security_trace_and_inspect_work() {
    let root = python_micro();
    let project = sdk().open_query(&root).expect("open query");
    let ws = project.workspace();

    assert_eq!(
        project.browse().defs(Default::default()).expect("defs").len(),
        bonsai_browse::defs(ws, &Default::default())
            .expect("raw defs")
            .len()
    );
    assert!(!project
        .browse()
        .calls(Default::default())
        .expect("calls")
        .is_empty());
    assert!(!project
        .browse()
        .imports(Default::default())
        .expect("imports")
        .is_empty());
    assert!(!project
        .browse()
        .vars(Default::default())
        .expect("vars")
        .is_empty());
    assert!(!project
        .browse()
        .strings(Default::default())
        .expect("strings")
        .is_empty());
    let _ = project.browse().comments(Default::default()).expect("comments");
    assert!(!project
        .browse()
        .args(Default::default())
        .expect("args")
        .is_empty());
    let _ = project.browse().classes(Default::default()).expect("classes");
    assert!(!project
        .browse()
        .refs("request", Default::default())
        .expect("refs")
        .is_empty());
    assert!(!project
        .browse()
        .search("token", Default::default(), usize::MAX)
        .expect("search")
        .is_empty());

    assert!(project.dump().hir("handle_request").expect("dump-hir").is_some());
    assert!(project.dump().cfg("handle_request").expect("dump-cfg").is_some());
    assert!(!project.dump().callgraph().is_empty());
    assert!(!project.dump().edges(Default::default()).is_empty());
    assert!(matches!(
        project.dump().ast(Default::default()),
        bonsai_browse::AstOutcome::Dumps(_)
    ));
    assert!(matches!(
        project.dump().resolve("handle_request", Default::default()),
        bonsai_browse::ResolveOutcome::Trace(_)
    ));
    assert!(matches!(
        project.dump().taint(bonsai_browse::TaintFilters {
            source: "handle_request",
            ..Default::default()
        }),
        bonsai_browse::TaintOutcome::Report(_)
    ));

    let native = project
        .export()
        .native_json(bonsai_sdk::NativeExportOptions {
            full_propagations: true,
            complete_chains: false,
        })
        .expect("native export");
    assert!(native["taint_graph"]["functions"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty()));
    assert!(project
        .export()
        .networkx_json()
        .expect("networkx")
        .contains("\"nodes\""));
    assert!(project.export().graphml().expect("graphml").contains("<graphml"));
    assert!(project
        .export()
        .cypher()
        .expect("cypher")
        .contains("CREATE CONSTRAINT bonsai_node_id"));
    assert!(!project.export().graph_projection().nodes.is_empty());

    assert!(!project
        .security()
        .sources(Default::default())
        .expect("sources")
        .is_empty());
    assert!(!project
        .security()
        .source_rows(Default::default())
        .expect("source rows")
        .is_empty());
    assert!(!project
        .security()
        .sinks(Default::default())
        .expect("sinks")
        .is_empty());
    assert!(!project
        .security()
        .sink_rows(Default::default())
        .expect("sink rows")
        .is_empty());
    let _ = project
        .security()
        .sanitizers(Default::default())
        .expect("sanitizers");
    let _ = project
        .security()
        .sanitizer_rows(Default::default())
        .expect("sanitizer rows");
    assert!(!project
        .security()
        .deps(Default::default())
        .expect("deps")
        .rows
        .is_empty());
    assert!(!project
        .security()
        .pack_inventory(Default::default())
        .expect("pack inventory")
        .is_empty());
    assert_eq!(
        project
            .security()
            .pack_audit(None)
            .expect("pack audit")
            .languages
            .len(),
        21
    );
    assert!(!project
        .security()
        .pack_tree(Default::default())
        .expect("pack tree")
        .languages
        .is_empty());
    let sdk = sdk();
    let rootless_pack = sdk.security_pack().expect("rootless security pack");
    assert!(!rootless_pack
        .inventory(Default::default())
        .expect("rootless pack inventory")
        .is_empty());
    assert_eq!(
        rootless_pack
            .audit(None)
            .expect("rootless pack audit")
            .languages
            .len(),
        21
    );
    assert!(!rootless_pack
        .tree(Default::default())
        .expect("rootless pack tree")
        .languages
        .is_empty());
    assert!(!project
        .security()
        .taint_analysis(Default::default())
        .expect("taint analysis")
        .findings
        .is_empty());
    assert!(!project
        .security()
        .source_analysis(Default::default())
        .expect("source analysis")
        .candidates
        .is_empty());

    let trace = project.trace().from("handle_request").expect("trace");
    assert!(!trace.steps.is_empty());
    assert!(project
        .trace()
        .to_json(&trace)
        .expect("trace json")
        .contains("trace_id"));
    assert!(project.trace().to_text(&trace).contains("Trace:"));
    assert!(project.trace().to_dot(&trace).contains("digraph trace"));
    assert!(!project
        .trace()
        .source_to_sink("handle_request", "system")
        .expect("source to sink trace")
        .steps
        .is_empty());

    assert!(!project
        .inspect()
        .matching_decls(Some("handle_request"), false)
        .expect("inspect decls")
        .is_empty());
    assert!(!project
        .inspect()
        .matching_func_ids(Some("handle_request"), false)
        .expect("inspect funcs")
        .is_empty());
    assert!(!project
        .inspect()
        .chains(bonsai_sdk::InspectQuery {
            pattern: Some("handle_request"),
            ..Default::default()
        })
        .expect("inspect chains")
        .is_empty());
}

#[test]
fn security_methods_require_rulepack() {
    let project = bonsai_sdk::Bonsai::new()
        .open_query(python_micro())
        .expect("open query");
    let err = project
        .security()
        .taint_analysis(Default::default())
        .expect_err("missing rulepack should error");
    assert!(err.to_string().contains("with_rulepack"));
}
