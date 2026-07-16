use super::*;

#[test]
fn native_export_uses_versioned_flat_flow_ir() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
def process(value):
    if value:
        while value:
            try:
                sink(value)
            except Exception as error:
                raise error
            finally:
                cleanup(value)
    else:
        return value
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
    let exported = native_export_json(&ws, dir.path(), false).expect("native export");

    assert_eq!(exported["schema"], "bonsai-native-export");
    assert_eq!(exported["schema_version"], 2);
    let file = exported["files"]
        .as_array()
        .and_then(|files| {
            files
                .iter()
                .find(|file| file["path"].as_str().is_some_and(|p| p.ends_with("app.py")))
        })
        .expect("exported app.py");
    let events = file["flow_events"].as_array().expect("flat flow event table");
    assert!(!events.is_empty(), "flow event table must contain parsed events");
    let ids: std::collections::BTreeSet<u64> = events
        .iter()
        .map(|event| event["event_id"].as_u64().expect("numeric event id"))
        .collect();
    assert_eq!(ids.len(), events.len(), "event ids must be unique within a file");
    for event in events {
        if let Some(parent) = event.get("parent_event_id").and_then(serde_json::Value::as_u64) {
            assert!(ids.contains(&parent), "parent event id {parent} must resolve");
        }
        for recursive_key in [
            "then_events",
            "else_events",
            "body",
            "catch_events",
            "finally_events",
        ] {
            assert!(
                event.get(recursive_key).is_none(),
                "flat compiler event must not embed {recursive_key}: {event}"
            );
        }
    }
    let process = file["decls"]
        .as_array()
        .and_then(|decls| decls.iter().find(|decl| decl["name"] == "process"))
        .expect("process declaration");
    let roots = process["flow_event_ids"].as_array().expect("root event ids");
    assert!(!roots.is_empty());
    assert!(roots
        .iter()
        .all(|root| root.as_u64().is_some_and(|id| ids.contains(&id))));
    assert!(events.iter().any(|event| event["region"] == "then"));
    assert!(events.iter().any(|event| event["region"] == "body"));
    assert!(events.iter().any(|event| event["region"] == "catch"));
    assert!(events.iter().any(|event| event["region"] == "finally"));
}

#[test]
fn materialized_chain_limits_are_always_finite() {
    let limits = ExportChainLimits::bounded_materialization();
    assert_eq!(
        limits.max_chains_per_target,
        EXPORT_FLOW_CHAIN_MAX_CHAINS_PER_TARGET
    );
    assert_eq!(limits.max_entry_probes, EXPORT_FLOW_CHAIN_MAX_ENTRY_PROBES);
}

#[test]
fn compressed_complete_rows_are_honestly_non_materialized() {
    assert!(!chain_rows_complete(true, 0));
    assert!(!flow_id_rows_complete(true, 0));
    assert!(chain_rows_incomplete_reason(true, 0, 16, 64, true)
        .is_some_and(|reason| reason.contains("compressed_callgraph")));
    assert!(flow_id_rows_incomplete_reason(true, 0, true)
        .is_some_and(|reason| reason.contains("compressed_callgraph")));
    let compiled = NativeExportConfig {
        full_propagations: false,
        complete_chains: true,
        compiled_propagations: true,
    };
    assert_eq!(propagation_mode(compiled), "compiled_idg");
    assert!(propagation_omitted_reason(compiled).is_none());
    let materialized = NativeExportConfig {
        full_propagations: true,
        complete_chains: true,
        compiled_propagations: false,
    };
    assert_eq!(propagation_mode(materialized), "materialized_entries");
    assert!(propagation_omitted_reason(materialized).is_none());
    assert_eq!(export_flow_label_options(), FlowIdLabelOptions::default());
}

#[test]
fn parser_gaps_make_buffered_and_streaming_exports_incomplete() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("Broken.java"),
        "class Broken { void method( { }\n",
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
    let config = NativeExportConfig {
        full_propagations: true,
        complete_chains: true,
        compiled_propagations: false,
    };

    let buffered = native_export_json_with_config(&ws, dir.path(), config).expect("buffered native export");
    assert_eq!(buffered["analysis_complete"], false);
    assert_eq!(
        buffered["analysis_incomplete_reasons"],
        serde_json::json!(["syntax-error-files:1"])
    );

    let mut streamed = Vec::new();
    write_native_export_json_with_config(&ws, dir.path(), config, &mut streamed)
        .expect("streaming native export");
    let streamed: serde_json::Value = serde_json::from_slice(&streamed).expect("parse streaming export");
    assert_eq!(streamed["analysis_complete"], false);
    assert_eq!(
        streamed["analysis_incomplete_reasons"],
        serde_json::json!(["syntax-error-files:1"])
    );
}

#[test]
fn unresolved_calls_make_native_export_incomplete() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        "def entry(value):\n    return unresolved_dependency(value)\n",
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
    let exported = native_export_json_with_config(
        &ws,
        dir.path(),
        NativeExportConfig {
            full_propagations: true,
            complete_chains: true,
            compiled_propagations: false,
        },
    )
    .expect("native export");

    assert_eq!(exported["analysis_complete"], false);
    assert_eq!(
        exported["analysis_incomplete_reasons"],
        serde_json::json!(["unresolved-call-sites:1"])
    );
}

#[test]
fn decorator_entrypoints_do_not_attach_across_function_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
class App:
    def route(self, path):
        def deco(fn):
            return fn
        return deco

app = App()

def caller():
    return helper("safe")

@app.route("/x")
def decorated(request):
    return request

def helper(value):
    return value
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let exported = native_export_json(&ws, dir.path(), false).expect("native export");
    let entries = exported["taint_graph"]["entry_points"]
        .as_array()
        .expect("entry_points");

    assert!(
        entries
            .iter()
            .any(|entry| entry["function"] == "decorated" && entry["kind"] == "decorator"),
        "decorated function should be a decorator entrypoint: {entries:#?}"
    );
    assert!(
        !entries
            .iter()
            .any(|entry| entry["function"] == "helper" && entry["kind"] == "decorator"),
        "called helper must not inherit an earlier decorator: {entries:#?}"
    );
}

#[test]
fn class_field_entrypoints_require_receiver_field_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
class Holder:
    pass

class ReceiverState:
    def seed(self, value):
        self.value = value

    def receiver_leak(self):
        return self.value

class LocalOnly:
    def seed(self, value):
        holder = Holder()
        holder.value = value

    def local_leak(self):
        return holder.value
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let exported = native_export_json(&ws, dir.path(), false).expect("native export");
    let entries = exported["taint_graph"]["entry_points"]
        .as_array()
        .expect("entry_points");

    assert!(
        entries.iter().any(|entry| {
            entry["function"] == "receiver_leak"
                && entry["kind"] == "class_field"
                && entry["params"]
                    .as_array()
                    .is_some_and(|params| params.iter().any(|param| param == "self.value"))
        }),
        "receiver field should create class_field entrypoint: {entries:#?}"
    );
    assert!(
        !entries.iter().any(|entry| {
            entry["function"] == "local_leak"
                && entry["kind"] == "class_field"
                && entry["params"]
                    .as_array()
                    .is_some_and(|params| params.iter().any(|param| param == "holder.value"))
        }),
        "local object field must not create class_field entrypoint: {entries:#?}"
    );
}

#[test]
fn assign_chains_project_function_local_idg_and_cfg_rows_name_their_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
def entry(user):
    before = user
    user = "clean"
    after = user
    helper(before)

def helper(p):
    deep = p
    return deep
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let exported = native_export_json(&ws, dir.path(), false).expect("native export");
    let chains = exported["taint_graph"]["assign_chains"]
        .as_array()
        .expect("assign_chains");
    let entry = chains
        .iter()
        .find(|row| row["function"] == "entry")
        .expect("entry assign-chain row");
    let user = entry["per_param"]
        .as_array()
        .expect("per_param")
        .iter()
        .find(|row| row["param_name"] == "user")
        .expect("user projection");
    let tainted: std::collections::BTreeSet<&str> = user["tainted"]
        .as_array()
        .expect("tainted names")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        tainted.contains("user") && tainted.contains("before"),
        "{tainted:?}"
    );
    assert!(
        !tainted.contains("after"),
        "the clean overwrite must prevent the original parameter from reaching `after`: {tainted:?}"
    );
    assert!(
        !tainted.contains("p") && !tainted.contains("deep"),
        "a function-local projection must not absorb callee storage: {tainted:?}"
    );

    let intra = exported["taint_graph"]["intra_taint"]
        .as_array()
        .expect("intra_taint");
    assert!(
        intra.iter().all(|row| row["backend"] == "cfg_local"),
        "block-oriented compatibility rows must identify their local CFG backend: {intra:#?}"
    );
}

#[test]
fn function_summaries_compose_resolved_callee_returns() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
def identity(value):
    return value

def wrapper(user):
    return identity(user)
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let exported = native_export_json(&ws, dir.path(), false).expect("native export");
    let summaries = exported["taint_graph"]["function_summaries"]
        .as_array()
        .expect("function_summaries");
    let wrapper = summaries
        .iter()
        .find(|summary| summary["function"] == "wrapper")
        .expect("wrapper return summary");
    assert_eq!(wrapper["returns_taint_of"], serde_json::json!([0]));
}

#[test]
fn function_summaries_preserve_demanded_java_field_flow() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("Demo.java"),
        r#"
class Box {
    String value;
}

class Demo {
    static String read(Box box) {
        return box.value;
    }

    static String entry(String args) {
        Box box = new Box();
        box.value = args;
        return read(box);
    }
}
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let exported = native_export_json(&ws, dir.path(), false).expect("native export");
    let summaries = exported["taint_graph"]["function_summaries"]
        .as_array()
        .expect("function_summaries");
    let entry = summaries
        .iter()
        .find(|summary| summary["function"] == "entry")
        .expect("entry return summary");
    assert_eq!(entry["returns_taint_of"], serde_json::json!([0]));
}

#[test]
fn wildcard_field_demand_matches_complete_export_summaries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("Demo.java"),
        r#"
class Box {
    String live;
    String unrelated;
}

class Demo {
    static String read(Box box) {
        external(box.unrelated);
        return box.live;
    }

    static String pass(Box box) {
        external(box);
        return read(box);
    }

    static String entry(String live, String unrelated) {
        Box box = new Box();
        box.live = live;
        box.unrelated = unrelated;
        external(box);
        return pass(box);
    }

    static void external(Object value) {}
}
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let scoped = native_export_json(&ws, dir.path(), false).expect("demand-driven export");
    let complete = native_export_json(&ws, dir.path(), true).expect("complete export");

    let entry = scoped["taint_graph"]["function_summaries"]
        .as_array()
        .expect("function_summaries")
        .iter()
        .find(|summary| summary["function"] == "entry")
        .expect("entry summary");
    assert_eq!(
        entry["returns_taint_of"],
        serde_json::json!([0]),
        "the live field must transit through both wrappers without promoting the unrelated sibling"
    );

    assert_eq!(
        scoped["taint_graph"]["function_summaries"],
        complete["taint_graph"]["function_summaries"]
    );
    assert_eq!(
        scoped["taint_graph"]["assign_chains"],
        complete["taint_graph"]["assign_chains"]
    );
}

#[test]
fn complete_chain_mode_uses_compressed_graph_even_for_small_workspaces() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
def leaf(value):
    return value

def entry(user):
    return leaf(user)
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
    let exported = native_export_json_with_config(
        &ws,
        dir.path(),
        NativeExportConfig {
            full_propagations: true,
            complete_chains: true,
            compiled_propagations: false,
        },
    )
    .expect("native export");

    assert_eq!(exported["flow_chains_mode"], "compressed_callgraph");
    assert_eq!(exported["flow_chains_complete"], false);
    assert!(exported["flow_chains"].as_array().is_some_and(Vec::is_empty));
    assert!(exported["flow_chains_incomplete_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("compressed_callgraph")));

    let taint = &exported["taint_graph"];
    assert_eq!(taint["chains_mode"], "compressed_callgraph");
    assert_eq!(taint["chains_complete"], false);
    assert!(taint["chains"].as_array().is_some_and(Vec::is_empty));
    assert!(taint["chains_incomplete_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("compressed_callgraph")));
    assert_eq!(taint["flow_id_labels_mode"], "compressed_callgraph");
    assert_eq!(taint["flow_id_labels_complete"], false);
    assert!(taint["flow_id_labels"].as_array().is_some_and(Vec::is_empty));
    assert!(taint["flow_id_labels_incomplete_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("compressed_callgraph")));
    assert!(taint["call_edges"]
        .as_array()
        .is_some_and(|edges| !edges.is_empty()));
    assert_eq!(
        exported["analysis_complete"], true,
        "the compressed semantic graph is exact even though concrete path/label rows are not materialized"
    );
}

#[test]
fn entry_points_preserve_func_identity_when_names_and_lines_collide() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("alpha.py"),
        "def entry(alpha):\n    return alpha\n",
    )
    .expect("write alpha");
    std::fs::write(dir.path().join("beta.py"), "def entry(beta):\n    return beta\n").expect("write beta");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let exported = native_export_json(&ws, dir.path(), false).expect("native export");
    let entries: Vec<_> = exported["taint_graph"]["entry_points"]
        .as_array()
        .expect("entry points")
        .iter()
        .filter(|entry| entry["function"] == "entry")
        .collect();
    assert_eq!(entries.len(), 2, "same name/line declarations must not merge");
    assert_ne!(entries[0]["func_id"], entries[1]["func_id"]);

    let parameter_sets: std::collections::BTreeSet<Vec<&str>> = entries
        .iter()
        .map(|entry| {
            entry["params"]
                .as_array()
                .expect("params")
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect()
        })
        .collect();
    assert_eq!(
        parameter_sets,
        std::collections::BTreeSet::from([vec!["alpha"], vec!["beta"]])
    );
}
