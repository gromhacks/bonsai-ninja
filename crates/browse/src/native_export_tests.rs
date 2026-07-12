use super::*;

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
    assert_eq!(export_flow_label_options(), FlowIdLabelOptions::default());
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
