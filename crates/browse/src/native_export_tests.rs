use super::*;

#[test]
fn complete_chain_mode_lifts_chain_caps() {
    let default_limits = ExportChainLimits::for_complete(false);
    let complete_limits = ExportChainLimits::for_complete(true);

    assert!(complete_limits.max_chains_per_target > default_limits.max_chains_per_target);
    assert!(complete_limits.max_entry_probes > default_limits.max_entry_probes);
    assert_eq!(complete_limits.max_chains_per_target, usize::MAX);
    assert_eq!(complete_limits.max_entry_probes, usize::MAX);
}

#[test]
fn complete_chain_mode_lifts_flow_label_caps() {
    let limits = ExportChainLimits::for_complete(true);
    let options = export_flow_label_options(true, limits);

    assert_eq!(options.max_chains, usize::MAX);
    assert_eq!(options.max_probes, usize::MAX);
    assert!(options.downstream_depth > FlowIdLabelOptions::default().downstream_depth);
    assert!(options.downstream_breadth > FlowIdLabelOptions::default().downstream_breadth);
    assert!(options.max_labels_per_func > FlowIdLabelOptions::default().max_labels_per_func);
    assert_eq!(options.downstream_depth, usize::MAX);
    assert_eq!(options.downstream_breadth, usize::MAX);
    assert_eq!(options.max_labels_per_func, usize::MAX);
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
