//! `Workspace::open_with_options` prewarms the workspace-wide
//! value-flow cache when `prewarm_value_flow` is on, and the same
//! option turns it off for `query_only` callers. Sidecar round-trips
//! via the conventional `.bonsai/value_flow.v2.bin` path.

use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::{Workspace, WorkspaceOpenOptions};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn registry() -> Arc<LanguageRegistry> {
    let r = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    r.register(adapter);
    r
}

fn tempdir_for_test(name: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    for attempt in 0..100 {
        let path = base.join(format!("{name}-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", path.display()),
        }
    }
    panic!("could not allocate tempdir for {name}");
}

fn write_python_workspace(root: &std::path::Path) {
    let body = "def get_input():\n    return input(\"> \")\n\n\
def process(value):\n    return value.strip()\n\n\
def emit(value):\n    print(value)\n\n\
def main():\n    raw = get_input()\n    cleaned = process(raw)\n    emit(cleaned)\n";
    std::fs::write(root.join("app.py"), body).expect("write app.py");
}

#[test]
fn full_open_prewarms_value_flow_cache() {
    let root = tempdir_for_test("bonsai-vf-full");
    write_python_workspace(&root);

    let ws = Workspace::open_with_options(&root, registry(), WorkspaceOpenOptions::default())
        .expect("open succeeds");

    assert!(
        !ws.value_flow().is_empty(),
        "default open should populate the value-flow cache"
    );
}

#[test]
fn query_only_skips_value_flow_prewarm() {
    let root = tempdir_for_test("bonsai-vf-query-only");
    write_python_workspace(&root);

    let ws = Workspace::open_with_options(&root, registry(), WorkspaceOpenOptions::query_only())
        .expect("open succeeds");

    // `query_only` opts out of every prewarm; with no sidecar on
    // disk, the cache stays empty until the first lazy fault.
    assert!(
        ws.value_flow().is_empty(),
        "query_only should skip value-flow prewarm"
    );
}

#[test]
fn returning_seed_names_populates_for_returned_param() {
    // Single function `def echo(x): return x` — `x`'s forward
    // closure must reach a `Return` node, so `returning_seed_names`
    // must contain "x". Without Return-node emission in the
    // value-flow graph builder this set is silently empty for
    // every function.
    let root = tempdir_for_test("bonsai-vf-returning");
    std::fs::write(
        root.join("app.py"),
        "def echo(x):\n    return x\n",
    )
    .expect("write fixture");

    let ws = Workspace::open_with_options(&root, registry(), WorkspaceOpenOptions::default())
        .expect("open succeeds");

    let global = ws.db().global_index();
    let echo_sym = global
        .find_by_name("echo")
        .iter()
        .copied()
        .next()
        .expect("echo decl present");
    let echo_func = bonsai_common::FuncId::new(echo_sym.raw());

    let returning = ws.value_flow().returning_seed_names(
        echo_func,
        ws.db(),
        ws.inter_taint_caches(),
    );
    assert!(
        returning.contains("x"),
        "echo(x) returns x — `x` must appear in returning_seed_names; got {:?}",
        returning
    );
}

#[test]
fn value_flow_sidecar_round_trips_via_query_only() {
    let root = tempdir_for_test("bonsai-vf-sidecar");
    write_python_workspace(&root);

    // First open: prewarm + persist sidecar.
    let _ = Workspace::open_with_options(&root, registry(), WorkspaceOpenOptions::default())
        .expect("first open succeeds");

    let sidecar = root.join(".bonsai").join("value_flow.v2.bin");
    assert!(sidecar.exists(), "default open should write the value-flow sidecar");

    // Second open in `query_only` mode hydrates from the sidecar.
    let ws2 = Workspace::open_with_options(&root, registry(), WorkspaceOpenOptions::query_only())
        .expect("second open succeeds");

    assert!(
        !ws2.value_flow().is_empty(),
        "query_only with a fresh sidecar should hydrate the value-flow cache from disk"
    );
}
