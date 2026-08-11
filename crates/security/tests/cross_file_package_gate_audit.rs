//! Package-gate soundness across files (WS1, corrected).
//!
//! An earlier WS1 attempt folded the UNION of every file's source imports
//! into each file's gate evidence so a package imported in a *sibling*
//! module would credit a bare receiver-agnostic source here. That defeated
//! per-file package gating — a `request.headers` framework source fired in a
//! module that imported a *different* framework (see the committed
//! `benchmark_gap_regressions::typescript_*_requires_matching_package_evidence`
//! invariants) — violating the standing "do NOT loosen the matcher package
//! gate" directive. It was reverted.
//!
//! The sound contract pinned here:
//!   * a bare receiver-agnostic source (`request.args.get`, whose only
//!     precision is the package gate) is credited ONLY from evidence in its
//!     OWN file — a sibling import does NOT cross-credit it;
//!   * the same source fires when the framework is imported in-file;
//!   * an absent package blocks the gate entirely.
//!
//! FQN/qualifier-carrying calls (`flask.request...`) and `receiver_type_in`
//! sinks keep their cross-file reach through the candidate path in
//! `call_context_allows`, which does not depend on the per-file import set.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

struct TempWs {
    path: PathBuf,
}

impl TempWs {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bonsai-ws1-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
    fn write(&self, name: &str, content: &str) {
        fs::write(self.path.join(name), content).unwrap();
    }
}

impl Drop for TempWs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn cmdi_findings(root: &Path) -> usize {
    let registry = bonsai_adapters::all_languages_registry();
    let pack = bonsai_security::load_rulepack(&repo_root().join("security-patterns")).expect("rulepack");
    let ws = bonsai_workspace::Workspace::index(root, registry).expect("index");
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("taint");
    report
        .findings
        .iter()
        .filter(|f| f.finding.sink.rule_id.contains("cmdi") || f.finding.sink.text.contains("os.system"))
        .count()
}

#[test]
fn local_import_evidence_credits_the_bare_source() {
    let ws = TempWs::new("local");
    // flask imported in the SAME file as the bare `request.args.get`
    // source: the package gate is satisfied locally and the flow fires.
    ws.write(
        "handler.py",
        "import os\nimport flask\ndef view():\n    cmd = request.args.get(\"c\")\n    os.system(cmd)\n",
    );
    assert!(
        cmdi_findings(&ws.path) >= 1,
        "a flask source with flask imported in-file must be credited"
    );
}

#[test]
fn sibling_import_does_not_cross_credit_a_bare_source() {
    let ws = TempWs::new("cross");
    // flask imported here only.
    ws.write("app.py", "import flask\napp = flask.Flask(__name__)\n");
    // handler.py does NOT import flask. A bare receiver-agnostic source
    // (`request.args.get`) whose only precision is the package gate must
    // NOT be credited from a sibling's import — that would defeat per-file
    // gating (the "do NOT loosen the gate" invariant).
    ws.write(
        "handler.py",
        "import os\ndef view():\n    cmd = request.args.get(\"c\")\n    os.system(cmd)\n",
    );
    assert_eq!(
        cmdi_findings(&ws.path),
        0,
        "a bare source in a module that doesn't import flask must NOT be cross-credited by a sibling import"
    );
}

#[test]
fn absent_package_still_blocks_the_gate() {
    let ws = TempWs::new("absent");
    // No flask anywhere in the workspace — the bare `request.args.get`
    // must NOT be credited as a flask source (precision preserved).
    ws.write(
        "handler.py",
        "import os\ndef view():\n    cmd = request.args.get(\"c\")\n    os.system(cmd)\n",
    );
    assert_eq!(
        cmdi_findings(&ws.path),
        0,
        "with no flask anywhere in the workspace, the request source must not be flask-credited"
    );
}
