//! Production rulepack regression for an exact read source nested in a call
//! argument. The same compiler flow must survive rule-derived transfer and
//! lifecycle facts; those facts may refine external APIs but cannot erase the
//! value selected by the Go syntax tree.

use bonsai_security::{load_rulepack, run_taint_analysis, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::PathBuf;
use std::sync::Arc;

const API_SOURCE: &str = r#"package api
import (
    "net/http"
    "github.com/labstack/echo/v4"
    "app/internal/service"
)
func Register(e *echo.Echo) {
    e.POST("/state/restore", func(c echo.Context) error {
        defer c.Request().Body.Close()
        obj, err := service.RestoreState(c.Request().Body)
        if err != nil { return c.NoContent(http.StatusBadRequest) }
        return c.JSON(http.StatusOK, obj)
    })
}
"#;

const STATE_SOURCE: &str = r#"package service
import (
    "encoding/gob"
    "io"
)
type SessionState struct{ User string; Roles []string; Raw map[string]any }
func init() { gob.Register(SessionState{}); gob.Register(map[string]any{}) }
func RestoreState(r io.Reader) (any, error) {
    dec := gob.NewDecoder(r)
    var v any
    if err := dec.Decode(&v); err != nil { return nil, err }
    return v, nil
}
"#;

const SAFE_SOURCE: &str = r#"package service
import (
    "encoding/json"
    "io"
)
func RestoreSafe(r io.Reader) (map[string]any, error) {
    var value map[string]any
    dec := json.NewDecoder(r)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&value); err != nil { return nil, err }
    return value, nil
}
"#;

fn rules_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../security-patterns")
}

#[test]
fn echo_request_body_reaches_cross_file_gob_decoder_after_deferred_close() {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace
        .vfs()
        .write("internal/api/state.go", Arc::<str>::from(API_SOURCE));
    workspace
        .vfs()
        .write("internal/service/state.go", Arc::<str>::from(STATE_SOURCE));
    workspace
        .vfs()
        .write("internal/service/safe.go", Arc::<str>::from(SAFE_SOURCE));
    for file in workspace.vfs().all_files() {
        let parsed = workspace.db().parse(file).expect("Go fixture parse");
        assert!(
            parsed.diagnostics.is_empty(),
            "diagnostics: {:?}",
            parsed.diagnostics
        );
        let _ = workspace.db().decl_index(file);
        let _ = workspace.db().import_index(file);
    }

    let pack = load_rulepack(&rules_root()).expect("bundled rulepack");
    let report = run_taint_analysis(&workspace, &pack, TaintAnalysisOptions::default())
        .expect("production taint analysis");

    assert!(
        report.analysis_complete,
        "incomplete: {:?}",
        report.analysis_incomplete_reasons
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "go.deser.gob_newdecoder"),
        "the exact Body read must reach gob.NewDecoder: {:#?}",
        report.findings
    );
}

#[test]
fn indexed_compiler_objects_preserve_the_same_nested_read_flow() {
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let root = std::env::temp_dir().join(format!(
        "bonsai-go-nested-read-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _cleanup = Cleanup(root.clone());
    std::fs::create_dir_all(root.join("internal/api")).expect("api directory");
    std::fs::create_dir_all(root.join("internal/service")).expect("service directory");
    std::fs::write(root.join("internal/api/state.go"), API_SOURCE).expect("api source");
    std::fs::write(root.join("internal/service/state.go"), STATE_SOURCE).expect("state source");
    std::fs::write(root.join("internal/service/safe.go"), SAFE_SOURCE).expect("safe source");
    std::fs::write(
        root.join("go.mod"),
        "module app\n\nrequire github.com/labstack/echo/v4 v4.0.0\n",
    )
    .expect("go.mod");

    let workspace =
        Workspace::index(&root, bonsai_adapters::all_languages_registry()).expect("index disk fixture");
    let pack = load_rulepack(&rules_root()).expect("bundled rulepack");
    let report = run_taint_analysis(&workspace, &pack, TaintAnalysisOptions::default())
        .expect("production taint analysis");

    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "go.deser.gob_newdecoder"),
        "indexed compiler objects lost the nested Body read: {:#?}",
        report.findings
    );
}
