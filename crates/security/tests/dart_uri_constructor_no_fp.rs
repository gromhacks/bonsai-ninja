use bonsai_security::{load_rulepack, run_taint_analysis, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn repository_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|path| path.join("security-patterns").is_dir())
        .map(std::path::Path::to_path_buf)
        .expect("repository root")
}

#[test]
fn uri_construction_without_network_io_is_not_ssrf() {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(
        "uri_builder.dart".to_string(),
        Arc::<str>::from(
            r#"
Uri buildHttps(String host) {
  return Uri.https(host, "/report");
}

Uri buildHttp(String host) {
  return Uri.http(host, "/report");
}
"#,
        ),
    );
    for file in workspace.vfs().all_files() {
        let _ = workspace.db().decl_index(file);
        let _ = workspace.db().import_index(file);
    }

    let pack = load_rulepack(&repository_root().join("security-patterns")).expect("bundled rulepack loads");
    let report = run_taint_analysis(
        &workspace,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");

    assert!(
        report.findings.is_empty(),
        "URI construction alone must not be reported as SSRF: {:#?}",
        report.findings
    );
}
