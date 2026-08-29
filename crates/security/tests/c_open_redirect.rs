//! Exact C HTTP redirect boundary coverage against the checked-in rulepack.

use bonsai_security::{load_rulepack, run_taint_analysis, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::PathBuf;
use std::sync::Arc;

fn rules_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn workspace(source: &str) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("redirect.c".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn redirect_findings(source: &str) -> usize {
    let pack = load_rulepack(&rules_root()).expect("checked-in rulepack loads");
    let ws = workspace(source);
    run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("C redirect taint analysis")
    .findings
    .iter()
    .filter(|finding| finding.finding.sink.rule_id == "c.open_redirect.mg_http_reply_location")
    .count()
}

#[test]
fn mongoose_location_redirect_requires_remote_target_and_exact_provider() {
    let vulnerable = r#"
#include <civetweb.h>
#include <mongoose.h>
void redirect(struct mg_connection *connection, const char *data, size_t len) {
  char target[128];
  mg_get_var(data, len, "next", target, sizeof(target));
  mg_http_reply(connection, 302, "Location: %s\r\n", "", target);
}
"#;
    assert_eq!(redirect_findings(vulnerable), 1);

    let literal_target = r#"
#include <civetweb.h>
#include <mongoose.h>
void redirect(struct mg_connection *connection, const char *data, size_t len) {
  char target[128];
  mg_get_var(data, len, "next", target, sizeof(target));
  mg_http_reply(connection, 302, "Location: %s\r\n", "", "/dashboard");
}
"#;
    assert_eq!(redirect_findings(literal_target), 0);

    let local_collision = r#"
#include <civetweb.h>
static void mg_http_reply(void *connection, int status, const char *headers,
                          const char *body, const char *target) {}
void redirect(void *connection, const char *data, size_t len) {
  char target[128];
  mg_get_var(data, len, "next", target, sizeof(target));
  mg_http_reply(connection, 302, "Location: %s\r\n", "", target);
}
"#;
    assert_eq!(redirect_findings(local_collision), 0);
}
