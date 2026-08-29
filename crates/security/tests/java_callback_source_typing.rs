//! External callback signatures come from typing rules, while callback spans
//! and parameter identities remain compiler facts. This test covers the
//! complete join and a same-named local negative boundary.

use bonsai_security::{Rulepack, SourceAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| bonsai_security::load_rulepack(&rules_root()).expect("load rulepack"))
}

#[test]
fn nested_callback_parameter_typing_reaches_source_matching_without_crossing_to_local_types() {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(
        "src/App.java",
        Arc::<str>::from(
            r#"import io.vertx.core.http.HttpServer;
import java.util.function.Consumer;

class App {
  void external(HttpServer server) {
    server.requestHandler(request -> {
      request.bodyHandler(buffer -> consume(buffer));
    });
  }

  void local(LocalServer server) {
    server.requestHandler(request -> {
      request.bodyHandler(buffer -> consume(buffer));
    });
  }

  void consume(Object value) {}
}

class LocalServer {
  void requestHandler(Consumer<LocalRequest> callback) {}
}
class LocalRequest {
  void bodyHandler(Consumer<Object> callback) {}
}
"#,
        ),
    );

    let report = bonsai_security::run_source_analysis(
        &workspace,
        rulepack(),
        SourceAnalysisOptions {
            source: Some("^java\\.source\\.vertx_body_handler_callback$".to_string()),
            ..Default::default()
        },
    )
    .expect("Java callback source analysis");
    let matching = report
        .candidates
        .iter()
        .filter(|candidate| candidate.source.rule_id == "java.source.vertx_body_handler_callback")
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "{:#?}", report.candidates);
    assert!(
        matching[0]
            .source
            .enclosing_fn
            .as_deref()
            .is_some_and(|name| name.starts_with("<lambda@")),
        "the callback source must retain its exact compiler-owned lambda scope: {matching:#?}"
    );
    assert_eq!(matching[0].source.line, 7);
}
