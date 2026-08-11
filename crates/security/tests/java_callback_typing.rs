use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn analyze(name: &str, source: &str, expected_source: &str) -> bonsai_security::TaintAnalysisReport {
    let root = std::env::temp_dir().join(format!(
        "bonsai-java-callback-typing-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create fixture root");
    std::fs::write(root.join("App.java"), source).expect("write Java fixture");
    let registry = bonsai_adapters::all_languages_registry();
    let workspace =
        bonsai_workspace::Workspace::index(Path::new(&root), registry).expect("index Java fixture");
    let pack = bonsai_security::load_rulepack(&repo_root().join("security-patterns"))
        .expect("load checked-in rulepack");
    let sources = bonsai_security::source_inventory(
        &workspace,
        &pack,
        bonsai_security::SecurityInventoryOptions {
            rule: Some(expected_source.to_string()),
            ..Default::default()
        },
    )
    .expect("match source inventory");
    assert!(
        sources.iter().any(|source| source.rule_id == expected_source),
        "rulepack callback typing did not type the source receiver: {sources:#?}"
    );
    let report = bonsai_security::run_taint_analysis(&workspace, &pack, Default::default())
        .expect("run taint analysis");
    let _ = std::fs::remove_dir_all(root);
    report
}

fn assert_no_source(name: &str, source: &str, unexpected_source: &str) {
    let root = std::env::temp_dir().join(format!(
        "bonsai-java-callback-typing-negative-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create fixture root");
    std::fs::write(root.join("App.java"), source).expect("write Java fixture");
    let registry = bonsai_adapters::all_languages_registry();
    let workspace =
        bonsai_workspace::Workspace::index(Path::new(&root), registry).expect("index Java fixture");
    let pack = bonsai_security::load_rulepack(&repo_root().join("security-patterns"))
        .expect("load checked-in rulepack");
    let sources = bonsai_security::source_inventory(
        &workspace,
        &pack,
        bonsai_security::SecurityInventoryOptions {
            rule: Some(unexpected_source.to_string()),
            ..Default::default()
        },
    )
    .expect("match source inventory");
    let _ = std::fs::remove_dir_all(root);
    assert!(
        sources.is_empty(),
        "callback typing crossed an unproven provider boundary: {sources:#?}"
    );
}

fn assert_source(report: &bonsai_security::TaintAnalysisReport, source_rule: &str) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.source.rule_id == source_rule),
        "expected source rule {source_rule}; findings: {:#?}",
        report.findings
    );
}

#[test]
fn vertx_inline_callback_parameter_type_comes_from_typing_rule() {
    let report = analyze(
        "vertx",
        r#"
import io.vertx.ext.web.Router;
class App {
  void routes(Router router) {
    router.get("/run").handler(ctx -> {
      try { Runtime.getRuntime().exec(ctx.request().getParam("cmd")); }
      catch (Exception ignored) {}
    });
  }
}
"#,
        "java.source.vertx_routingcontext_request_getparam",
    );
    assert_source(&report, "java.source.vertx_routingcontext_request_getparam");
}

#[test]
fn webflux_inline_callback_parameter_type_comes_from_typing_rule() {
    let report = analyze(
        "webflux",
        r#"
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
class App {
  Object routes() {
    return route(GET("/run"), request -> {
      try { return Runtime.getRuntime().exec(request.queryParam("cmd").orElse("")); }
      catch (Exception ignored) { return null; }
    });
  }
}
"#,
        "java.source.spring_webflux_serverrequest_queryparam",
    );
    assert_source(&report, "java.source.spring_webflux_serverrequest_queryparam");
}

#[test]
fn functional_interface_callback_parameter_type_comes_from_typing_rule() {
    let report = analyze(
        "graphql",
        r#"
import graphql.schema.DataFetcher;
class App {
  void configure() {
    DataFetcher<Object> fetcher = environment -> {
      try { return Runtime.getRuntime().exec((String) environment.getArgument("cmd")); }
      catch (Exception ignored) { return null; }
    };
  }
}
"#,
        "java.source.graphql_datafetching_environment_getargument",
    );
    assert_source(
        &report,
        "java.source.graphql_datafetching_environment_getargument",
    );
}

#[test]
fn local_route_callback_without_provider_import_is_not_typed() {
    assert_no_source(
        "local-route",
        r#"
class App {
  Object route(Object predicate, Handler handler) { return null; }
  Object routes() {
    return route("/run", request -> request.queryParam("cmd"));
  }
  interface Handler { Object apply(LocalRequest request); }
  static class LocalRequest { Object queryParam(String name) { return null; } }
}
"#,
        "java.source.spring_webflux_serverrequest_queryparam",
    );
}

#[test]
fn local_route_callback_shadows_provider_import() {
    assert_no_source(
        "shadowed-route",
        r#"
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
class App {
  Object route(Object predicate, Handler handler) { return null; }
  Object routes() {
    return route("/run", request -> request.queryParam("cmd"));
  }
  interface Handler { Object apply(LocalRequest request); }
  static class LocalRequest { Object queryParam(String name) { return null; } }
}
"#,
        "java.source.spring_webflux_serverrequest_queryparam",
    );
}

#[test]
fn unrelated_functional_interface_is_not_typed_as_graphql() {
    assert_no_source(
        "local-fetcher",
        r#"
import graphql.schema.DataFetcher;
class App {
  interface LocalFetcher { Object apply(LocalEnvironment environment); }
  void configure() {
    LocalFetcher fetcher = environment -> environment.getArgument("cmd");
  }
  static class LocalEnvironment { Object getArgument(String name) { return null; } }
}
"#,
        "java.source.graphql_datafetching_environment_getargument",
    );
}
