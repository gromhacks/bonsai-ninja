use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("C.java".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(String, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } => out.push((name.clone(), receiver_types.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls(then_events, out);
                collect_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls(body, out);
                collect_calls(catch_events, out);
                collect_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

fn decl_type_aliases(db: &AnalyzerDb, fn_name: &str) -> Vec<(String, String)> {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == fn_name {
                return decl
                    .type_aliases
                    .iter()
                    .map(|alias| (alias.name.clone(), alias.type_name.clone()))
                    .collect();
            }
        }
    }
    Vec::new()
}

fn try_body_event_names(events: &[FlowEvent]) -> Vec<String> {
    for event in events {
        match event {
            FlowEvent::Try { body, .. } => {
                return body
                    .iter()
                    .filter_map(|event| match event {
                        FlowEvent::Assign { target, .. } => Some(format!("assign:{target}")),
                        FlowEvent::Call { name, .. } => Some(format!("call:{name}")),
                        _ => None,
                    })
                    .collect();
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let then_names = try_body_event_names(then_events);
                if !then_names.is_empty() {
                    return then_names;
                }
                let else_names = try_body_event_names(else_events);
                if !else_names.is_empty() {
                    return else_names;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                let names = try_body_event_names(body);
                if !names.is_empty() {
                    return names;
                }
            }
            _ => {}
        }
    }
    Vec::new()
}

#[test]
fn try_with_resources_initializer_precedes_body_events() {
    let db = db_with(
        r#"
class C {
  Object restore(byte[] data) throws Exception {
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
      return ois.readObject();
    }
  }
}
class ObjectInputStream {
  ObjectInputStream(Object input) {}
  Object readObject() { return null; }
}
class ByteArrayInputStream {
  ByteArrayInputStream(byte[] data) {}
}
"#,
    );
    let global = db.global_index();
    let restore = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "restore")
        .expect("restore declaration");
    let names = try_body_event_names(&restore.flow_events);
    let assign_idx = names
        .iter()
        .position(|name| name == "assign:ois")
        .expect("resource assignment should be emitted");
    let read_idx = names
        .iter()
        .position(|name| name == "call:ois.readObject")
        .expect("try body readObject call should be emitted");
    assert!(
        assign_idx < read_idx,
        "try-with-resources initializer must precede body events; got {names:?}"
    );
}

#[test]
fn enhanced_for_loop_variable_supplies_receiver_type() {
    let db = db_with(
        r#"
import javax.servlet.http.Cookie;

class C {
  void handle(Cookie[] cookies) {
    for (Cookie theCookie : cookies) {
      theCookie.getValue();
    }
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls
            .iter()
            .any(|(name, receiver_types)| name == "theCookie.getValue"
                && receiver_types.iter().any(|ty| ty == "Cookie")),
        "enhanced-for receiver type should be attached to Cookie.getValue calls, got {calls:?}"
    );
}

#[test]
fn inline_constructor_receiver_supplies_receiver_type() {
    let db = db_with(
        r#"
class C {
  void handle() {
    new java.util.Random().nextFloat();
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls
            .iter()
            .any(|(name, receiver_types)| name.ends_with("nextFloat")
                && receiver_types.iter().any(|ty| ty == "Random")
                && receiver_types.iter().any(|ty| ty == "java.util.Random")),
        "inline constructor receiver type should include simple and qualified Random evidence, got {calls:?}"
    );
}

#[test]
fn nested_qualified_receiver_type_preserves_its_owner() {
    let db = db_with(
        r#"
class App {
  record Envelope(String cmd) {}
}

class Pipeline {
  String run(App.Envelope envelope) {
    return envelope.cmd();
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "run" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "envelope.cmd"
                && receiver_types.iter().any(|ty| ty == "App.Envelope")
                && receiver_types.iter().any(|ty| ty == "Envelope")
        }),
        "nested Java type ownership must survive AST lowering, got {calls:?}"
    );
}

#[test]
fn securerandom_factory_refines_random_declared_receiver_type() {
    let db = db_with(
        r#"
class C {
  void handle() throws Exception {
    java.util.Random generator = java.security.SecureRandom.getInstance("SHA1PRNG");
    generator.nextDouble();
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "generator.nextDouble"
                && receiver_types.iter().any(|ty| ty == "Random")
                && receiver_types.iter().any(|ty| ty == "SecureRandom")
                && receiver_types.iter().any(|ty| ty == "java.security.SecureRandom")
        }),
        "SecureRandom.getInstance assigned to Random should retain concrete receiver evidence, got {calls:?}"
    );
}

#[test]
fn typed_receiver_includes_same_file_base_types() {
    let db = db_with(
        r#"
class Base {
  void sink(String value) {}
}

class Child extends Base {}

class C {
  void handle(String value) {
    Child child = new Child();
    child.sink(value);
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "child.sink"
                && receiver_types.iter().any(|ty| ty == "Child")
                && receiver_types.iter().any(|ty| ty == "Base")
        }),
        "typed receiver should include its same-file base classes for rule matching, got {calls:?}"
    );
}

#[test]
fn jdbc_platform_supertypes_are_exported_as_semantic_receiver_types() {
    let db = db_with(
        r#"
class C {
  void handle(java.sql.Connection connection, String sql) throws Exception {
    java.sql.PreparedStatement statement = connection.prepareStatement(sql);
    statement.execute();
  }
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "statement.execute"
                && receiver_types.iter().any(|ty| ty == "PreparedStatement")
                && receiver_types.iter().any(|ty| ty == "Statement")
        }),
        "JDBC receiver should carry declared type and semantic supertype, got {calls:?}"
    );
}

#[test]
fn fully_qualified_declared_types_are_retained_as_receiver_evidence() {
    let db = db_with(
        r#"
class C {
  void handle(javax.naming.directory.InitialDirContext ctx,
      javax.servlet.http.HttpServletRequest request) throws Exception {
    request.getParameter("uid");
    ctx.search("ou=users", "uid=alice", null);
  }
}

"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "handle" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "ctx.search"
                && receiver_types.iter().any(|ty| ty == "InitialDirContext")
                && receiver_types
                    .iter()
                    .any(|ty| ty == "javax.naming.directory.InitialDirContext")
        }),
        "FQN JNDI receiver should carry both simple and package-qualified types, got {calls:?}"
    );
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name == "request.getParameter"
                && receiver_types.iter().any(|ty| ty == "HttpServletRequest")
                && receiver_types
                    .iter()
                    .any(|ty| ty == "javax.servlet.http.HttpServletRequest")
        }),
        "FQN servlet receiver should carry both simple and package-qualified types, got {calls:?}"
    );
}

#[test]
fn vertx_route_handler_lambda_param_is_routing_context() {
    let db = db_with(
        r#"
import io.vertx.ext.web.Router;
import io.vertx.core.AbstractVerticle;

class C extends AbstractVerticle {
  void start() {
    Router router = Router.router(vertx);
    router.get("/users").handler(ctx -> {
      String sortBy = ctx.request().getParam("sort_by");
    });
  }
}
"#,
    );
    let aliases = decl_type_aliases(&db, "start");
    assert!(
        aliases
            .iter()
            .any(|(name, ty)| name == "ctx" && ty == "RoutingContext")
            && aliases
                .iter()
                .any(|(name, ty)| name == "ctx" && ty == "io.vertx.ext.web.RoutingContext"),
        "Vert.x route handler lambda param should be typed as RoutingContext, got {aliases:?}"
    );
}

#[test]
fn webflux_route_lambda_param_is_server_request() {
    let db = db_with(
        r#"
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

class C {
  Object routes(Service svc) {
    return route(GET("/probe"), req -> {
      String url = req.queryParam("url").orElse("");
      return svc.fetch(url);
    });
  }
}
class Service {
  Object fetch(String url) { return null; }
}
"#,
    );
    let aliases = decl_type_aliases(&db, "routes");
    assert!(
        aliases
            .iter()
            .any(|(name, ty)| name == "req" && ty == "ServerRequest")
            && aliases.iter().any(|(name, ty)| {
                name == "req" && ty == "org.springframework.web.reactive.function.server.ServerRequest"
            }),
        "WebFlux route lambda param should be typed as ServerRequest, got {aliases:?}"
    );
}

#[test]
fn graphql_datafetcher_lambda_param_is_datafetching_environment() {
    let db = db_with(
        r#"
import graphql.schema.DataFetcher;
import java.util.Map;

class C {
  private UserRepo repo;
  void graphQL() {
    DataFetcher<Map<String,Object>> byName = env -> {
      return repo.findByName(env.getArgument("name"));
    };
  }
}
class UserRepo {
  Object findByName(Object name) { return null; }
}
"#,
    );
    let aliases = decl_type_aliases(&db, "byName");
    assert!(
        aliases
            .iter()
            .any(|(name, ty)| name == "env" && ty == "DataFetchingEnvironment")
            && aliases
                .iter()
                .any(|(name, ty)| name == "env" && ty == "graphql.schema.DataFetchingEnvironment"),
        "GraphQL DataFetcher lambda param should be typed as DataFetchingEnvironment, got {aliases:?}"
    );
    assert!(
        aliases
            .iter()
            .any(|(name, ty)| name == "repo" && ty == "UserRepo"),
        "GraphQL DataFetcher lambda should inherit captured class field receiver types, got {aliases:?}"
    );
}
