use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("A.java", "class A { public static void main(String[] s) {} }")]
    );
}

#[test]
fn url_rebuild_assignment_lowers_exact_call_composition() {
    use bonsai_lang_api::{LanguageAdapter, StringCompositionPart};
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "UrlProbe.java",
            r#"
class UrlProbe {
  String rebuild(java.net.URI uri) {
    String safe = "https://" + uri.getHost()
        + (uri.getPath() == null ? "/" : uri.getPath());
    return safe;
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("Java declaration index");
    let [fact] = index.string_compositions.as_slice() else {
        panic!("expected one composition: {:#?}", index.string_compositions);
    };
    assert_eq!(fact.target.as_deref(), Some("safe"));
    assert!(matches!(
        fact.parts.as_slice(),
        [
            StringCompositionPart::Literal { value },
            StringCompositionPart::Call { .. },
            StringCompositionPart::CallOrLiteral { fallback, .. }
        ] if value == "https://" && fallback == "/"
    ));
}

#[test]
fn url_guard_syntax_emits_typed_conditions_and_static_scalars() {
    use bonsai_lang_api::{ConditionExpressionFact, LanguageAdapter, StaticScalarValue};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "UrlGuard.java",
            r#"
import java.net.*;
import java.util.*;
class UrlGuard {
  private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "partner.example.com");
  void fetch(String raw) throws Exception {
    URL parsed = new URL(raw);
    if (!"https".equalsIgnoreCase(parsed.getProtocol())) throw new SecurityException();
    if (!ALLOWED_HOSTS.contains(parsed.getHost())) throw new SecurityException();
    InetAddress addr = InetAddress.getByName(parsed.getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) throw new SecurityException();
    HttpURLConnection conn = (HttpURLConnection) parsed.openConnection();
    conn.setInstanceFollowRedirects(false);
  }
  void authenticate(Object email, Object password) {
    if (!(email instanceof String) || !(password instanceof String)) {
      throw new IllegalArgumentException();
    }
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("Java declaration index");

    assert!(index
        .branch_conditions
        .iter()
        .any(|fact| matches!(&fact.expression, Some(ConditionExpressionFact::Not { .. }))));
    assert!(index.branch_conditions.iter().any(|fact| matches!(
        &fact.expression,
        Some(ConditionExpressionFact::Any { operands, .. }) if operands.len() == 2
    )));
    assert!(index.branch_conditions.iter().any(|fact| matches!(
        &fact.expression,
        Some(ConditionExpressionFact::Any { operands, .. })
            if operands.iter().all(|operand| matches!(
                operand,
                ConditionExpressionFact::Not { operand, .. }
                    if matches!(
                        operand.as_ref(),
                        ConditionExpressionFact::TypeTest { type_name, .. }
                            if type_name == "String"
                    )
            ))
    )));
    assert!(index
        .call_receivers
        .iter()
        .any(|fact| { fact.static_value == Some(StaticScalarValue::String("https".to_string())) }));
    assert!(index
        .call_argument_values
        .iter()
        .any(|fact| { fact.static_value == Some(StaticScalarValue::Boolean(false)) }));
    let allowlist = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("ALLOWED_HOSTS"))
        .expect("static Set.of assignment");
    assert_eq!(allowlist.exact_static_call_args.as_ref().map(Vec::len), Some(2));
}

#[test]
fn finite_map_selection_requires_java_util_map_final_binding_and_literal_default() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Selections.java",
            r#"
import java.util.Map;
class Selections {
  private static final Map<String, String> SORTABLE =
      Map.of("id", "id", "email", "email");
  private static Map<String, String> MUTABLE =
      Map.of("id", "id");

  String safe(String key) {
    String column = SORTABLE.getOrDefault(key, "id");
    return column;
  }
  String dynamicDefault(String key, String fallback) {
    String dynamic = SORTABLE.getOrDefault(key, fallback);
    return dynamic;
  }
  String shadowed(Map<String, String> SORTABLE, String key) {
    String shadow = SORTABLE.getOrDefault(key, "id");
    return shadow;
  }
  String lambdaShadow(String key) {
    java.util.function.Function<Map<String, String>, String> select =
        SORTABLE -> SORTABLE.getOrDefault(key, "id");
    return select.apply(SORTABLE);
  }
  String inferredLambdaShadow(String key) {
    java.util.function.BiFunction<Map<String, String>, String, String> select =
        (SORTABLE, fallback) -> SORTABLE.getOrDefault(key, fallback);
    return select.apply(SORTABLE, "id");
  }
  String catchShadow(String key) {
    try {
      throw new RuntimeException();
    } catch (RuntimeException SORTABLE) {
      String caught = SORTABLE.getOrDefault(key, "id");
      return caught;
    }
  }
  String enhancedForShadow(String key, Iterable<Map<String, String>> values) {
    for (Map<String, String> SORTABLE : values) {
      String looped = SORTABLE.getOrDefault(key, "id");
      return looped;
    }
    return "id";
  }
  String nonFinal(String key) {
    String mutable = MUTABLE.getOrDefault(key, "id");
    return mutable;
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("Java declaration index");

    assert_eq!(
        index
            .finite_literal_selections
            .iter()
            .filter_map(|fact| fact.target.as_deref())
            .collect::<Vec<_>>(),
        ["column"]
    );
}

#[test]
fn finite_map_selection_rejects_a_shadowing_java_value() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Shadow.java",
            r#"
import java.util.Map;
class Shadow {
  static final FakeMap Map = new FakeMap();
  static final java.util.Map<String, String> LOOKUP = Map.of("id", "id");
  String unsafe(String key) {
    String selected = LOOKUP.getOrDefault(key, "id");
    return selected;
  }
}
class FakeMap {
  java.util.Map<String, String> of(String key, String value) {
    return java.util.Map.of(key, key);
  }
}
"#,
        )],
    );
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    let index = ws.db().decl_index(file).expect("Java declaration index");
    assert!(index.finite_literal_selections.is_empty());
}

#[test]
fn inherited_bare_member_call_has_explicit_receiver_fact() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.java",
            r#"
class Base { String cmd() { return ""; } }
class Repository extends Base {
  String run() { return cmd(); }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run declaration");

    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: CallKind::Method,
                ..
            } if name == "this.cmd" && receiver == "this"
        )),
        "{:#?}",
        run.flow_events
    );
}

#[test]
fn explicit_super_invocation_remains_constructor_syntax() {
    use bonsai_lang_api::{CallKind, FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Storage.java",
            r#"
class Base { Base(String data) {} }
class Derived extends Base {
  Derived(String data) { super(data); }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let derived = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Derived" && decl.kind == bonsai_lang_api::DeclKind::Constructor)
        .expect("derived constructor");

    assert!(
        derived.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                call_kind: CallKind::Constructor,
                ..
            } if name == "Base" && receiver == "super"
        )),
        "{:#?}",
        derived.flow_events
    );
}

#[test]
fn generic_receiver_carries_tree_sitter_upper_bound() {
    use bonsai_lang_api::{FlowEvent, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Box.java",
            r#"
class Payload { String cmd() { return ""; } }
class Box<T extends Payload> {
  T data;
  String read() { return data.cmd(); }
}
"#,
        )],
    );
    for file in ws.db().vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    let global = ws.db().global_index();
    let read = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "read")
        .expect("read method");

    assert!(
        read.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                receiver: Some(receiver),
                receiver_types,
                ..
            } if receiver == "data" && receiver_types.iter().any(|ty| ty == "Payload")
        )),
        "{:#?}",
        read.flow_events
    );
}

#[test]
fn replacement_helpers_emit_exact_escape_and_constraint_summaries() {
    use bonsai_lang_api::{CharacterConstraintDomain, LanguageAdapter};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Escapes.java",
            r#"
class Escapes {
  static String html(String value) {
    return value.replace("&", "&amp;").replace("<", "&lt;");
  }
  static String header(String value) {
    return value.replaceAll("[\\r\\n]", "_");
  }
  static String incomplete(String value) {
    return value.replaceAll("[\\r\\n]", value);
  }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Java declaration index");
    assert_eq!(
        index.character_substitutions.len(),
        2,
        "{:#?}",
        index.character_substitutions
    );
    assert!(index.character_constraints.iter().any(|fact| matches!(
        &fact.domain,
        CharacterConstraintDomain::ExcludesExact { characters }
            if characters.contains(&"\r".to_string()) && characters.contains(&"\n".to_string())
    )));
}

#[test]
fn switch_character_transform_requires_total_identity_default() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Escaper.java",
            r#"
class Escaper {
  static String safe(String value) {
    StringBuilder out = new StringBuilder(value.length());
    for (char c : value.toCharArray()) {
      switch (c) {
        case '*': out.append("\\2a"); break;
        case '(': out.append("\\28"); break;
        default: out.append(c);
      }
    }
    return out.toString();
  }
  static String partial(String value) {
    StringBuilder out = new StringBuilder(value.length());
    for (char c : value.toCharArray()) {
      switch (c) {
        case '*': out.append("\\2a"); break;
        default: out.append("x");
      }
    }
    return out.toString();
  }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Java declaration index");
    assert_eq!(
        index
            .character_substitutions
            .iter()
            .filter(|fact| !fact.exact_mappings.is_empty())
            .count(),
        1,
        "partial switch must not produce a transform summary: {:#?}",
        index.character_substitutions
    );
    assert!(index.character_substitutions[0]
        .exact_mappings
        .iter()
        .any(|entry| entry.key == "*" && entry.value == "\\2a"));
}

#[test]
fn array_call_arguments_preserve_exact_positional_scalar_facts() {
    use bonsai_lang_api::{LanguageAdapter, StaticScalarValue};

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Command.java",
            r#"
class Command {
  void run(String host) throws Exception {
    Runtime.getRuntime().exec(new String[] { "sh", "-c", "ping " + host });
  }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Java declaration index");
    let sequence = index
        .call_argument_values
        .iter()
        .find_map(|fact| fact.exact_static_sequence_values.as_ref())
        .expect("exact Java array initializer");
    assert_eq!(
        sequence,
        &vec![
            Some(StaticScalarValue::String("sh".to_string())),
            Some(StaticScalarValue::String("-c".to_string())),
            None,
        ]
    );
}

#[test]
fn compiled_pattern_constraints_resolve_the_exact_immutable_binding() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Patterns.java",
            r#"
class Pattern {
  static Pattern compile(String value) { return new Pattern(); }
  PatternMatcher matcher(String value) { return new PatternMatcher(); }
}
class PatternMatcher { String replaceAll(String value) { return ""; } }
class Patterns {
  private static final Pattern CONTROL = Pattern.compile("\\p{Cntrl}");
  static String safe(String value) {
    return CONTROL.matcher(value).replaceAll("_");
  }
  static String shadowed(String value) {
    Pattern CONTROL = Pattern.compile(".*");
    return CONTROL.matcher(value).replaceAll("_");
  }
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Java declaration index");
    assert_eq!(
        index.character_constraints.len(),
        1,
        "a shadowing mutable binding must not inherit the field's proof: {:#?}",
        index.character_constraints
    );
    let safe = index
        .defs
        .iter()
        .find(|decl| decl.name == "safe")
        .expect("safe method");
    assert_eq!(index.character_constraints[0].function_span, safe.span);
}

#[test]
fn final_field_assignment_carries_exact_immutable_owner() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "Config.java",
            r#"
class Client {}
class Config {
  private final Client stable = new Client();
  private Client mutable = new Client();
}
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Java declaration index");
    let owner = index
        .defs
        .iter()
        .find(|decl| decl.name == "Config")
        .expect("Config class")
        .symbol;
    let stable = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("stable"))
        .expect("stable field assignment");
    let mutable = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("mutable"))
        .expect("mutable field assignment");
    assert!(stable.target_is_immutable);
    assert_eq!(stable.target_owner, Some(owner));
    assert!(!mutable.target_is_immutable);
    assert_eq!(mutable.target_owner, None);
}

#[test]
fn same_origin_helper_requires_single_slash_and_static_fallback() {
    use bonsai_lang_api::LanguageAdapter;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_java::JavaAdapter::new());
    for (condition, fallback, expected) in [
        (
            r#"target == null || !target.startsWith("/") || target.startsWith("//")"#,
            r#"return "/";"#,
            true,
        ),
        (
            r#"target == null || !target.startsWith("/")"#,
            r#"return "/";"#,
            false,
        ),
        (
            r#"target == null || !target.startsWith("/") || target.startsWith("//")"#,
            "return target;",
            false,
        ),
    ] {
        let source = format!(
            "class Redirect {{ static String sameSite(String target) {{ if ({condition}) {{ {fallback} }} return target; }} }}"
        );
        let ws = bonsai_testkit::workspace_with(vec![Arc::clone(&adapter)], &[("Redirect.java", &source)]);
        let file = ws.db().vfs().all_files()[0];
        let index = ws.db().decl_index(file).expect("Java declaration index");
        assert_eq!(
            !index.same_origin_path_constraints.is_empty(),
            expected,
            "{condition}: {:#?}",
            index.same_origin_path_constraints
        );
    }
}
