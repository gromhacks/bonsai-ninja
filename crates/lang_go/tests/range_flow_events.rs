use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{
    CharacterConstraintDomain, CharacterConstraintOutput, FlowEvent, LanguageRegistry, StringCompositionPart,
};
use bonsai_vfs::Vfs;
use std::sync::Arc;

type AssignSummary = (String, Option<String>, Option<String>, Vec<String>);

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(String, bonsai_common::Span)>) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => out.push((name.clone(), *span)),
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

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.go".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_go::GoAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn collect_assigns(events: &[FlowEvent], out: &mut Vec<AssignSummary>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => out.push((
                target.clone(),
                source_name.clone(),
                source_call.clone(),
                source_names.clone(),
            )),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assigns(then_events, out);
                collect_assigns(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assigns(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assigns(body, out);
                collect_assigns(catch_events, out);
                collect_assigns(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_returns(events: &[FlowEvent], out: &mut Vec<(Option<String>, bonsai_lang_api::ExpressionFlow)>) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_name,
                value_flow,
                ..
            } => out.push((value_name.clone(), value_flow.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_returns(then_events, out);
                collect_returns(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_returns(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_returns(body, out);
                collect_returns(catch_events, out);
                collect_returns(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn range_clauses_emit_precise_iteration_value_assignments() {
    let db = db_with(
        r#"
package main

func tokenize(cmd string) <-chan string { return nil }

func entry(cmd string, tokens []string) {
    for tok := range tokenize(cmd) {
        use(tok)
    }
    for _, t := range tokens {
        use(t)
    }
}
"#,
    );
    let global = db.global_index();
    let mut assigns = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "entry" {
                collect_assigns(&decl.flow_events, &mut assigns);
            }
        }
    }

    assert!(
        assigns
            .iter()
            .any(|(target, _, source_call, _)| target == "tok" && source_call.as_deref() == Some("tokenize")),
        "single-target channel range should bind tok from tokenize() return: {assigns:?}"
    );
    assert!(
        assigns.iter().any(|(target, source_name, _, source_names)| {
            target == "t"
                && (source_name.as_deref() == Some("tokens")
                    || source_names.iter().any(|name| name == "tokens"))
        }),
        "two-target range should bind value variable from ranged collection: {assigns:?}"
    );
    assert!(
        !assigns.iter().any(|(target, _, _, _)| target == "range"),
        "Go range lowering must not keep broad synthetic range assignments: {assigns:?}"
    );
}

#[test]
fn dynamic_lookup_key_selects_but_does_not_taint_stored_value() {
    let db = db_with(
        r#"
package main

var pages = map[string]string{"home": "safe"}

func entry(name string) {
    value, ok := pages[name]
    if !ok { return }
    sink(value)
    sink(pages[name])
}
"#,
    );
    let global = db.global_index();
    let decl = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");

    let mut assigns = Vec::new();
    collect_assigns(&decl.flow_events, &mut assigns);
    let value = assigns
        .iter()
        .find(|(target, _, _, _)| target == "value")
        .expect("selected value assignment");
    assert!(
        value.3.iter().any(|source| source == "pages") && value.3.iter().all(|source| source != "name"),
        "selected value must inherit the table, not its dynamic selector: {assigns:?}"
    );
    let ok = assigns
        .iter()
        .find(|(target, _, _, _)| target == "ok")
        .expect("comma-ok assignment");
    assert!(
        ok.1.is_none() && ok.3.is_empty(),
        "comma-ok membership result must not inherit key or table taint: {assigns:?}"
    );

    let direct_lookup = decl
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } if name == "sink" => args.first(),
            _ => None,
        })
        .find(|arg| arg.value_text.contains("pages["))
        .expect("direct lookup call argument");
    assert_eq!(direct_lookup.place.as_deref(), Some("pages"));
    assert!(
        direct_lookup.source_names.iter().all(|source| source != "name"),
        "direct lookup call argument must not turn the selector into value flow: {direct_lookup:?}"
    );
}

#[test]
fn multiple_return_values_preserve_exact_go_positions() {
    let db = db_with(
        r#"
package main

func fail(value string) error { return nil }
func safe() string { return "safe" }

func render(name string) (string, error) {
    if name == "" { return "", fail(name) }
    return safe(), nil
}
"#,
    );
    let global = db.global_index();
    let decl = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "render")
        .expect("render declaration");
    let mut returns = Vec::new();
    collect_returns(&decl.flow_events, &mut returns);
    assert_eq!(
        returns.len(),
        2,
        "expected both parsed return statements: {returns:#?}"
    );
    assert!(
        returns
            .iter()
            .all(|(value_name, flow)| value_name.is_none() && flow.tuple_items.len() == 2),
        "Go multiple returns must lower to positional compiler facts: {returns:#?}"
    );
    let error_return = returns
        .iter()
        .find(|(_, flow)| flow.tuple_items[1].call_sites.len() == 1)
        .expect("error call in second return position");
    assert!(
        error_return.1.tuple_items[0].is_empty(),
        "an error built from the selector must not taint the clean first result: {error_return:#?}"
    );
    let success_return = returns
        .iter()
        .find(|(_, flow)| flow.tuple_items[0].call_sites.len() == 1)
        .expect("success call in first return position");
    assert!(
        success_return.1.tuple_items[1].is_empty(),
        "the literal nil error must remain clean and position-specific: {success_return:#?}"
    );
}

#[test]
fn go_string_compositions_preserve_runtime_component_calls_and_path_boundaries() {
    let db = db_with(
        r#"
package main
import (
    "net/url"
    "os"
    "strings"
)
func rebuild(raw string, rel string) string {
    u, _ := url.Parse(raw)
    safe := "https://" + u.Hostname() + u.EscapedPath()
    if strings.HasPrefix(rel, ".." + string(os.PathSeparator)) { return "" }
    return safe
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source file");
    let index = db.decl_index(file).expect("Go declaration index");
    assert!(
        index.string_compositions.iter().any(|fact| {
            matches!(
                fact.parts.as_slice(),
                [
                    StringCompositionPart::Literal { value },
                    StringCompositionPart::Call { .. },
                    StringCompositionPart::Call { .. }
                ] if value == "https://"
            )
        }),
        "URL reconstruction must be a complete compiler fact: {:#?}",
        index.string_compositions
    );
    assert!(
        index.string_compositions.iter().any(|fact| {
            matches!(
                fact.parts.as_slice(),
                [StringCompositionPart::Literal { value }, StringCompositionPart::Call { .. }]
                    if value == ".."
            )
        }),
        "relative-path boundary must be exact compiler IR: {:#?}",
        index.string_compositions
    );
    let boundary = index
        .string_compositions
        .iter()
        .find(|fact| {
            matches!(
                fact.parts.as_slice(),
                [StringCompositionPart::Literal { value }, StringCompositionPart::Call { .. }]
                    if value == ".."
            )
        })
        .expect("relative boundary composition");
    assert!(
        index
            .call_argument_values
            .iter()
            .any(|argument| argument.argument_index == 1 && argument.argument_span == boundary.value_span),
        "the compiler must join the exact prefix argument to its composition: args={:#?}, boundary={boundary:#?}",
        index.call_argument_values
    );
    let wrapper_span = match boundary.parts.as_slice() {
        [_, StringCompositionPart::Call { span }] => *span,
        _ => unreachable!(),
    };
    let mut calls = Vec::new();
    for decl in &index.defs {
        collect_calls(&decl.flow_events, &mut calls);
    }
    assert!(
        calls
            .iter()
            .any(|(name, span)| name == "string" && *span == wrapper_span),
        "the wrapper call and composition must share one compiler span: calls={calls:#?}, boundary={boundary:#?}"
    );
}

#[test]
fn strings_map_control_filter_emits_exact_character_constraint_only_for_complete_callback() {
    let db = db_with(
        r#"
package main
import "strings"

func safe(s string) string {
    return strings.Map(func(r rune) rune {
        if r < 0x20 || r == 0x7f { return '_' }
        return r
    }, s)
}

func partial(s string) string {
    return strings.Map(func(r rune) rune {
        if r == '\n' { return '_' }
        return r
    }, s)
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source file");
    let index = db.decl_index(file).expect("Go declaration index");
    let [constraint] = index.character_constraints.as_slice() else {
        panic!(
            "only the complete C0 filter should lower: {:#?}",
            index.character_constraints
        );
    };
    assert!(matches!(constraint.output, CharacterConstraintOutput::Return));
    assert_eq!(constraint.input_param_index, Some(0));
    assert!(matches!(
        &constraint.domain,
        CharacterConstraintDomain::ProviderBound {
            factory_call,
            operation_call,
            domain,
        }
            if factory_call == "strings.Map"
                && operation_call == "strings.Map"
                && matches!(domain.as_ref(), CharacterConstraintDomain::ExcludesExact { characters }
            if characters == &["\r".to_string(), "\n".to_string()]
                )
    ));
}

#[test]
fn guarded_append_loop_emits_exact_character_constraint_without_security_policy() {
    let db = db_with(
        r#"
package main

func safe(filename string) string {
    clean := make([]byte, 0, 255)
    for i := 0; i < len(filename); i++ {
        ch := filename[i]
        if ch >= 0x20 && ch != 0x7f {
            clean = append(clean, ch)
        }
    }
    return string(clean)
}

func weak(filename string) string {
    clean := make([]byte, 0, 255)
    for i := 0; i < len(filename); i++ {
        ch := filename[i]
        if ch != '\n' { clean = append(clean, ch) }
    }
    return string(clean)
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source file");
    let index = db.decl_index(file).expect("Go declaration index");
    let safe = index
        .defs
        .iter()
        .find(|decl| decl.name == "safe")
        .expect("safe decl");
    let facts = index
        .character_constraints
        .iter()
        .filter(|fact| fact.function_span == safe.span)
        .collect::<Vec<_>>();
    assert_eq!(
        facts.len(),
        1,
        "safe loop should lower once: {:#?}",
        index.character_constraints
    );
    assert_eq!(facts[0].input_place, "filename");
    assert_eq!(facts[0].input_param_index, Some(0));
    assert!(matches!(
        &facts[0].output,
        CharacterConstraintOutput::Assignment { target } if target == "clean"
    ));
    assert!(matches!(
        &facts[0].domain,
        CharacterConstraintDomain::ExcludesExact { characters }
            if characters == &["\r".to_string(), "\n".to_string()]
    ));
    let weak = index
        .defs
        .iter()
        .find(|decl| decl.name == "weak")
        .expect("weak decl");
    assert!(
        index
            .character_constraints
            .iter()
            .all(|fact| fact.function_span != weak.span),
        "a partial newline-only filter is not a complete CR/LF boundary"
    );
}

#[test]
fn same_origin_predicate_and_fallback_lower_to_caller_postcondition() {
    let db = db_with(
        r#"
package main

func sameOrigin(s string) bool {
    return len(s) > 0 && s[0] == '/' && (len(s) == 1 || s[1] != '/')
}

func redirect(target string) {
    if !sameOrigin(target) { target = "/" }
    consume(target)
}

func weak(target string) {
    if len(target) > 0 { target = "/" }
    consume(target)
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source file");
    let index = db.decl_index(file).expect("Go declaration index");
    let redirect = index
        .defs
        .iter()
        .find(|decl| decl.name == "redirect")
        .expect("redirect decl");
    let facts = index
        .same_origin_path_constraints
        .iter()
        .filter(|fact| fact.function_span == redirect.span)
        .collect::<Vec<_>>();
    let [fact] = facts.as_slice() else {
        panic!(
            "exact same-origin caller fact missing: {:#?}",
            index.same_origin_path_constraints
        );
    };
    assert_eq!(fact.input_place, "target");
    assert_eq!(fact.input_param_index, Some(0));
    assert!(fact.rejects_scheme && fact.rejects_authority);
    assert!(fact.requires_absolute_path && fact.rejects_scheme_relative_path);
    let weak = index
        .defs
        .iter()
        .find(|decl| decl.name == "weak")
        .expect("weak decl");
    assert!(index
        .same_origin_path_constraints
        .iter()
        .all(|fact| fact.function_span != weak.span));

    let local_db = db_with(
        r#"
package main
func sameOrigin(s string) bool {
    return len(s) > 0 && s[0] == '/' && (len(s) == 1 || s[1] != '/')
}
func redirect() {
    target := source()
    if !sameOrigin(target) { target = "/" }
    consume(target)
}
"#,
    );
    let local_file = local_db
        .vfs()
        .all_files()
        .into_iter()
        .next()
        .expect("Go source file");
    let local_index = local_db.decl_index(local_file).expect("Go declaration index");
    let local = local_index
        .same_origin_path_constraints
        .first()
        .expect("caller-local same-origin fact");
    assert_eq!(local.input_place, "target");
    assert_eq!(local.input_param_index, None);
}

#[test]
fn callback_selector_guards_are_api_neutral_compiler_facts() {
    let db = db_with(
        r#"
package main
import (
    "github.com/golang-jwt/jwt/v5"
)

func verify(raw string, key []byte) {
    jwt.Parse(raw, func(t *jwt.Token) (any, error) {
        if t.Method.Alg() != "HS256" { return nil, jwt.ErrSignatureInvalid }
        return key, nil
    })
}

func unsafe(raw string, key []byte) {
    jwt.Parse(raw, func(t *jwt.Token) (any, error) { return key, nil })
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source file");
    let index = db.decl_index(file).expect("Go declaration index");
    let imports = db.import_index(file).expect("Go imports");
    assert!(
        imports.imports.iter().any(|import| {
            import.module == "github.com/golang-jwt/jwt/v5" && import.alias.as_deref() == Some("jwt")
        }),
        "semantic import versions must preserve the package binding: {imports:#?}"
    );
    assert_eq!(
        index
            .compiler_guards
            .iter()
            .filter(|fact| fact.capability == "callback.selector-result-pinned")
            .count(),
        1,
        "only the algorithm-pinned callback is proven; imports={imports:#?}, guards={:#?}",
        index.compiler_guards,
    );
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| fact.capability == "callback.selector-result-pinned")
        .expect("selector-pin fact");
    assert!(fact.evidence.contains(&"callback-argument:1".to_string()));
    assert!(fact.evidence.contains(&"selector:Method.Alg".to_string()));
    assert!(fact.evidence.contains(&"literal:hs256".to_string()));
}

#[test]
fn relative_path_boundary_helper_is_an_exact_compiler_fact() {
    let db = db_with(
        r#"
package main
import "path/filepath"

func boundarySafe(rel string) bool {
    return len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)
}

func prefixOnly(rel string) bool {
    return len(rel) >= 2 && rel[:2] == ".."
}

func load(rel string) {
    if boundarySafe(rel) { return }
    if prefixOnly(rel) { return }
}
"#,
    );
    let file = db.vfs().all_files().into_iter().next().expect("Go source file");
    let index = db.decl_index(file).expect("Go declaration index");
    let guards = index
        .compiler_guards
        .iter()
        .filter(|fact| fact.capability == bonsai_lang_api::COMPILER_GUARD_RELATIVE_PATH_BOUNDARY_REJECTION)
        .collect::<Vec<_>>();

    assert_eq!(
        guards.len(),
        1,
        "only the boundary-aware helper may be promoted: {:#?}",
        index.compiler_guards
    );
}
