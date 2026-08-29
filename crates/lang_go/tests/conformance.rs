use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_go::GoAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [("a.go", "package main\nfunc main() {}")]
    );
}

#[test]
fn variadic_parameter_declaration_keeps_its_exact_binding() {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "variadic.go",
            "package main\nfunc collect(prefix string, values ...string) { sink(values) }\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Go declaration index");
    let collect = index
        .defs
        .iter()
        .find(|decl| decl.name == "collect")
        .expect("collect declaration");

    assert_eq!(collect.params, ["prefix", "values"]);
    assert!(collect
        .type_aliases
        .iter()
        .any(|alias| { alias.name == "values" && alias.type_name == "string" }));
}

#[test]
fn nested_call_arguments_retain_exact_direct_call_spans() {
    use bonsai_lang_api::RefKind;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "nested.go",
            r#"package main
import "path/filepath"
func clean(root, input string) string {
    return filepath.Clean(filepath.Join(root, input))
}
func compound(root, input string) string {
    return filepath.Clean("prefix/" + filepath.Join(root, input))
}
func multi(input string) string {
    rootAbs, err := filepath.Abs(input)
    _ = err
    return rootAbs
}
func pair(input string) (string, error) { return input, nil }
func entry() { _, _ = pair("fixed") }
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Go declaration index");

    let calls = index
        .refs
        .iter()
        .filter(|reference| reference.kind == RefKind::Call)
        .collect::<Vec<_>>();
    let direct_outer = calls
        .iter()
        .find(|reference| reference.name == "filepath.Clean" && reference.span.start < 150)
        .expect("direct outer call");
    let direct_argument = index
        .call_argument_values
        .iter()
        .find(|argument| argument.call_span == direct_outer.span && argument.argument_index == 0)
        .unwrap_or_else(|| {
            panic!(
                "missing direct argument: outer={direct_outer:#?}; refs={:#?}; arguments={:#?}",
                index.refs, index.call_argument_values
            )
        });
    let inner_span = direct_argument
        .direct_call_span
        .unwrap_or_else(|| panic!("missing nested direct call: {direct_argument:#?}"));
    assert!(calls
        .iter()
        .any(|reference| reference.name == "filepath.Join" && reference.span == inner_span));

    let compound_outer = calls
        .iter()
        .filter(|reference| reference.name == "filepath.Clean")
        .max_by_key(|reference| reference.span.start)
        .expect("compound outer call");
    let compound_argument = index
        .call_argument_values
        .iter()
        .find(|argument| argument.call_span == compound_outer.span && argument.argument_index == 0)
        .expect("compound argument fact");
    assert_eq!(compound_argument.direct_call_span, None);

    let multi_value = index
        .assignment_values
        .iter()
        .find(|fact| fact.direct_call_name.as_deref() == Some("filepath.Abs"))
        .unwrap_or_else(|| panic!("missing tuple-result value fact: {:#?}", index.assignment_values));
    assert_eq!(
        multi_value.target, None,
        "a complete multi-target RHS fact must not claim one target projection"
    );

    let entry = index
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    assert!(
        entry
            .flow_events
            .iter()
            .any(|event| matches!(event, bonsai_lang_api::FlowEvent::Call { name, .. } if name == "pair")),
        "a call whose results are assigned only to blank identifiers must remain executable: {:#?}",
        entry.flow_events
    );
    let graph = workspace.cached_resolved_call_graph();
    let pair = graph
        .nodes()
        .iter()
        .find(|node| node.name.as_ref() == "pair")
        .expect("pair callgraph node");
    let callers = graph.callers_of(pair.func).collect::<Vec<_>>();
    assert!(
        !callers.is_empty(),
        "a discarded multi-result call must remain in the resolved callgraph: nodes={:#?}; unresolved={:#?}",
        graph.nodes(),
        graph.unresolved_workspace_site_records()
    );
}

#[test]
fn selector_writes_and_post_call_member_reads_keep_exact_places() {
    use bonsai_lang_api::{FlowEvent, RefKind};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "main.go",
            r#"package main
import (
    "encoding/xml"
    "github.com/labstack/echo"
)
func configure(dec *xml.Decoder, entities map[string]string, c echo.Context) {
    dec.Strict = false
    dec.Entity = entities
    _ = c.Request().Body
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Go declaration index");
    let configure = index
        .defs
        .iter()
        .find(|decl| decl.name == "configure")
        .expect("configure declaration");
    let assignments = configure
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        assignments.contains(&"dec.Strict"),
        "events={:?}",
        configure.flow_events
    );
    assert!(
        assignments.contains(&"dec.Entity"),
        "events={:?}",
        configure.flow_events
    );
    assert!(
        index
            .refs
            .iter()
            .any(|reference| reference.kind == RefKind::Read && reference.name == "c.Request().Body"),
        "refs={:?}; events={:?}",
        index.refs,
        configure.flow_events
    );
}

#[test]
fn selector_after_call_argument_keeps_property_read_value_identity() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "main.go",
            r#"package main
type Body struct{}
type Request struct{ Body *Body }
type Context interface { Request() *Request }
func consume(body *Body) {}
func handler(c Context) { consume(c.Request().Body) }
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Go declaration index");
    let handler = index
        .defs
        .iter()
        .find(|decl| decl.name == "handler")
        .expect("handler declaration");
    let consume_span = handler
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { span, name, args, .. } if name == "consume" => {
                assert_eq!(args.len(), 1);
                assert_eq!(args[0].place.as_deref(), Some("c.Request().Body"));
                Some(*span)
            }
            _ => None,
        })
        .expect("consume call");
    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == consume_span && fact.argument_index == 0)
        .unwrap_or_else(|| panic!("missing argument fact: {:#?}", index.call_argument_values));

    assert_eq!(argument.value_kind, Some(AssignValueKind::PropertyRead));
    assert_eq!(argument.value_flow.place.as_deref(), Some("c.Request().Body"));
    assert_eq!(
        argument
            .value_flow
            .projection
            .as_ref()
            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
            .as_deref(),
        Some("c.Request().Body")
    );
    assert!(
        argument.direct_call_span.is_some(),
        "the nested Request() receiver call must remain independently typed"
    );
}

#[test]
fn selector_after_call_argument_inside_lambda_keeps_property_read_value_identity() {
    use bonsai_lang_api::{AssignValueKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "main.go",
            r#"package main
type Body struct{}
type Request struct{ Body *Body }
type Context interface { Request() *Request }
type Router interface { POST(string, func(Context) error) }
func register(router Router) {
    router.POST("/restore", func(c Context) error {
        service.RestoreState(c.Request().Body)
        return nil
    })
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace.db().decl_index(file).expect("Go declaration index");
    let lambda = index
        .defs
        .iter()
        .find(|decl| decl.name.starts_with("<lambda@"))
        .expect("route lambda declaration");
    let call_span = lambda
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { span, name, args, .. } if name == "service.RestoreState" => {
                assert_eq!(args.len(), 1);
                assert_eq!(args[0].place.as_deref(), Some("c.Request().Body"));
                Some(*span)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing RestoreState call: {:#?}", lambda.flow_events));
    let argument = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == call_span && fact.argument_index == 0)
        .unwrap_or_else(|| panic!("missing argument fact: {:#?}", index.call_argument_values));

    assert_eq!(argument.value_kind, Some(AssignValueKind::PropertyRead));
    assert_eq!(argument.value_flow.place.as_deref(), Some("c.Request().Body"));
    assert_eq!(
        argument
            .value_flow
            .projection
            .as_ref()
            .map(bonsai_lang_api::ExpressionProjection::canonical_place)
            .as_deref(),
        Some("c.Request().Body")
    );
}

#[test]
fn package_qualifier_collisions_keep_exact_import_and_receiver_bindings() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_go::GoAdapter::new())],
        &[(
            "bindings.go",
            r#"package demo
import (
    "context"
    flag "flag"
    exec "os/exec"
)

func imported(ctx context.Context) {
    _ = flag.Arg(0)
    _ = flag.Args()
    _ = exec.Command("tool")
    _ = exec.CommandContext(ctx, "tool")
}

func collision(
    flag interface { Arg(int) string; Args() []string },
    exec interface { Command(string) any; CommandContext(context.Context, string) any },
    ctx context.Context,
) {
    _ = flag.Arg(0)
    _ = flag.Args()
    _ = exec.Command("tool")
    _ = exec.CommandContext(ctx, "tool")
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let imports = workspace
        .db()
        .compiler_import_index_uncached(file)
        .expect("Go import index");
    assert!(imports
        .imports
        .iter()
        .any(|import| { import.module == "flag" && import.alias.as_deref() == Some("flag") }));
    assert!(imports
        .imports
        .iter()
        .any(|import| { import.module == "os/exec" && import.alias.as_deref() == Some("exec") }));

    let index = workspace.db().decl_index(file).expect("Go declaration index");
    for function in ["imported", "collision"] {
        let decl = index
            .defs
            .iter()
            .find(|decl| decl.name == function)
            .unwrap_or_else(|| panic!("missing {function} declaration"));
        let calls = decl
            .flow_events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Call { name, receiver, .. } => Some((name.as_str(), receiver.as_deref())),
                _ => None,
            })
            .collect::<Vec<_>>();
        for method in ["Arg", "Args"] {
            assert!(
                calls
                    .iter()
                    .any(|(name, receiver)| { name.ends_with(method) && *receiver == Some("flag") }),
                "{function} lost the exact flag receiver for {method}: {calls:#?}"
            );
        }
        for method in ["Command", "CommandContext"] {
            assert!(
                calls
                    .iter()
                    .any(|(name, receiver)| { name.ends_with(method) && *receiver == Some("exec") }),
                "{function} lost the exact exec receiver for {method}: {calls:#?}"
            );
        }
    }
}
