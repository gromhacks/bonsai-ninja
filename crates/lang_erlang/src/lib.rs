//! Erlang language adapter.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_from_tree_with_handler, extract_imports_via,
    kit::{
        collect_kinds, first_identifier_descendant, first_identifier_like_child, language_from_pack,
        node_text, parse_with, populate_call_argument_static_values, span_of, walk_flow_events,
    },
    AdapterContext, AdapterError, AssignValueKind, AssignmentValueFact, AssignmentValueIndex,
    CallTargetExtraction, CompilerGuardFact, DeclIndex, ExpressionFlow, ExpressionPlaceExtraction,
    FiniteLiteralSelectionFact, FlowEvent, GrammarHandler, ImportIndex, ImportScope, ImportSpec,
    LanguageAdapter, LanguageCapabilities, LanguageId, PatternBindingSite, StaticAggregateFieldValue,
    StaticScalarValue, StringCompositionFact, StringCompositionPart, Visibility,
};
use tree_sitter::{Language, Node, Tree};

/// Decode immutable Erlang scalar syntax into compiler facts. Security and
/// framework meaning stays in rule data; this adapter only proves the exact
/// parsed atom/string value. Escaped quoted forms fail closed until the
/// frontend can preserve their decoded codepoints without ambiguity.
fn erlang_static_scalar(node: Node<'_>, src: &[u8]) -> Option<StaticScalarValue> {
    let raw = node_text(&node, src).trim();
    let value = match node.kind() {
        "atom" => {
            if let Some(quoted) = raw.strip_prefix('\'').and_then(|value| value.strip_suffix('\'')) {
                (!quoted.is_empty() && !quoted.contains(['\\', '\n', '\r'])).then_some(quoted)?
            } else {
                (!raw.is_empty()
                    && raw
                        .chars()
                        .all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric()))
                .then_some(raw)?
            }
        }
        "string" => {
            let quoted = raw.strip_prefix('"')?.strip_suffix('"')?;
            (!quoted.contains(['\\', '\n', '\r'])).then_some(quoted)?
        }
        _ => return None,
    };
    Some(StaticScalarValue::String(value.to_string()))
}

/// Decode Erlang's conventional list-of-two-tuples data shape as exact named
/// aggregate fields. The syntax relationship is generic: no option names or
/// values are interpreted here. Dynamic values remain absent, while dynamic
/// keys, malformed tuples, duplicate keys, and improper container shapes fail
/// closed because their overwrite semantics cannot be proven.
fn erlang_static_tuple_list_fields(node: Node<'_>, src: &[u8]) -> Option<Vec<StaticAggregateFieldValue>> {
    fn collect(
        node: Node<'_>,
        src: &[u8],
        prefix: &mut Vec<String>,
        seen: &mut std::collections::HashSet<Vec<String>>,
        out: &mut Vec<StaticAggregateFieldValue>,
    ) -> Option<()> {
        if node.kind() != "list" {
            return None;
        }
        let mut cursor = node.walk();
        for entry in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() != "comment")
        {
            if entry.kind() != "tuple" {
                return None;
            }
            let mut tuple_cursor = entry.walk();
            let items = entry
                .named_children(&mut tuple_cursor)
                .filter(|child| child.kind() != "comment")
                .collect::<Vec<_>>();
            let [key, value] = items.as_slice() else {
                return None;
            };
            let StaticScalarValue::String(key) = erlang_static_scalar(*key, src)? else {
                return None;
            };
            prefix.push(key);
            if !seen.insert(prefix.clone()) {
                return None;
            }
            if value.kind() == "list" {
                collect(*value, src, prefix, seen, out)?;
            } else if let Some(value) = erlang_static_scalar(*value, src) {
                out.push(StaticAggregateFieldValue {
                    path: prefix.clone(),
                    value,
                });
            }
            prefix.pop();
        }
        Some(())
    }

    let mut out = Vec::new();
    collect(
        node,
        src,
        &mut Vec::new(),
        &mut std::collections::HashSet::new(),
        &mut out,
    )?;
    (!out.is_empty()).then_some(out)
}

fn populate_erlang_static_tuple_list_fields(index: &mut DeclIndex, tree: &Tree, src: &[u8]) {
    for fact in &mut index.call_argument_values {
        let Some(node) = bonsai_lang_api::kit::node_at_span(tree.root_node(), fact.argument_span, &["list"])
        else {
            continue;
        };
        let Some(fields) = erlang_static_tuple_list_fields(node, src) else {
            continue;
        };
        fact.exact_static_aggregate_fields.extend(fields);
        fact.exact_static_aggregate_fields
            .sort_by(|left, right| left.path.cmp(&right.path));
        fact.exact_static_aggregate_fields.dedup();
    }
}

fn erlang_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn erlang_nodes_below<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    out.sort_by_key(Node::start_byte);
    out
}

fn erlang_call_parts<'tree>(node: Node<'tree>, src: &[u8]) -> Option<(String, Vec<Node<'tree>>)> {
    let target = erlang_call_target(node, src)?;
    let call = if node.kind() == "remote" {
        node.child_by_field_name("fun")?
    } else {
        node
    };
    let args = call.child_by_field_name("args")?;
    Some((target.full_text, erlang_named_children(args)))
}

/// Exact finite string-list macro definitions. The preprocessor spelling is
/// adapter syntax; consumers assign any security meaning to the collection.
/// Duplicate definitions and non-literal elements fail closed.
fn erlang_finite_string_macros(tree: &Tree, src: &[u8]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut definitions = std::collections::BTreeMap::<String, Vec<Vec<String>>>::new();
    for definition in collect_kinds(tree, &["pp_define"]) {
        let (Some(lhs), Some(replacement)) = (
            definition.child_by_field_name("lhs"),
            definition.child_by_field_name("replacement"),
        ) else {
            continue;
        };
        let Some(name) = lhs.child_by_field_name("name") else {
            continue;
        };
        if replacement.kind() != "list" {
            continue;
        }
        let values = erlang_named_children(replacement)
            .into_iter()
            .map(|node| match erlang_static_scalar(node, src) {
                Some(StaticScalarValue::String(value)) => Some(value),
                _ => None,
            })
            .collect::<Option<Vec<_>>>();
        let name = node_text(&name, src).trim();
        if let (Some(values), false) = (values, name.is_empty()) {
            if !values.is_empty() {
                definitions.entry(name.to_string()).or_default().push(values);
            }
        }
    }
    definitions
        .into_iter()
        .filter_map(|(name, values)| match values.as_slice() {
            [values] => Some((name, values.clone())),
            _ => None,
        })
        .collect()
}

type ErlangMapPatternFields = (
    Vec<(String, StaticScalarValue)>,
    std::collections::BTreeMap<String, String>,
);

fn erlang_map_pattern_fields(pattern: Node<'_>, src: &[u8]) -> Option<ErlangMapPatternFields> {
    if pattern.kind() != "map_expr" {
        return None;
    }
    let mut static_fields = Vec::new();
    let mut bindings = std::collections::BTreeMap::new();
    for field in erlang_named_children(pattern) {
        if field.kind() != "map_field" {
            return None;
        }
        let (Some(key), Some(value)) = (
            field.child_by_field_name("key"),
            field.child_by_field_name("value"),
        ) else {
            return None;
        };
        let StaticScalarValue::String(key) = erlang_static_scalar(key, src)? else {
            return None;
        };
        if let Some(value) = erlang_static_scalar(value, src) {
            static_fields.push((key, value));
        } else if value.kind() == "var" {
            let binding = node_text(&value, src).trim();
            if binding.is_empty() {
                return None;
            }
            bindings.insert(binding.to_string(), key);
        } else {
            return None;
        }
    }
    Some((static_fields, bindings))
}

fn erlang_static_scalar_evidence(value: &StaticScalarValue) -> String {
    match value {
        StaticScalarValue::String(value) => format!("string:{value}"),
        StaticScalarValue::Integer(value) => format!("integer:{value}"),
        StaticScalarValue::Boolean(value) => format!("boolean:{value}"),
        StaticScalarValue::Null => "null".to_string(),
    }
}

/// Prove a nested Erlang case arm that can execute a call only after a parsed
/// record/map carries fixed scalar fields and a bound field is a member of one
/// immutable finite string collection. This records compiler evidence only;
/// rule data owns the meaning of parse/member/configuration call spellings.
fn collect_erlang_finite_pattern_membership_guards(
    tree: &Tree,
    src: &[u8],
    file: FileId,
    defs: &[bonsai_lang_api::Decl],
    argument_values: &[bonsai_lang_api::CallArgumentValueFact],
) -> Vec<CompilerGuardFact> {
    let finite_macros = erlang_finite_string_macros(tree, src);
    let mut facts = Vec::new();
    for outer_case in collect_kinds(tree, &["case_expr"]) {
        let Some(scrutinee) = outer_case.child_by_field_name("expr") else {
            continue;
        };
        let Some((scrutinee_call, scrutinee_args)) = erlang_call_parts(scrutinee, src) else {
            continue;
        };
        for outer_clause in erlang_named_children(outer_case)
            .into_iter()
            .filter(|node| node.kind() == "cr_clause")
        {
            let (Some(pattern), Some(body)) = (
                outer_clause.child_by_field_name("pat"),
                outer_clause.child_by_field_name("body"),
            ) else {
                continue;
            };
            let Some((static_fields, bindings)) = erlang_map_pattern_fields(pattern, src) else {
                continue;
            };
            for inner_case in erlang_nodes_below(body, "case_expr") {
                let Some(membership) = inner_case.child_by_field_name("expr") else {
                    continue;
                };
                let Some((membership_call, membership_args)) = erlang_call_parts(membership, src) else {
                    continue;
                };
                let [subject, collection] = membership_args.as_slice() else {
                    continue;
                };
                let subject = node_text(subject, src).trim();
                let Some(field) = bindings.get(subject) else {
                    continue;
                };
                if collection.kind() != "macro_call_expr" {
                    continue;
                }
                let Some(macro_name) = collection.child_by_field_name("name") else {
                    continue;
                };
                let macro_name = node_text(&macro_name, src).trim();
                let Some(values) = finite_macros.get(macro_name) else {
                    continue;
                };
                for accepted_clause in erlang_named_children(inner_case)
                    .into_iter()
                    .filter(|node| node.kind() == "cr_clause")
                {
                    let (Some(accepted_pattern), Some(accepted_body)) = (
                        accepted_clause.child_by_field_name("pat"),
                        accepted_clause.child_by_field_name("body"),
                    ) else {
                        continue;
                    };
                    if erlang_static_scalar(accepted_pattern, src)
                        != Some(StaticScalarValue::String("true".to_string()))
                    {
                        continue;
                    }
                    for guarded_call in erlang_nodes_below(accepted_body, "remote") {
                        let Some(target) = erlang_call_target(guarded_call, src) else {
                            continue;
                        };
                        let Some((guarded_target, guarded_args)) = erlang_call_parts(guarded_call, src)
                        else {
                            continue;
                        };
                        let guarded_call_span = span_of(file, &target.node);
                        let Some(function_span) = defs
                            .iter()
                            .filter(|decl| {
                                let owner = decl.body_span.unwrap_or(decl.span);
                                owner.start <= guarded_call_span.start && guarded_call_span.end <= owner.end
                            })
                            .min_by_key(|decl| decl.span.len())
                            .map(|decl| decl.span)
                        else {
                            continue;
                        };
                        let mut evidence = vec![
                            format!("scrutinee-call:{scrutinee_call}"),
                            format!("membership-call:{membership_call}"),
                            format!("finite-string-membership-field:{field}"),
                            format!("finite-string-membership-count:{}", values.len()),
                        ];
                        for (field, value) in &static_fields {
                            evidence.push(format!(
                                "static-field:{field}={}",
                                erlang_static_scalar_evidence(value)
                            ));
                        }
                        for (guarded_index, guarded) in guarded_args.iter().enumerate() {
                            let projected_guarded = if guarded.kind() == "tuple" {
                                erlang_named_children(*guarded).into_iter().next()
                            } else {
                                Some(*guarded)
                            };
                            let Some(projected_guarded) = projected_guarded else {
                                continue;
                            };
                            let guarded = node_text(&projected_guarded, src).trim();
                            for (scrutinee_index, scrutinee) in scrutinee_args.iter().enumerate() {
                                if node_text(scrutinee, src).trim() == guarded {
                                    evidence.push(format!(
                                        "guarded-argument:{guarded_index}=scrutinee-argument:{scrutinee_index}"
                                    ));
                                }
                            }
                        }
                        for argument in argument_values
                            .iter()
                            .filter(|fact| fact.call_span == guarded_call_span)
                        {
                            for field in &argument.exact_static_aggregate_fields {
                                evidence.push(format!(
                                    "guarded-static-field:{}.{path}={value}",
                                    argument.argument_index,
                                    path = field.path.join("."),
                                    value = erlang_static_scalar_evidence(&field.value),
                                ));
                            }
                        }
                        evidence.push(format!("guarded-call:{guarded_target}"));
                        evidence.sort();
                        evidence.dedup();
                        facts.push(CompilerGuardFact {
                            function_span,
                            guarded_call_span,
                            proof_span: span_of(file, &accepted_clause),
                            capability: "case-arm.finite-pattern-membership".to_string(),
                            evidence,
                        });
                    }
                }
            }
        }
    }
    facts.sort_by_key(|fact| (fact.function_span.start, fact.guarded_call_span.start));
    facts.dedup();
    facts
}

/// Lower uniquely defined, scalar preprocessor constants as immutable
/// compiler values. Macro expansion syntax remains adapter-owned; duplicate
/// definitions and dynamic replacements fail closed.
fn collect_erlang_static_scalar_macros(tree: &Tree, src: &[u8], file: FileId) -> Vec<AssignmentValueFact> {
    let mut definitions: std::collections::BTreeMap<String, Vec<(Node<'_>, Node<'_>, Node<'_>)>> =
        std::collections::BTreeMap::new();
    for definition in collect_kinds(tree, &["pp_define"]) {
        let (Some(lhs), Some(value)) = (
            definition.child_by_field_name("lhs"),
            definition.child_by_field_name("replacement"),
        ) else {
            continue;
        };
        let Some(name_node) = lhs.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(&name_node, src).trim();
        if name.is_empty() {
            continue;
        }
        definitions
            .entry(name.to_string())
            .or_default()
            .push((definition, name_node, value));
    }
    let mut facts = Vec::new();
    for (name, definitions) in definitions {
        let [(definition, name_node, value)] = definitions.as_slice() else {
            continue;
        };
        let Some(static_value) = erlang_static_scalar(*value, src) else {
            continue;
        };
        facts.push(AssignmentValueFact {
            assignment_span: span_of(file, definition),
            target: Some(name),
            target_is_immutable: true,
            target_owner: None,
            target_span: Some(span_of(file, name_node)),
            value_span: span_of(file, value),
            call_sites: Vec::new(),
            value_flow: ExpressionFlow::default(),
            static_value: Some(static_value),
            exact_callable_return: None,
            inline_callback_static_return: None,
            inline_callback_fields: Vec::new(),
            exact_static_call_args: None,
            direct_call_name: None,
            direct_call_span: None,
            direct_call_receiver: None,
            direct_call_receiver_span: None,
            direct_call_receiver_flow: None,
        });
    }
    facts
}

fn collect_erlang_string_compositions(
    index: &DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<StringCompositionFact> {
    let mut facts = Vec::new();
    for expression in collect_kinds(tree, &["binary_op_expr"]) {
        let (Some(left), Some(right)) = (
            expression.child_by_field_name("lhs"),
            expression.child_by_field_name("rhs"),
        ) else {
            continue;
        };
        let operator = src
            .get(left.end_byte()..right.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim);
        if operator != Some("++") {
            continue;
        }
        let mut parts = Vec::new();
        if !lower_erlang_string_composition(expression, file, src, &mut parts) || parts.len() < 2 {
            continue;
        }
        let value_span = span_of(file, &expression);
        let assignment = index
            .assignment_values
            .iter()
            .filter(|fact| fact.value_span.start <= value_span.start && value_span.end <= fact.value_span.end)
            .min_by_key(|fact| fact.value_span.len());
        facts.push(StringCompositionFact {
            container_span: assignment.map_or(value_span, |fact| fact.assignment_span),
            value_span,
            dynamic_anchor_span: None,
            target: assignment.and_then(|fact| fact.target.clone()),
            parts,
        });
    }
    facts
}

fn lower_erlang_string_composition(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<StringCompositionPart>,
) -> bool {
    if let Some(StaticScalarValue::String(value)) = erlang_static_scalar(node, src) {
        out.push(StringCompositionPart::Literal { value });
        return true;
    }
    if matches!(node.kind(), "var" | "macro_call_expr") {
        let name = if node.kind() == "macro_call_expr" {
            node.child_by_field_name("name")
        } else {
            Some(node)
        };
        let Some(name) = name else { return false };
        let place = node_text(&name, src).trim();
        if place.is_empty() {
            return false;
        }
        out.push(StringCompositionPart::Place {
            place: place.to_string(),
        });
        return true;
    }
    if node.kind() == "remote" {
        let Some(target) = erlang_remote_target(node, src) else {
            return false;
        };
        out.push(StringCompositionPart::Call {
            span: span_of(file, &target.node),
        });
        return true;
    }
    if node.kind() != "binary_op_expr" {
        return false;
    }
    let (Some(left), Some(right)) = (node.child_by_field_name("lhs"), node.child_by_field_name("rhs")) else {
        return false;
    };
    let operator = src
        .get(left.end_byte()..right.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim);
    operator == Some("++")
        && lower_erlang_string_composition(left, file, src, out)
        && lower_erlang_string_composition(right, file, src, out)
}

/// Emit a finite-literal return fact for one Erlang function clause only when
/// its complete normal body is the single parsed literal return already
/// lowered by the frontend. Multi-clause dispatch remains represented by
/// multiple declarations; consumers must prove every resolved clause.
fn collect_erlang_finite_literal_returns(
    index: &DeclIndex,
    tree: &Tree,
    src: &[u8],
) -> Vec<FiniteLiteralSelectionFact> {
    let mut facts = Vec::new();
    for decl in &index.defs {
        let [FlowEvent::Return {
            span,
            value_kind: Some(AssignValueKind::Literal),
            value_flow,
            ..
        }] = decl.flow_events.as_slice()
        else {
            continue;
        };
        if !value_flow.is_empty() {
            continue;
        }
        let Some(value) = bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &[]) else {
            continue;
        };
        if erlang_static_scalar(value, src).is_none() {
            continue;
        }
        facts.push(FiniteLiteralSelectionFact {
            selection_span: *span,
            assignment_span: None,
            target: None,
            call_span: None,
            argument_index: None,
        });
    }
    bonsai_lang_api::kit::sort_dedup_finite_literal_selections(&mut facts);
    facts
}

fn erlang_comprehension_binding(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if !matches!(node.kind(), "generator" | "b_generator" | "map_generator") {
        return None;
    }
    Some((node.named_child(0)?, node.named_child(1)?))
}

fn erlang_case_pattern_bindings(node: Node<'_>) -> Vec<PatternBindingSite<'_>> {
    if node.kind() != "case_expr" {
        return Vec::new();
    }
    let Some(source) = node.child_by_field_name("expr") else {
        return Vec::new();
    };
    let mut sites = Vec::new();
    let mut cursor = node.walk();
    for clause in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "cr_clause")
    {
        let Some(pattern) = clause.child_by_field_name("pat") else {
            continue;
        };
        sites.push(PatternBindingSite {
            span_node: pattern,
            pattern,
            source,
        });
    }
    sites
}

fn erlang_remote_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() != "remote" {
        return None;
    }
    let module = node.child_by_field_name("module")?;
    let function = node.child_by_field_name("fun")?;
    let callee = function
        .child_by_field_name("expr")
        .or_else(|| function.child_by_field_name("name"))
        .or_else(|| first_identifier_like_child(&function))
        .or_else(|| first_identifier_descendant(function))
        .unwrap_or(function);
    let module = node_text(&module, src).trim_end_matches(':').trim();
    let function = node_text(&callee, src).trim();
    if module.is_empty() || function.is_empty() {
        return None;
    }
    Some(CallTargetExtraction {
        node: callee,
        full_text: format!("{module}:{function}"),
    })
}

fn erlang_call_target<'tree>(node: Node<'tree>, src: &[u8]) -> Option<CallTargetExtraction<'tree>> {
    if node.kind() == "remote" {
        return erlang_remote_target(node, src);
    }
    if node.kind() != "call" {
        return None;
    }
    let expression = node.child_by_field_name("expr")?;
    if let Some(target) = erlang_remote_target(expression, src) {
        return Some(target);
    }
    let callee = expression
        .child_by_field_name("expr")
        .or_else(|| expression.child_by_field_name("name"))
        .or_else(|| first_identifier_like_child(&expression))
        .or_else(|| first_identifier_descendant(expression))
        .unwrap_or(expression);
    let full_text = node_text(&callee, src).trim().to_string();
    (!full_text.is_empty()).then_some(CallTargetExtraction {
        node: callee,
        full_text,
    })
}

fn erlang_call_ref_node(node: Node<'_>) -> bool {
    if node.kind() != "remote" {
        return true;
    }
    let Some(parent) = node.parent() else {
        return true;
    };
    parent.kind() != "call"
        || parent
            .child_by_field_name("expr")
            .is_none_or(|expression| expression.id() != node.id())
}

fn erlang_expression_places(node: Node<'_>, src: &[u8]) -> ExpressionPlaceExtraction {
    if node.kind() != "macro_call_expr" {
        return ExpressionPlaceExtraction::default();
    }
    let Some(name) = node.child_by_field_name("name") else {
        return ExpressionPlaceExtraction::default();
    };
    let place = node_text(&name, src).trim();
    if place.is_empty() {
        return ExpressionPlaceExtraction::default();
    }
    ExpressionPlaceExtraction {
        places: vec![place.to_string()],
        consumed_node_ids: vec![node.id()],
    }
}

pub const LANG_ID: LanguageId = LanguageId::new("erlang");
const PACK_NAME: &str = "erlang";

// Erlang's tree-sitter grammar (WhatsApp) uses its own construct nodes.
// This adapter declares the complete production inventory so shared lowering
// can emit case / if / try / receive flow without a cross-language fallback.
const HANDLER: GrammarHandler = GrammarHandler {
    expression_value_kind_extractor: None,
    literal_value_kinds: &["atom", "char", "float", "integer"],
    string_literal_kinds: &["string", "macro_string", "multi_string"],
    comment_kinds: &["comment"],
    doc_comment_prefixes: &["%% @doc"],
    // Module/export/behaviour attributes are declaration metadata handled by
    // the adapter's exact attribute passes, not callable decorators.
    decorator_kinds: &[],
    parameter_container_kinds: &["expr_args"],
    parameter_kinds: &["var"],
    parameter_annotation_name_extractor: None,
    binding_identifier_kinds: &["var"],
    identifier_kinds: &["var"],
    pattern_binding_extractor: Some(erlang_case_pattern_bindings),
    // Map matches are binding patterns just like tuples and lists:
    // `#{host := Host} = request()` binds the value-side variable.  The
    // grammar-declared `map_field` key/value fields let shared lowering walk
    // only value bindings; literal atom keys never become locals.
    aggregate_pattern_kinds: &["tuple", "list", "map_expr"],
    comprehension_kinds: &["list_comprehension", "binary_comprehension", "map_comprehension"],
    comprehension_binding_clause_kinds: &["generator", "b_generator", "map_generator"],
    comprehension_binding_extractor: Some(erlang_comprehension_binding),
    named_aggregate_kinds: &["map_expr"],
    positional_aggregate_kinds: &["tuple", "list"],
    aggregate_pair_kinds: &["map_field"],
    aggregate_key_field_names: &["key"],
    aggregate_value_field_names: &["value"],
    static_field_name_kinds: &["atom"],
    expression_place_extractor: Some(erlang_expression_places),
    transparent_call_wrapper_kinds: &["remote"],
    single_expression_group_kinds: &["block_expr"],
    nested_type_ownership: true,
    // Erlang functions: `fun_decl` is the umbrella; clauses are
    // `function_clause`. We index both so single- and multi-clause
    // functions both produce decls.
    fn_kinds: &["fun_decl", "function_clause"],
    class_kinds: &[],
    class_decl_kinds: &[],
    method_kinds: &[],
    method_context_kinds: &[],
    method_owner_barrier_kinds: &[],
    constructor_method_kinds: &[],
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    if_kinds: &["if_expr", "case_expr"],
    branch_then_field_names: &[],
    branch_else_field_names: &[],
    branch_condition_field_names: &["expr"],
    branch_condition_is_first_named_child: false,
    condition_group_kinds: &[],
    condition_all_operators: &["andalso"],
    condition_any_operators: &["orelse"],
    condition_not_operators: &["not"],
    condition_not_operator_kinds: &[],
    loop_body_field_names: &["body"],
    loop_body_kinds: &["clause_body"],
    loop_header_container_kinds: &[],
    loop_update_field_names: &[],
    branch_arm_kinds: &["cr_clause", "if_clause", "clause_body"],
    exclusive_branch_arm_kinds: &["cr_clause", "if_clause"],
    fallthrough_branch_arm_kinds: &[],
    additional_alternative_kinds: &["cr_clause", "if_clause"],
    for_kinds: &[],
    // Comprehensions (`[E || X <- L]`, `<< ... >>`) go through the shared
    // walker's comprehension branch (list_comprehension /
    // binary_comprehension with nested `generator` binding clauses);
    // tree-sitter-erlang has no foreach-shaped node kind.
    foreach_kinds: &[],
    while_kinds: &[],
    do_kinds: &[],
    loop_kinds: &[],
    call_kinds: &["call", "remote"],
    call_callee_field_names: &["expr", "fun"],
    call_receiver_field_names: &["module"],
    call_member_field_names: &["fun"],
    call_argument_field_names: &["args"],
    call_argument_container_kinds: &["expr_args"],
    // The pinned tree-sitter-erlang grammar represents `module:fun(args)` as a
    // `remote { module, fun: call { expr, args } }` node. The remote node is
    // the semantic call owner; declare its nested `call` as an argument
    // wrapper so shared lowering reads the exact `expr_args` without
    // duplicating the inner component as another call event.
    call_argument_wrapper_kinds: &["call"],
    call_target_extractor: Some(erlang_call_target),
    call_ref_node_filter: Some(erlang_call_ref_node),
    lambda_body_field_names: &["body"],
    argument_passing_mode_extractor: None,
    nested_call_component_kinds: &["remote"],
    call_ref_kinds: &["call", "remote"],
    assignment_kinds: &["match_expr"],
    return_kinds: &[],
    throw_kinds: &[],
    lambda_kinds: &["anonymous_fun"],
    try_kinds: &["try_expr"],
    catch_kinds: &["catch_clause"],
    exclusive_catch_arm_kinds: &["catch_clause"],
    // tree-sitter-erlang names the `after` region `try_after` (not the
    // Elixir `after_block`); with the wrong name the always-run cleanup
    // was misfiled into the try body instead of `finally_events`.
    finally_kinds: &["try_after"],
    break_kinds: &[],
    continue_kinds: &[],
    yield_kinds: &[],
    await_kinds: &[],
    defer_kinds: &[],
    using_kinds: &["receive_expr"],
    using_body_field_names: &["body"],
    try_body_field_names: &["body"],
    special_forms: &[],
    method_receiver_param_index: None,
    implicit_receiver_names: &[],
    implicit_receiver_prefixes: &[],
    tail_expression_returns: true,
    void_return_type_names: &[],
    ..bonsai_lang_api::EMPTY_HANDLER
};

#[derive(Debug, Default, Copy, Clone)]
pub struct ErlangAdapter;

impl ErlangAdapter {
    /// Construct a stateless Erlang adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ErlangAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Erlang"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["erl", "hrl"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            module_default_export_names: &[],
            universal_type_names: &[],
            module_path_syntax: bonsai_lang_api::ModulePathSyntax::none(),
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &[],
            implicit_receiver_tokens: &[],
            callable_declaration_family: bonsai_lang_api::CallableDeclarationFamily::FunctionClauses,
            callable_reference_syntax: bonsai_lang_api::CallableReferenceSyntax {
                prefixes: &["fun "],
                numeric_arity_suffix: true,
                symbol_wrapper: None,
                trailing_invocation_punctuation: false,
            },
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn grammar_handler(&self) -> Option<&'static GrammarHandler> {
        Some(&HANDLER)
    }
    fn additional_grammar_node_kinds(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("custom lowering", "atom"),
            ("custom lowering", "b_generator"),
            ("custom lowering", "behaviour_attribute"),
            ("custom lowering", "binary_comprehension"),
            ("custom lowering", "call"),
            ("custom lowering", "case_expr"),
            ("custom lowering", "cr_clause"),
            ("custom lowering", "export_attribute"),
            ("custom lowering", "fa"),
            ("custom lowering", "generator"),
            ("custom lowering", "guard_clause"),
            ("custom lowering", "if_clause"),
            ("custom lowering", "if_expr"),
            ("custom lowering", "import_attribute"),
            ("custom lowering", "list_comprehension"),
            ("custom lowering", "map_comprehension"),
            ("custom lowering", "map_expr"),
            ("custom lowering", "map_field"),
            ("custom lowering", "map_generator"),
            ("custom lowering", "match_expr"),
            ("custom lowering", "module_attribute"),
            ("custom lowering", "pp_include"),
            ("custom lowering", "pp_include_lib"),
            ("custom lowering", "remote"),
            ("custom lowering", "var"),
        ]
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let parsed = parse_with(PACK_NAME, file, ctx);
        let mut decl_index = parsed.as_ref().map_or_else(
            || DeclIndex {
                file,
                ..DeclIndex::default()
            },
            |(snapshot, tree)| {
                decl_index_from_tree_with_handler(file, snapshot.text.as_bytes(), tree, &HANDLER)
            },
        );
        bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        // Erlang exports are explicit: `-export([fn/arity, ...]).`
        // Functions not in any -export attribute are module-private.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            decl_index
                .assignment_values
                .extend(collect_erlang_static_scalar_macros(
                    tree,
                    snapshot.text.as_bytes(),
                    file,
                ));
            decl_index
                .assignment_values
                .sort_by_key(|fact| (fact.assignment_span.start, fact.assignment_span.end));
            decl_index.assignment_values.dedup();
            populate_call_argument_static_values(
                &mut decl_index,
                tree,
                file,
                snapshot.text.as_bytes(),
                &HANDLER,
                erlang_static_scalar,
            );
            populate_erlang_static_tuple_list_fields(&mut decl_index, tree, snapshot.text.as_bytes());
            decl_index
                .compiler_guards
                .extend(collect_erlang_finite_pattern_membership_guards(
                    tree,
                    snapshot.text.as_bytes(),
                    file,
                    &decl_index.defs,
                    &decl_index.call_argument_values,
                ));
            decl_index
                .string_compositions
                .extend(collect_erlang_string_compositions(
                    &decl_index,
                    tree,
                    snapshot.text.as_bytes(),
                    file,
                ));
            decl_index
                .string_compositions
                .sort_by_key(|fact| (fact.value_span.start, fact.value_span.end));
            decl_index.string_compositions.dedup();
            decl_index
                .branch_conditions
                .extend(collect_erlang_branch_conditions(
                    tree,
                    snapshot.text.as_bytes(),
                    file,
                ));
            decl_index.branch_conditions.sort_by_key(|fact| {
                (
                    fact.branch_span.start,
                    fact.branch_span.end,
                    fact.condition_span.start,
                    fact.condition_span.end,
                )
            });
            decl_index.branch_conditions.dedup();
            let exported_names = collect_erlang_exported_names(tree, snapshot.text.as_bytes());
            for decl in &mut decl_index.defs {
                if !exported_names.contains(&decl.name) {
                    decl.visibility = Visibility::Module;
                }
            }
            apply_erlang_module_semantics(&mut decl_index, tree, snapshot.text.as_bytes(), file);
        }
        // Second pass: rewrite flow events using full source text.
        // Record-pattern destructuring, `maps:get` accesses, and tail
        // returns aren't reachable from the tree-walker alone — they
        // need language-specific inspection of parsed expression nodes.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let map_field_assigns =
                collect_erlang_map_literal_field_assigns(tree, snapshot.text.as_bytes(), file);
            let assignment_values = AssignmentValueIndex::new(&decl_index.assignment_values);
            for decl in &mut decl_index.defs {
                if let Some(params) = erlang_clause_param_slots(snapshot.text.as_ref(), decl.span, &decl.name)
                {
                    decl.params = params;
                }
                augment_erlang_param_pattern_bindings(decl, snapshot.text.as_ref());
                repair_erlang_try_regions(&mut decl.flow_events, tree, snapshot.text.as_bytes(), file);
                normalize_erlang_access_events(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                    &assignment_values,
                );
                demote_erlang_non_tail_branch_returns(&mut decl.flow_events, &assignment_values);
                bonsai_lang_api::kit::annotate_tuple_call_result_bindings(
                    &mut decl.flow_events,
                    tree,
                    snapshot.text.as_bytes(),
                    &HANDLER,
                );
                augment_erlang_record_flow_events(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                    &assignment_values,
                );
                bonsai_lang_api::kit::insert_flow_field_assignments(
                    &mut decl.flow_events,
                    &map_field_assigns,
                );
                inject_erlang_fun_ref_aliases(
                    &mut decl.flow_events,
                    snapshot.text.as_ref(),
                    &assignment_values,
                );
                rewrite_erlang_throw_calls(&mut decl.flow_events);
                augment_erlang_tail_return_event(
                    &mut decl.flow_events,
                    decl.span,
                    tree,
                    snapshot.text.as_ref(),
                );
                inject_erlang_comprehension_generator_bindings(
                    &mut decl.flow_events,
                    tree,
                    snapshot.text.as_bytes(),
                    file,
                );
                decl.has_implicit_returns = true;
            }
        } else {
            // Parser unavailable — degrade gracefully by normalizing
            // events with empty source (no record / map rewrites).
            let assignment_values = AssignmentValueIndex::default();
            for decl in &mut decl_index.defs {
                normalize_erlang_access_events(&mut decl.flow_events, "", &assignment_values);
                decl.has_implicit_returns = true;
            }
        }
        for decl in &mut decl_index.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
        }
        if let Some((snapshot, tree)) = parsed.as_ref() {
            decl_index.finite_literal_selections =
                collect_erlang_finite_literal_returns(&decl_index, tree, snapshot.text.as_bytes());
        }
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        // Local constructor-result receiver typing follows adapter facts and
        // declarations; spelling alone is not constructor evidence.
        bonsai_lang_api::apply_constructor_result_type_aliases(&mut decl_index);
        bonsai_lang_api::apply_class_field_type_aliases(&mut decl_index);
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Repair the exact value binding and executable body of Erlang `catch`
/// clauses. The grammar nests the visible `catch_clause` under an invisible
/// `_try_catch` node, so the shared direct-child try walker cannot assign its
/// `desc` field or body without an adapter-owned CST fact.
fn repair_erlang_try_regions(events: &mut [FlowEvent], tree: &Tree, src: &[u8], file: FileId) {
    for event in events {
        match event {
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
                catch_arms,
            } => {
                repair_erlang_try_regions(body, tree, src, file);
                repair_erlang_try_regions(catch_events, tree, src, file);
                repair_erlang_try_regions(finally_events, tree, src, file);

                let try_node = usize::try_from(span.start)
                    .ok()
                    .zip(usize::try_from(span.end).ok())
                    .and_then(|(start, end)| tree.root_node().named_descendant_for_byte_range(start, end))
                    .and_then(|mut node| loop {
                        if node.kind() == "try_expr" && span_of(file, &node) == *span {
                            break Some(node);
                        }
                        let Some(parent) = node.parent() else {
                            break None;
                        };
                        if span_of(file, &parent) != *span {
                            break None;
                        }
                        node = parent;
                    });
                let Some(try_node) = try_node else {
                    continue;
                };
                let clauses = collect_kinds_from_node(try_node, "catch_clause")
                    .into_iter()
                    .filter(|clause| {
                        nearest_erlang_try_ancestor(*clause).is_some_and(|owner| owner.id() == try_node.id())
                    })
                    .collect::<Vec<_>>();
                *catch_arms = clauses
                    .iter()
                    .map(|clause| {
                        let parameter = clause
                            .child_by_field_name("pat")
                            .map(|node| node_text(&node, src).trim().to_string())
                            .filter(|name| !name.is_empty() && name != "_");
                        let types = descendant_by_field_name(*clause, "class")
                            .map(|class| class.child_by_field_name("class").unwrap_or(class))
                            .map(|class| {
                                node_text(&class, src)
                                    .trim()
                                    .trim_end_matches(':')
                                    .trim()
                                    .to_string()
                            })
                            .filter(|class| !class.is_empty() && class != "_")
                            .into_iter()
                            .collect();
                        bonsai_lang_api::CatchArmFact {
                            span: span_of(file, clause),
                            parameter,
                            types,
                        }
                    })
                    .collect();
                let [clause] = clauses.as_slice() else {
                    // More than one catch arm has no single catch binding.
                    if clauses.len() > 1 {
                        *catch_param = None;
                        catch_types.clear();
                    }
                    continue;
                };

                *catch_param = clause
                    .child_by_field_name("pat")
                    .map(|node| node_text(&node, src).trim().to_string())
                    .filter(|name| !name.is_empty() && name != "_");
                catch_types.clear();
                if let Some(class) = descendant_by_field_name(*clause, "class") {
                    let class = class.child_by_field_name("class").unwrap_or(class);
                    let class = node_text(&class, src).trim().trim_end_matches(':').trim();
                    if !class.is_empty() && class != "_" {
                        catch_types.push(class.to_string());
                    }
                }
                if let Some(catch_body) = descendant_by_field_name(*clause, "body")
                    .or_else(|| first_descendant_of_kind(*clause, "clause_body"))
                {
                    *catch_events = walk_flow_events(catch_body, file, src, &HANDLER, &[]);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                repair_erlang_try_regions(then_events, tree, src, file);
                repair_erlang_try_regions(else_events, tree, src, file);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                repair_erlang_try_regions(body, tree, src, file);
            }
            _ => {}
        }
    }
}

fn nearest_erlang_try_ancestor(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "try_expr" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn collect_kinds_from_node<'tree>(root: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            out.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    out
}

fn descendant_by_field_name<'tree>(root: Node<'tree>, field: &str) -> Option<Node<'tree>> {
    if let Some(node) = root.child_by_field_name(field) {
        return Some(node);
    }
    let mut cursor = root.walk();
    let found = root
        .named_children(&mut cursor)
        .find_map(|child| descendant_by_field_name(child, field));
    found
}

fn first_descendant_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    collect_kinds_from_node(root, kind).into_iter().next()
}

/// Attach functions to the exact `-module(...)` owner and retain parsed
/// `-behaviour(...)` declarations as generic owner bases. The adapter assigns
/// no runtime/security meaning to a behaviour atom; rule data decides whether
/// implementing one creates an input boundary.
fn apply_erlang_module_semantics(index: &mut DeclIndex, tree: &Tree, src: &[u8], file: FileId) {
    let Some(module_attribute) = collect_kinds(tree, &["module_attribute"]).into_iter().next() else {
        return;
    };
    let Some(module_name_node) = module_attribute.child_by_field_name("name") else {
        return;
    };
    let module_name = node_text(&module_name_node, src).trim();
    if module_name.is_empty() {
        return;
    }
    let mut behaviours = collect_kinds(tree, &["behaviour_attribute"])
        .into_iter()
        .filter_map(|attribute| attribute.child_by_field_name("name"))
        .map(|name| node_text(&name, src).trim().to_string())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    behaviours.sort();
    behaviours.dedup();

    let next_symbol = index
        .defs
        .iter()
        .map(|decl| decl.symbol.raw())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let module_symbol = bonsai_common::SymbolId::new(next_symbol);
    let module_path = bonsai_lang_api::ModulePath::from_segments([module_name.to_string()]);
    for decl in &mut index.defs {
        if decl.name != bonsai_lang_api::MODULE_DECL_NAME {
            decl.parent = Some(module_symbol);
        }
        decl.module_path = module_path.clone();
        if decl.name != bonsai_lang_api::MODULE_DECL_NAME {
            decl.qualified_name = Some(format!("{module_name}.{}", decl.name));
        }
    }
    index.defs.push(bonsai_lang_api::Decl {
        symbol: module_symbol,
        kind: bonsai_lang_api::DeclKind::Module,
        name: module_name.to_string(),
        qualified_name: Some(module_name.to_string()),
        module_path,
        span: span_of(file, &module_attribute),
        name_span: span_of(file, &module_name_node),
        visibility: Visibility::Public,
        parent: None,
        body_span: None,
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        param_default_calls: Vec::new(),
        type_aliases: Vec::new(),
        bases: behaviours,
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        receiver_field_initializers: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    });
}

fn collect_erlang_branch_conditions(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<bonsai_lang_api::BranchConditionFact> {
    let mut facts = Vec::new();
    for conditional in collect_kinds(tree, &["if_expr"]) {
        let mut cursor = conditional.walk();
        for (index, clause) in conditional
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "if_clause")
            .enumerate()
        {
            let mut stack = vec![clause];
            let mut condition = None;
            while let Some(node) = stack.pop() {
                if node.kind() == "guard_clause" {
                    condition = node.child_by_field_name("exprs").or_else(|| node.named_child(0));
                    break;
                }
                let mut child_cursor = node.walk();
                stack.extend(node.named_children(&mut child_cursor));
            }
            let Some(condition) = condition else {
                continue;
            };
            facts.push(bonsai_lang_api::BranchConditionFact {
                branch_span: if index == 0 {
                    span_of(file, &conditional)
                } else {
                    span_of(file, &clause)
                },
                condition_span: span_of(file, &condition),
                polarity: bonsai_lang_api::BranchConditionPolarity::Positive,
                membership: None,
                expression: Some(bonsai_lang_api::kit::lower_boolean_condition_expression(
                    condition, file, &HANDLER, src,
                )),
            });
        }
    }
    facts
}

type ErlangMapFieldAssigns = bonsai_lang_api::kit::FlowFieldAssignInsertion;

fn collect_erlang_map_literal_field_assigns(
    tree: &Tree,
    src: &[u8],
    file: FileId,
) -> Vec<ErlangMapFieldAssigns> {
    let mut out = Vec::new();
    for assignment in collect_kinds(tree, &["match_expr"]) {
        let Some(left) = assignment.child_by_field_name("lhs") else {
            continue;
        };
        let Some(right) = assignment.child_by_field_name("rhs") else {
            continue;
        };
        if right.kind() != "map_expr" {
            continue;
        }
        let target = node_text(&left, src).trim().to_string();
        if target.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        let mut cursor = right.walk();
        for field in right.named_children(&mut cursor) {
            if field.kind() != "map_field" {
                continue;
            }
            let Some(key_node) = field.child_by_field_name("key") else {
                continue;
            };
            let Some(value_node) = field.child_by_field_name("value") else {
                continue;
            };
            let Some(key) = erlang_map_key(key_node, src) else {
                continue;
            };
            let sources = erlang_value_source_names(node_text(&value_node, src));
            fields.push(FlowEvent::Assign {
                span: span_of(file, &value_node),
                target: format!("{target}.{key}"),
                source_name: (sources.len() == 1).then(|| sources[0].clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: sources,
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            });
        }
        if !fields.is_empty() {
            out.push(ErlangMapFieldAssigns {
                assign_span: span_of(file, &assignment),
                target,
                fields,
            });
        }
    }
    out
}

fn erlang_map_key(node: Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&node, src).trim();
    let key = raw.trim_matches(['"', '\'']);
    if !erlang_atom_name(key) {
        return None;
    }
    Some(key.to_string())
}

/// Extract Erlang `-import` attributes and `-include` / `-include_lib`
/// preprocessor directives into the canonical `ImportSpec` shape.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // tree-sitter-erlang exposes three import-flavored attributes:
    //   `import_attribute` for `-import(Mod, [F/A, ...]).`
    //   `pp_include` for `-include("X.hrl").`
    //   `pp_include_lib` for `-include_lib("app/include/X.hrl").`
    for import_node in collect_kinds(tree, &["import_attribute"]) {
        if let Some(module_node) = import_node.child_by_field_name("module") {
            let module = node_text(&module_node, src).to_string();
            imports.push(ImportSpec {
                span: span_of(file, &import_node),
                module: module.clone(),
                alias: None,
                is_wildcard: false,
                original_name: None,
                scope: ImportScope::Module,
            });
            for imported in erlang_imported_function_names(&import_node, src) {
                imports.push(ImportSpec {
                    span: span_of(file, &import_node),
                    module: module.clone(),
                    alias: None,
                    is_wildcard: false,
                    original_name: Some(imported),
                    scope: ImportScope::Local,
                });
            }
        }
    }
    for include_node in collect_kinds(tree, &["pp_include", "pp_include_lib"]) {
        if let Some(file_node) = include_node.child_by_field_name("file") {
            // The file path is wrapped in quotes — strip them so the
            // matcher index sees a clean module name.
            let module = node_text(&file_node, src)
                .trim_matches(|ch: char| matches!(ch, '"' | '\''))
                .to_string();
            if !module.is_empty() {
                imports.push(ImportSpec {
                    span: span_of(file, &include_node),
                    module,
                    alias: None,
                    is_wildcard: false,
                    original_name: None,
                    scope: ImportScope::Module,
                });
            }
        }
    }
    imports
}

fn erlang_imported_function_names(import_node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![*import_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "fa" {
            if let Some(fun_node) = node.child_by_field_name("fun") {
                let name = node_text(&fun_node, src).trim().to_string();
                if !name.is_empty() && !out.iter().any(|existing| existing == &name) {
                    out.push(name);
                }
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

/// Rewrite flow events so that `maps:get/2` calls and `Record#tag.field`
/// accesses surface as place-paths the matcher can reason about. The
/// walker emits raw textual fragments — this stage canonicalizes them.
fn normalize_erlang_access_events(
    events: &mut [FlowEvent],
    src: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                normalize_erlang_split_dot_args(args);
                for arg in args {
                    if let Some(source) = erlang_fun_ref_source(&arg.value_text) {
                        arg.value_text.clone_from(&source);
                        // `fun name/arity` is Erlang's exact callable-value
                        // syntax. Lower the grammar-proven target as a place
                        // so shared callgraph construction can distinguish it
                        // from a compound expression that merely mentions a
                        // function name.
                        arg.place = Some(source.clone());
                        push_unique_string(&mut arg.source_names, source);
                        continue;
                    }
                    // Prefer `maps:get` rewrites (they consume a pair of
                    // args), fall back to single record access.
                    if let Some(access) = erlang_maps_get_access(&arg.value_text) {
                        arg.value_text.clone_from(&access);
                        arg.place = Some(access.clone());
                        push_unique_string(&mut arg.source_names, access);
                    } else if let Some(access) = single_erlang_record_access(&arg.value_text) {
                        arg.value_text.clone_from(&access);
                        arg.place = Some(access);
                    }
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                // The walker may not have populated source_call when the RHS
                // is a plain function-call expression. Recover it from the
                // exact Tree-sitter RHS node, never the assignment statement.
                if source_call.is_none() && source_call_args.is_empty() {
                    if let Some((callee, args)) = erlang_assignment_call_rhs(src, *span, assignment_values) {
                        *source_call = Some(callee);
                        *source_call_args = args;
                    }
                }
                for arg in source_call_args.iter_mut() {
                    if let Some(source) = erlang_fun_ref_source(arg) {
                        *arg = source;
                    } else if let Some(access) = single_erlang_record_access(arg) {
                        *arg = access;
                    }
                }
                // For `X = maps:get(key, M)`, the access path `M.key`
                // becomes a virtual source name.
                if source_call.as_deref().is_some_and(erlang_maps_get_callee_name) {
                    if let Some(access) = erlang_maps_get_access_from_args(source_call_args) {
                        push_unique_string(source_names, access);
                    }
                }
                if let Some(rhs_text) = assignment_values.rendering(*span, src) {
                    for source in erlang_comprehension_generator_sources(rhs_text) {
                        push_unique_string(source_names, source);
                    }
                    let dot_accesses = erlang_pseudo_dot_accesses(rhs_text);
                    if !dot_accesses.is_empty() {
                        let structural_bases = dot_accesses
                            .iter()
                            .filter_map(|access| access.split_once('.').map(|(base, _)| base))
                            .collect::<std::collections::HashSet<_>>();
                        if source_name
                            .as_deref()
                            .is_some_and(|name| structural_bases.contains(name.trim()))
                        {
                            *source_name = None;
                        }
                        source_names.retain(|name| !structural_bases.contains(name.trim()));
                        for access in dot_accesses {
                            push_unique_string(source_names, access);
                        }
                    }
                }
                // Any record access in the parsed RHS counts as a source —
                // covers patterns like
                // `Y = case Rec#tag.f of ... end`.
                if let Some(rhs_text) = assignment_values.rendering(*span, src) {
                    for access in erlang_record_accesses_in_text(rhs_text) {
                        push_unique_string(source_names, access);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_erlang_access_events(then_events, src, assignment_values);
                normalize_erlang_access_events(else_events, src, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_erlang_access_events(body, src, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_erlang_access_events(body, src, assignment_values);
                normalize_erlang_access_events(catch_events, src, assignment_values);
                normalize_erlang_access_events(finally_events, src, assignment_values);
            }
            _ => {}
        }
    }
}

/// Erlang `case`/`if` arms return a value to their enclosing expression, but
/// they return from the function only when that expression is itself in tail
/// position. Shared branch lowering deliberately records tail-arm `Return`
/// facts for expression-oriented languages. When the parsed branch is the
/// exact RHS of an assignment, those facts are expression results instead;
/// retaining them would make the executable-flow normalizer discard every
/// following sibling as unreachable.
///
/// The distinction comes solely from [`AssignmentValueIndex`] spans selected
/// by Tree-sitter. No source spelling or API identity participates.
fn demote_erlang_non_tail_branch_returns(events: &mut [FlowEvent], assignments: &AssignmentValueIndex) {
    fn strip_returns(events: &mut Vec<FlowEvent>) {
        events.retain(|event| !matches!(event, FlowEvent::Return { .. }));
    }

    fn visit(events: &mut [FlowEvent], assignments: &AssignmentValueIndex) {
        let assigned_value_spans: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Assign { span, .. } | FlowEvent::AggregateAssign { span, .. } => {
                    assignments.value_span(*span)
                }
                _ => None,
            })
            .collect();
        for event in events {
            match event {
                FlowEvent::Branch {
                    span,
                    then_events,
                    else_events,
                    ..
                } => {
                    let is_assignment_value = assigned_value_spans.iter().any(|value| {
                        value.file == span.file && value.start <= span.start && span.end <= value.end
                    });
                    if is_assignment_value {
                        strip_returns(then_events);
                        strip_returns(else_events);
                    }
                    visit(then_events, assignments);
                    visit(else_events, assignments);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => visit(body, assignments),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    visit(body, assignments);
                    visit(catch_events, assignments);
                    visit(finally_events, assignments);
                }
                _ => {}
            }
        }
    }

    visit(events, assignments);
}

/// The Erlang grammar treats the compatibility fixture spelling
/// `C.capacity` as two adjacent call arguments (`C.` and `capacity`).
/// Rejoin that losslessly into the same projected storage path used by
/// records and maps. This also prevents the structural base `C` from
/// becoming an independent value source.
fn normalize_erlang_split_dot_args(args: &mut Vec<bonsai_lang_api::CallArg>) {
    let mut index = 0usize;
    while index + 1 < args.len() {
        let base = args[index].value_text.trim().trim_end_matches('.').trim();
        let field = args[index + 1].value_text.trim();
        let is_base = !base.is_empty()
            && base
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
            && base.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        let is_field = !field.is_empty()
            && field
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
            && field.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if !args[index].value_text.trim().ends_with('.') || !is_base || !is_field {
            index += 1;
            continue;
        }
        let access = format!("{base}.{field}");
        args[index].value_text.clone_from(&access);
        args[index].place = Some(access.clone());
        args[index].source_names.clear();
        args[index].source_names.push(access);
        args.remove(index + 1);
        index += 1;
    }
}

fn erlang_pseudo_dot_accesses(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split(|ch: char| !(ch == '_' || ch == '.' || ch.is_ascii_alphanumeric())) {
        let Some((base, field)) = token.split_once('.') else {
            continue;
        };
        if field.contains('.')
            || base.is_empty()
            || field.is_empty()
            || !base
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
            || !field
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
            || !base.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            || !field.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            continue;
        }
        push_unique_string(&mut out, format!("{base}.{field}"));
    }
    out
}

/// Add exact callback-alias facts for Erlang's function-reference
/// syntax: `Cb = fun helper/1`.
fn inject_erlang_fun_ref_aliases(
    events: &mut Vec<FlowEvent>,
    src: &str,
    assignment_values: &AssignmentValueIndex,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_erlang_fun_ref_aliases(then_events, src, assignment_values);
                inject_erlang_fun_ref_aliases(else_events, src, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_erlang_fun_ref_aliases(body, src, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_erlang_fun_ref_aliases(body, src, assignment_values);
                inject_erlang_fun_ref_aliases(catch_events, src, assignment_values);
                inject_erlang_fun_ref_aliases(finally_events, src, assignment_values);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = erlang_fun_ref_alias_assignment(&event, src, assignment_values);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

/// Rewrite Erlang exception BIF calls (`throw/1`, `error/1`, `exit/1`,
/// and their `erlang:`-qualified forms) into `FlowEvent::Throw`. These
/// raise via plain `call` nodes, so the walker emits them as `Call`
/// events; without this pass `throw(X)` is never a Throw and try/catch
/// taint seeding (G8) can't link the thrown value to the catch binding.
fn rewrite_erlang_throw_calls(events: &mut [FlowEvent]) {
    // Recurse into nested bodies first so throws inside branch / loop /
    // try regions are rewritten too.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_erlang_throw_calls(then_events);
                rewrite_erlang_throw_calls(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_erlang_throw_calls(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_erlang_throw_calls(body);
                rewrite_erlang_throw_calls(catch_events);
                rewrite_erlang_throw_calls(finally_events);
            }
            _ => {}
        }
    }
    for event in events.iter_mut() {
        if let Some(throw) = erlang_throw_from_call(event) {
            *event = throw;
        }
    }
}

/// Build a `Throw` from a `Call` to `throw`/`error`/`exit`, taking the
/// thrown value name from the first argument when it is a bare Erlang
/// variable (so G8 can pre-taint the catch binding).
fn erlang_throw_from_call(event: &FlowEvent) -> Option<FlowEvent> {
    let FlowEvent::Call { span, name, args, .. } = event else {
        return None;
    };
    // Match bare exception BIFs (`throw`, `error`, `exit`) and their
    // explicit `erlang:` / `erlang.` forms only. Other modules expose
    // ordinary functions with the same tail (`logger:error`) and must
    // remain call events for security rules and call inventory output.
    let trimmed = name.trim();
    let (module, short) = trimmed
        .rsplit_once([':', '.'])
        .map_or((None, trimmed), |(module, short)| {
            (Some(module.trim()), short.trim())
        });
    if !matches!(short, "throw" | "error" | "exit") {
        return None;
    }
    if module.is_some_and(|module| module != "erlang") {
        return None;
    }
    let value_name = args.first().and_then(|arg| {
        let text = arg.value_text.trim();
        if erlang_variable_name(text) {
            Some(text.to_string())
        } else {
            arg.source_names
                .iter()
                .find(|name| erlang_variable_name(name))
                .cloned()
        }
    });
    Some(FlowEvent::Throw {
        span: *span,
        value_name,
        thrown_type: None,
    })
}

fn erlang_fun_ref_alias_assignment(
    event: &FlowEvent,
    src: &str,
    assignment_values: &AssignmentValueIndex,
) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return None;
    };
    let target = target.trim();
    if !erlang_variable_name(target) {
        return None;
    }
    let rhs = assignment_values.rendering(*span, src)?;
    let source_name = erlang_fun_ref_source(rhs.trim_end_matches('.').trim())?;
    Some(FlowEvent::Assign {
        span: *span,
        target: target.to_string(),
        source_name: Some(source_name),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding: true,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
    })
}

fn erlang_fun_ref_source(rhs: &str) -> Option<String> {
    let rest = rhs.strip_prefix("fun ")?.trim_start();
    let (name, arity) = rest.rsplit_once('/')?;
    let name = name.trim();
    let arity = arity.trim();
    if !erlang_atom_name(name) || !arity.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(name.to_string())
}

/// Synthesize parameter destructuring assignments for Erlang record
/// patterns in function heads. `f(R = #user{name = N}) -> ...` turns
/// into a synthetic `N = R.name` Assign event prepended to the body so
/// the taint engine can flow `R.name -> N`.
fn augment_erlang_param_pattern_bindings(decl: &mut bonsai_lang_api::Decl, src: &str) {
    let Some(decl_text) = erlang_span_text(src, decl.span) else {
        return;
    };
    let Some(params_text) = erlang_function_params_text(decl_text) else {
        return;
    };
    let raw_args = split_top_level_args(params_text);
    let mut synthetic_events = Vec::new();
    for (param_index, raw_arg) in raw_args.iter().enumerate() {
        let slot_param_name = decl
            .params
            .get(param_index)
            .filter(|name| !name.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| format!("_Arg{param_index}"));
        let bindings = erlang_record_pattern_bindings(raw_arg);
        if !bindings.is_empty() {
            // Pick the variable bound to the whole record (or fall back to
            // the existing param name, or a generated `Arg<i>`).
            let param_name = erlang_pattern_param_name(raw_arg)
                .or_else(|| {
                    decl.params
                        .get(param_index)
                        .filter(|name| erlang_variable_name(name))
                        .cloned()
                })
                .unwrap_or_else(|| format!("Arg{param_index}"));
            // Replace the param at this index so callers see the canonical
            // record-bound name rather than the raw pattern text.
            if param_index < decl.params.len() {
                decl.params[param_index].clone_from(&param_name);
            } else {
                decl.params.push(param_name.clone());
            }
            for (field_name, bound_variable) in bindings {
                synthetic_events.push(FlowEvent::Assign {
                    span: decl.span,
                    target: bound_variable,
                    source_name: Some(format!("{param_name}.{field_name}")),
                    source_call: None,
                    source_call_args: Vec::new(),
                    source_names: vec![format!("{param_name}.{field_name}")],
                    declares_new_binding: false,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Destructure),
                });
            }
            continue;
        }

        for bound_variable in erlang_pattern_bound_variables(raw_arg) {
            if bound_variable == "_" || bound_variable == slot_param_name {
                continue;
            }
            synthetic_events.push(FlowEvent::Assign {
                span: decl.span,
                target: bound_variable,
                source_name: Some(slot_param_name.clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: vec![slot_param_name.clone()],
                declares_new_binding: false,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Destructure),
            });
        }
    }
    // Prepend so destructuring lands before any body events that may
    // reference the bound variables.
    if !synthetic_events.is_empty() {
        synthetic_events.append(&mut decl.flow_events);
        decl.flow_events = synthetic_events;
    }
}

/// Expand record-construction assignments into per-field assignments.
/// `R = #user{name = N, email = E}` produces synthetic
/// `R.name = N` and `R.email = E` events alongside the original, which
/// lets the taint engine track field-level flow.
fn augment_erlang_record_flow_events(
    events: &mut Vec<FlowEvent>,
    src: &str,
    assignment_values: &AssignmentValueIndex,
) {
    // Recurse into nested events first so child branches/bodies are
    // augmented before we walk the top-level list.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                augment_erlang_record_flow_events(then_events, src, assignment_values);
                augment_erlang_record_flow_events(else_events, src, assignment_values);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                augment_erlang_record_flow_events(body, src, assignment_values);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                augment_erlang_record_flow_events(body, src, assignment_values);
                augment_erlang_record_flow_events(catch_events, src, assignment_values);
                augment_erlang_record_flow_events(finally_events, src, assignment_values);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let mut synthetic_field_assigns = Vec::new();
        // Only assignments to a record value need expansion — peek at
        // the textual RHS for `#tag{field = value, ...}` initializers.
        if let FlowEvent::Assign { span, target, .. } = &event {
            if let Some(rhs_text) = assignment_values.rendering(*span, src) {
                for (field_name, field_value) in erlang_record_field_initializers(rhs_text) {
                    synthetic_field_assigns.push(FlowEvent::Assign {
                        span: *span,
                        target: format!("{target}.{field_name}"),
                        source_name: None,
                        source_call: None,
                        source_call_args: Vec::new(),
                        source_names: erlang_value_source_names(&field_value),
                        declares_new_binding: false,
                        value_kind: None,
                    });
                }
            }
        }
        // Keep the original event ahead of the synthetic ones — tools
        // expect the assignment to appear before its field expansions.
        rewritten.push(event);
        rewritten.extend(synthetic_field_assigns);
    }
    *events = rewritten;
}

/// Synthesize a tail-return event for Erlang functions whose final
/// expression is implicitly returned. Erlang has no `return` keyword —
/// the last expression of a clause is its value — so the walker can't
/// emit a Return naturally; we add one textually.
fn augment_erlang_tail_return_event(
    events: &mut Vec<FlowEvent>,
    span: bonsai_common::Span,
    tree: &Tree,
    src: &str,
) {
    // Don't double up if any Return already exists (e.g. via early `case`
    // arm rewrites).
    if events
        .iter()
        .any(|event| matches!(event, FlowEvent::Return { .. }))
    {
        return;
    }
    let Some((value_text, value_name, value_span)) = erlang_tail_return_value(src, span) else {
        return;
    };
    let value_node = usize::try_from(value_span.start)
        .ok()
        .zip(usize::try_from(value_span.end).ok())
        // Use the smallest named syntax node for the exact tail span. The
        // generic descendant query may return an enclosing clause when the
        // range begins or ends on trivia, which would incorrectly pull calls
        // from earlier expressions into a literal tail return.
        .and_then(|(start, end)| tree.root_node().named_descendant_for_byte_range(start, end));
    let value_flow = value_node
        .map(|value| {
            bonsai_lang_api::kit::expression_flow_from_node_with_handler(
                value,
                value_span.file,
                src.as_bytes(),
                &HANDLER,
            )
        })
        .unwrap_or_default();
    events.push(FlowEvent::Return {
        span: value_span,
        value_kind: value_node.and_then(|value| HANDLER.expression_value_kind(value, src.as_bytes())),
        value_text: Some(value_text),
        value_name,
        value_flow,
    });
}

/// Parse `Lhs = callee(args, ...)` out of an assignment span and return
/// `(callee, args)` if the RHS is a clean call expression.
fn erlang_assignment_call_rhs(
    src: &str,
    span: bonsai_common::Span,
    assignment_values: &AssignmentValueIndex,
) -> Option<(String, Vec<String>)> {
    let rhs = assignment_values.rendering(span, src)?;
    erlang_call_expr(rhs.trim_end_matches('.').trim())
}

/// Extract source operands from Erlang list/binary comprehension
/// generators, e.g. `[Part || Part <- string:tokens(Cmd, " ")]`.
fn erlang_comprehension_generator_sources(rhs_text: &str) -> Vec<String> {
    let Some((_, qualifiers)) = split_top_level_erlang_comprehension(rhs_text) else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for qualifier in split_top_level_args(qualifiers) {
        let Some((_, generator_source)) = split_top_level_erlang_generator(&qualifier) else {
            continue;
        };
        for source in erlang_value_source_names(generator_source) {
            push_unique_string(&mut sources, source);
        }
    }
    sources
}

/// Normalize compiler evaluation order for Erlang list/binary/map
/// comprehensions and materialize every generator-pattern binding.
///
/// The generic assignment walk visits the outer match before nested RHS
/// calls, while Erlang evaluates generators and the body first. Move that one
/// carrier assignment behind the comprehension events, and insert any
/// bindings not already emitted by the single-pattern generic extractor
/// before the body. This is AST-span scheduling only; it never parses the
/// rendered comprehension text.
type ErlangComprehensionBindings = Vec<(String, Vec<String>)>;

fn inject_erlang_comprehension_generator_bindings(
    events: &mut Vec<FlowEvent>,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let mut plans = Vec::new();
    for comprehension in collect_kinds(
        tree,
        &["list_comprehension", "binary_comprehension", "map_comprehension"],
    ) {
        let bindings = erlang_comprehension_generator_bindings_from_node(comprehension, src);
        if !bindings.is_empty() {
            plans.push((span_of(file, &comprehension), bindings));
        }
    }
    normalize_erlang_comprehension_event_group(events, &plans);
}

fn normalize_erlang_comprehension_event_group(
    events: &mut Vec<FlowEvent>,
    plans: &[(bonsai_common::Span, ErlangComprehensionBindings)],
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_erlang_comprehension_event_group(then_events, plans);
                normalize_erlang_comprehension_event_group(else_events, plans);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_erlang_comprehension_event_group(body, plans);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_erlang_comprehension_event_group(body, plans);
                normalize_erlang_comprehension_event_group(catch_events, plans);
                normalize_erlang_comprehension_event_group(finally_events, plans);
            }
            _ => {}
        }
    }

    for (comprehension_span, bindings) in plans {
        let contains = |outer: bonsai_common::Span, inner: bonsai_common::Span| {
            outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
        };
        let carrier_index = events.iter().position(|event| {
            matches!(event, FlowEvent::Assign { .. })
                && event.span() != *comprehension_span
                && contains(event.span(), *comprehension_span)
        });
        let carrier = carrier_index.map(|index| events.remove(index));

        let Some(first_inside) = events
            .iter()
            .position(|event| contains(*comprehension_span, event.span()))
        else {
            if let Some(carrier) = carrier {
                events.insert(carrier_index.unwrap_or(events.len()).min(events.len()), carrier);
            }
            continue;
        };

        let present = events
            .iter()
            .filter_map(|event| match event {
                FlowEvent::Assign { target, .. } if contains(*comprehension_span, event.span()) => {
                    Some(target.clone())
                }
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        let missing = bindings
            .iter()
            .filter(|(target, _)| !target.is_empty() && !present.contains(target))
            .map(|(target, sources)| FlowEvent::Assign {
                span: *comprehension_span,
                target: target.clone(),
                source_name: (sources.len() == 1).then(|| sources[0].clone()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: sources.clone(),
                declares_new_binding: true,
                value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
            })
            .collect::<Vec<_>>();
        events.splice(first_inside..first_inside, missing);

        if let Some(carrier) = carrier {
            let after_body = events
                .iter()
                .rposition(|event| contains(*comprehension_span, event.span()))
                .map_or(events.len(), |index| index + 1);
            events.insert(after_body, carrier);
        }
    }
}

fn erlang_comprehension_generator_bindings_from_node(
    comprehension: Node<'_>,
    src: &[u8],
) -> ErlangComprehensionBindings {
    fn collect_generators<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
        if matches!(node.kind(), "generator" | "b_generator" | "map_generator") {
            out.push(node);
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_generators(child, out);
        }
    }

    fn collect_variables(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "var" {
            push_unique_string(out, node_text(&node, src).trim().to_string());
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_variables(child, src, out);
        }
    }

    let mut generators = Vec::new();
    collect_generators(comprehension, &mut generators);
    let mut bindings = Vec::new();
    for generator in generators {
        let Some(lhs) = generator.child_by_field_name("lhs") else {
            continue;
        };
        let Some(rhs) = generator.child_by_field_name("rhs") else {
            continue;
        };
        let mut targets = Vec::new();
        collect_variables(lhs, src, &mut targets);
        let mut sources = Vec::new();
        collect_variables(rhs, src, &mut sources);
        if !sources.is_empty() {
            for target in targets {
                bindings.push((target, sources.clone()));
            }
        }
    }
    bindings
}

fn split_top_level_erlang_comprehension(text: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '|' if matches!(iter.peek(), Some((_, '|'))) && depth == 1 => {
                let _ = iter.next();
                let qualifiers = text[idx + 2..].trim();
                let qualifiers = qualifiers
                    .strip_suffix(']')
                    .or_else(|| qualifiers.strip_suffix(">>"))
                    .unwrap_or(qualifiers)
                    .trim();
                return Some((text[..idx].trim(), qualifiers));
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_erlang_generator(text: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '<' if matches!(iter.peek(), Some((_, '-'))) && depth == 0 => {
                let _ = iter.next();
                return Some((text[..idx].trim(), text[idx + 2..].trim()));
            }
            _ => {}
        }
    }
    None
}

/// Identify the implicit return expression of an Erlang function clause.
/// Returns `(normalized text, optional value name, byte span)` so the
/// caller can emit a synthetic Return event.
fn erlang_tail_return_value(
    src: &str,
    span: bonsai_common::Span,
) -> Option<(String, Option<String>, bonsai_common::Span)> {
    let span_text = erlang_span_text(src, span)?;
    // Skip past the `->` arrow into the body.
    let arrow_offset = find_erlang_arrow(span_text)?;
    let body_start = arrow_offset + 2;
    let body = span_text[body_start..].trim_end();
    // Drop the trailing `.` that terminates every clause.
    let body = body.strip_suffix('.').unwrap_or(body).trim_end();
    // The last `,`- or `;`-separated expression is the implicit return.
    let (relative_expr_start, last_expr) = last_erlang_sequence_expr(body)?;
    let trimmed_expr = last_expr.trim();
    let normalized_expr = normalize_erlang_return_expr(trimmed_expr)?;
    let value_name = erlang_return_value_name(&normalized_expr);
    // Translate the exact, whitespace-adjusted relative offset back to the
    // source file's byte coordinates.
    let absolute_start = usize::try_from(span.start).ok()? + body_start + relative_expr_start;
    let absolute_end = absolute_start + trimmed_expr.len();
    Some((
        normalized_expr,
        value_name,
        bonsai_common::Span::new(
            span.file,
            u64::try_from(absolute_start).unwrap_or(u64::MAX),
            u64::try_from(absolute_end).unwrap_or(u64::MAX),
        ),
    ))
}

/// Slice the source text for a span, returning `None` if the bytes
/// fall outside the buffer or land inside a multi-byte char.
fn erlang_span_text(src: &str, span: bonsai_common::Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?.min(src.len());
    let end = usize::try_from(span.end).ok()?.min(src.len());
    if start >= end || !src.is_char_boundary(start) || !src.is_char_boundary(end) {
        return None;
    }
    Some(&src[start..end])
}

/// Slice the parameter list out of a function-clause header. The header
/// is everything before `->`; we extract the contents of its outermost
/// parentheses.
fn erlang_function_params_text(text: &str) -> Option<&str> {
    let arrow_offset = find_erlang_arrow(text)?;
    let header = &text[..arrow_offset];
    let open_paren = header.find('(')?;
    let close_paren = header.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    Some(&header[open_paren + 1..close_paren])
}

fn erlang_clause_param_slots(src: &str, span: bonsai_common::Span, name: &str) -> Option<Vec<String>> {
    let text = erlang_span_text(src, span)?;
    let arrow_offset = find_erlang_arrow(text)?;
    let header = &text[..arrow_offset];
    let name_start = header.find(name)?;
    let after_name = header[name_start + name.len()..].trim_start();
    if !after_name.starts_with('(') {
        return Some(Vec::new());
    }
    let close = find_matching_erlang_delim(after_name, 0, b'(', b')')?;
    let params_text = &after_name[1..close];
    if params_text.trim().is_empty() {
        return Some(Vec::new());
    }
    let args = split_top_level_args(params_text);
    Some(
        args.iter()
            .enumerate()
            .map(|(idx, arg)| erlang_pattern_param_name(arg).unwrap_or_else(|| format!("_Arg{idx}")))
            .collect(),
    )
}

/// Pick the variable name out of a pattern fragment. Handles the
/// `R = #user{...}` shape by treating `=` as a separator and returning
/// the first variable-shaped token.
fn erlang_pattern_param_name(arg: &str) -> Option<String> {
    for part in split_top_level_args(&arg.replace('=', ",")) {
        let candidate = part.trim();
        if erlang_variable_name(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn erlang_pattern_bound_variables(arg: &str) -> Vec<String> {
    erlang_value_source_names(arg)
        .into_iter()
        .filter(|name| erlang_variable_name(name))
        .collect()
}

/// Extract `(field, variable)` pairs from a record pattern. Only entries
/// whose RHS is a bare variable count — literals/expressions don't bind.
fn erlang_record_pattern_bindings(text: &str) -> Vec<(String, String)> {
    erlang_record_field_initializers(text)
        .into_iter()
        .filter(|(_, value)| erlang_variable_name(value))
        .collect()
}

/// Walk `#tag{f1 = v1, f2 = v2, ...}` shapes inside `text` and return
/// each `(field, normalized value)` pair. Multiple records inside the
/// same input are flattened into a single list.
fn erlang_record_field_initializers(text: &str) -> Vec<(String, String)> {
    let mut field_value_pairs = Vec::new();
    for record_body in erlang_record_bodies(text) {
        for part in split_top_level_args(&record_body) {
            let Some((field, value)) = split_top_level_match_expr(&part) else {
                continue;
            };
            let field = field.trim();
            // Field labels must be lowercase atoms; skip anything else
            // (defends against malformed parses).
            if !erlang_atom_name(field) {
                continue;
            }
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            field_value_pairs.push((field.to_string(), normalize_erlang_value_expr(value)));
        }
    }
    field_value_pairs
}

/// Pull the body of every `#tag{...}` record literal out of `text`,
/// returning the contents (excluding braces) of each. Quoted regions
/// and escape sequences are skipped so `#` inside a string doesn't
/// trigger a false match.
fn erlang_record_bodies(text: &str) -> Vec<String> {
    let mut record_bodies = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        // String/char-literal pass-through: ignore everything until the
        // matching close quote so `#` inside a literal isn't seen as a
        // record marker.
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        if ch != '#' {
            continue;
        }
        // Walk past the record tag (an atom-like identifier).
        let mut tag_end = idx + ch.len_utf8();
        while tag_end < text.len() && erlang_ident_byte(text.as_bytes()[tag_end]) {
            tag_end += 1;
        }
        // Reject `#` not followed by an atom + `{` — could be a map
        // pattern or a comment.
        if tag_end == idx + ch.len_utf8() || text.as_bytes().get(tag_end) != Some(&b'{') {
            continue;
        }
        if let Some(brace_end) = find_matching_erlang_delim(text, tag_end, b'{', b'}') {
            record_bodies.push(text[tag_end + 1..brace_end].to_string());
        }
        // Advance the outer iterator past the consumed tag bytes so we
        // don't re-scan inside the record.
        while iter.peek().is_some_and(|(next, _)| *next <= tag_end) {
            let _ = iter.next();
        }
    }
    record_bodies
}

/// Find the byte index of the `close` byte that pairs with the `open`
/// byte at `open_idx`, respecting nesting and string literals.
fn find_matching_erlang_delim(text: &str, open_idx: usize, open: u8, close: u8) -> Option<usize> {
    if text.as_bytes().get(open_idx) != Some(&open) {
        return None;
    }
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text
        .char_indices()
        .skip_while(|(byte_idx, _)| *byte_idx < open_idx)
    {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        // Guard `is_ascii()` before narrowing: `ch as u8` truncates to the
        // low byte, so a non-ASCII char whose codepoint & 0xFF equals an
        // ASCII delimiter (e.g. 'Ż' U+017B & 0xFF == b'{') would otherwise
        // be miscounted as a brace/paren and drift the depth.
        if ch.is_ascii() && ch as u8 == open {
            depth = depth.saturating_add(1);
        } else if ch.is_ascii() && ch as u8 == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

/// Canonicalize a value expression so taint tracking sees a stable place
/// path. `maps:get(key, M)` and single record accesses collapse to a
/// dotted path; everything else passes through unchanged.
fn normalize_erlang_value_expr(value: &str) -> String {
    let value = value.trim().trim_end_matches('.').trim();
    if let Some(access) = erlang_maps_get_access(value) {
        return access;
    }
    if let Some(access) = single_erlang_record_access(value) {
        return access;
    }
    value.to_string()
}

/// Collect every variable / record-access / `maps:get` source named
/// inside `value`. Used to populate `source_names` so the taint engine
/// can connect field-level reads back to their roots.
fn erlang_value_source_names(value: &str) -> Vec<String> {
    let mut sources = Vec::new();
    for access in erlang_record_accesses_in_text(value) {
        push_unique_string(&mut sources, access);
    }
    if let Some(access) = erlang_maps_get_access(value) {
        push_unique_string(&mut sources, access);
    }
    // Tokenize variable names by walking char-by-char outside string
    // literals. Append a sentinel space so the trailing token gets
    // flushed.
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in value.chars().chain(std::iter::once(' ')) {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'') {
            // Flush whatever's accumulated before entering the literal.
            if erlang_variable_name(&token) {
                push_unique_string(&mut sources, token.clone());
            }
            token.clear();
            quote = Some(ch);
            continue;
        }
        if ch == '_' || ch == '@' || ch.is_ascii_alphanumeric() {
            token.push(ch);
            continue;
        }
        // Hit a non-ident byte: flush the accumulated token if it looks
        // like an Erlang variable.
        if erlang_variable_name(&token) {
            push_unique_string(&mut sources, token.clone());
        }
        token.clear();
    }
    sources
}

/// Locate the `->` separating an Erlang clause head from its body,
/// returning the byte index of the `-`. Skips arrows inside string
/// literals.
fn find_erlang_arrow(text: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        if ch == '-' && matches!(iter.peek(), Some((_, '>'))) {
            return Some(idx);
        }
    }
    None
}

/// Split `text` on the first top-level `=` into `(lhs, rhs)`. Skips
/// `==`, `=<`, `=>` operators and any `=` inside parens / brackets /
/// strings.
fn split_top_level_match_expr(text: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                // Skip compound operators: `==`, `=<`, `=>`.
                let next_char = iter.peek().map(|(_, next)| *next);
                if matches!(next_char, Some('=' | '<' | '>')) {
                    continue;
                }
                return Some((&text[..idx], &text[idx + 1..]));
            }
            _ => {}
        }
    }
    None
}

/// Find the start byte and slice of the last expression in a comma /
/// semicolon-separated sequence. Erlang's body is a sequence and the
/// final expression is the implicit return value.
fn last_erlang_sequence_expr(body: &str) -> Option<(usize, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut last_expr_start = 0usize;
    for (idx, ch) in body.char_indices() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '"' | '\'') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            // Top-level `,` or `;` — the next expression starts here.
            ',' | ';' if depth == 0 => last_expr_start = idx + ch.len_utf8(),
            _ => {}
        }
    }
    let raw_last_expr = &body[last_expr_start..];
    let leading = raw_last_expr
        .len()
        .saturating_sub(raw_last_expr.trim_start().len());
    let last_expr = raw_last_expr.trim();
    (!last_expr.is_empty()).then_some((last_expr_start + leading, last_expr))
}

/// Canonicalize a return expression. Every non-empty Erlang tail expression
/// is a returned value; structured `ExpressionFlow` is subsequently lowered
/// from its exact tree-sitter node, so calls and compound expressions must not
/// be discarded merely because they are not storage-place spellings.
fn normalize_erlang_return_expr(expr: &str) -> Option<String> {
    let expr = expr.trim().trim_end_matches('.').trim();
    if expr.is_empty() {
        return None;
    }
    if erlang_return_container_expr(expr) {
        return Some(expr.to_string());
    }
    if let Some(access) = erlang_maps_get_access(expr) {
        return Some(access);
    }
    if let Some(access) = single_erlang_record_access(expr) {
        return Some(access);
    }
    if erlang_variable_name(expr) || erlang_atom_name(expr) || erlang_quoted_literal(expr) {
        return Some(expr.to_string());
    }
    Some(expr.to_string())
}

fn erlang_return_container_expr(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.starts_with("<<") && trimmed.ends_with(">>"))
}

/// `Some(value)` when `value` is taintable as a return — variables or
/// dotted place paths qualify; literals don't.
fn erlang_return_value_name(value: &str) -> Option<String> {
    (erlang_variable_name(value) || value.contains('.')).then(|| value.to_string())
}

/// `true` if `text` is a `"..."` string or `'...'` quoted-atom literal.
fn erlang_quoted_literal(text: &str) -> bool {
    let text = text.trim();
    (text.starts_with('"') && text.ends_with('"') && text.len() >= 2)
        || (text.starts_with('\'') && text.ends_with('\'') && text.len() >= 2)
}

/// Parse `callee(arg1, arg2, ...)` into `(callee, args)`. The callee
/// must be a clean module-or-local name (`mod:fun` collapses to
/// `mod.fun`); trailing characters after the close paren reject the
/// match.
fn erlang_call_expr(text: &str) -> Option<(String, Vec<String>)> {
    let open_paren = text.find('(')?;
    let close_paren = text.rfind(')')?;
    if close_paren <= open_paren || !text[close_paren + 1..].trim().is_empty() {
        return None;
    }
    let callee = text[..open_paren].trim();
    if !erlang_callee_name(callee) {
        return None;
    }
    let args = split_top_level_args(&text[open_paren + 1..close_paren]);
    // Normalize remote-call syntax to dotted form so downstream matchers
    // see a consistent name shape.
    Some((callee.replace(':', "."), args))
}

/// `true` when `text` is a syntactically-valid Erlang callee (module-
/// qualified or local).
fn erlang_callee_name(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    text.chars()
        .all(|ch| ch == '_' || ch == ':' || ch == '@' || ch.is_ascii_alphanumeric())
}

/// `Some(access)` only when `text` is exactly one record access
/// (whitespace permitted around it). Anything else — multiple accesses,
/// or trailing tokens — returns `None`.
fn single_erlang_record_access(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let accesses = erlang_record_accesses_in_text(trimmed);
    if accesses.len() == 1 && record_access_consumes_text(trimmed) {
        accesses.into_iter().next()
    } else {
        None
    }
}

/// `true` when the only meaningful content of `text` is a single record
/// access — used to decide whether to substitute the canonical place
/// path in for the original expression.
fn record_access_consumes_text(text: &str) -> bool {
    let Some(hash_idx) = text.find('#') else {
        return false;
    };
    let Some((start, end)) = erlang_record_access_bounds(text, hash_idx) else {
        return false;
    };
    // No leading or trailing tokens around the access.
    text[..start].trim().is_empty() && text[end..].trim().is_empty()
}

/// Walk `text` collecting every `Var#tag.field` access as a normalized
/// `Var.field` place path.
fn erlang_record_accesses_in_text(text: &str) -> Vec<String> {
    let mut accesses = Vec::new();
    for (idx, ch) in text.char_indices() {
        if ch != '#' {
            continue;
        }
        if let Some((access, _start, _end)) = erlang_record_access_at(text, idx) {
            push_unique_string(&mut accesses, access);
        }
    }
    accesses
}

/// Try to parse a `Var#tag.field` access centered on the `#` at
/// `hash_idx`, returning `(canonical "Var.field", start, end)`. Returns
/// `None` when any required token is malformed.
fn erlang_record_access_at(text: &str, hash_idx: usize) -> Option<(String, usize, usize)> {
    let (start, end) = erlang_record_access_bounds(text, hash_idx)?;
    let before_hash = &text[start..hash_idx];
    let after_hash = &text[hash_idx + 1..end];
    let (record_name, field_name) = after_hash.split_once('.')?;
    // All three pieces must be syntactically valid; otherwise we'd
    // surface garbage place paths.
    if !erlang_variable_name(before_hash) || !erlang_atom_name(record_name) || !erlang_atom_name(field_name) {
        return None;
    }
    Some((format!("{before_hash}.{field_name}"), start, end))
}

/// Compute the byte bounds of the record access centered on `hash_idx`.
/// Walks identifier bytes leftward (the variable) and rightward (the
/// `tag.field` suffix).
fn erlang_record_access_bounds(text: &str, hash_idx: usize) -> Option<(usize, usize)> {
    if hash_idx >= text.len() || !text.is_char_boundary(hash_idx) {
        return None;
    }
    let bytes = text.as_bytes();
    // Left edge: walk back over the variable name.
    let mut start = hash_idx;
    while start > 0 && erlang_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    // Reject `#tag` with no preceding variable — that's record creation,
    // not access.
    if start == hash_idx {
        return None;
    }
    // Right edge: walk past `tag` then require a `.`, then walk past
    // `field`.
    let mut record_end = hash_idx + 1;
    while record_end < bytes.len() && erlang_ident_byte(bytes[record_end]) {
        record_end += 1;
    }
    if record_end == hash_idx + 1 || bytes.get(record_end) != Some(&b'.') {
        return None;
    }
    let field_start = record_end + 1;
    let mut end = field_start;
    while end < bytes.len() && erlang_ident_byte(bytes[end]) {
        end += 1;
    }
    if end == field_start {
        return None;
    }
    Some((start, end))
}

/// `true` if `text` matches Erlang's variable lexical form
/// (uppercase or `_` start, ident chars after).
fn erlang_variable_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
        && chars.all(|ch| ch == '_' || ch == '@' || ch.is_ascii_alphanumeric())
}

/// `true` if `text` matches Erlang's bare-atom lexical form (lowercase
/// or `_` start, ident chars after — no `@`, since that's variable-only).
fn erlang_atom_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// `true` if `byte` is part of an Erlang identifier (`_`, `@`, alnum).
fn erlang_ident_byte(byte: u8) -> bool {
    byte == b'_' || byte == b'@' || byte.is_ascii_alphanumeric()
}

/// Append `value` to `values` unless it is empty or already present.
fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

/// Parse a complete `maps:get(key, M)` or `maps:get(key, M, Default)`
/// expression and return its place path `M.key`.
fn erlang_maps_get_access(text: &str) -> Option<String> {
    let text = text.trim();
    let body = text
        .strip_prefix("maps:get(")
        .and_then(|rest| rest.strip_suffix(')'))?;
    let args = split_top_level_args(body);
    erlang_maps_get_access_from_args(&args)
}

/// Build a place path from already-split `maps:get` argument strings.
/// Requires both a fixed key and a clean map identifier — bails on
/// dynamic keys or expression-shaped maps.
fn erlang_maps_get_access_from_args(args: &[String]) -> Option<String> {
    if args.len() < 2 {
        return None;
    }
    let key = erlang_fixed_map_key(&args[0])?;
    let map = args[1].trim();
    // The map argument must be an identifier-shaped name; otherwise the
    // place path would be ambiguous.
    if map.is_empty()
        || !map
            .chars()
            .all(|ch| ch == '_' || ch == '@' || ch == '$' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(format!("{map}.{key}"))
}

/// `true` if `name` denotes the `maps:get` BIF in either remote-call
/// or normalized dotted form.
fn erlang_maps_get_callee_name(name: &str) -> bool {
    let trimmed = name.trim();
    trimmed == "maps:get" || trimmed == "maps.get"
}

/// Validate an Erlang map key as an atom-shaped fixed value. Returns
/// the cleaned key (no quotes, no leading colon) when valid.
fn erlang_fixed_map_key(text: &str) -> Option<String> {
    let key = text
        .trim()
        .trim_start_matches(':')
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if key.is_empty() {
        return None;
    }
    let mut chars = key.chars();
    // First char must look like the start of an atom.
    if !chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
    {
        return None;
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(key.to_string())
}

/// Split a comma-separated argument list at the top nesting level,
/// trimming each piece. Respects parens / brackets / braces / quotes
/// so commas inside nested structures stay in place.
fn split_top_level_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut arg_start = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (idx, ch) in text.char_indices() {
        if let Some(open_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(text[arg_start..idx].trim().to_string());
                arg_start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(text[arg_start..].trim().to_string());
    args
}

/// Collect every function name in `-export([f/arity, g/arity, ...]).`
/// attributes. Functions not exported are module-private; they are
/// visible inside the module but not callable from other modules.
fn collect_erlang_exported_names(tree: &tree_sitter::Tree, src: &[u8]) -> std::collections::HashSet<String> {
    let mut exported_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for export_node in collect_kinds(tree, &["export_attribute"]) {
        // Walk for any `atom` descendant; export entries look like
        // `f/2` so the function name is the leading atom of each
        // `arity_qualifier` child. Be permissive: any atom inside
        // an export_attribute is treated as an exported name.
        let mut stack = vec![export_node];
        while let Some(node) = stack.pop() {
            if node.kind() == "atom" {
                let name_text = node_text(&node, src).trim();
                if !name_text.is_empty() {
                    exported_names.insert(name_text.to_string());
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    exported_names
}

#[cfg(test)]
mod tests;
