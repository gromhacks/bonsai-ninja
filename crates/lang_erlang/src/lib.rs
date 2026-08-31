//! Erlang language adapter.
use bonsai_common::{FileId, Span};
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
    if let Some(place) = erlang_maps_get_place(node, src) {
        return ExpressionPlaceExtraction {
            places: vec![place],
            consumed_node_ids: vec![node.id()],
        };
    }
    if node.kind() == "record_field_expr" {
        let (Some(base), Some(field)) = (
            node.child_by_field_name("expr"),
            node.child_by_field_name("field")
                .and_then(|field| field.child_by_field_name("name")),
        ) else {
            return ExpressionPlaceExtraction::default();
        };
        let base = node_text(&base, src).trim();
        let field = node_text(&field, src).trim();
        if erlang_variable_name(base) && erlang_atom_name(field) {
            return ExpressionPlaceExtraction {
                places: vec![format!("{base}.{field}")],
                consumed_node_ids: vec![node.id()],
            };
        }
        return ExpressionPlaceExtraction::default();
    }
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

/// `maps:get/2,3` is a documented Erlang/OTP map projection. Lower the exact
/// parsed call as a field place so all consumers share the same compiler fact;
/// do not rediscover its arguments from rendered call text.
fn erlang_maps_get_place(node: Node<'_>, src: &[u8]) -> Option<String> {
    let (callee, args) = erlang_call_parts(node, src)?;
    if callee != "maps:get" || !(2..=3).contains(&args.len()) {
        return None;
    }
    let key = erlang_fixed_map_key(node_text(&args[0], src))?;
    let map = node_text(&args[1], src).trim();
    erlang_variable_name(map).then(|| format!("{map}.{key}"))
}

pub const LANG_ID: LanguageId = LanguageId::new("erlang");
const PACK_NAME: &str = "erlang";

// Erlang's tree-sitter grammar (WhatsApp) uses its own construct nodes.
// This adapter declares the complete production inventory so shared lowering
// can emit case / if / try / receive flow without a cross-language fallback.
const HANDLER: GrammarHandler = GrammarHandler {
    control_target_extractor: None,
    loop_label_extractor: None,
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
    named_aggregate_kinds: &["map_expr", "record_expr"],
    positional_aggregate_kinds: &["tuple", "list"],
    aggregate_pair_kinds: &["map_field", "record_field"],
    aggregate_key_field_names: &["key", "name"],
    aggregate_value_field_names: &["value", "expr"],
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
    loop_condition_field_names: &[],
    loop_condition_extractor: None,
    loop_kind_extractor: None,
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
    try_node_filter: None,
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
        // Second pass: enrich exact Tree-sitter facts that the shared walker
        // cannot represent directly, while retaining parsed spans as the
        // semantic source of truth.
        if let Some((snapshot, tree)) = parsed.as_ref() {
            let parameter_patterns =
                collect_erlang_parameter_pattern_plans(tree, file, snapshot.text.as_bytes());
            let assignment_values = AssignmentValueIndex::new(&decl_index.assignment_values);
            let (fun_ref_values, fun_ref_aliases) =
                collect_erlang_fun_refs(tree, file, snapshot.text.as_bytes());
            for decl in &mut decl_index.defs {
                apply_erlang_parameter_pattern_plan(decl, &parameter_patterns);
                repair_erlang_try_regions(&mut decl.flow_events, tree, snapshot.text.as_bytes(), file);
                normalize_erlang_access_events(&mut decl.flow_events, &fun_ref_values);
                demote_erlang_non_tail_branch_returns(&mut decl.flow_events, &assignment_values);
                bonsai_lang_api::kit::annotate_tuple_call_result_bindings(
                    &mut decl.flow_events,
                    tree,
                    snapshot.text.as_bytes(),
                    &HANDLER,
                );
                inject_erlang_fun_ref_aliases(&mut decl.flow_events, &fun_ref_aliases);
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
            // Parser unavailable — retain already-lowered generic events.
            for decl in &mut decl_index.defs {
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

/// Apply documented Erlang runtime value semantics to already parsed call
/// facts. Record-field places are lowered directly by
/// [`erlang_expression_places`]; this pass never reparses an assignment or
/// call expression.
fn normalize_erlang_access_events(
    events: &mut [FlowEvent],
    fun_refs: &std::collections::BTreeMap<Span, String>,
) {
    for event in events {
        match event {
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if let Some(source) = fun_refs.get(&arg.span) {
                        arg.value_text.clone_from(source);
                        // `fun name/arity` is Erlang's exact callable-value
                        // syntax. Lower the grammar-proven target as a place
                        // so shared callgraph construction can distinguish it
                        // from a compound expression that merely mentions a
                        // function name.
                        arg.place = Some(source.clone());
                        push_unique_string(&mut arg.source_names, source.clone());
                        continue;
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_erlang_access_events(then_events, fun_refs);
                normalize_erlang_access_events(else_events, fun_refs);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_erlang_access_events(body, fun_refs);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_erlang_access_events(body, fun_refs);
                normalize_erlang_access_events(catch_events, fun_refs);
                normalize_erlang_access_events(finally_events, fun_refs);
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

/// Add exact callback-alias facts for Erlang's function-reference
/// syntax: `Cb = fun helper/1`.
fn inject_erlang_fun_ref_aliases(
    events: &mut Vec<FlowEvent>,
    aliases: &std::collections::BTreeMap<Span, String>,
) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_erlang_fun_ref_aliases(then_events, aliases);
                inject_erlang_fun_ref_aliases(else_events, aliases);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_erlang_fun_ref_aliases(body, aliases);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_erlang_fun_ref_aliases(body, aliases);
                inject_erlang_fun_ref_aliases(catch_events, aliases);
                inject_erlang_fun_ref_aliases(finally_events, aliases);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let alias = erlang_fun_ref_alias_assignment(&event, aliases);
        rewritten.push(event);
        if let Some(alias) = alias {
            rewritten.push(alias);
        }
    }
    *events = rewritten;
}

fn collect_erlang_fun_refs(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> (
    std::collections::BTreeMap<Span, String>,
    std::collections::BTreeMap<Span, String>,
) {
    let mut values = std::collections::BTreeMap::new();
    let mut aliases = std::collections::BTreeMap::new();
    for value in collect_kinds(tree, &["internal_fun"]) {
        let Some(function) = value.child_by_field_name("fun") else {
            continue;
        };
        if function.kind() != "atom" {
            continue;
        }
        let function = node_text(&function, src).trim();
        if erlang_atom_name(function) {
            values.insert(span_of(file, &value), function.to_string());
        }
    }
    for assignment in collect_kinds(tree, &["match_expr"]) {
        let (Some(target), Some(value)) = (
            assignment.child_by_field_name("lhs"),
            assignment.child_by_field_name("rhs"),
        ) else {
            continue;
        };
        if target.kind() != "var" || value.kind() != "internal_fun" {
            continue;
        }
        if let Some(function) = values.get(&span_of(file, &value)) {
            aliases.insert(span_of(file, &assignment), function.clone());
        }
    }
    (values, aliases)
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
    let segments = bonsai_common::qualified_name_segments(name);
    let short = match segments.as_slice() {
        [short] => *short,
        [module, short] if *module == "erlang" => *short,
        _ => return None,
    };
    if !matches!(short, "throw" | "error" | "exit") {
        return None;
    }
    let value_name = args.first().and_then(|arg| {
        arg.place
            .as_ref()
            .filter(|place| erlang_variable_name(place))
            .cloned()
            .or_else(|| {
                arg.source_names
                    .iter()
                    .find(|name| erlang_variable_name(name))
                    .cloned()
            })
    });
    Some(FlowEvent::Throw {
        span: *span,
        value_name,
        thrown_type: None,
    })
}

fn erlang_fun_ref_alias_assignment(
    event: &FlowEvent,
    aliases: &std::collections::BTreeMap<Span, String>,
) -> Option<FlowEvent> {
    let FlowEvent::Assign { span, target, .. } = event else {
        return None;
    };
    let target = target.trim();
    if !erlang_variable_name(target) {
        return None;
    }
    let source_name = aliases.get(span)?.clone();
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

#[derive(Clone, Debug)]
struct ErlangParameterPatternPlan {
    clause_span: bonsai_common::Span,
    params: Vec<String>,
    bindings: Vec<FlowEvent>,
}

/// Lower function-clause parameter patterns from their exact Tree-sitter
/// nodes. Record fields and tuple/list bindings are compiler facts; rendered
/// function headers are never split or reparsed.
fn collect_erlang_parameter_pattern_plans(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<ErlangParameterPatternPlan> {
    let mut plans = Vec::new();
    for clause in collect_kinds(tree, &["function_clause"]) {
        let Some(arguments) = clause.child_by_field_name("args") else {
            continue;
        };
        let mut cursor = arguments.walk();
        let arguments = arguments.named_children(&mut cursor).collect::<Vec<_>>();
        let mut params = Vec::with_capacity(arguments.len());
        let mut bindings = Vec::new();
        for (index, argument) in arguments.into_iter().enumerate() {
            let whole_binding = erlang_pattern_whole_binding(argument, src);
            let slot = whole_binding.unwrap_or_else(|| format!("_Arg{index}"));
            params.push(slot.clone());

            let mut field_bound = std::collections::HashSet::new();
            collect_erlang_record_pattern_bindings(
                argument,
                &slot,
                file,
                src,
                &mut field_bound,
                &mut bindings,
            );
            let mut variables = Vec::new();
            collect_erlang_pattern_variables(argument, src, &mut variables);
            for variable in variables {
                if variable == "_" || variable == slot || field_bound.contains(&variable) {
                    continue;
                }
                bindings.push(erlang_destructure_binding(
                    span_of(file, &argument),
                    variable,
                    slot.clone(),
                ));
            }
        }
        plans.push(ErlangParameterPatternPlan {
            clause_span: span_of(file, &clause),
            params,
            bindings,
        });
    }
    plans
}

fn erlang_pattern_whole_binding(argument: Node<'_>, src: &[u8]) -> Option<String> {
    if argument.kind() == "var" {
        let variable = node_text(&argument, src).trim();
        return erlang_variable_name(variable).then(|| variable.to_string());
    }
    if argument.kind() != "match_expr" {
        return None;
    }
    ["lhs", "rhs"]
        .into_iter()
        .filter_map(|field| argument.child_by_field_name(field))
        .find(|node| node.kind() == "var")
        .and_then(|node| {
            let variable = node_text(&node, src).trim();
            erlang_variable_name(variable).then(|| variable.to_string())
        })
}

fn collect_erlang_pattern_variables(node: Node<'_>, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "var" {
        push_unique_string(out, node_text(&node, src).trim().to_string());
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_erlang_pattern_variables(child, src, out);
    }
}

fn collect_erlang_record_pattern_bindings(
    node: Node<'_>,
    slot: &str,
    file: FileId,
    src: &[u8],
    field_bound: &mut std::collections::HashSet<String>,
    out: &mut Vec<FlowEvent>,
) {
    if node.kind() == "record_expr" {
        let mut cursor = node.walk();
        for field in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "record_field")
        {
            let (Some(name), Some(value)) = (
                field.child_by_field_name("name"),
                field.child_by_field_name("expr"),
            ) else {
                continue;
            };
            let field_name = node_text(&name, src).trim();
            if !erlang_atom_name(field_name) {
                continue;
            }
            let mut variables = Vec::new();
            collect_erlang_pattern_variables(value, src, &mut variables);
            for variable in variables {
                if variable == "_" || !field_bound.insert(variable.clone()) {
                    continue;
                }
                out.push(erlang_destructure_binding(
                    span_of(file, &field),
                    variable,
                    format!("{slot}.{field_name}"),
                ));
            }
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_erlang_record_pattern_bindings(child, slot, file, src, field_bound, out);
    }
}

fn erlang_destructure_binding(span: bonsai_common::Span, target: String, source: String) -> FlowEvent {
    FlowEvent::Assign {
        span,
        target,
        source_name: Some(source.clone()),
        source_call: None,
        source_call_args: Vec::new(),
        source_names: vec![source],
        declares_new_binding: false,
        value_kind: Some(bonsai_lang_api::AssignValueKind::Destructure),
    }
}

fn apply_erlang_parameter_pattern_plan(
    decl: &mut bonsai_lang_api::Decl,
    plans: &[ErlangParameterPatternPlan],
) {
    let Some(plan) = plans.iter().find(|plan| plan.clause_span == decl.span) else {
        return;
    };
    decl.params.clone_from(&plan.params);
    if !plan.bindings.is_empty() {
        let mut bindings = plan.bindings.clone();
        bindings.append(&mut decl.flow_events);
        decl.flow_events = bindings;
    }
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
    let Some(clause) = collect_kinds(tree, &["function_clause"])
        .into_iter()
        .find(|clause| span_of(span.file, clause) == span)
    else {
        return;
    };
    let Some(body) = clause.child_by_field_name("body") else {
        return;
    };
    let mut cursor = body.walk();
    let Some(value_node) = body
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .last()
    else {
        return;
    };
    let value_span = span_of(span.file, &value_node);
    let value_text = node_text(&value_node, src.as_bytes()).trim().to_string();
    let value_flow = bonsai_lang_api::kit::expression_flow_from_node_with_handler(
        value_node,
        value_span.file,
        src.as_bytes(),
        &HANDLER,
    );
    let value_name = value_flow.place.clone();
    events.push(FlowEvent::Return {
        span: value_span,
        value_kind: HANDLER.expression_value_kind(value_node, src.as_bytes()),
        value_text: Some(value_text),
        value_name,
        value_flow,
    });
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

/// Append `value` to `values` unless it is empty or already present.
fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
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
