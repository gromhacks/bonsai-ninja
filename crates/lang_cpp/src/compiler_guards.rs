//! Exact local C++ guard shapes. Operation and type spellings are evidence for
//! rule-owned models, never implicit sanitizer semantics in the frontend.
use bonsai_common::FileId;
use bonsai_lang_api::{
    kit::{node_text, span_of},
    CompilerGuardFact,
};
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

const CAPABILITY: &str = "terminal-predicate.compound-static-allowlist";

struct Summary {
    name: String,
    input_type: String,
    evidence: Vec<String>,
}

pub(super) fn cpp_compound_predicate_call_guards(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<CompilerGuardFact> {
    let root = tree.root_node();
    // This local proof has no namespace/import resolver. Restrict it to exact
    // translation-unit bindings instead of merging same-named nested owners.
    let functions = children(root)
        .into_iter()
        .filter(|node| node.kind() == "function_definition")
        .collect::<Vec<_>>();
    let mut external_shadows = HashSet::new();
    let mut collections = HashMap::new();
    let mut ambiguous = HashSet::new();
    for node in children(root) {
        if node.kind() == "declaration" {
            for declarator in declarators(node) {
                if let Some(name) = binding(declarator) {
                    external_shadows.insert(node_text(&name, src).to_string());
                }
            }
            if let Some((name, ty)) = static_collection(node, src) {
                if collections.insert(name.clone(), ty).is_some() {
                    ambiguous.insert(name);
                }
            }
        } else if let Some(name) = node.child_by_field_name("name") {
            // Type aliases, namespace definitions and macros may shadow a
            // qualified external provider just as local values shadow calls.
            external_shadows.insert(node_text(&name, src).to_string());
        }
    }
    collections.retain(|name, _| !ambiguous.contains(name));
    if collections.is_empty() {
        return Vec::new();
    }
    let summaries = functions
        .iter()
        .copied()
        .filter_map(|function| summarize(function, src, &collections, &external_shadows))
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        return Vec::new();
    }
    let mut facts = Vec::new();
    for function in functions.iter().copied() {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        if body.has_error() || !descendants(body, &["goto_statement", "labeled_statement"]).is_empty() {
            continue;
        }
        let statements = children(body);
        let calls = descendants(body, &["call_expression"]);
        for (position, pair) in statements.windows(2).enumerate() {
            let [guard, statement] = pair else { continue };
            let Some(predicate) = rejecting_call(*guard, src) else {
                continue;
            };
            let Some(callee) = predicate
                .child_by_field_name("function")
                .filter(|callee| callee.kind() == "identifier")
            else {
                continue;
            };
            let name = node_text(&callee, src);
            let matching = summaries
                .iter()
                .filter(|summary| summary.name == name)
                .collect::<Vec<_>>();
            let [summary] = matching.as_slice() else { continue };
            if external_shadows.contains(name) || local_binding(function, *guard, name, src).is_some() {
                continue;
            }
            // There must be one actual definition, not just one overload whose
            // body happened to fit this proof skeleton.
            if functions
                .iter()
                .filter(|candidate| function_name(**candidate, src) == Some(name))
                .count()
                != 1
            {
                continue;
            }
            let Some(predicate_args) = arguments(predicate) else {
                continue;
            };
            let [input, output] = predicate_args.as_slice() else {
                continue;
            };
            if input.kind() != "identifier"
                || output.kind() != "identifier"
                || node_text(input, src) == node_text(output, src)
            {
                continue;
            }
            let input_name = node_text(input, src);
            let Some(input_declaration) = local_binding(function, *guard, input_name, src) else {
                continue;
            };
            let Some(output_declaration) = local_binding(function, *guard, node_text(output, src), src)
            else {
                continue;
            };
            if type_name(input_declaration, src).as_deref() != Some(&summary.input_type)
                || type_name(output_declaration, src).as_deref() != Some(&summary.input_type)
                || !plain_local_value(output_declaration, node_text(output, src), src)
            {
                continue;
            }
            let Some(call) = statement_call(*statement) else {
                continue;
            };
            let Some(call_name) = call
                .child_by_field_name("function")
                .filter(|node| node.kind() == "identifier")
            else {
                continue;
            };
            if external_shadows.contains(node_text(&call_name, src))
                || local_binding(function, call, node_text(&call_name, src), src).is_some()
                || functions
                    .iter()
                    .any(|candidate| function_name(*candidate, src) == Some(node_text(&call_name, src)))
            {
                continue;
            }
            let Some(call_arguments) = arguments(call) else {
                continue;
            };
            let mut evidence = summary.evidence.clone();
            let mut matched = false;
            let mut pure = true;
            for (index, argument) in call_arguments.iter().copied().enumerate() {
                if let Some(method) = projection(argument, input_name, src) {
                    matched = true;
                    evidence.push(format!("guarded-argument:{index}=predicate-argument:0"));
                    evidence.push(format!("guarded-argument:{index}:projection:{method}"));
                } else if scalar(argument, src).is_none() {
                    pure = false;
                }
            }
            if !matched || !pure {
                continue;
            }
            if let Some(related) = statements.get(position + 2).copied().and_then(statement_call) {
                evidence.extend(related_evidence(
                    function,
                    call,
                    related,
                    &calls,
                    &external_shadows,
                    src,
                ));
            }
            evidence.sort();
            evidence.dedup();
            facts.push(CompilerGuardFact {
                function_span: span_of(file, &function),
                guarded_call_span: span_of(file, &call_name),
                proof_span: span_of(file, guard),
                capability: CAPABILITY.to_string(),
                evidence,
            });
        }
    }
    facts.sort_by(|a, b| {
        (a.function_span.start, a.guarded_call_span.start, &a.evidence).cmp(&(
            b.function_span.start,
            b.guarded_call_span.start,
            &b.evidence,
        ))
    });
    facts.dedup();
    facts
}

fn summarize(
    function: Node<'_>,
    src: &[u8],
    collections: &HashMap<String, String>,
    shadows: &HashSet<String>,
) -> Option<Summary> {
    let name = function_name(function, src)?.to_string();
    let parameters = parameters(function)?;
    let [input_parameter, output_parameter] = parameters.as_slice() else {
        return None;
    };
    let input = binding(input_parameter.child_by_field_name("declarator")?)?;
    let output = binding(output_parameter.child_by_field_name("declarator")?)?;
    let input_type = type_name(*input_parameter, src)?;
    if type_name(*output_parameter, src)? != input_type || shadows.contains(input_type.split("::").next()?) {
        return None;
    }
    let body = function.child_by_field_name("body")?;
    if body.has_error() {
        return None;
    }
    let statements = children(body);
    let [prefix_guard, rest_declaration, token_statement, final_return] = statements.as_slice() else {
        return None;
    };
    if prefix_guard.kind() != "if_statement"
        || prefix_guard.child_by_field_name("alternative").is_some()
        || !returns_boolean(prefix_guard.child_by_field_name("consequence")?, false, src)
    {
        return None;
    }
    let prefix_call = zero_comparison(prefix_guard.child_by_field_name("condition")?, "!=", src)?;
    let (prefix_receiver, prefix_method) = method_call(prefix_call, src)?;
    if prefix_receiver != node_text(&input, src) {
        return None;
    }
    let prefix_args = arguments(prefix_call)?;
    let [literal, offset] = prefix_args.as_slice() else {
        return None;
    };
    let prefix = string_literal(*literal, src)?;
    if integer(*offset, src) != Some(0) {
        return None;
    }
    let (rest, remainder_call) = single_initializer(*rest_declaration)?;
    // `auto` preserves the modelled operation's return type without an
    // unproved conversion or a user-defined wrapper constructor.
    if type_name(*rest_declaration, src)?.as_str() != "auto" {
        return None;
    }
    let (remainder_receiver, remainder_method) = method_call(remainder_call, src)?;
    let remainder_args = arguments(remainder_call)?;
    let [skip] = remainder_args.as_slice() else {
        return None;
    };
    if remainder_receiver != node_text(&input, src)
        || integer(*skip, src) != u128::try_from(prefix.len()).ok()
    {
        return None;
    }
    let assignment = statement_expression(*token_statement)?;
    if assignment.kind() != "assignment_expression"
        || operator(assignment, src) != Some("=")
        || node_text(&assignment.child_by_field_name("left")?, src) != node_text(&output, src)
    {
        return None;
    }
    let token_call = assignment.child_by_field_name("right")?;
    let (token_receiver, token_method) = method_call(token_call, src)?;
    if token_receiver != node_text(&rest, src) {
        return None;
    }
    let token_args = arguments(token_call)?;
    let [start, boundary_call] = token_args.as_slice() else {
        return None;
    };
    if integer(*start, src) != Some(0) {
        return None;
    }
    let (boundary_receiver, boundary_method) = method_call(*boundary_call, src)?;
    if boundary_receiver != node_text(&rest, src) {
        return None;
    }
    let boundary_args = arguments(*boundary_call)?;
    let [boundary] = boundary_args.as_slice() else {
        return None;
    };
    let boundary = character(*boundary, src)?;
    if final_return.kind() != "return_statement" {
        return None;
    }
    let membership_call = zero_comparison(first_child(*final_return)?, ">", src)?;
    let (collection, membership_method) = method_call(membership_call, src)?;
    let collection_type = collections.get(collection)?;
    if shadows.contains(collection_type.split("::").next()?)
        || local_binding(function, *final_return, collection, src).is_some()
    {
        return None;
    }
    let member_args = arguments(membership_call)?;
    let [member] = member_args.as_slice() else {
        return None;
    };
    if node_text(member, src) != node_text(&output, src) {
        return None;
    }
    let places = [
        node_text(&input, src),
        node_text(&output, src),
        node_text(&rest, src),
        collection,
    ];
    if places.iter().collect::<HashSet<_>>().len() != places.len() {
        return None;
    }
    Some(Summary {
        name,
        input_type: input_type.clone(),
        evidence: vec![
            "predicate-complete:true".to_string(),
            "finite-static-string-membership:true".to_string(),
            format!("predicate-input-type:{input_type}"),
            format!("membership-collection-type:{collection_type}"),
            format!("prefix-call:{prefix_method}"),
            format!("prefix-value:string:{prefix}"),
            "prefix-position:number:0".to_string(),
            format!("prefix-remainder-call:{remainder_method}"),
            format!("membership-call:{membership_method}"),
            format!("membership-token-call:{token_method}"),
            format!("membership-boundary-call:{boundary_method}"),
            format!("membership-boundary-codepoint:{}", u32::from(boundary)),
            "membership-token-boundary:true".to_string(),
            "membership-subject-derived-from-prefix:true".to_string(),
        ],
    })
}

fn related_evidence(
    function: Node<'_>,
    guarded: Node<'_>,
    related: Node<'_>,
    calls: &[Node<'_>],
    shadows: &HashSet<String>,
    src: &[u8],
) -> Vec<String> {
    let Some(name_node) = related.child_by_field_name("function") else {
        return Vec::new();
    };
    let name = node_text(&name_node, src);
    if guarded
        .child_by_field_name("function")
        .is_none_or(|callee| node_text(&callee, src) != name)
        || calls.iter().any(|call| {
            call.start_byte() > related.end_byte()
                && call
                    .child_by_field_name("function")
                    .is_some_and(|callee| node_text(&callee, src) == name)
        })
    {
        return Vec::new();
    }
    let (Some(args), Some(guarded_args)) = (arguments(related), arguments(guarded)) else {
        return Vec::new();
    };
    if args.len() != guarded_args.len()
        || args.first().is_none_or(|arg| arg.kind() != "identifier")
        || args.first().map(|arg| node_text(arg, src)) != guarded_args.first().map(|arg| node_text(arg, src))
    {
        return Vec::new();
    }
    let mut evidence = vec![format!("related-call:{name}:argument:0=guarded-argument:0")];
    for (index, arg) in args.into_iter().enumerate().skip(1) {
        if arg.kind() == "identifier"
            && (shadows.contains(node_text(&arg, src))
                || local_binding(function, related, node_text(&arg, src), src).is_some())
        {
            return Vec::new();
        }
        let Some(value) = scalar(arg, src) else {
            return Vec::new();
        };
        evidence.push(format!("related-call:{name}:argument:{index}={value}"));
    }
    evidence
}

fn static_collection(node: Node<'_>, src: &[u8]) -> Option<(String, String)> {
    if !children(node)
        .iter()
        .any(|child| child.kind() == "type_qualifier" && node_text(child, src) == "const")
    {
        return None;
    }
    let (name, value) = single_initializer(node)?;
    if declarators(node).first()?.child_by_field_name("declarator")? != name
        || value.kind() != "initializer_list"
    {
        return None;
    }
    let items = children(value);
    if items.is_empty() || items.iter().any(|item| string_literal(*item, src).is_none()) {
        return None;
    }
    Some((node_text(&name, src).to_string(), type_name(node, src)?))
}

fn local_binding<'tree>(
    function: Node<'tree>,
    at: Node<'tree>,
    name: &str,
    src: &[u8],
) -> Option<Node<'tree>> {
    let parameters = parameters(function).unwrap_or_default();
    let locals = function
        .child_by_field_name("body")
        .map(children)
        .unwrap_or_default();
    parameters
        .into_iter()
        .chain(
            locals
                .into_iter()
                .filter(|node| node.kind() == "declaration" && node.end_byte() <= at.start_byte()),
        )
        .filter(|node| {
            declarators(*node)
                .into_iter()
                .filter_map(binding)
                .any(|binding| node_text(&binding, src) == name)
        })
        .next_back()
}

fn plain_local_value(node: Node<'_>, name: &str, src: &[u8]) -> bool {
    node.kind() == "declaration"
        && declarators(node)
            .iter()
            .any(|decl| decl.kind() == "identifier" && node_text(decl, src) == name)
}

fn type_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    Some(
        node_text(&node.child_by_field_name("type")?, src)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(""),
    )
}

fn function_declarator(mut node: Node<'_>) -> Option<Node<'_>> {
    node = node.child_by_field_name("declarator")?;
    while node.kind() != "function_declarator" {
        node = node.child_by_field_name("declarator")?;
    }
    Some(node)
}

fn function_name<'src>(node: Node<'_>, src: &'src [u8]) -> Option<&'src str> {
    let name = function_declarator(node)?.child_by_field_name("declarator")?;
    (name.kind() == "identifier").then(|| node_text(&name, src))
}

fn parameters(node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let params = children(function_declarator(node)?.child_by_field_name("parameters")?);
    params
        .iter()
        .all(|node| node.kind() == "parameter_declaration")
        .then_some(params)
}

fn binding(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "identifier" {
            return Some(node);
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            node = inner;
        } else if matches!(node.kind(), "reference_declarator" | "parenthesized_declarator") {
            let inner = children(node);
            let [value] = inner.as_slice() else { return None };
            node = *value;
        } else {
            return None;
        }
    }
}

fn declarators(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children_by_field_name("declarator", &mut cursor).collect()
}

fn single_initializer(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if node.kind() != "declaration" {
        return None;
    }
    let declarations = declarators(node);
    let [initializer] = declarations.as_slice() else {
        return None;
    };
    if initializer.kind() != "init_declarator" {
        return None;
    }
    Some((
        binding(initializer.child_by_field_name("declarator")?)?,
        initializer.child_by_field_name("value")?,
    ))
}

fn rejecting_call<'tree>(node: Node<'tree>, src: &[u8]) -> Option<Node<'tree>> {
    if node.kind() != "if_statement" || node.child_by_field_name("alternative").is_some() {
        return None;
    }
    let ret = single_return(node.child_by_field_name("consequence")?)?;
    if first_child(ret).is_some_and(|value| !matches!(value.kind(), "number_literal" | "true" | "false")) {
        return None;
    }
    let condition = unwrap(node.child_by_field_name("condition")?)?;
    let argument = condition.child_by_field_name("argument")?;
    if condition.kind() != "unary_expression"
        || src
            .get(condition.start_byte()..argument.start_byte())
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(str::trim)
            != Some("!")
    {
        return None;
    }
    (argument.kind() == "call_expression").then_some(argument)
}

fn returns_boolean(node: Node<'_>, value: bool, src: &[u8]) -> bool {
    single_return(node)
        .and_then(first_child)
        .is_some_and(|node| node_text(&node, src) == if value { "true" } else { "false" })
}

fn single_return(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "compound_statement" {
        let statements = children(node);
        let [value] = statements.as_slice() else {
            return None;
        };
        node = *value;
    }
    (node.kind() == "return_statement").then_some(node)
}

fn zero_comparison<'tree>(node: Node<'tree>, expected: &str, src: &[u8]) -> Option<Node<'tree>> {
    let node = unwrap(node)?;
    if node.kind() != "binary_expression" || operator(node, src) != Some(expected) {
        return None;
    }
    let left = unwrap(node.child_by_field_name("left")?)?;
    let right = unwrap(node.child_by_field_name("right")?)?;
    (left.kind() == "call_expression" && integer(right, src) == Some(0)).then_some(left)
}

fn operator<'src>(node: Node<'_>, src: &'src [u8]) -> Option<&'src str> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    std::str::from_utf8(src.get(left.end_byte()..right.start_byte())?)
        .ok()
        .map(str::trim)
}

fn method_call<'src>(node: Node<'_>, src: &'src [u8]) -> Option<(&'src str, &'src str)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "field_expression" {
        return None;
    }
    let receiver = function.child_by_field_name("argument")?;
    let method = function.child_by_field_name("field")?;
    (receiver.kind() == "identifier" && method.kind() == "field_identifier")
        .then(|| (node_text(&receiver, src), node_text(&method, src)))
}

fn projection<'src>(node: Node<'_>, place: &str, src: &'src [u8]) -> Option<&'src str> {
    let node = unwrap(node)?;
    if node.kind() == "identifier" && node_text(&node, src) == place {
        return Some("identity");
    }
    let (receiver, method) = method_call(node, src)?;
    (receiver == place && arguments(node)?.is_empty()).then_some(method)
}

fn arguments(node: Node<'_>) -> Option<Vec<Node<'_>>> {
    Some(children(node.child_by_field_name("arguments")?))
}

fn statement_expression(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "expression_statement")
        .then(|| first_child(node))
        .flatten()
        .and_then(unwrap)
}

fn statement_call(node: Node<'_>) -> Option<Node<'_>> {
    statement_expression(node).filter(|node| node.kind() == "call_expression")
}

fn unwrap(mut node: Node<'_>) -> Option<Node<'_>> {
    while matches!(node.kind(), "condition_clause" | "parenthesized_expression") {
        let inner = children(node);
        let [value] = inner.as_slice() else { return None };
        node = *value;
    }
    Some(node)
}

fn scalar(node: Node<'_>, src: &[u8]) -> Option<String> {
    match node.kind() {
        "number_literal" => integer(node, src).map(|value| format!("number:{value}")),
        "identifier" => Some(format!("place:{}", node_text(&node, src))),
        "string_literal" => string_literal(node, src).map(|value| format!("string:{value}")),
        _ => None,
    }
}

fn string_literal<'src>(node: Node<'_>, src: &'src [u8]) -> Option<&'src str> {
    if node.kind() != "string_literal" {
        return None;
    }
    let inner = node_text(&node, src).strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains('\\')).then_some(inner)
}

fn character(node: Node<'_>, src: &[u8]) -> Option<char> {
    if node.kind() != "char_literal" {
        return None;
    }
    let inner = node_text(&node, src).strip_prefix('\'')?.strip_suffix('\'')?;
    if inner == "\\0" {
        return Some('\0');
    }
    let mut chars = inner.chars();
    let value = chars.next()?;
    (value.is_ascii() && value != '\\' && chars.next().is_none()).then_some(value)
}

fn integer(node: Node<'_>, src: &[u8]) -> Option<u128> {
    if node.kind() != "number_literal" {
        return None;
    }
    node_text(&node, src)
        .trim_end_matches(['u', 'U', 'l', 'L'])
        .parse()
        .ok()
}

fn descendants<'tree>(node: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    // One explicit heap walk per requested syntax projection; never recurse
    // through arbitrarily nested source IR on a platform-default stack.
    let mut out = Vec::new();
    let mut pending = children(node);
    while let Some(node) = pending.pop() {
        if kinds.contains(&node.kind()) {
            out.push(node);
        }
        pending.extend(children(node));
    }
    out
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .collect()
}

fn first_child(node: Node<'_>) -> Option<Node<'_>> {
    children(node).first().copied()
}
