use super::*;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("lua grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set lua grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse lua source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn require_member_assignment_emits_local_member_binding() {
    let imports = parse_import_specs("local helper = require('util').helper\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.is_none()
            && spec.original_name.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Module
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.as_deref() == Some("helper")
            && spec.original_name.as_deref() == Some("helper")
            && !spec.is_wildcard
            && spec.scope == ImportScope::Local
    }));
}

#[test]
fn plain_require_assignment_remains_namespace_binding_only() {
    let imports = parse_import_specs("local util = require('util')\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "util"
            && spec.alias.as_deref() == Some("util")
            && spec.original_name.is_none()
            && !spec.is_wildcard
            && spec.scope == ImportScope::Module
    }));
    assert!(
        imports.iter().all(|spec| spec.scope != ImportScope::Local),
        "plain require assignment should not invent member imports: {imports:?}"
    );
}

fn predicate_expression(src: &str) -> ConditionExpressionFact {
    let language = language_from_pack(PACK_NAME).expect("lua grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set lua grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse lua source");
    assert!(!tree.root_node().has_error());
    let index = decl_index_from_tree_with_handler(FileId::new(0), src.as_bytes(), &tree, &HANDLER);
    let facts = collect_lua_predicate_returns(&index.defs, &tree, FileId::new(0), src.as_bytes());
    let [fact] = facts.as_slice() else {
        panic!("expected one complete predicate summary: {facts:?}");
    };
    fact.expression.clone()
}

#[test]
fn call_not_equal_nil_lowers_to_exact_call_truthiness() {
    let src = r#"
local function valid(value)
  return value:match("^[%w%.%-]+$") ~= nil
end
"#;
    let ConditionExpressionFact::Truthy { operand, .. } = predicate_expression(src) else {
        panic!("call ~= nil must lower to direct call truthiness");
    };
    assert!(operand.direct_call_span.is_some());
}

#[test]
fn call_equal_nil_lowers_to_negated_exact_call_truthiness() {
    let src = r#"
local function valid(value)
  return value:find("%.%.") == nil
end
"#;
    let ConditionExpressionFact::Not { operand, .. } = predicate_expression(src) else {
        panic!("call == nil must lower to negated direct call truthiness");
    };
    let ConditionExpressionFact::Truthy { operand, .. } = *operand else {
        panic!("nil equality must negate the call truthiness atom");
    };
    assert!(operand.direct_call_span.is_some());
}

#[test]
fn non_call_nil_comparison_remains_exact_equality() {
    let src = r#"
local function present(value)
  return value ~= nil
end
"#;
    let ConditionExpressionFact::Equality {
        relation: ConditionEquality::NotEqual,
        left,
        right,
        ..
    } = predicate_expression(src)
    else {
        panic!("ordinary value comparison must remain exact equality");
    };
    assert!(left.direct_call_span.is_none());
    assert_eq!(right.static_value, Some(StaticScalarValue::Null));
}

#[test]
fn predicate_summary_rejects_helpers_with_alternate_returns() {
    let src = r#"
local function ambiguous(value, allow)
  if allow then return true end
  return value:find("%.%.") == nil
end
"#;
    let language = language_from_pack(PACK_NAME).expect("lua grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set lua grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse lua source");
    assert!(!tree.root_node().has_error());
    let index = decl_index_from_tree_with_handler(FileId::new(0), src.as_bytes(), &tree, &HANDLER);
    let facts = collect_lua_predicate_returns(&index.defs, &tree, FileId::new(0), src.as_bytes());

    assert!(facts.is_empty(), "alternate returns must fail closed: {facts:?}");
}

#[test]
fn require_member_call_assignment_retains_import_derived_local_binding() {
    let imports = parse_import_specs("local runtime = require('provider.module').configure()\n");

    assert!(
        imports.iter().any(|spec| {
            spec.module == "provider.module"
                && spec.alias.as_deref() == Some("runtime")
                && spec.original_name.as_deref() == Some("configure")
                && !spec.is_wildcard
                && spec.scope == ImportScope::Local
        }),
        "a nested member call on require(...) must retain the exact assignment binding: {imports:?}"
    );
}
