//! Qualified assignment helpers. Canonical place construction is derived
//! from adapter-declared Tree-sitter fields by `argument_place`; this module
//! never reparses rendered source syntax.
//!
use tree_sitter::Node;

use super::{argument_place, GrammarHandler};

/// Lower one parsed assignment target to its canonical place. The optional
/// adapter decoder is deliberately assignment-scoped; it cannot cause an
/// ordinary zero-argument call expression to masquerade as a storage read.
pub(super) fn assignment_place(node: Node<'_>, src: &[u8], handler: &GrammarHandler) -> Option<String> {
    handler
        .assignment_place_extractor
        .and_then(|extract| extract(node, src))
        .or_else(|| argument_place(&node, src, handler))
}

/// True when the node is a declaration that did not surface a
/// `value` / `right` field — typed declarations without an
/// initializer (`int x;`, `let x: T;`). Used to suppress noisy
/// "assignment-of-default" emission in adapters that emit
/// declaration syntax.
pub(super) fn type_only_declaration_without_initializer(node: &Node<'_>, handler: &GrammarHandler) -> bool {
    handler.type_only_declaration_kinds.contains(&node.kind())
        && node.child_by_field_name("value").is_none()
        && node.child_by_field_name("right").is_none()
}

/// For an assign-target node that's a member / subscript expression,
/// return the fully-qualified dotted form (`self.cmd`, `env.cmd`).
/// Returns `None` for plain identifier targets; their adapter-classified
/// identifier node is already the canonical binding.
///
/// This is how G3 (field taint) and G4 (container-element taint)
/// preserve write-side granularity: `self.cmd = x` produces BOTH an
/// Assign with target `cmd` (bare) AND an Assign with target
/// `self.cmd` (qualified). Downstream reads of `self.cmd` match the
/// qualified form; legacy consumers that only see `cmd` still work.
pub(super) fn qualified_assign_target(
    node: Option<Node<'_>>,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<String> {
    let target_node = node?;
    let target_kind = target_node.kind();
    if let Some(place) = handler
        .assignment_place_extractor
        .and_then(|extract| extract(target_node, src))
    {
        return Some(place);
    }
    if !handler.member_expression_kinds.contains(&target_kind)
        && !handler.subscript_expression_kinds.contains(&target_kind)
    {
        return None;
    }
    argument_place(&target_node, src, handler)
}
