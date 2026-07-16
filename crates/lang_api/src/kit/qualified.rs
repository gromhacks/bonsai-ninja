//! Qualified-target normalization shared by every adapter that
//! wants to write a granular field-write fact (`self.cmd = x`,
//! `env['cmd'] = x`, `obj->field = x`).
//!
//! These helpers convert per-grammar member-access / subscript
//! shapes into the canonical dotted form the taint engine and
//! security matcher use as identity keys. Keeping the
//! normalization here (rather than per-adapter) means
//! `obj['cmd']`, `obj.cmd`, and `obj->cmd` all hash to the same
//! `obj.cmd` token regardless of the grammar that emitted them.
//!
//! There is a less-correct variant of `normalise_qualified_text`
//! in `bonsai_security::analysis` that doesn't handle nested
//! brackets; phase-3 left it in place to preserve behavior. The
//! adapter-side version (this module) is the canonical engine
//! input.
//!
//! `binary_operator_is_assignment` and `type_only_declaration_without_initializer`
//! live alongside because they're the assignment-shape probes
//! that drive `qualified_assign_target` invocation.

use tree_sitter::Node;

use super::node_text;

/// True when this binary node is a real `=` assignment expression,
/// not an `==` comparison or `=>` arrow. Walks the child token
/// stream looking for the literal `=` character (which tree-sitter
/// emits as an unnamed terminal between the LHS and RHS named
/// children).
pub(super) fn binary_operator_is_assignment(node: &Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let child = cursor.node();
        if !child.is_named() {
            let text = node_text(&child, src).trim();
            if text == "=" {
                return true;
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
    false
}

/// True when the node is a declaration that did not surface a
/// `value` / `right` field — typed declarations without an
/// initializer (`int x;`, `let x: T;`). Used to suppress noisy
/// "assignment-of-default" emission in adapters that emit
/// declaration syntax.
pub(super) fn type_only_declaration_without_initializer(node: &Node<'_>) -> bool {
    matches!(
        node.kind(),
        "variable_declaration" | "parameter" | "formal_parameter" | "field_declaration"
    ) && node.child_by_field_name("value").is_none()
        && node.child_by_field_name("right").is_none()
}

/// For an assign-target node that's a member / subscript expression,
/// return the fully-qualified dotted form (`self.cmd`, `env.cmd`).
/// Returns `None` for plain identifier targets — those are handled by
/// the `sanitize_assign_target` path which displays the clean name.
///
/// This is how G3 (field taint) and G4 (container-element taint)
/// preserve write-side granularity: `self.cmd = x` produces BOTH an
/// Assign with target `cmd` (bare) AND an Assign with target
/// `self.cmd` (qualified). Downstream reads of `self.cmd` match the
/// qualified form; legacy consumers that only see `cmd` still work.
pub(super) fn qualified_assign_target(node: Option<Node<'_>>, src: &[u8]) -> Option<String> {
    let target_node = node?;
    let target_kind = target_node.kind();
    // Member / field / navigation / attribute / subscript kinds we know
    // how to normalise into dotted form.
    const QUALIFIED_KINDS: &[&str] = &[
        "member_expression",
        "member_access_expression",
        "field_access",
        "field_expression",
        "selector_expression",
        "navigation_expression",
        "attribute",
        "dot_index_expression",
        "subscript_expression",
        "subscript",
        "element_reference",
        "array_access",
        "element_access_expression",
        "bracket_index_expression",
        "index_expression",
        "indexing_expression",
    ];
    if !QUALIFIED_KINDS.contains(&target_kind) {
        return None;
    }
    let raw_text = node_text(&target_node, src).trim().to_string();
    if raw_text.is_empty() {
        return None;
    }
    // Strip subscript index contents: `env['cmd']` → `env.cmd`. For
    // member expressions the raw text is already the dotted form.
    let canonical_text = normalise_qualified_text(&raw_text);
    // Reject non-canonical results — whitespace means a multi-line or
    // operator-laden expression that we can't safely use as a key.
    if canonical_text.contains(|c: char| c.is_whitespace()) {
        return None;
    }
    if canonical_text.is_empty() {
        return None;
    }
    Some(canonical_text)
}

/// `env['cmd']` → `env.cmd` — canonicalise subscript syntax to dotted
/// so the taint-state key is consistent regardless of source syntax.
///
/// ## Adapter-side variant (this function)
///
/// Inputs come from `node_text(...)` of a tree-sitter
/// `subscript_expression` / `member_expression` / `field_access` /
/// similar QUALIFIED_KIND. These nodes are grammar-clean: no
/// concatenation, no nested brackets at depth ≥ 2, no whitespace
/// padding around `.`. The simple bool-flag bracket-tracking is
/// correct for this input shape.
///
/// The engine has a richer variant at `bonsai_taint::text::normalise_qualified_text`
/// for inputs that may have been concatenated, sigil-stripped, or
/// aliased. See that function's doc-comment for the side-by-side
/// comparison and reasoning for keeping both.
pub(super) fn normalise_qualified_text(text: &str) -> String {
    let mut canonical = String::with_capacity(text.len());
    let mut inside_brackets = false;
    let mut chars = text.trim().chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            // `obj->field` → `obj.field`.
            '-' if matches!(chars.peek(), Some('>')) => {
                chars.next();
                canonical.push('.');
            }
            // Subscript open: emit a `.` and start swallowing index contents.
            '[' => {
                inside_brackets = true;
                canonical.push('.');
            }
            ']' => {
                inside_brackets = false;
            }
            // Drop quote characters inside subscripts — we want
            // `env['cmd']` → `env.cmd`, not `env.'cmd'`.
            '\'' | '"' if inside_brackets => {}
            // Drop the Ruby / Elixir symbol-key sigil inside
            // subscripts so `params[:token]` → `params.token`, the
            // same canonical projection the engine-side
            // `bonsai_taint::text::normalise_qualified_text` and the
            // kit's `extract_qualified_accesses` produce. Without this
            // the symbol key kept its colon (`params.:token`) and a
            // field-precise seed (`params.token`) could not address
            // the projected read node.
            ':' if inside_brackets => {}
            _ => canonical.push(ch),
        }
    }
    // Trim any leading/trailing dots that fell out of the bracket
    // collapse (`obj['']` → `obj.`).
    canonical.trim_matches('.').to_string()
}

#[cfg(test)]
#[path = "qualified_tests.rs"]
mod tests;
