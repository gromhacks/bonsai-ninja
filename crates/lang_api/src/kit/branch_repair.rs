//! Branch-arm repair for grammars whose tree-sitter shape doesn't
//! cleanly partition `then`/`else` events.
//!
//! Two repair strategies, applied in order:
//!
//! 1. **Span-based partition.** When a grammar emits both arms under
//!    a single `body` field, we walk the events and move any whose
//!    span starts after the literal `else` keyword into `else_events`.
//! 2. **First-else synthesis.** When a C-like grammar exposes the
//!    first arm but drops a simple else-arm assignment, we
//!    synthesize that assignment from source bytes — only when both
//!    arms appear lexically in the source span and the assignment
//!    operator is at brace/paren/bracket depth 0.
//!
//! This is a recovery layer, not a primary strategy. Adapters that
//! can emit a structural `else_events` should always do so; the
//! repair is a last resort for grammars that genuinely conflate the
//! two arms.
//!
//! See `docs/contributing/adapter-contract.mdx` ("Branch arm contract") for the
//! design rationale.

use crate::FlowEvent;
use bonsai_common::{FileId, Span};
use tree_sitter::Node;

use super::{is_ident_continue_byte, node_text};

/// True when a tree-sitter node `kind` is the kind of node that an adapter
/// would emit as a single branch arm — typically the `body` field of an
/// `if`/`else` whose payload is a statement or expression.
pub(super) fn looks_like_branch_arm_node(kind: &str) -> bool {
    matches!(
        kind,
        "statement"
            | "statements"
            | "block"
            | "block_statement"
            | "function_body"
            | "compound_statement"
            | "expression_statement"
            | "variable_declaration_statement"
            | "declaration_statement"
            | "return_statement"
            | "throw_statement"
            | "revert_statement"
            | "if_statement"
            | "for_statement"
            | "while_statement"
            | "do_while_statement"
    ) || kind.ends_with("_statement")
        || kind.ends_with("_expression")
}

/// Repair `then`/`else` partitioning when the adapter dumped both arms into
/// `then_events` because the grammar didn't distinguish them.
///
/// First we try a span partition: any event whose span begins after the
/// literal `else` keyword (matched as a whole word, outside identifiers and
/// strings) gets moved to `else_events`. If that yields nothing — typically
/// because a C-like grammar elided the else-arm assignment from its child
/// list — we fall back to synthesizing a single assignment from raw bytes.
pub(super) fn repair_branch_events_by_else_keyword(
    then_events: &mut Vec<FlowEvent>,
    else_events: &mut Vec<FlowEvent>,
    node: &Node<'_>,
    src: &[u8],
) {
    // Only repair when the adapter dropped the partition entirely.
    if !else_events.is_empty() || then_events.is_empty() {
        return;
    }
    let branch_text = node_text(node, src);
    // Locate the `else` keyword inside the branch span, ignoring
    // appearances inside identifiers like `elseif` or `whatelse`.
    let Some(else_offset_in_branch) = find_keyword_outside_identifier(branch_text, "else") else {
        return;
    };
    let Ok(else_offset_in_branch) = u64::try_from(else_offset_in_branch) else {
        return;
    };
    let else_keyword_start = node.start_byte() as u64 + else_offset_in_branch;
    // Span partition: any event whose span starts at or after the else
    // keyword belongs to the else arm.
    let mut events_after_else = Vec::new();
    then_events.retain(|event| {
        let belongs_to_else = event_span(event).is_some_and(|span| span.start >= else_keyword_start);
        if belongs_to_else {
            events_after_else.push(event.clone());
        }
        !belongs_to_else
    });
    if !events_after_else.is_empty() {
        *else_events = events_after_else;
        return;
    }
    // No events in the else arm — synthesize one from source if it looks
    // like a simple assignment. Use the file id from any `then` event since
    // we know they share the file with the else arm.
    if let Some(file) = then_events.first().and_then(event_span).map(|span| span.file) {
        if let Some(synthesized_assign) = synthesize_first_else_assignment(
            branch_text,
            node.start_byte(),
            else_offset_in_branch as usize,
            file,
        ) {
            else_events.push(synthesized_assign);
        }
    }
}

/// Synthesize a single `Assign` event for the else arm by parsing source
/// bytes. Used as a last resort when the grammar produced no children for
/// the else arm but the source text clearly contains `else <var> = <expr>`.
///
/// Conservative on every input that doesn't look like a simple assignment:
/// returns `None` rather than guess at compound expressions, calls, or
/// multi-statement bodies.
fn synthesize_first_else_assignment(
    branch_text: &str,
    branch_start_byte: usize,
    else_offset_in_branch: usize,
    file: FileId,
) -> Option<FlowEvent> {
    // Step past the `else` keyword.
    let after_else_offset = else_offset_in_branch.checked_add("else".len())?;
    let text_after_else = branch_text.get(after_else_offset..)?;
    let mut byte_offset_in_branch = after_else_offset;
    // Skip whitespace, then skip an optional opening brace.
    let stripped_leading_ws = text_after_else.trim_start();
    byte_offset_in_branch += text_after_else.len().saturating_sub(stripped_leading_ws.len());
    let body_text = if let Some(after_brace) = stripped_leading_ws.strip_prefix('{') {
        byte_offset_in_branch += 1;
        after_brace
    } else {
        stripped_leading_ws
    };
    // Find the first top-level `=` (not `==`, not part of `+=`, etc.).
    let (assign_op_offset, assign_op_len) = find_simple_assignment_operator(body_text)?;
    let lhs_text = body_text.get(..assign_op_offset)?;
    let rhs_start_offset = assign_op_offset + assign_op_len;
    let rhs_tail_text = body_text.get(rhs_start_offset..)?;
    // RHS terminates at the first statement boundary.
    let rhs_len = rhs_tail_text
        .find([';', '}', '\n', '\r'])
        .unwrap_or(rhs_tail_text.len());
    let rhs_text = rhs_tail_text.get(..rhs_len)?.trim();
    // LHS may have leading noise (open brace, semicolon) — take the last
    // identifier-like token after the rightmost separator.
    let target_text = lhs_text.rsplit(['{', ';', '\n', '\r']).next()?.trim();
    if target_text.is_empty() || rhs_text.is_empty() || !looks_like_assignment_target(target_text) {
        return None;
    }
    // RHS qualifies as a `source_name` only if it parses as a single
    // identifier path — never a compound expression.
    let rhs_as_source_name = looks_like_assignment_target(rhs_text).then(|| rhs_text.to_string());
    let mut rhs_identifiers = identifier_tokens(rhs_text);
    if let Some(simple_rhs) = rhs_as_source_name.as_ref() {
        rhs_identifiers.push(simple_rhs.clone());
    }
    rhs_identifiers.sort();
    rhs_identifiers.dedup();
    let assign_start_byte = branch_start_byte
        + byte_offset_in_branch
        + lhs_text.len().saturating_sub(lhs_text.trim_start().len());
    let assign_end_byte = branch_start_byte + byte_offset_in_branch + rhs_start_offset + rhs_len;
    Some(FlowEvent::Assign {
        span: Span::new(
            file,
            u64::try_from(assign_start_byte).unwrap_or(u64::MAX),
            u64::try_from(assign_end_byte).unwrap_or(u64::MAX),
        ),
        target: target_text.to_string(),
        source_name: rhs_as_source_name,
        source_call: None,
        source_call_args: Vec::new(),
        source_names: rhs_identifiers,
    })
}

/// Find the first top-level `=` that represents a simple assignment.
/// Returns `(byte_offset, operator_length)` so callers can step past it.
///
/// Tracks paren/bracket/brace depth and string-literal state so we don't
/// mistake an `==` inside a guard, an `=` inside a default argument, or a
/// `=` inside a string for the assignment we're after.
fn find_simple_assignment_operator(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut byte_idx = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    // Track whether we're inside a string literal and which quote opened it.
    let mut active_quote: Option<u8> = None;
    let mut escape_next = false;
    while byte_idx < bytes.len() {
        let byte = bytes[byte_idx];
        if let Some(quote_byte) = active_quote {
            // Walk through the string literal — only the matching close
            // quote (when not escaped) ends it.
            if escape_next {
                escape_next = false;
            } else if byte == b'\\' {
                escape_next = true;
            } else if byte == quote_byte {
                active_quote = None;
            }
            byte_idx += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => active_quote = Some(byte),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => {
                // Closing the outer brace ends the candidate region — bail
                // before we accidentally consume something past the body.
                if brace_depth == 0 {
                    return None;
                }
                brace_depth -= 1;
            }
            b'=' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                // Only accept a plain `=`. Reject when the neighbour bytes
                // make this part of `==`, `!=`, `<=`, `>=`, `=>`, or any
                // compound `+=`/`-=`/`*=`/`/=`/`%=`/`&=`/`|=`/`^=`.
                let prev_byte = byte_idx.checked_sub(1).and_then(|i| bytes.get(i)).copied();
                let next_byte = bytes.get(byte_idx + 1).copied();
                if matches!(
                    prev_byte,
                    Some(b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^')
                ) || matches!(next_byte, Some(b'=' | b'>'))
                {
                    byte_idx += 1;
                    continue;
                }
                return Some((byte_idx, 1));
            }
            _ => {}
        }
        byte_idx += 1;
    }
    None
}

/// True when `text` looks like a single identifier path (`foo`, `foo.bar`,
/// `$ctx.user`). Conservative — anything with whitespace, parens, or other
/// punctuation is rejected.
fn looks_like_assignment_target(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut chars = trimmed.chars();
    // First char must start an identifier (or `$` for shell-shaped names).
    matches!(chars.next(), Some(c) if c == '_' || c == '$' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c == '$' || c == '.' || c.is_ascii_alphanumeric())
}

/// Extract every standalone identifier token from `text`. Used to populate
/// `Assign::source_names` for compound RHS expressions where we can't pin
/// down a single bare-identifier source.
fn identifier_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let bytes = text.as_bytes();
    let mut byte_idx = 0usize;
    while byte_idx < bytes.len() {
        // Skip until we hit an identifier-start byte.
        if !(bytes[byte_idx] == b'_' || bytes[byte_idx].is_ascii_alphabetic()) {
            byte_idx += 1;
            continue;
        }
        let token_start = byte_idx;
        byte_idx += 1;
        while byte_idx < bytes.len() && (bytes[byte_idx] == b'_' || bytes[byte_idx].is_ascii_alphanumeric()) {
            byte_idx += 1;
        }
        if let Ok(token) = std::str::from_utf8(&bytes[token_start..byte_idx]) {
            tokens.push(token.to_string());
        }
    }
    tokens
}

/// Span lookup for any `FlowEvent` variant. Centralizes the match so the
/// caller doesn't repeat it whenever we need to compare or partition events
/// by source position.
fn event_span(event: &FlowEvent) -> Option<Span> {
    match event {
        FlowEvent::Call { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Assign { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Lifecycle { span, .. } => Some(*span),
    }
}

/// Find the first occurrence of `keyword` that isn't part of a longer
/// identifier. Returns the byte offset of the keyword's first byte, or
/// `None` if no whole-word match exists.
fn find_keyword_outside_identifier(text: &str, keyword: &str) -> Option<usize> {
    let haystack = text.as_bytes();
    let needle = keyword.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut byte_idx = 0usize;
    while byte_idx + needle.len() <= haystack.len() {
        if &haystack[byte_idx..byte_idx + needle.len()] == needle {
            // Whole-word: neither neighbour byte is an identifier-continue.
            let prev_byte_ok = byte_idx == 0 || !is_ident_continue_byte(haystack[byte_idx - 1]);
            let after_idx = byte_idx + needle.len();
            let next_byte_ok = after_idx == haystack.len() || !is_ident_continue_byte(haystack[after_idx]);
            if prev_byte_ok && next_byte_ok {
                return Some(byte_idx);
            }
        }
        byte_idx += 1;
    }
    None
}
