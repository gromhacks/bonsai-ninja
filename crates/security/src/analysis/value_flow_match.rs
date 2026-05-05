// Phase 4 deliverable — wired into the security pipeline in Phase 5
// (consumer cutover). Until then, dead-code warnings are expected;
// the tests below exercise the public surface so the logic is
// validated even before integration.
#![allow(dead_code)]

//! Rule-match → value-flow node selectors.
//!
//! Phase 4 deliverable. Replaces the seed-derivation logic in
//! `source_seed_set` with a node-selector that picks specific
//! `ValueFlowNode`s in a precomputed `ValueFlowGraph` matching the
//! source rule, then forwards-closes from those nodes to find sink
//! reachability.
//!
//! Today's `source_seed_set` (in `analysis/mod.rs`) walks the
//! decl's flow events to build a `TokenSet` seed for the engine.
//! With value-flow, the engine has already run; the security pass
//! filters the resulting graph instead. The Task #279 carve-out
//! (don't taint `os` for `os.getenv` source) lives here as a
//! node-filter, not as a seed restriction.

use crate::matcher::RuleMatch;
use crate::rule::MatchKind;
use bonsai_taint::{ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind};

/// Select every `ValueFlowNode` in the graph that corresponds to
/// the source rule's matched value.
///
/// Inclusion rules:
///
/// 1. The node lives in the same function as the rule match's
///    enclosing function (already implied since the graph is per-
///    entry-function).
/// 2. The node's `value_text` matches the rule's `match_text` either
///    by exact match or via the qualified-tail rule (`os.getenv`
///    matches `getenv`, the unqualified tail).
/// 3. The node is a `Param`, `AssignTarget`, `CallArg`, or `Return`
///    kind — not a `Read`-only node, since reads are downstream of
///    the actual value definition.
///
/// Carve-outs (Task #279 and friends):
///
/// - When the rule's `match_text` is qualified (`os.getenv`), we
///   only select nodes whose `value_text` matches the *tail*
///   (`getenv`), never the *receiver* (`os`). Tainting the receiver
///   would cross-contaminate every other `os.<x>` call in the
///   function.
pub(crate) fn rule_match_to_nodes(rule_match: &RuleMatch, graph: &ValueFlowGraph) -> Vec<ValueFlowNode> {
    let match_text = rule_match.match_text.as_str();
    if match_text.is_empty() {
        return Vec::new();
    }
    let tail = qualified_tail(match_text);

    graph
        .nodes
        .iter()
        .filter(|n| {
            matches!(
                n.kind,
                ValueFlowNodeKind::Param
                    | ValueFlowNodeKind::AssignTarget
                    | ValueFlowNodeKind::CallArg
                    | ValueFlowNodeKind::Return
            )
        })
        .filter(|n| node_value_matches(&n.value_text, match_text, tail))
        .cloned()
        .collect()
}

/// Tail-aware match: a rule whose `match_text` is qualified accepts
/// nodes whose value matches the unqualified tail OR the full text.
/// A bare-tail rule only matches the unqualified form.
fn node_value_matches(node_text: &str, full_match: &str, tail: &str) -> bool {
    if node_text == full_match {
        return true;
    }
    if !tail.is_empty() && node_text == tail {
        return true;
    }
    // The Task #279 anti-rule: if `full_match` is qualified
    // (`os.getenv`) and `node_text` is the *receiver* of that
    // qualifier (`os`), reject — even though `os` is a substring of
    // `os.getenv`.
    if !tail.is_empty() && full_match != tail {
        if let Some(receiver) = receiver_of_qualified(full_match, tail) {
            if node_text == receiver {
                return false;
            }
        }
    }
    false
}

/// Last segment of a qualified name, splitting on `.` / `:` / `/`.
/// `os.getenv` → `getenv`. Bare names are returned unchanged.
fn qualified_tail(match_text: &str) -> &str {
    match_text
        .rsplit_once(['.', ':', '/'])
        .map(|(_, tail)| tail)
        .unwrap_or(match_text)
}

/// The receiver part of a qualified name (everything before the
/// trailing `.` / `:` / `/` separator). Returns `None` when the name
/// is bare or when the math would underflow.
fn receiver_of_qualified<'a>(match_text: &'a str, tail: &str) -> Option<&'a str> {
    let tail_len = tail.len();
    if tail_len == 0 || tail_len + 1 > match_text.len() {
        return None;
    }
    let cut = match_text.len() - tail_len - 1;
    Some(&match_text[..cut])
}

/// Whether the rule should drive the `MatchKind::Param` shape — used
/// by callers when deciding whether to seed param nodes in addition
/// to the matched value-text. Mirrors the `is_param_rule` check in
/// today's `source_seed_set`.
#[must_use]
pub(crate) fn is_param_rule(rule_match: &RuleMatch, pack: &crate::loader::Rulepack) -> bool {
    pack.find_rule_by_id(&rule_match.rule_id)
        .is_some_and(|rule| rule.match_spec.kind == MatchKind::Param)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::{FileId, FuncId, Precision, Span};

    fn span(start: u64, end: u64) -> Span {
        Span {
            file: FileId::new(0),
            start,
            end,
        }
    }

    fn node(text: &str, kind: ValueFlowNodeKind) -> ValueFlowNode {
        ValueFlowNode {
            func: FuncId::new(1),
            span: span(0, 4),
            value_text: text.to_string(),
            kind,
        }
    }

    fn rule_match(text: &str) -> RuleMatch {
        RuleMatch {
            rule_id: "r".to_string(),
            language: "python".to_string(),
            file: "a.py".to_string(),
            line: 1,
            column: 1,
            span: span(0, 1),
            match_text: text.to_string(),
            enclosing_fn: None,
        }
    }

    #[test]
    fn selects_exact_match_param() {
        let mut graph = ValueFlowGraph::new();
        let n = node("args", ValueFlowNodeKind::Param);
        graph.nodes.insert(n.clone());
        let _ = Precision::Exact; // suppress unused
        let m = rule_match("args");
        let selected = rule_match_to_nodes(&m, &graph);
        assert_eq!(selected, vec![n]);
    }

    #[test]
    fn selects_qualified_tail_match() {
        let mut graph = ValueFlowGraph::new();
        let n = node("getenv", ValueFlowNodeKind::AssignTarget);
        graph.nodes.insert(n.clone());
        let m = rule_match("os.getenv");
        let selected = rule_match_to_nodes(&m, &graph);
        assert_eq!(selected, vec![n]);
    }

    #[test]
    fn rejects_receiver_of_qualified() {
        let mut graph = ValueFlowGraph::new();
        let receiver = node("os", ValueFlowNodeKind::AssignTarget);
        graph.nodes.insert(receiver.clone());
        let m = rule_match("os.getenv");
        let selected = rule_match_to_nodes(&m, &graph);
        assert!(
            selected.is_empty(),
            "Task #279: receiver of a qualified source rule must not be selected; got {selected:?}"
        );
    }

    #[test]
    fn rejects_read_only_nodes() {
        let mut graph = ValueFlowGraph::new();
        let read_only = node("args", ValueFlowNodeKind::Read);
        graph.nodes.insert(read_only);
        let m = rule_match("args");
        let selected = rule_match_to_nodes(&m, &graph);
        assert!(selected.is_empty(), "Read-only nodes are not value origins");
    }

    #[test]
    fn empty_match_text_returns_empty() {
        let mut graph = ValueFlowGraph::new();
        graph.nodes.insert(node("x", ValueFlowNodeKind::Param));
        let m = rule_match("");
        assert!(rule_match_to_nodes(&m, &graph).is_empty());
    }
}
