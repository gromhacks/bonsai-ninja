use super::*;
use bonsai_common::{FileId, FuncId, Span};

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
