//! Adapter-dispatched lowering for call semantics encoded by non-call CST
//! nodes.
//!
//! The shared compiler owns only this dispatch point. Concrete node kinds,
//! emitted callable identities, argument fields, and receiver syntax stay in
//! the active language adapter.

use bonsai_common::FileId;
use tree_sitter::Node;

use super::{FlowEvent, GrammarHandler};

pub(super) fn pseudo_call_event(
    node: Node<'_>,
    file: FileId,
    src: &[u8],
    handler: &GrammarHandler,
) -> Option<FlowEvent> {
    handler
        .pseudo_call_extractor
        .and_then(|extract| extract(node, file, src, handler))
}
