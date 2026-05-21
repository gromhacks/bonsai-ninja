//! On-disk encoding for [`bonsai_taint::ValueFlowGraph`] entries.
//!
//! The in-memory shape duplicates `value_text: String` across the
//! `nodes` set, the `forward` map (key + edge.from + edge.to), and
//! the `backward` map. A graph with N nodes and E edges holds
//! roughly `N + 5E` String allocations.
//!
//! On disk we deduplicate aggressively:
//!
//! - Every distinct [`ValueFlowNode`] is assigned a `NodeIdx` and
//!   listed once in `OnDiskEntry::nodes`.
//! - Every distinct [`ValueFlowEdge`] is assigned an `EdgeIdx` and
//!   listed once in `OnDiskEntry::edges`.
//! - `forward` and `backward` are `Vec<(NodeIdx, Vec<EdgeIdx>)>` —
//!   the same edge is referenced from both sides without copying its
//!   payload.
//! - Every `value_text` becomes a 4-byte [`StrId`] into the
//!   workspace-wide string pool maintained by the writer.
//!
//! On read, [`decode`] rebuilds the in-memory `ValueFlowGraph`
//! structure (still with allocated `String`s — the goal here is bounded
//! peak RAM, not eliminating allocations entirely; the in-memory
//! `ValueFlowGraph` shape is a public type many consumers depend on).

use ahash::{AHashMap, AHashSet};
use bonsai_common::{FileId, FuncId, Precision, Span};
use bonsai_factstore::{StrId, StringPoolView};
use bonsai_taint::{ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One per-function record persisted to a fact store: the value-flow
/// graph plus the set of seed names whose forward closure reaches a
/// `Return` node in the same function.
///
/// These are paired because every consumer that asks for one
/// typically asks for both, and computing them together saves a
/// second pass over the graph.
#[derive(Clone, Debug, Default)]
pub struct ValueFlowEntry {
    /// The seed-free per-entry value-flow graph.
    pub graph: ValueFlowGraph,
    /// Names of `Param` / `AssignTarget` origins whose forward
    /// closure reaches a `Return` node in this function.
    pub returning_seeds: AHashSet<String>,
}

/// Errors surfaced when reading a corrupt or out-of-range entry.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// The bytes failed bincode parsing — the file was truncated,
    /// hand-edited, or written by a future format version.
    #[error("bincode: {0}")]
    Bincode(#[from] bincode::Error),

    /// A string id referenced by the entry is outside the pool's
    /// id range.
    #[error("string id {id} not in pool (count={count})")]
    UnknownStringId {
        /// The id the entry referenced.
        id: u32,
        /// Total strings in the pool.
        count: u32,
    },

    /// A node index referenced by an edge or adjacency map points
    /// past the entry's node table.
    #[error("node index {idx} out of bounds (nodes={count})")]
    UnknownNodeIdx {
        /// The index the structure referenced.
        idx: u32,
        /// Number of nodes in the entry.
        count: usize,
    },

    /// An edge index referenced by an adjacency map points past the
    /// entry's edge table.
    #[error("edge index {idx} out of bounds (edges={count})")]
    UnknownEdgeIdx {
        /// The index the structure referenced.
        idx: u32,
        /// Number of edges in the entry.
        count: usize,
    },
}

/// Encode an entry into bincode bytes, interning every `value_text`
/// into the caller's string pool via the closure `intern`.
///
/// The closure shape lets the caller hold the writer's mutex once
/// per entry rather than once per string — `intern` is invoked
/// inline during encoding.
pub fn encode<F>(entry: &ValueFlowEntry, intern: &mut F) -> Vec<u8>
where
    F: FnMut(&str) -> StrId,
{
    let on_disk = build_on_disk(entry, intern);
    bincode::serialize(&on_disk).expect("bincode encoding of ValueFlowEntry never fails")
}

/// Decode bytes produced by [`encode`] back into a [`ValueFlowEntry`].
/// `pool` must be the string pool from the same fact-store file the
/// bytes were read from — string ids are scoped to that file.
pub fn decode(bytes: &[u8], pool: &StringPoolView<'_>) -> Result<ValueFlowEntry, DecodeError> {
    let on_disk: OnDiskEntry = bincode::deserialize(bytes)?;
    on_disk.into_in_memory(pool)
}

/// On-disk shape persisted via bincode. Every reference to a `String`
/// has been replaced by a [`StrId`] into the workspace-wide pool;
/// edges are stored once and referenced by index from both adjacency
/// maps.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct OnDiskEntry {
    nodes: Vec<OnDiskNode>,
    edges: Vec<OnDiskEdge>,
    /// `(node_idx, edge_idx_list)` pairs. Sorted by `node_idx`
    /// ascending so encoding is deterministic across runs.
    forward: Vec<(u32, Vec<u32>)>,
    backward: Vec<(u32, Vec<u32>)>,
    precision: Precision,
    saturated: bool,
    /// Sorted ascending so encoding is deterministic.
    returning_seeds: Vec<u32>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OnDiskNode {
    func: u32,
    span_file: u32,
    span_start: u64,
    span_end: u64,
    value_text_id: u32,
    kind: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OnDiskEdge {
    from_idx: u32,
    to_idx: u32,
    via_span_file: u32,
    via_span_start: u64,
    via_span_end: u64,
    precision: Precision,
}

fn build_on_disk<F>(entry: &ValueFlowEntry, intern: &mut F) -> OnDiskEntry
where
    F: FnMut(&str) -> StrId,
{
    // Step 1: assign a stable NodeIdx to every node in the graph.
    // We collect from `nodes`, `forward.keys`, `backward.keys`, and
    // every edge endpoint so a malformed in-memory graph (key not
    // present in `nodes`) still encodes losslessly.
    let mut node_to_idx: AHashMap<ValueFlowNode, u32> = AHashMap::new();
    let mut nodes_in_order: Vec<ValueFlowNode> = Vec::new();
    record_node(&entry.graph.nodes, &mut node_to_idx, &mut nodes_in_order);
    record_nodes_iter(entry.graph.forward.keys(), &mut node_to_idx, &mut nodes_in_order);
    record_nodes_iter(entry.graph.backward.keys(), &mut node_to_idx, &mut nodes_in_order);
    for edge in entry.graph.forward.values().flat_map(|set| set.iter()) {
        record_one_node(&edge.from, &mut node_to_idx, &mut nodes_in_order);
        record_one_node(&edge.to, &mut node_to_idx, &mut nodes_in_order);
    }
    for edge in entry.graph.backward.values().flat_map(|set| set.iter()) {
        record_one_node(&edge.from, &mut node_to_idx, &mut nodes_in_order);
        record_one_node(&edge.to, &mut node_to_idx, &mut nodes_in_order);
    }

    let nodes: Vec<OnDiskNode> = nodes_in_order
        .iter()
        .map(|n| OnDiskNode {
            func: n.func.raw(),
            span_file: n.span.file.raw(),
            span_start: n.span.start,
            span_end: n.span.end,
            value_text_id: intern(&n.value_text),
            kind: encode_node_kind(n.kind),
        })
        .collect();

    // Step 2: dedup edges. Two edges are "equal" when their
    // `from`, `to`, `precision`, and `via_span` match — same as
    // `ValueFlowEdge`'s `Eq`.
    let mut edge_to_idx: AHashMap<ValueFlowEdge, u32> = AHashMap::new();
    let mut edges_in_order: Vec<ValueFlowEdge> = Vec::new();
    for edge in entry.graph.forward.values().flat_map(|set| set.iter()) {
        record_one_edge(edge, &mut edge_to_idx, &mut edges_in_order);
    }
    for edge in entry.graph.backward.values().flat_map(|set| set.iter()) {
        record_one_edge(edge, &mut edge_to_idx, &mut edges_in_order);
    }

    let edges: Vec<OnDiskEdge> = edges_in_order
        .iter()
        .map(|e| OnDiskEdge {
            from_idx: *node_to_idx.get(&e.from).expect("recorded above"),
            to_idx: *node_to_idx.get(&e.to).expect("recorded above"),
            via_span_file: e.via_span.file.raw(),
            via_span_start: e.via_span.start,
            via_span_end: e.via_span.end,
            precision: e.precision,
        })
        .collect();

    // Step 3: build adjacency maps as `(NodeIdx, Vec<EdgeIdx>)`.
    let forward = build_adjacency(&entry.graph.forward, &node_to_idx, &edge_to_idx);
    let backward = build_adjacency(&entry.graph.backward, &node_to_idx, &edge_to_idx);

    // Step 4: returning seeds, interned and sorted.
    let mut returning_seeds: Vec<u32> = entry.returning_seeds.iter().map(|s| intern(s)).collect();
    returning_seeds.sort_unstable();
    returning_seeds.dedup();

    OnDiskEntry {
        nodes,
        edges,
        forward,
        backward,
        precision: entry.graph.precision,
        saturated: entry.graph.saturated,
        returning_seeds,
    }
}

fn record_one_node(n: &ValueFlowNode, map: &mut AHashMap<ValueFlowNode, u32>, out: &mut Vec<ValueFlowNode>) {
    if !map.contains_key(n) {
        let idx = u32::try_from(map.len()).expect("> 2^32 unique nodes per graph");
        map.insert(n.clone(), idx);
        out.push(n.clone());
    }
}

fn record_node(
    set: &AHashSet<ValueFlowNode>,
    map: &mut AHashMap<ValueFlowNode, u32>,
    out: &mut Vec<ValueFlowNode>,
) {
    for n in set {
        record_one_node(n, map, out);
    }
}

fn record_nodes_iter<'a, I>(iter: I, map: &mut AHashMap<ValueFlowNode, u32>, out: &mut Vec<ValueFlowNode>)
where
    I: IntoIterator<Item = &'a ValueFlowNode>,
{
    for n in iter {
        record_one_node(n, map, out);
    }
}

fn record_one_edge(e: &ValueFlowEdge, map: &mut AHashMap<ValueFlowEdge, u32>, out: &mut Vec<ValueFlowEdge>) {
    if !map.contains_key(e) {
        let idx = u32::try_from(map.len()).expect("> 2^32 unique edges per graph");
        map.insert(e.clone(), idx);
        out.push(e.clone());
    }
}

fn build_adjacency(
    in_memory: &AHashMap<ValueFlowNode, AHashSet<ValueFlowEdge>>,
    node_to_idx: &AHashMap<ValueFlowNode, u32>,
    edge_to_idx: &AHashMap<ValueFlowEdge, u32>,
) -> Vec<(u32, Vec<u32>)> {
    let mut out: Vec<(u32, Vec<u32>)> = Vec::with_capacity(in_memory.len());
    for (node, edges) in in_memory {
        let node_idx = *node_to_idx.get(node).expect("recorded above");
        let mut edge_idxs: Vec<u32> = edges
            .iter()
            .map(|e| *edge_to_idx.get(e).expect("recorded above"))
            .collect();
        edge_idxs.sort_unstable();
        out.push((node_idx, edge_idxs));
    }
    out.sort_by_key(|(idx, _)| *idx);
    out
}

impl OnDiskEntry {
    fn into_in_memory(self, pool: &StringPoolView<'_>) -> Result<ValueFlowEntry, DecodeError> {
        let nodes_count = self.nodes.len();
        let edges_count = self.edges.len();

        // Resolve the node table once so adjacency lookups can use
        // owned clones cheaply.
        let mut nodes: Vec<ValueFlowNode> = Vec::with_capacity(nodes_count);
        for (i, node) in self.nodes.iter().enumerate() {
            let value_text = pool
                .get(node.value_text_id)
                .ok_or(DecodeError::UnknownStringId {
                    id: node.value_text_id,
                    count: pool.len(),
                })?
                .to_string();
            nodes.push(ValueFlowNode {
                func: FuncId::new(node.func),
                span: Span::new(FileId::new(node.span_file), node.span_start, node.span_end),
                value_text,
                kind: decode_node_kind(node.kind).ok_or_else(|| {
                    DecodeError::Bincode(
                        bincode::ErrorKind::Custom(format!(
                            "unknown ValueFlowNodeKind discriminant {} at node {i}",
                            node.kind
                        ))
                        .into(),
                    )
                })?,
            });
        }

        // Resolve edges, mapping endpoint indices through the node
        // table.
        let mut edges: Vec<ValueFlowEdge> = Vec::with_capacity(edges_count);
        for edge in &self.edges {
            let from = nodes
                .get(edge.from_idx as usize)
                .ok_or(DecodeError::UnknownNodeIdx {
                    idx: edge.from_idx,
                    count: nodes_count,
                })?
                .clone();
            let to = nodes
                .get(edge.to_idx as usize)
                .ok_or(DecodeError::UnknownNodeIdx {
                    idx: edge.to_idx,
                    count: nodes_count,
                })?
                .clone();
            edges.push(ValueFlowEdge {
                from,
                to,
                precision: edge.precision,
                via_span: Span::new(
                    FileId::new(edge.via_span_file),
                    edge.via_span_start,
                    edge.via_span_end,
                ),
            });
        }

        // Rebuild the in-memory `nodes` set as a freshly-allocated
        // AHashSet so we don't rely on insertion order from the disk
        // record.
        let mut graph = ValueFlowGraph::new();
        graph.precision = self.precision;
        graph.saturated = self.saturated;
        for node in &nodes {
            graph.nodes.insert(node.clone());
        }

        for (node_idx, edge_idxs) in &self.forward {
            let node = nodes
                .get(*node_idx as usize)
                .ok_or(DecodeError::UnknownNodeIdx {
                    idx: *node_idx,
                    count: nodes_count,
                })?
                .clone();
            let entry_set = graph.forward.entry(node).or_default();
            for edge_idx in edge_idxs {
                let edge = edges
                    .get(*edge_idx as usize)
                    .ok_or(DecodeError::UnknownEdgeIdx {
                        idx: *edge_idx,
                        count: edges_count,
                    })?
                    .clone();
                entry_set.insert(edge);
            }
        }
        for (node_idx, edge_idxs) in &self.backward {
            let node = nodes
                .get(*node_idx as usize)
                .ok_or(DecodeError::UnknownNodeIdx {
                    idx: *node_idx,
                    count: nodes_count,
                })?
                .clone();
            let entry_set = graph.backward.entry(node).or_default();
            for edge_idx in edge_idxs {
                let edge = edges
                    .get(*edge_idx as usize)
                    .ok_or(DecodeError::UnknownEdgeIdx {
                        idx: *edge_idx,
                        count: edges_count,
                    })?
                    .clone();
                entry_set.insert(edge);
            }
        }

        let mut returning_seeds: AHashSet<String> = AHashSet::with_capacity(self.returning_seeds.len());
        for id in &self.returning_seeds {
            let s = pool.get(*id).ok_or(DecodeError::UnknownStringId {
                id: *id,
                count: pool.len(),
            })?;
            returning_seeds.insert(s.to_string());
        }

        Ok(ValueFlowEntry {
            graph,
            returning_seeds,
        })
    }
}

fn encode_node_kind(kind: ValueFlowNodeKind) -> u8 {
    // Stable wire discriminants — DO NOT renumber on enum reorder.
    // Bumping the fact-store FORMAT_VERSION is the right way to
    // change these.
    match kind {
        ValueFlowNodeKind::Param => 0,
        ValueFlowNodeKind::AssignTarget => 1,
        ValueFlowNodeKind::CallArg => 2,
        ValueFlowNodeKind::Return => 3,
        ValueFlowNodeKind::Catch => 4,
        ValueFlowNodeKind::Read => 5,
    }
}

fn decode_node_kind(disc: u8) -> Option<ValueFlowNodeKind> {
    match disc {
        0 => Some(ValueFlowNodeKind::Param),
        1 => Some(ValueFlowNodeKind::AssignTarget),
        2 => Some(ValueFlowNodeKind::CallArg),
        3 => Some(ValueFlowNodeKind::Return),
        4 => Some(ValueFlowNodeKind::Catch),
        5 => Some(ValueFlowNodeKind::Read),
        _ => None,
    }
}

#[cfg(test)]
#[path = "value_flow_disk_tests.rs"]
mod tests;
