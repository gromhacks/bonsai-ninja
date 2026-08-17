//! Small callgraph path types plus test-only concrete path enumeration.
//!
//! Production navigation preserves transitive relationships as a compressed
//! graph. The concrete path walker remains test-only for proving graph
//! corridor behavior; no production inspect, browse, SDK, or export surface
//! calls it.

#[cfg(test)]
use crate::CallEdge;
#[cfg(test)]
use crate::ResolvedCallGraph;
#[cfg(test)]
use bonsai_common::{FuncId, Precision};
#[cfg(test)]
use std::cmp::Ordering;

/// One bounded source-to-target path over the resolved call graph.
///
/// `funcs` contains the function nodes in caller-to-callee order.
/// `edges` contains the exact semantic call edges between adjacent
/// functions, also in caller-to-callee order.
#[derive(Clone, Debug)]
#[cfg(test)]
pub struct ResolvedPath {
    pub funcs: Vec<FuncId>,
    pub edges: Vec<CallEdge>,
    pub precision: Precision,
}

/// Why a bounded diagnostic path query may have returned fewer paths than
/// the semantic graph contains.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PathTruncation {
    /// The bounded walk completed without dropping any candidate path.
    None,
    /// At least one candidate hit the configured edge-depth cap.
    MaxDepth,
    /// The command emitted `max_paths` paths and stopped.
    MaxPaths,
    /// The graph walk hit its probe budget before exhausting candidates.
    ProbeBudget,
}

impl PathTruncation {
    #[must_use]
    pub fn is_truncated(self) -> bool {
        !matches!(self, PathTruncation::None)
    }

    #[must_use]
    pub fn label(self) -> Option<&'static str> {
        match self {
            PathTruncation::None => None,
            PathTruncation::MaxDepth => Some("max-depth cap"),
            PathTruncation::MaxPaths => Some("max-paths cap"),
            PathTruncation::ProbeBudget => Some("path-probe budget"),
        }
    }
}

/// Enumerate ranked source-to-target paths over the resolved semantic
/// call graph.
///
/// This walks only `Exact` / `Narrowed` edges. It never widens an
/// unresolved call into a guessed edge, and every result carries the
/// weakest precision observed on the path. Results are ranked before
/// returning by hop count, precision, and stable FuncId order.
#[must_use]
#[cfg(test)]
pub fn enumerate_paths_resolved(
    cg: &ResolvedCallGraph,
    from: FuncId,
    to: FuncId,
    max_paths: usize,
    max_depth: usize,
    max_probes: usize,
) -> (Vec<ResolvedPath>, PathTruncation) {
    if max_paths == 0 {
        return (Vec::new(), PathTruncation::MaxPaths);
    }
    // Compile the exact reverse corridor once before enumerating concrete
    // paths. A forward simple-path walk without this relation explores every
    // unrelated branch reachable from `from` merely to discover that it can
    // never reach `to`; on large callgraphs that is exponential work. The
    // reverse fixed point is O(V+E), syntax-graph exact, and does not impose a
    // repository-shaped search cap.
    let mut can_reach_target = ahash::AHashSet::new();
    let mut reverse_work = vec![to];
    can_reach_target.insert(to);
    while let Some(callee) = reverse_work.pop() {
        let mut callers: Vec<FuncId> = cg
            .callers_of(callee)
            .filter(|edge| edge.precision.is_semantic())
            .map(|edge| edge.from)
            .collect();
        callers.sort_unstable_by_key(|func| func.raw());
        callers.dedup();
        for caller in callers {
            if can_reach_target.insert(caller) {
                reverse_work.push(caller);
            }
        }
    }
    if !can_reach_target.contains(&from) {
        return (Vec::new(), PathTruncation::None);
    }
    let mut queue = std::collections::BinaryHeap::new();
    let mut initial_seen = ahash::AHashSet::new();
    initial_seen.insert(from);
    queue.push(PathState {
        funcs: vec![from],
        edges: Vec::new(),
        seen: initial_seen,
        precision: Precision::Exact,
        order: 0,
    });
    let mut next_order = 1usize;
    let mut probes = 0usize;
    let mut truncation = PathTruncation::None;
    let mut results = Vec::new();
    let mut emitted: ahash::AHashSet<Vec<(FuncId, u64, u64, u32)>> = ahash::AHashSet::default();

    while let Some(state) = queue.pop() {
        probes = probes.saturating_add(1);
        if max_probes != 0 && probes > max_probes {
            truncation = PathTruncation::ProbeBudget;
            break;
        }
        let current = *state.funcs.last().expect("path state has at least one func");
        if current == to {
            let key = path_identity(&state.funcs, &state.edges);
            if emitted.insert(key) {
                if results.len() >= max_paths {
                    truncation = PathTruncation::MaxPaths;
                    break;
                }
                results.push(ResolvedPath {
                    funcs: state.funcs,
                    edges: state.edges,
                    precision: state.precision,
                });
            }
            continue;
        }
        if max_depth != 0 && state.edges.len() >= max_depth {
            if truncation == PathTruncation::None {
                truncation = PathTruncation::MaxDepth;
            }
            continue;
        }

        let mut edges: Vec<&CallEdge> = cg
            .callees_of(current)
            .filter(|edge| edge.precision.is_semantic() && can_reach_target.contains(&edge.to))
            .collect();
        edges.sort_by_key(|edge| {
            (
                edge.to.raw(),
                edge.span.file.raw(),
                edge.span.start,
                edge.span.end,
                edge_kind_rank(edge.kind),
                precision_rank(edge.precision),
            )
        });
        for edge in edges {
            if state.seen.contains(&edge.to) {
                continue;
            }
            let mut next_funcs = state.funcs.clone();
            next_funcs.push(edge.to);
            let mut next_edges = state.edges.clone();
            next_edges.push(edge.clone());
            let mut next_seen = state.seen.clone();
            next_seen.insert(edge.to);
            let next_precision = state.precision.meet(edge.precision);
            queue.push(PathState {
                funcs: next_funcs,
                edges: next_edges,
                seen: next_seen,
                precision: next_precision,
                order: next_order,
            });
            next_order = next_order.saturating_add(1);
        }
    }

    results.sort_by(|a, b| {
        a.edges
            .len()
            .cmp(&b.edges.len())
            .then_with(|| precision_rank(a.precision).cmp(&precision_rank(b.precision)))
            .then_with(|| a.funcs.cmp(&b.funcs))
    });
    (results, truncation)
}

#[derive(Clone)]
#[cfg(test)]
struct PathState {
    funcs: Vec<FuncId>,
    edges: Vec<CallEdge>,
    seen: ahash::AHashSet<FuncId>,
    precision: Precision,
    order: usize,
}

#[cfg(test)]
impl PathState {
    fn hops(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
impl PartialEq for PathState {
    fn eq(&self, other: &Self) -> bool {
        self.hops() == other.hops()
            && precision_rank(self.precision) == precision_rank(other.precision)
            && self.order == other.order
    }
}

#[cfg(test)]
impl Eq for PathState {}

#[cfg(test)]
impl PartialOrd for PathState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
impl Ord for PathState {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .hops()
            .cmp(&self.hops())
            .then_with(|| precision_rank(other.precision).cmp(&precision_rank(self.precision)))
            .then_with(|| other.order.cmp(&self.order))
    }
}

#[cfg(test)]
fn path_identity(funcs: &[FuncId], edges: &[CallEdge]) -> Vec<(FuncId, u64, u64, u32)> {
    funcs
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, func)| {
            let edge = edges.get(idx);
            (
                func,
                edge.map_or(0, |edge| edge.span.start),
                edge.map_or(0, |edge| edge.span.end),
                edge.map_or(u32::MAX, |edge| edge.span.file.raw()),
            )
        })
        .collect()
}

#[cfg(test)]
fn edge_kind_rank(kind: crate::EdgeKind) -> u8 {
    match kind {
        crate::EdgeKind::Direct => 0,
        crate::EdgeKind::Virtual => 1,
        crate::EdgeKind::Indirect => 2,
        crate::EdgeKind::Unknown => 3,
    }
}

#[cfg(test)]
fn precision_rank(precision: Precision) -> u8 {
    match precision {
        Precision::Exact => 0,
        Precision::Narrowed => 1,
        Precision::OverApproximate => 2,
        Precision::Unknown => 3,
    }
}
