//! Function-local compiler summaries over the workspace IDG.
//!
//! Export consumers need two projections that should not require one
//! workspace-sized closure per function or parameter:
//!
//! - formal parameters that can reach a function's return value; and
//! - local storage reached from each formal parameter.
//!
//! This module compacts every function to its own node address space and CSR.
//! Return summaries compose resolved call inputs and outputs with a monotone
//! worklist.  Recursive and mutually recursive call components therefore run
//! to their least fixed point without an iteration or graph-size cap.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{FuncId, Precision, Span};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::edge::{IdgEdge, IdgEdgeKind};
use crate::node::{NodeId, PlaceId};
use crate::place::Place;
use crate::query::ReachabilityIndex;
use crate::segment::IdgSegment;
use crate::symbolic::{structured_storage_parts, SymbolicFieldTransformKind};
use crate::workspace::{IdgWorkspace, SegmentId};

/// One transient graph used by the source-local storage projection. It is
/// created for a single segment and released before the next segment.
struct LocalFunctionGraph {
    segment: SegmentId,
    local_nodes: Vec<NodeId>,
    params: Vec<(u32, u32)>,
    edges: Vec<(u32, u32)>,
}

impl LocalFunctionGraph {
    fn new(segment: SegmentId) -> Self {
        Self {
            segment,
            local_nodes: Vec::new(),
            params: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn add_node(&mut self, local_node: NodeId, place: Option<&Place>) -> u32 {
        let compact =
            u32::try_from(self.local_nodes.len()).expect("function-local IDG node count exceeds u32");
        self.local_nodes.push(local_node);
        if let Some(Place::Param { idx }) = place {
            self.params.push((*idx, compact));
        }
        compact
    }

    fn add_base_edge(&mut self, from: u32, to: u32) {
        self.edges.push((from, to));
    }

    fn reachability(&mut self) -> ReachabilityIndex {
        self.edges.sort_unstable();
        self.edges.dedup();
        ReachabilityIndex::from_pairs(self.local_nodes.len(), &self.edges)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CallBoundaryKey {
    caller: FuncId,
    callee: FuncId,
    span: Span,
}

struct CallBoundary {
    key: CallBoundaryKey,
    input_start: u32,
    input_end: u32,
    output_start: u32,
    output_end: u32,
}

struct CallBoundaries {
    rows: Vec<CallBoundary>,
    /// Flat `(caller source, callee input)` relation.
    inputs: Vec<(u32, u32)>,
    /// Flat `(callee output, caller continuation)` relation.
    outputs: Vec<(u32, u32)>,
    /// Dense `FuncId.raw() -> boundary range` table. Boundaries are sorted by
    /// caller, so recursive recompilation never allocates one vector per
    /// function.
    caller_offsets: Box<[u32]>,
}

impl CallBoundaries {
    fn for_caller(&self, caller: FuncId) -> &[CallBoundary] {
        let index = caller.raw() as usize;
        let Some(&start) = self.caller_offsets.get(index) else {
            return &[];
        };
        let Some(&end) = self.caller_offsets.get(index + 1) else {
            return &[];
        };
        &self.rows[start as usize..end as usize]
    }

    fn inputs(&self, boundary: &CallBoundary) -> &[(u32, u32)] {
        &self.inputs[boundary.input_start as usize..boundary.input_end as usize]
    }

    fn outputs(&self, boundary: &CallBoundary) -> &[(u32, u32)] {
        &self.outputs[boundary.output_start as usize..boundary.output_end as usize]
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BoundaryPairRow {
    key: CallBoundaryKey,
    pair: (u32, u32),
}

const BOUNDARY_PAIR_BYTES: usize = 36;
const BOUNDARY_RUN_ROWS: usize = 100_000;
const BOUNDARY_READ_ROWS: usize = 1_024;

#[derive(Copy, Clone)]
struct BoundaryRunEntry {
    offset: u64,
    count: u32,
}

/// External sorted runs for the call-boundary relation. Repeated
/// `(caller, callee, span)` keys never accumulate in the compiler heap; only
/// one bounded run buffer and the final compact range relation are resident.
struct BoundaryPairSpool {
    file: std::fs::File,
    write_offset: u64,
    runs: Vec<BoundaryRunEntry>,
    buffer: Vec<BoundaryPairRow>,
}

impl BoundaryPairSpool {
    fn new() -> Self {
        Self {
            file: tempfile::tempfile().expect("create call-boundary run spool"),
            write_offset: 0,
            runs: Vec::new(),
            buffer: Vec::with_capacity(BOUNDARY_RUN_ROWS),
        }
    }

    fn push(&mut self, row: BoundaryPairRow) {
        self.buffer.push(row);
        if self.buffer.len() == BOUNDARY_RUN_ROWS {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        self.buffer.sort_unstable();
        self.buffer.dedup();
        self.file
            .seek(SeekFrom::Start(self.write_offset))
            .expect("seek call-boundary run spool");
        let mut payload = Vec::with_capacity(self.buffer.len().saturating_mul(BOUNDARY_PAIR_BYTES));
        for row in &self.buffer {
            payload.extend_from_slice(&row.key.caller.raw().to_le_bytes());
            payload.extend_from_slice(&row.key.callee.raw().to_le_bytes());
            payload.extend_from_slice(&row.key.span.file.raw().to_le_bytes());
            payload.extend_from_slice(&row.key.span.start.to_le_bytes());
            payload.extend_from_slice(&row.key.span.end.to_le_bytes());
            payload.extend_from_slice(&row.pair.0.to_le_bytes());
            payload.extend_from_slice(&row.pair.1.to_le_bytes());
        }
        self.file
            .write_all(&payload)
            .expect("write call-boundary run spool");
        self.runs.push(BoundaryRunEntry {
            offset: self.write_offset,
            count: u32::try_from(self.buffer.len()).expect("boundary run length exceeds u32"),
        });
        self.write_offset = self
            .write_offset
            .saturating_add(u64::try_from(payload.len()).expect("boundary payload length exceeds u64"));
        self.buffer.clear();
    }

    fn finish(mut self) -> BoundaryRunMerger {
        self.flush();
        BoundaryRunMerger::new(&self.file, &self.runs)
    }
}

struct BoundaryRunReader {
    file: std::fs::File,
    offset: u64,
    remaining: u32,
    buffer: Vec<u8>,
    position: usize,
}

impl BoundaryRunReader {
    fn refill(&mut self) {
        let records = usize::try_from(self.remaining)
            .expect("boundary run length fits usize")
            .min(BOUNDARY_READ_ROWS);
        self.buffer.resize(records.saturating_mul(BOUNDARY_PAIR_BYTES), 0);
        self.file
            .seek(SeekFrom::Start(self.offset))
            .expect("seek sorted call-boundary run");
        self.file
            .read_exact(&mut self.buffer)
            .expect("read sorted call-boundary run page");
        self.offset = self
            .offset
            .saturating_add(u64::try_from(self.buffer.len()).expect("boundary page length fits u64"));
        self.position = 0;
    }

    fn next(&mut self) -> Option<BoundaryPairRow> {
        if self.remaining == 0 {
            return None;
        }
        if self.position == self.buffer.len() {
            self.refill();
        }
        let end = self.position.saturating_add(BOUNDARY_PAIR_BYTES);
        let record = &self.buffer[self.position..end];
        self.position = end;
        self.remaining -= 1;
        let word = |start| u32::from_le_bytes(record[start..start + 4].try_into().expect("word bytes"));
        let wide = |start| u64::from_le_bytes(record[start..start + 8].try_into().expect("wide bytes"));
        Some(BoundaryPairRow {
            key: CallBoundaryKey {
                caller: FuncId::new(word(0)),
                callee: FuncId::new(word(4)),
                span: Span::new(bonsai_common::FileId::new(word(8)), wide(12), wide(20)),
            },
            pair: (word(28), word(32)),
        })
    }
}

struct BoundaryRunMerger {
    readers: Vec<BoundaryRunReader>,
    pending: BinaryHeap<Reverse<(BoundaryPairRow, usize)>>,
    previous: Option<BoundaryPairRow>,
}

impl BoundaryRunMerger {
    fn new(file: &std::fs::File, runs: &[BoundaryRunEntry]) -> Self {
        let mut readers = Vec::with_capacity(runs.len());
        for run in runs {
            readers.push(BoundaryRunReader {
                file: file.try_clone().expect("clone call-boundary run spool"),
                offset: run.offset,
                remaining: run.count,
                buffer: Vec::new(),
                position: 0,
            });
        }
        let mut pending = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            if let Some(row) = reader.next() {
                pending.push(Reverse((row, index)));
            }
        }
        Self {
            readers,
            pending,
            previous: None,
        }
    }
}

impl Iterator for BoundaryRunMerger {
    type Item = BoundaryPairRow;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Reverse((row, reader_index)) = self.pending.pop()?;
            if let Some(next) = self.readers[reader_index].next() {
                self.pending.push(Reverse((next, reader_index)));
            }
            if self.previous == Some(row) {
                continue;
            }
            self.previous = Some(row);
            return Some(row);
        }
    }
}

struct FunctionLayout {
    segment: SegmentId,
    /// Segment-local nodes in compact function order. This is the only
    /// workspace-sized address vector retained after boundary discovery.
    local_nodes: Vec<NodeId>,
    /// `(source parameter index, compact node)`.
    params: Vec<(u32, u32)>,
    /// Compact structural Return/Throw ports used by callers.
    outputs: Vec<u32>,
    return_node: Option<u32>,
}

impl FunctionLayout {
    fn new(segment: SegmentId) -> Self {
        Self {
            segment,
            local_nodes: Vec::new(),
            params: Vec::new(),
            outputs: Vec::new(),
            return_node: None,
        }
    }

    fn compact_of(&self, local: NodeId) -> Option<u32> {
        self.local_nodes
            .binary_search_by_key(&local.0, |node| node.0)
            .ok()
            .and_then(|index| u32::try_from(index).ok())
    }
}

struct FunctionCompilation {
    reach: ReachabilityIndex,
    summary: Vec<(u32, u32)>,
    derived_edges: Vec<(u32, u32)>,
}

#[derive(Copy, Clone)]
struct CompactAddress {
    func: FuncId,
    compact: u32,
    boundary: u8,
}

struct CompactAddressPagePair {
    from_segment: SegmentId,
    to_segment: SegmentId,
    from: Arc<[CompactAddress]>,
    to: Arc<[CompactAddress]>,
}

const BOUNDARY_PARAM: u8 = 1;
const BOUNDARY_RETURN: u8 = 2;
const BOUNDARY_THROW: u8 = 3;
const COMPACT_ADDRESS_BYTES: usize = 9;

/// Temporary compiler-object address pages used only while stitching call
/// boundaries. Each node is nine bytes (`FuncId`, compact index, structural
/// boundary tag); the source AST/IDG segment is never duplicated. Pages live
/// in an anonymous file and a tiny exact FIFO working set.
struct CompactAddressPager {
    file: std::fs::File,
    entries: Vec<Option<(u64, u32)>>,
    write_offset: u64,
    cache: AHashMap<SegmentId, Arc<[CompactAddress]>>,
    cache_order: VecDeque<SegmentId>,
    cache_capacity: usize,
}

impl CompactAddressPager {
    fn new(segment_count: usize) -> Self {
        Self {
            file: tempfile::tempfile().expect("create function-summary address spool"),
            entries: vec![None; segment_count],
            write_offset: 0,
            cache: AHashMap::default(),
            cache_order: VecDeque::new(),
            cache_capacity: bonsai_common::compiler_worker_count(rayon::current_num_threads()).max(2),
        }
    }

    fn write_page(&mut self, segment: SegmentId, addresses: &[CompactAddress]) {
        self.file
            .seek(SeekFrom::Start(self.write_offset))
            .expect("seek function-summary address spool");
        let mut payload = Vec::with_capacity(addresses.len().saturating_mul(COMPACT_ADDRESS_BYTES));
        for address in addresses {
            payload.extend_from_slice(&address.func.raw().to_le_bytes());
            payload.extend_from_slice(&address.compact.to_le_bytes());
            payload.push(address.boundary);
        }
        self.file
            .write_all(&payload)
            .expect("write function-summary address spool");
        let count = u32::try_from(addresses.len()).expect("segment compact-address count exceeds u32");
        if let Some(entry) = self.entries.get_mut(segment.0 as usize) {
            *entry = Some((self.write_offset, count));
        }
        self.write_offset = self
            .write_offset
            .saturating_add(u64::try_from(payload.len()).expect("address payload length exceeds u64"));
    }

    fn page(&mut self, segment: SegmentId) -> Option<Arc<[CompactAddress]>> {
        if let Some(page) = self.cache.get(&segment) {
            return Some(Arc::clone(page));
        }
        let (offset, count) = self.entries.get(segment.0 as usize).copied().flatten()?;
        let payload_len = (count as usize).checked_mul(COMPACT_ADDRESS_BYTES)?;
        let mut payload = vec![0_u8; payload_len];
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.read_exact(&mut payload))
            .expect("read function-summary address spool");
        let mut addresses = Vec::with_capacity(count as usize);
        for record in payload.chunks_exact(COMPACT_ADDRESS_BYTES) {
            let func = FuncId::new(u32::from_le_bytes(record[0..4].try_into().expect("func bytes")));
            let compact = u32::from_le_bytes(record[4..8].try_into().expect("compact bytes"));
            addresses.push(CompactAddress {
                func,
                compact,
                boundary: record[8],
            });
        }
        let page: Arc<[CompactAddress]> = Arc::from(addresses);
        self.cache.insert(segment, Arc::clone(&page));
        self.cache_order.push_back(segment);
        while self.cache.len() > self.cache_capacity {
            if let Some(evicted) = self.cache_order.pop_front() {
                self.cache.remove(&evicted);
            }
        }
        Some(page)
    }
}

fn edge_is_within_precision(edge: &IdgEdge, max_precision: Option<Precision>) -> bool {
    max_precision.is_none_or(|max| edge.meta.precision <= max)
}

fn build_layout(workspace: &IdgWorkspace) -> (AHashMap<FuncId, FunctionLayout>, CompactAddressPager) {
    let mut layouts = AHashMap::default();
    let mut addresses = CompactAddressPager::new(workspace.segment_count());
    for (segment_id, segment) in workspace.segment_views() {
        let mut segment_addresses = Vec::with_capacity(segment.nodes.nodes.len());
        for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
            let local = NodeId(u32::try_from(node_index).expect("segment-local IDG node count exceeds u32"));
            let layout = layouts
                .entry(node.func)
                .or_insert_with(|| FunctionLayout::new(segment_id));
            debug_assert_eq!(layout.segment, segment_id);
            let compact =
                u32::try_from(layout.local_nodes.len()).expect("function-local IDG node count exceeds u32");
            layout.local_nodes.push(local);
            match segment.places.get(node.place) {
                Some(Place::Param { idx }) => layout.params.push((*idx, compact)),
                Some(Place::Return) => {
                    layout.return_node = Some(compact);
                    layout.outputs.push(compact);
                }
                Some(Place::Throw { .. }) => layout.outputs.push(compact),
                _ => {}
            }
            let boundary = match segment.places.get(node.place) {
                Some(Place::Param { .. }) => BOUNDARY_PARAM,
                Some(Place::Return) => BOUNDARY_RETURN,
                Some(Place::Throw { .. }) => BOUNDARY_THROW,
                _ => 0,
            };
            segment_addresses.push(CompactAddress {
                func: node.func,
                compact,
                boundary,
            });
        }
        addresses.write_page(segment_id, &segment_addresses);
    }
    for layout in layouts.values_mut() {
        layout.params.sort_unstable();
        layout.params.dedup();
        layout.outputs.sort_unstable();
        layout.outputs.dedup();
    }
    (layouts, addresses)
}

fn compact_address(addresses: &[CompactAddress], node: NodeId) -> Option<CompactAddress> {
    addresses.get(node.0 as usize).copied()
}

fn record_call_boundary(
    inputs: &mut BoundaryPairSpool,
    outputs: &mut BoundaryPairSpool,
    from_addresses: &[CompactAddress],
    to_addresses: &[CompactAddress],
    edge: &IdgEdge,
    max_precision: Option<Precision>,
) {
    if !edge_is_within_precision(edge, max_precision) || edge.meta.kind == IdgEdgeKind::IntraAggregateConsume
    {
        return;
    }
    let Some(from) = compact_address(from_addresses, edge.from) else {
        return;
    };
    let Some(to) = compact_address(to_addresses, edge.to) else {
        return;
    };

    // Only structural formal/return places define compiler call-summary
    // boundaries. Compatibility field edges can carry the same edge kind but
    // never get to invent a callee from endpoint ownership.
    let structural = match edge.meta.kind {
        IdgEdgeKind::InterCallArg => to.boundary == BOUNDARY_PARAM,
        IdgEdgeKind::InterReturn => from.boundary == BOUNDARY_RETURN,
        IdgEdgeKind::InterThrow => from.boundary == BOUNDARY_THROW,
        _ => false,
    };
    if !structural {
        return;
    }

    match edge.meta.kind {
        IdgEdgeKind::InterCallArg => inputs.push(BoundaryPairRow {
            key: CallBoundaryKey {
                caller: from.func,
                callee: to.func,
                span: edge.meta.via_span,
            },
            pair: (from.compact, to.compact),
        }),
        IdgEdgeKind::InterReturn | IdgEdgeKind::InterThrow => outputs.push(BoundaryPairRow {
            key: CallBoundaryKey {
                caller: to.func,
                callee: from.func,
                span: edge.meta.via_span,
            },
            pair: (from.compact, to.compact),
        }),
        _ => {}
    }
}

fn build_call_boundaries(input_rows: BoundaryPairSpool, output_rows: BoundaryPairSpool) -> CallBoundaries {
    let mut input_rows = input_rows.finish().peekable();
    let mut output_rows = output_rows.finish().peekable();
    let mut rows = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    while input_rows.peek().is_some() || output_rows.peek().is_some() {
        let key = match (input_rows.peek(), output_rows.peek()) {
            (Some(input), Some(output)) => std::cmp::min(input.key, output.key),
            (Some(input), None) => input.key,
            (None, Some(output)) => output.key,
            (None, None) => break,
        };
        let input_start = u32::try_from(inputs.len()).expect("call-boundary input count exceeds u32");
        while input_rows.peek().is_some_and(|row| row.key == key) {
            inputs.push(input_rows.next().expect("peeked boundary input").pair);
        }
        let input_end = u32::try_from(inputs.len()).expect("call-boundary input count exceeds u32");
        let output_start = u32::try_from(outputs.len()).expect("call-boundary output count exceeds u32");
        while output_rows.peek().is_some_and(|row| row.key == key) {
            outputs.push(output_rows.next().expect("peeked boundary output").pair);
        }
        let output_end = u32::try_from(outputs.len()).expect("call-boundary output count exceeds u32");
        rows.push(CallBoundary {
            key,
            input_start,
            input_end,
            output_start,
            output_end,
        });
    }

    let max_caller = rows
        .iter()
        .map(|boundary| boundary.key.caller.raw() as usize)
        .max();
    let mut caller_offsets = vec![0_u32; max_caller.map_or(1, |max| max.saturating_add(2))];
    for boundary in &rows {
        caller_offsets[boundary.key.caller.raw() as usize + 1] += 1;
    }
    for index in 1..caller_offsets.len() {
        caller_offsets[index] += caller_offsets[index - 1];
    }
    CallBoundaries {
        rows,
        inputs,
        outputs,
        caller_offsets: caller_offsets.into_boxed_slice(),
    }
}

/// Decode and compact one source segment's ordinary function-local relation.
/// The result lives only while that segment's dirty functions are compiled.
/// Recursive fixed-point rounds may page the exact segment again, but no
/// semantic edge is retained in a second whole-workspace graph.
fn segment_base_edges(
    segment: &IdgSegment,
    layouts: &AHashMap<FuncId, FunctionLayout>,
    max_precision: Option<Precision>,
) -> AHashMap<FuncId, Vec<(u32, u32)>> {
    let mut next_compact: AHashMap<FuncId, u32> = AHashMap::default();
    let mut addresses = Vec::with_capacity(segment.nodes.nodes.len());
    for node in &segment.nodes.nodes {
        let compact = next_compact.entry(node.func).or_default();
        let address = layouts
            .get(&node.func)
            .is_some_and(|layout| (*compact as usize) < layout.local_nodes.len())
            .then_some((node.func, *compact));
        *compact = compact.saturating_add(1);
        addresses.push(address);
    }

    let mut by_func: AHashMap<FuncId, Vec<(u32, u32)>> = AHashMap::default();
    for edge in &segment.edges {
        if !edge_is_within_precision(edge, max_precision)
            || edge.meta.kind == IdgEdgeKind::IntraAggregateConsume
            || !edge.meta.kind.is_intra()
        {
            continue;
        }
        let Some((from_func, from)) = addresses.get(edge.from.0 as usize).copied().flatten() else {
            continue;
        };
        let Some((to_func, to)) = addresses.get(edge.to.0 as usize).copied().flatten() else {
            continue;
        };
        if from_func == to_func {
            by_func.entry(from_func).or_default().push((from, to));
        }
    }
    for edges in by_func.values_mut() {
        edges.sort_unstable();
        edges.dedup();
    }
    by_func
}

fn compile_function(
    func: FuncId,
    layout: &FunctionLayout,
    base_edges: &[(u32, u32)],
    boundaries: &CallBoundaries,
    summaries: &AHashMap<FuncId, Vec<(u32, u32)>>,
) -> FunctionCompilation {
    let mut derived_edges = Vec::new();
    for boundary in boundaries.for_caller(func) {
        let callee_summary = summaries
            .get(&boundary.key.callee)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for &(caller_input, callee_input) in boundaries.inputs(boundary) {
            for &(callee_output, caller_continuation) in boundaries.outputs(boundary) {
                if callee_summary
                    .binary_search(&(callee_input, callee_output))
                    .is_ok()
                    && base_edges
                        .binary_search(&(caller_input, caller_continuation))
                        .is_err()
                {
                    derived_edges.push((caller_input, caller_continuation));
                }
            }
        }
    }
    derived_edges.sort_unstable();
    derived_edges.dedup();

    let mut edges = base_edges.to_vec();
    edges.extend_from_slice(&derived_edges);
    let reach = ReachabilityIndex::from_pairs(layout.local_nodes.len(), &edges);
    let mut summary = Vec::new();
    for &output in &layout.outputs {
        let backward = reach.backward_closure(&[NodeId(output)]);
        for &(_, param) in &layout.params {
            if backward.contains(NodeId(param)) {
                summary.push((param, output));
            }
        }
    }
    summary.sort_unstable();
    summary.dedup();
    FunctionCompilation {
        reach,
        summary,
        derived_edges,
    }
}

fn compile_summaries_to_fixed_point(
    workspace: &IdgWorkspace,
    layouts: &AHashMap<FuncId, FunctionLayout>,
    boundaries: &CallBoundaries,
    callers_by_callee: &AHashMap<FuncId, Vec<FuncId>>,
    max_precision: Option<Precision>,
) -> AHashMap<FuncId, Vec<(u32, u32)>> {
    let mut summaries: AHashMap<FuncId, Vec<(u32, u32)>> =
        layouts.keys().copied().map(|func| (func, Vec::new())).collect();
    let mut pending: AHashSet<FuncId> = layouts.keys().copied().collect();

    while !pending.is_empty() {
        let mut by_segment: BTreeMap<SegmentId, Vec<FuncId>> = BTreeMap::new();
        for func in pending.drain() {
            if let Some(layout) = layouts.get(&func) {
                by_segment.entry(layout.segment).or_default().push(func);
            }
        }
        for (segment_id, mut funcs) in by_segment {
            funcs.sort_unstable_by_key(|func| func.raw());
            let Some(segment) = workspace.segment_view(segment_id) else {
                continue;
            };
            let base_edges = segment_base_edges(&segment, layouts, max_precision);
            for func in funcs {
                let Some(layout) = layouts.get(&func) else {
                    continue;
                };
                let edges = base_edges.get(&func).map(Vec::as_slice).unwrap_or_default();
                let compilation = compile_function(func, layout, edges, boundaries, &summaries);
                if summaries.get(&func) == Some(&compilation.summary) {
                    continue;
                }
                summaries.insert(func, compilation.summary);
                if let Some(callers) = callers_by_callee.get(&func) {
                    pending.extend(callers.iter().copied());
                }
            }
        }
    }
    summaries
}

/// Batched ordinary summaries plus the functions whose result can depend on
/// the symbolic access-path relation.
pub(crate) struct ReturnSummaryBatch {
    pub(crate) indices: AHashMap<FuncId, Vec<u32>>,
    pub(crate) symbolic_sensitive: AHashSet<FuncId>,
    pub(crate) symbolic_callees: AHashMap<FuncId, Vec<FuncId>>,
    pub(crate) contextual_edges: Vec<ContextualSummaryEdge>,
}

/// One derived call-summary edge addressed in the workspace's segmented node
/// space. Canonical function-local edges remain in the IDG and are streamed
/// directly into the contextual CSR; retaining them here would duplicate the
/// dominant workspace relation. Raw interprocedural edges are deliberately
/// absent: query evaluation enters callees and returns only through matched
/// call boundaries.
#[derive(Copy, Clone)]
pub(crate) struct ContextualSummaryEdge {
    pub(crate) segment: SegmentId,
    pub(crate) from: NodeId,
    pub(crate) to: NodeId,
}

pub(crate) fn return_taint_param_indices(
    workspace: &IdgWorkspace,
    funcs: &[FuncId],
    max_precision: Option<Precision>,
) -> ReturnSummaryBatch {
    let (layouts, mut address_pages) = build_layout(workspace);
    let mut boundary_inputs = BoundaryPairSpool::new();
    let mut boundary_outputs = BoundaryPairSpool::new();
    for (segment_id, segment) in workspace.segment_views() {
        let Some(addresses) = address_pages.page(segment_id) else {
            continue;
        };
        for edge in &segment.edges {
            record_call_boundary(
                &mut boundary_inputs,
                &mut boundary_outputs,
                &addresses,
                &addresses,
                edge,
                max_precision,
            );
        }
    }
    workspace
        .visit_cross_file_edges(|edges| {
            // Relation chunks are persisted in canonical stitch order, which
            // need not cluster endpoint pages. Boundary assembly is set-like
            // and sorted below, so a compact index order groups the same exact
            // rows by segment pair while retaining only two decoded pages.
            let mut order: Vec<usize> = (0..edges.len()).collect();
            order.sort_unstable_by_key(|index| {
                let edge = &edges[*index];
                (edge.from_segment.0, edge.to_segment.0)
            });
            let mut current_pages: Option<CompactAddressPagePair> = None;
            for index in order {
                let edge = &edges[index];
                let pair = (edge.from_segment, edge.to_segment);
                if current_pages
                    .as_ref()
                    .is_none_or(|pages| (pages.from_segment, pages.to_segment) != pair)
                {
                    let Some(from_addresses) = address_pages.page(edge.from_segment) else {
                        continue;
                    };
                    let Some(to_addresses) = address_pages.page(edge.to_segment) else {
                        continue;
                    };
                    current_pages = Some(CompactAddressPagePair {
                        from_segment: edge.from_segment,
                        to_segment: edge.to_segment,
                        from: from_addresses,
                        to: to_addresses,
                    });
                }
                let Some(pages) = current_pages.as_ref() else {
                    continue;
                };
                record_call_boundary(
                    &mut boundary_inputs,
                    &mut boundary_outputs,
                    &pages.from,
                    &pages.to,
                    &edge.edge,
                    max_precision,
                );
            }
        })
        .expect("validated IDG cross-file relation remains readable");
    drop(address_pages);
    let boundaries = build_call_boundaries(boundary_inputs, boundary_outputs);

    let mut callers_by_callee: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
    let mut return_continuations_by_caller: AHashMap<FuncId, Vec<(FuncId, u32)>> = AHashMap::default();
    for boundary in &boundaries.rows {
        callers_by_callee
            .entry(boundary.key.callee)
            .or_default()
            .push(boundary.key.caller);
        for &(_, continuation) in boundaries.outputs(boundary) {
            return_continuations_by_caller
                .entry(boundary.key.caller)
                .or_default()
                .push((boundary.key.callee, continuation));
        }
    }
    for callers in callers_by_callee.values_mut() {
        callers.sort_unstable_by_key(|func| func.raw());
        callers.dedup();
    }
    for continuations in return_continuations_by_caller.values_mut() {
        continuations.sort_unstable_by_key(|(callee, continuation)| (callee.raw(), *continuation));
        continuations.dedup();
    }

    let ordinary = compile_summaries_to_fixed_point(
        workspace,
        &layouts,
        &boundaries,
        &callers_by_callee,
        max_precision,
    );

    let mut requested: Vec<FuncId> = funcs.to_vec();
    requested.sort_unstable_by_key(|func| func.raw());
    requested.dedup();
    let requested_set: AHashSet<FuncId> = requested.iter().copied().collect();
    let mut indices: AHashMap<FuncId, Vec<u32>> =
        requested.iter().copied().map(|func| (func, Vec::new())).collect();
    let symbolic_consumers = symbolic_consumer_nodes_streaming(workspace, &layouts, max_precision);
    let mut directly_sensitive = AHashSet::default();
    let mut return_callers_by_callee: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
    let mut contextual_edges = Vec::new();
    let mut layout_funcs: Vec<FuncId> = layouts.keys().copied().collect();
    layout_funcs.sort_unstable_by_key(|func| {
        layouts
            .get(func)
            .map_or((u32::MAX, func.raw()), |layout| (layout.segment.0, func.raw()))
    });
    let mut cached_segment = None;
    let mut cached_base_edges: AHashMap<FuncId, Vec<(u32, u32)>> = AHashMap::default();
    for func in layout_funcs {
        let Some(layout) = layouts.get(&func) else {
            continue;
        };
        if cached_segment != Some(layout.segment) {
            cached_base_edges = workspace
                .segment_view(layout.segment)
                .map_or_else(AHashMap::default, |segment| {
                    segment_base_edges(&segment, &layouts, max_precision)
                });
            cached_segment = Some(layout.segment);
        }
        let base_edges = cached_base_edges
            .get(&func)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let compilation = compile_function(func, layout, base_edges, &boundaries, &ordinary);
        for (from, to) in compilation.derived_edges {
            let Some(from) = layout.local_nodes.get(from as usize).copied() else {
                continue;
            };
            let Some(to) = layout.local_nodes.get(to as usize).copied() else {
                continue;
            };
            contextual_edges.push(ContextualSummaryEdge {
                segment: layout.segment,
                from,
                to,
            });
        }
        let Some(return_node) = layout.return_node else {
            continue;
        };
        let backward = compilation.reach.backward_closure(&[NodeId(return_node)]);
        if symbolic_consumers
            .get(&func)
            .is_some_and(|nodes| nodes.iter().any(|node| backward.contains(NodeId(*node))))
        {
            directly_sensitive.insert(func);
        }
        if let Some(continuations) = return_continuations_by_caller.get(&func) {
            for &(callee, continuation) in continuations {
                if backward.contains(NodeId(continuation)) {
                    return_callers_by_callee.entry(callee).or_default().push(func);
                }
            }
        }
        if requested_set.contains(&func) {
            let returning = layout
                .params
                .iter()
                .filter_map(|(index, node)| backward.contains(NodeId(*node)).then_some(*index))
                .collect();
            indices.insert(func, returning);
        }
    }
    contextual_edges.sort_unstable_by_key(|edge| (edge.segment.0, edge.from.0, edge.to.0));
    contextual_edges.dedup_by_key(|edge| (edge.segment.0, edge.from.0, edge.to.0));

    for callers in return_callers_by_callee.values_mut() {
        callers.sort_unstable_by_key(|func| func.raw());
        callers.dedup();
    }
    let mut symbolic_sensitive = directly_sensitive.clone();
    let mut pending: Vec<FuncId> = directly_sensitive.into_iter().collect();
    while let Some(callee) = pending.pop() {
        let Some(callers) = return_callers_by_callee.get(&callee) else {
            continue;
        };
        for caller in callers {
            if symbolic_sensitive.insert(*caller) {
                pending.push(*caller);
            }
        }
    }

    let mut symbolic_callees: AHashMap<FuncId, Vec<FuncId>> = AHashMap::default();
    for (callee, callers) in &return_callers_by_callee {
        if !symbolic_sensitive.contains(callee) {
            continue;
        }
        for caller in callers {
            if symbolic_sensitive.contains(caller) {
                symbolic_callees.entry(*caller).or_default().push(*callee);
            }
        }
    }
    for callees in symbolic_callees.values_mut() {
        callees.sort_unstable_by_key(|func| func.raw());
        callees.dedup();
    }

    ReturnSummaryBatch {
        indices,
        symbolic_sensitive,
        symbolic_callees,
        contextual_edges,
    }
}

fn symbolic_consumer_nodes_streaming(
    workspace: &IdgWorkspace,
    layouts: &AHashMap<FuncId, FunctionLayout>,
    max_precision: Option<Precision>,
) -> AHashMap<FuncId, AHashSet<u32>> {
    let symbolic = workspace.symbolic_field();
    if !workspace.has_symbolic_transforms() {
        return AHashMap::default();
    }
    let mut scalar_targets = AHashSet::default();
    workspace
        .visit_symbolic_transforms(|transforms| {
            scalar_targets.extend(
                transforms
                    .iter()
                    .filter(|transform| transform.kind == SymbolicFieldTransformKind::ScalarReturn)
                    .filter(|transform| max_precision.is_none_or(|max| transform.precision <= max))
                    .map(|transform| (transform.target, transform.write_span)),
            );
            Ok(())
        })
        .expect("validated IDG symbolic relation remains readable");
    let mut consumers: AHashMap<FuncId, AHashSet<u32>> = AHashMap::default();
    for (segment_id, segment) in workspace.segment_views() {
        for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
            let Some(place) = segment.places.get(node.place) else {
                continue;
            };
            let Some((parts, write_span, is_read)) = structured_storage_parts(&segment, place) else {
                continue;
            };
            let full = parts.join(".");
            let full_base = symbolic.base_id(segment_id, node.func, &full);
            let bare_consumer = is_read && full_base.is_some();
            let exact_consumer = is_read
                && (1..parts.len()).any(|split| {
                    let base = parts[..split].join(".");
                    symbolic.base_id(segment_id, node.func, &base).is_some()
                });
            let scalar_consumer = write_span
                .zip(full_base)
                .is_some_and(|(span, base)| scalar_targets.contains(&(base, span)));
            if !bare_consumer && !exact_consumer && !scalar_consumer {
                continue;
            }
            let local = NodeId(u32::try_from(node_index).expect("segment-local IDG node count exceeds u32"));
            let Some(compact) = layouts
                .get(&node.func)
                .and_then(|layout| layout.compact_of(local))
            else {
                continue;
            };
            consumers.entry(node.func).or_default().insert(compact);
        }
    }
    consumers
}

fn storage_name(workspace: &IdgWorkspace, segment_id: SegmentId, place_id: PlaceId) -> Option<String> {
    let segment = workspace.segment_view(segment_id)?;
    let (name, path) = match segment.places.get(place_id)? {
        Place::Read { name, path } | Place::Write { name, path, .. } => (*name, path),
        _ => return None,
    };
    let mut storage = segment.strings.get(name)?.to_string();
    for part in path {
        storage.push('.');
        storage.push_str(segment.strings.get(*part)?);
    }
    (!storage.trim().is_empty()).then_some(storage)
}

pub(crate) fn local_storage_taint_by_param(
    workspace: &IdgWorkspace,
    funcs: &[FuncId],
    max_precision: Option<Precision>,
) -> AHashMap<FuncId, Vec<Vec<String>>> {
    let mut all_flows = AHashMap::with_capacity(funcs.len());
    try_visit_local_storage_taint_by_param(workspace, funcs, max_precision, |func, flows| {
        all_flows.insert(func, flows);
        Result::<(), std::convert::Infallible>::Ok(())
    })
    .expect("infallible local-storage summary collector");
    all_flows
}

/// Visit function-local parameter/storage summaries one source segment at a
/// time. Local storage never crosses a function boundary, so retaining a
/// second compact graph for every workspace function is unnecessary. This is
/// an allocation-lifetime optimization only: every requested function and
/// every precision-eligible intra-function edge is processed exactly once.
pub(crate) fn try_visit_local_storage_taint_by_param<E>(
    workspace: &IdgWorkspace,
    funcs: &[FuncId],
    max_precision: Option<Precision>,
    mut visit: impl FnMut(FuncId, Vec<Vec<String>>) -> Result<(), E>,
) -> Result<(), E> {
    let mut requested_by_segment: AHashMap<SegmentId, Vec<FuncId>> = AHashMap::default();
    for func in funcs {
        let Some(segment) = workspace.segment_for_func(*func) else {
            visit(*func, Vec::new())?;
            continue;
        };
        requested_by_segment.entry(segment).or_default().push(*func);
    }
    for requested in requested_by_segment.values_mut() {
        requested.sort_unstable_by_key(|func| func.raw());
        requested.dedup();
    }

    for (segment_id, segment) in workspace.segment_views() {
        let Some(requested) = requested_by_segment.get(&segment_id) else {
            continue;
        };
        let requested_set: AHashSet<FuncId> = requested.iter().copied().collect();
        let mut graphs = AHashMap::default();
        let mut addresses = vec![None; segment.nodes.nodes.len()];
        for (node_index, node) in segment.nodes.nodes.iter().enumerate() {
            if !requested_set.contains(&node.func) {
                continue;
            }
            let local_node =
                NodeId(u32::try_from(node_index).expect("segment-local IDG node count exceeds u32"));
            let graph = graphs
                .entry(node.func)
                .or_insert_with(|| LocalFunctionGraph::new(segment_id));
            let compact = graph.add_node(local_node, segment.places.get(node.place));
            addresses[node_index] = Some((node.func, compact));
        }
        for edge in &segment.edges {
            if !edge_is_within_precision(edge, max_precision) {
                continue;
            }
            let Some((from_func, from)) = addresses.get(edge.from.0 as usize).copied().flatten() else {
                continue;
            };
            let Some((to_func, to)) = addresses.get(edge.to.0 as usize).copied().flatten() else {
                continue;
            };
            if from_func == to_func {
                if let Some(graph) = graphs.get_mut(&from_func) {
                    graph.add_base_edge(from, to);
                }
            }
        }

        for func in requested {
            let Some(graph) = graphs.get_mut(func) else {
                visit(*func, Vec::new())?;
                continue;
            };
            let param_slots = graph
                .params
                .iter()
                .map(|(idx, _)| *idx as usize + 1)
                .max()
                .unwrap_or(0);
            let mut per_param: Vec<BTreeSet<String>> = (0..param_slots).map(|_| BTreeSet::new()).collect();
            let params = graph.params.clone();
            let segment_id = graph.segment;
            let reachability = graph.reachability();
            for (param_idx, param_node) in params {
                let Some(names) = per_param.get_mut(param_idx as usize) else {
                    continue;
                };
                let closure = reachability.forward_closure(&[NodeId(param_node)]);
                for reached in closure.iter() {
                    let Some(local_node) = graph.local_nodes.get(reached.0 as usize) else {
                        continue;
                    };
                    let Some(segment) = workspace.segment_view(segment_id) else {
                        continue;
                    };
                    let Some(node) = segment.nodes.get(*local_node) else {
                        continue;
                    };
                    if let Some(name) = storage_name(workspace, segment_id, node.place) {
                        names.insert(name);
                    }
                }
            }
            visit(
                *func,
                per_param
                    .into_iter()
                    .map(|names| names.into_iter().collect())
                    .collect(),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_boundary_external_merge_is_sorted_exact_and_deduplicated_across_runs() {
        let key = CallBoundaryKey {
            caller: FuncId::new(1),
            callee: FuncId::new(2),
            span: Span::new(bonsai_common::FileId::new(3), 4, 5),
        };
        let mut inputs = BoundaryPairSpool::new();
        for index in (0..=BOUNDARY_RUN_ROWS).rev() {
            let index = u32::try_from(index).expect("test boundary index fits u32");
            inputs.push(BoundaryPairRow {
                key,
                pair: (index, index + 1),
            });
        }
        // This duplicate lands in the final run and must be removed against
        // the same row already emitted by the full first run.
        inputs.push(BoundaryPairRow { key, pair: (0, 1) });

        let mut outputs = BoundaryPairSpool::new();
        outputs.push(BoundaryPairRow { key, pair: (7, 8) });
        let boundaries = build_call_boundaries(inputs, outputs);

        assert_eq!(boundaries.rows.len(), 1);
        assert_eq!(
            boundaries.inputs(&boundaries.rows[0]).len(),
            BOUNDARY_RUN_ROWS + 1
        );
        assert_eq!(boundaries.inputs(&boundaries.rows[0]).first(), Some(&(0, 1)));
        assert_eq!(
            boundaries.inputs(&boundaries.rows[0]).last(),
            Some(&(BOUNDARY_RUN_ROWS as u32, BOUNDARY_RUN_ROWS as u32 + 1))
        );
        assert_eq!(boundaries.outputs(&boundaries.rows[0]), &[(7, 8)]);
    }
}
