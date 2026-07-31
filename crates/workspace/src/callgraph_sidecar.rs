//! Versioned resolved-callgraph sidecar.
//!
//! Metadata and graph facts are separate factstore entries. Warm-up and cache
//! inspection can therefore prove source/build/dependency freshness without
//! decoding or allocating the graph. Query consumers read the graph entry and
//! validate its MessagePack payload before use.

use crate::cache_fingerprint::dependency_metadata_fingerprint_for_sidecar;
use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::{
    CallEdge, CallGraphLocalBinding, CallGraphNode, ResolvedCallGraph, UnresolvedWorkspaceCallSite,
};
use bonsai_common::{wire, workspace_bonsai_dir, FileId, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_hash::fnv1a_bytes64;
use bonsai_idg::workspace_adapter::CallGraphRelation;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// v24 (2026-07-31): AST value/type bindings are no longer classified as
// import/module aliases. Unresolved field receivers therefore cannot fall
// through to unrelated same-leaf workspace callables.
// v23 (2026-07-31): semantic receiver retention requires an exact raw module
// qualifier; only compiler-resolved imports may drop a terminal trailer.
// v22 (2026-07-30): unresolved explicit constructor syntax no longer falls
// back to the lexically enclosing class unless the adapter declares that
// constructor method spelling. Raw instance-field chains also require an
// exact module qualifier instead of using the import-only terminal-trailer
// fallback. These prevent Java `new External(...)` and `value.field.get()`
// from becoming unrelated workspace calls.
// v21 (2026-07-30): rebuild endpoint identities after nested class-like
// declarations gained complete lexical parent chains in compiler-object v13.
// v20 (2026-07-30): partition callable metadata with its declaring file.
// The fixed table now stores only compact FuncId->FileId identity, while
// exact-name hash buckets locate candidate symbols without decoding every
// callable name in the workspace.
// v19 (2026-07-30): store the callable table and exact per-file
// outgoing/incoming adjacency as independently decodable factstore entries.
// Query commands can now load only the files their compiler worklist touches;
// full consumers reconstruct the identical graph from the outgoing union.
// v18 (2026-07-30): invalidate graphs built with pre-v11 compiler objects,
// whose anonymous-body method ownership could resolve calls against the wrong
// enclosing type.
// v17 (2026-07-25): graph payloads retain exact unresolved workspace call
// sites so completeness diagnostics distinguish resolver gaps from external
// calls.
// v16 (2026-07-20): graph payloads retain compiler-resolved local callable
// bindings so the IDG does not keep assignment bodies resident.
// v15 (2026-07-20): graph payloads include a deterministic compact endpoint
// name table so later phases can release whole-file declaration bodies.
// v14 (2026-07-20): graph payloads stream directly and contain only compact
// typed edges; numeric adjacency indexes are rebuilt after decode.
// v13 (2026-07-18): metadata and graph payloads are independent factstore
// entries, so freshness checks do not recursively decode millions of edges.
// v12 (2026-07-16): MessagePack replaced the retired binary codec.
pub const CALLGRAPH_CACHE_VERSION: u32 = 24;

const CALLGRAPH_TABLE_ID: u32 = 102;
const METADATA_KEY: u64 = 0;
const IDENTITY_TABLE_KEY: u64 = 1;
const FILE_PARTITION_KEY_BASE: u64 = 0x1000_0000_0000_0000;
const NAME_BUCKET_KEY_BASE: u64 = 0x4000_0000_0000_0000;
const KEY_PAYLOAD_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const FIXED_ENTRY_COUNT: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CallgraphMetadata {
    version: u32,
    matcher_policy_fingerprint: u128,
    /// Sorted `(workspace path, content hash)` pairs for every indexed file.
    files: Vec<(String, u64)>,
    dependency_metadata_fingerprint: u64,
    /// Producer identity retained for diagnostics and artifact integrity.
    /// Freshness is governed by the callgraph semantic ABI plus exact input
    /// fingerprints, not by unrelated changes elsewhere in the binary.
    build_fingerprint: u64,
    /// Sorted full-workspace FileIds with an independently decodable
    /// adjacency partition.
    partition_files: Vec<u32>,
    /// Sorted exact-name bucket factstore keys.
    name_bucket_keys: Vec<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CallgraphFilePartition {
    file: FileId,
    nodes: Vec<CallGraphNode>,
    outgoing: Vec<CallEdge>,
    incoming: Vec<CallEdge>,
    local_bindings: Vec<CallGraphLocalBinding>,
    unresolved_workspace_sites: Vec<UnresolvedWorkspaceCallSite>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CallgraphNameBucket {
    entries: Vec<(String, Vec<FuncId>)>,
}

#[derive(Default)]
struct CallgraphPartitionOrdinals {
    nodes: Vec<usize>,
    outgoing: Vec<usize>,
    incoming: Vec<usize>,
    local_bindings: Vec<usize>,
    unresolved_workspace_sites: Vec<usize>,
}

/// Read-only, file-partitioned callgraph query service.
///
/// Opening validates the same exact source/dependency contract as the full
/// graph loader but decodes only the compact function-to-file identity table.
/// Exact-name buckets and file-local callable/adjacency pages are fetched as
/// the compiler worklist advances.
pub(crate) struct CallgraphQueryService {
    reader: FactStoreReader,
    metadata: CallgraphMetadata,
    identities: Vec<(FuncId, FileId)>,
    relation_cache: Mutex<CallgraphRelationCache>,
    relation_error: Mutex<Option<String>>,
}

struct CallgraphRelationCache {
    capacity: usize,
    partitions: AHashMap<u32, Arc<CallgraphFilePartition>>,
    lru: VecDeque<u32>,
}

impl CallgraphRelationCache {
    fn new() -> Self {
        let requested = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        Self {
            // One active partition per memory-scheduled compiler worker.
            // A constrained process therefore holds one exact file relation;
            // larger machines can serve parallel transfer workers without a
            // global graph. This is a residency schedule, never graph scope.
            capacity: bonsai_common::compiler_worker_count(requested).max(1),
            partitions: AHashMap::new(),
            lru: VecDeque::new(),
        }
    }

    fn get(&mut self, file: u32) -> Option<Arc<CallgraphFilePartition>> {
        let partition = self.partitions.get(&file).cloned()?;
        self.lru.retain(|cached| *cached != file);
        self.lru.push_back(file);
        Some(partition)
    }

    fn insert(&mut self, file: u32, partition: Arc<CallgraphFilePartition>) {
        if self.partitions.contains_key(&file) {
            return;
        }
        while self.partitions.len() >= self.capacity {
            let Some(evicted) = self.lru.pop_front() else {
                break;
            };
            self.partitions.remove(&evicted);
        }
        self.partitions.insert(file, partition);
        self.lru.push_back(file);
    }
}

/// One callable's exact semantic degree counts read from a partitioned
/// callgraph sidecar without hydrating the complete graph.
#[derive(Clone, Debug)]
pub struct CallgraphSidecarSummaryRow {
    pub function: FuncId,
    pub name: String,
    pub qualified_name: Option<String>,
    pub file: FileId,
    pub name_start: u64,
    pub callers: usize,
    pub outgoing: usize,
}

impl CallgraphQueryService {
    pub(crate) fn open_checked(path: &Path, db: &AnalyzerDb) -> std::io::Result<Self> {
        let inputs = current_source_fingerprints(db);
        Self::open_checked_with_source_fingerprints(path, &inputs)
    }

    /// Open the partitioned query service against an independently
    /// fingerprinted complete workspace.
    ///
    /// Scoped compiler sessions retain global FileIds but intentionally do
    /// not ingest unrelated source text. They validate the sidecar by
    /// streaming the complete input fingerprints from disk, then use this
    /// loader so storage optimization never weakens freshness.
    pub(crate) fn open_checked_with_source_inputs(
        path: &Path,
        inputs: &[(u32, String, u64)],
    ) -> std::io::Result<Self> {
        let mut fingerprints = inputs
            .iter()
            .map(|(_, source_path, hash)| (source_path.clone(), *hash))
            .collect::<Vec<_>>();
        // FileIds follow component-wise `PathBuf` order; the callgraph's
        // path-only freshness table is canonicalized by encoded path text.
        // Sort after dropping FileIds so `build-tools/` versus
        // `build-tools-internal/` cannot produce a false cache miss.
        fingerprints.sort();
        Self::open_checked_with_source_fingerprints(path, &fingerprints)
    }

    fn open_checked_with_source_fingerprints(
        path: &Path,
        fingerprints: &[(String, u64)],
    ) -> std::io::Result<Self> {
        let (reader, metadata) = open_sidecar(path)?;
        validate_metadata(path, &metadata)?;
        if fingerprints != metadata.files {
            let first_mismatch = fingerprints
                .iter()
                .zip(metadata.files.iter())
                .position(|(current, recorded)| current != recorded);
            let detail = first_mismatch
                .and_then(|index| fingerprints.get(index).zip(metadata.files.get(index)))
                .map_or_else(
                    || "length differs".to_string(),
                    |(current, recorded)| format!("current={current:?} recorded={recorded:?}"),
                );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "callgraph sidecar source fingerprint mismatch: current={} recorded={} first_mismatch={} ({detail})",
                    fingerprints.len(),
                    metadata.files.len(),
                    first_mismatch
                        .map(|index| index.to_string())
                        .unwrap_or_else(|| "length".to_string()),
                ),
            ));
        }
        let identities = decode_identities(&reader)?;
        if identities
            .windows(2)
            .any(|pair| pair[0].0.raw() >= pair[1].0.raw())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "callgraph identity table is not strictly sorted",
            ));
        }
        for (_, file) in &identities {
            if metadata.partition_files.binary_search(&file.raw()).is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "callgraph identity references missing file partition {}",
                        file.raw()
                    ),
                ));
            }
        }
        Ok(Self {
            reader,
            metadata,
            identities,
            relation_cache: Mutex::new(CallgraphRelationCache::new()),
            relation_error: Mutex::new(None),
        })
    }

    fn node_file(&self, func: FuncId) -> Option<FileId> {
        self.identities
            .binary_search_by_key(&func.raw(), |(function, _)| function.raw())
            .ok()
            .map(|index| self.identities[index].1)
    }

    pub(crate) fn callable_nodes_named(&self, name: &str) -> std::io::Result<Vec<CallGraphNode>> {
        let key = name_bucket_key(name);
        if self.metadata.name_bucket_keys.binary_search(&key).is_err() {
            return Ok(Vec::new());
        }
        let bucket = decode_name_bucket(&self.reader, key)?;
        let Some((_, functions)) = bucket
            .entries
            .into_iter()
            .find(|(candidate, _)| candidate == name)
        else {
            return Ok(Vec::new());
        };
        let expected = functions.len();
        let mut by_file = BTreeMap::<u32, AHashSet<FuncId>>::new();
        for function in functions {
            let file = self.node_file(function).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("name bucket references unknown function {}", function.raw()),
                )
            })?;
            by_file.entry(file.raw()).or_default().insert(function);
        }
        let mut out = Vec::new();
        let mut found = AHashSet::new();
        for (file, requested) in by_file {
            for node in self.partition(FileId::new(file))?.nodes {
                if !requested.contains(&node.func) {
                    continue;
                }
                if node.name.as_ref() != name && node.qualified_name.as_deref() != Some(name) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "callgraph name bucket maps {name:?} to mismatched function {}",
                            node.func.raw()
                        ),
                    ));
                }
                found.insert(node.func);
                out.push(node);
            }
        }
        if found.len() != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("callgraph name bucket {name:?} references a missing callable node"),
            ));
        }
        Ok(out)
    }

    fn partition(&self, file: FileId) -> std::io::Result<CallgraphFilePartition> {
        if self.metadata.partition_files.binary_search(&file.raw()).is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("callgraph node references missing file partition {}", file.raw()),
            ));
        }
        decode_partition(&self.reader, file.raw())
    }

    fn cached_relation_partition(&self, function: FuncId) -> std::io::Result<Arc<CallgraphFilePartition>> {
        let file = self.node_file(function).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("callgraph callable table is missing function {}", function.raw()),
            )
        })?;
        if let Some(partition) = self.relation_cache.lock().get(file.raw()) {
            return Ok(partition);
        }
        let decoded = Arc::new(self.partition(file)?);
        let mut cache = self.relation_cache.lock();
        if let Some(partition) = cache.get(file.raw()) {
            return Ok(partition);
        }
        cache.insert(file.raw(), decoded.clone());
        Ok(decoded)
    }

    pub(crate) fn callable_node(&self, function: FuncId) -> std::io::Result<CallGraphNode> {
        let partition = self.cached_relation_partition(function)?;
        partition
            .nodes
            .binary_search_by_key(&function.raw(), |node| node.func.raw())
            .ok()
            .map(|index| partition.nodes[index].clone())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("callgraph partition is missing function {}", function.raw()),
                )
            })
    }

    fn record_relation_error(&self, error: std::io::Error) {
        let mut slot = self.relation_error.lock();
        if slot.is_none() {
            *slot = Some(error.to_string());
        }
    }

    /// Visit every exact persisted partition in canonical FileId order.
    ///
    /// The decoded partition is dropped before the next one is opened. Broad
    /// consumers such as native export can therefore process the complete
    /// compiler graph without materializing its multi-million-edge adjacency
    /// relation in memory.
    pub(crate) fn visit_partitions(
        &self,
        mut visit: impl FnMut(FileId, &[CallGraphNode], &[CallEdge], &[CallEdge], &[UnresolvedWorkspaceCallSite]),
    ) -> std::io::Result<()> {
        for file in &self.metadata.partition_files {
            let partition = self.partition(FileId::new(*file))?;
            visit(
                partition.file,
                &partition.nodes,
                &partition.outgoing,
                &partition.incoming,
                &partition.unresolved_workspace_sites,
            );
        }
        Ok(())
    }

    fn summary_rows(&self) -> std::io::Result<Vec<CallgraphSidecarSummaryRow>> {
        let mut rows = Vec::with_capacity(self.identities.len());
        let mut seen_identities = vec![false; self.identities.len()];
        for file in &self.metadata.partition_files {
            let partition = self.partition(FileId::new(*file))?;
            let mut caller_pairs = partition
                .incoming
                .iter()
                .filter(|edge| edge.precision.is_semantic())
                .map(|edge| (edge.to, edge.from))
                .collect::<Vec<_>>();
            caller_pairs.sort_unstable_by_key(|(callee, caller)| (callee.raw(), caller.raw()));
            caller_pairs.dedup();
            let mut outgoing_pairs = partition
                .outgoing
                .iter()
                .filter(|edge| edge.precision.is_semantic())
                .map(|edge| (edge.from, edge.to))
                .collect::<Vec<_>>();
            outgoing_pairs.sort_unstable_by_key(|(caller, callee)| (caller.raw(), callee.raw()));
            outgoing_pairs.dedup();

            let caller_counts = grouped_endpoint_counts(&caller_pairs);
            let outgoing_counts = grouped_endpoint_counts(&outgoing_pairs);
            for node in partition.nodes {
                let identity_index = self
                    .identities
                    .binary_search_by_key(&node.func.raw(), |(function, _)| function.raw())
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "callgraph partition references unknown function {}",
                                node.func.raw()
                            ),
                        )
                    })?;
                if self.identities[identity_index].1 != node.file || seen_identities[identity_index] {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "callgraph identity table does not uniquely match function {}",
                            node.func.raw()
                        ),
                    ));
                }
                seen_identities[identity_index] = true;
                rows.push(CallgraphSidecarSummaryRow {
                    function: node.func,
                    name: node.name.into(),
                    qualified_name: node.qualified_name.map(Into::into),
                    file: node.file,
                    name_start: node.name_span.start,
                    callers: caller_counts.get(&node.func).copied().unwrap_or(0),
                    outgoing: outgoing_counts.get(&node.func).copied().unwrap_or(0),
                });
            }
        }
        if seen_identities.iter().any(|seen| !seen) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "callgraph identity table does not match file-partitioned callable nodes",
            ));
        }
        Ok(rows)
    }

    pub(crate) fn functions_with_semantic_callers(
        &self,
        functions: &[FuncId],
    ) -> std::io::Result<AHashSet<FuncId>> {
        let requested = functions.iter().copied().collect::<AHashSet<_>>();
        let mut by_file = BTreeMap::<u32, AHashSet<FuncId>>::new();
        for function in &requested {
            let file = self.node_file(*function).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("callgraph callable table is missing function {}", function.raw()),
                )
            })?;
            by_file.entry(file.raw()).or_default().insert(*function);
        }
        let mut called = AHashSet::new();
        for (file, targets) in by_file {
            let partition = self.partition(FileId::new(file))?;
            for edge in partition.incoming {
                if edge.precision.is_semantic() && targets.contains(&edge.to) {
                    called.insert(edge.to);
                }
            }
        }
        Ok(called)
    }

    pub(crate) fn materialize_reachable(&self, starts: &[FuncId]) -> std::io::Result<ResolvedCallGraph> {
        self.materialize_reachable_with_max_precision(starts, None)
    }

    pub(crate) fn materialize_reachable_with_max_precision(
        &self,
        starts: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> std::io::Result<ResolvedCallGraph> {
        let mut stack = starts.to_vec();
        stack.sort_unstable_by_key(|func| func.raw());
        stack.dedup();
        let mut visited = AHashSet::new();
        let mut loaded = BTreeMap::<u32, CallgraphFilePartition>::new();
        let mut edges = Vec::new();
        while let Some(function) = stack.pop() {
            if !visited.insert(function) {
                continue;
            }
            let file = self.node_file(function).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "reachable callgraph target {} has no callable node",
                        function.raw()
                    ),
                )
            })?;
            if !loaded.contains_key(&file.raw()) {
                loaded.insert(file.raw(), self.partition(file)?);
            }
            let partition = loaded
                .get(&file.raw())
                .expect("partition inserted for reachable node");
            for edge in partition
                .outgoing
                .iter()
                .filter(|edge| edge.from == function && max_precision.is_none_or(|max| edge.precision <= max))
            {
                edges.push(edge.clone());
                if !visited.contains(&edge.to) {
                    stack.push(edge.to);
                }
            }
        }

        let nodes = loaded
            .values()
            .flat_map(|partition| partition.nodes.iter())
            .filter(|node| visited.contains(&node.func))
            .cloned()
            .collect::<Vec<_>>();
        let local_bindings = loaded
            .values()
            .flat_map(|partition| partition.local_bindings.iter())
            .filter(|binding| visited.contains(&binding.caller))
            .cloned()
            .collect::<Vec<_>>();
        let unresolved_workspace_sites = loaded
            .values()
            .flat_map(|partition| partition.unresolved_workspace_sites.iter())
            .filter(|site| visited.contains(&site.caller))
            .copied()
            .collect::<Vec<_>>();
        Ok(ResolvedCallGraph::from_persisted_parts(
            nodes,
            edges,
            local_bindings,
            unresolved_workspace_sites,
        ))
    }

    /// Materialize the exact persisted subgraph that lies on at least one
    /// path from `starts` to `targets`.
    ///
    /// The reverse pass proves which callables can reach a target. The
    /// forward pass then follows only those proven callables from the source
    /// set. Both passes decode one file partition at a time; traversal work is
    /// uncapped and the result contains every persisted edge on every
    /// source-to-target path.
    pub(crate) fn materialize_between(
        &self,
        starts: &[FuncId],
        targets: &[FuncId],
    ) -> std::io::Result<ResolvedCallGraph> {
        self.materialize_between_with_max_precision(starts, targets, None)
    }

    pub(crate) fn materialize_between_with_max_precision(
        &self,
        starts: &[FuncId],
        targets: &[FuncId],
        max_precision: Option<bonsai_common::Precision>,
    ) -> std::io::Result<ResolvedCallGraph> {
        if starts.is_empty() || targets.is_empty() {
            return Ok(ResolvedCallGraph::from_persisted_parts(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ));
        }

        let mut can_reach_target = AHashSet::new();
        let mut reverse_pending = BTreeMap::<u32, Vec<FuncId>>::new();
        for &target in targets {
            if can_reach_target.insert(target) {
                let file = self.node_file(target).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("path target {} has no callable node", target.raw()),
                    )
                })?;
                reverse_pending.entry(file.raw()).or_default().push(target);
            }
        }
        while let Some((file, mut functions)) = reverse_pending.pop_first() {
            functions.sort_unstable_by_key(|func| func.raw());
            functions.dedup();
            let requested = functions.into_iter().collect::<AHashSet<_>>();
            let partition = self.partition(FileId::new(file))?;
            for edge in partition.incoming.iter().filter(|edge| {
                requested.contains(&edge.to) && max_precision.is_none_or(|max| edge.precision <= max)
            }) {
                if !can_reach_target.insert(edge.from) {
                    continue;
                }
                let caller_file = self.node_file(edge.from).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("path predecessor {} has no callable node", edge.from.raw()),
                    )
                })?;
                reverse_pending
                    .entry(caller_file.raw())
                    .or_default()
                    .push(edge.from);
            }
        }

        let mut visited = AHashSet::new();
        let mut forward_pending = BTreeMap::<u32, Vec<FuncId>>::new();
        for &start in starts {
            if !can_reach_target.contains(&start) || !visited.insert(start) {
                continue;
            }
            let file = self.node_file(start).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("path source {} has no callable node", start.raw()),
                )
            })?;
            forward_pending.entry(file.raw()).or_default().push(start);
        }

        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut local_bindings = Vec::new();
        let mut unresolved_workspace_sites = Vec::new();
        while let Some((file, mut functions)) = forward_pending.pop_first() {
            functions.sort_unstable_by_key(|func| func.raw());
            functions.dedup();
            let requested = functions.into_iter().collect::<AHashSet<_>>();
            let partition = self.partition(FileId::new(file))?;
            nodes.extend(
                partition
                    .nodes
                    .iter()
                    .filter(|node| requested.contains(&node.func))
                    .cloned(),
            );
            local_bindings.extend(
                partition
                    .local_bindings
                    .iter()
                    .filter(|binding| requested.contains(&binding.caller))
                    .cloned(),
            );
            unresolved_workspace_sites.extend(
                partition
                    .unresolved_workspace_sites
                    .iter()
                    .filter(|site| requested.contains(&site.caller))
                    .copied(),
            );
            for edge in partition.outgoing.iter().filter(|edge| {
                requested.contains(&edge.from)
                    && can_reach_target.contains(&edge.to)
                    && max_precision.is_none_or(|max| edge.precision <= max)
            }) {
                edges.push(edge.clone());
                if !visited.insert(edge.to) {
                    continue;
                }
                let callee_file = self.node_file(edge.to).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("path successor {} has no callable node", edge.to.raw()),
                    )
                })?;
                forward_pending
                    .entry(callee_file.raw())
                    .or_default()
                    .push(edge.to);
            }
        }

        Ok(ResolvedCallGraph::from_persisted_parts(
            nodes,
            edges,
            local_bindings,
            unresolved_workspace_sites,
        ))
    }

    /// Materialize every exact one-edge path from `starts` to `targets`.
    ///
    /// A direct edge is a proven minimum-hop path, so ranked path queries can
    /// answer it without first compiling the potentially enormous set of
    /// longer ancestors of a polymorphic target.
    pub(crate) fn materialize_direct_between(
        &self,
        starts: &[FuncId],
        targets: &[FuncId],
    ) -> std::io::Result<ResolvedCallGraph> {
        let requested_targets = targets.iter().copied().collect::<AHashSet<_>>();
        let mut sources_by_file = BTreeMap::<u32, AHashSet<FuncId>>::new();
        for &start in starts {
            let file = self.node_file(start).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("direct path source {} has no callable node", start.raw()),
                )
            })?;
            sources_by_file.entry(file.raw()).or_default().insert(start);
        }

        let mut edges = Vec::new();
        let mut local_bindings = Vec::new();
        let mut unresolved_workspace_sites = Vec::new();
        for (file, sources) in sources_by_file {
            let partition = self.partition(FileId::new(file))?;
            edges.extend(
                partition
                    .outgoing
                    .iter()
                    .filter(|edge| sources.contains(&edge.from) && requested_targets.contains(&edge.to))
                    .cloned(),
            );
            local_bindings.extend(
                partition
                    .local_bindings
                    .iter()
                    .filter(|binding| sources.contains(&binding.caller))
                    .cloned(),
            );
            unresolved_workspace_sites.extend(
                partition
                    .unresolved_workspace_sites
                    .iter()
                    .filter(|site| sources.contains(&site.caller))
                    .copied(),
            );
        }

        let functions = edges
            .iter()
            .flat_map(|edge| [edge.from, edge.to])
            .collect::<AHashSet<_>>();
        let mut functions_by_file = BTreeMap::<u32, AHashSet<FuncId>>::new();
        for &function in &functions {
            let file = self.node_file(function).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("direct path endpoint {} has no callable node", function.raw()),
                )
            })?;
            functions_by_file.entry(file.raw()).or_default().insert(function);
        }
        let mut nodes = Vec::new();
        for (file, requested) in functions_by_file {
            nodes.extend(
                self.partition(FileId::new(file))?
                    .nodes
                    .into_iter()
                    .filter(|node| requested.contains(&node.func)),
            );
        }
        Ok(ResolvedCallGraph::from_persisted_parts(
            nodes,
            edges,
            local_bindings,
            unresolved_workspace_sites,
        ))
    }
}

impl CallGraphRelation for CallgraphQueryService {
    fn visit_callees(&self, caller: FuncId, visit: &mut dyn FnMut(&CallEdge)) {
        match self.cached_relation_partition(caller) {
            Ok(partition) => {
                for edge in partition.outgoing.iter().filter(|edge| edge.from == caller) {
                    visit(edge);
                }
            }
            Err(error) => self.record_relation_error(error),
        }
    }

    fn visit_callers(&self, callee: FuncId, visit: &mut dyn FnMut(&CallEdge)) {
        match self.cached_relation_partition(callee) {
            Ok(partition) => {
                for edge in partition.incoming.iter().filter(|edge| edge.to == callee) {
                    visit(edge);
                }
            }
            Err(error) => self.record_relation_error(error),
        }
    }

    fn visit_local_callable_bindings(&self, visit: &mut dyn FnMut(FuncId, &str, FuncId)) {
        for file in &self.metadata.partition_files {
            let partition = match self.partition(FileId::new(*file)) {
                Ok(partition) => partition,
                Err(error) => {
                    self.record_relation_error(error);
                    return;
                }
            };
            for binding in &partition.local_bindings {
                visit(binding.caller, &binding.name, binding.target);
            }
        }
    }

    fn check_error(&self) -> Result<(), String> {
        self.relation_error.lock().clone().map_or(Ok(()), Err)
    }
}

fn grouped_endpoint_counts(pairs: &[(FuncId, FuncId)]) -> AHashMap<FuncId, usize> {
    let mut counts = AHashMap::new();
    for (endpoint, _) in pairs {
        *counts.entry(*endpoint).or_insert(0) += 1;
    }
    counts
}

/// Read the complete exact callgraph summary one file partition at a time.
///
/// `source_inputs` is the validated compiler source generation: `(FileId,
/// path, content_hash)`. It proves freshness without opening Tree-sitter
/// bodies. Every persisted partition is still decoded and checked; only the
/// multi-million-edge resident adjacency graph is avoided.
pub fn callgraph_sidecar_summary_with_source_inputs(
    workspace_root: &Path,
    source_inputs: &[(u32, String, u64)],
) -> std::io::Result<Vec<CallgraphSidecarSummaryRow>> {
    let path = callgraph_sidecar_path(workspace_root);
    CallgraphQueryService::open_checked_with_source_inputs(&path, source_inputs)?.summary_rows()
}

#[must_use]
pub fn callgraph_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"))
}

pub(crate) fn save_callgraph_sidecar(
    path: &Path,
    db: &AnalyzerDb,
    graph: Arc<ResolvedCallGraph>,
) -> std::io::Result<()> {
    let mut node_files = AHashMap::new();
    // Retain compact positions into the immutable graph, not cloned graph
    // payloads. Each exact file partition is materialized only while its
    // factstore entry is synchronously encoded below.
    let mut partition_ordinals = BTreeMap::<u32, CallgraphPartitionOrdinals>::new();
    let mut identities = Vec::with_capacity(graph.nodes().len());
    let mut name_bucket_ordinals = BTreeMap::<u64, Vec<(usize, bool)>>::new();
    for (node_index, node) in graph.nodes().iter().enumerate() {
        if node_files.insert(node.func, node.file).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("callgraph contains duplicate function {}", node.func.raw()),
            ));
        }
        identities.push((node.func, node.file));
        name_bucket_ordinals
            .entry(name_bucket_key(node.name.as_ref()))
            .or_default()
            .push((node_index, false));
        if let Some(name) = node.qualified_name.as_deref() {
            name_bucket_ordinals
                .entry(name_bucket_key(name))
                .or_default()
                .push((node_index, true));
        }
        partition_ordinals
            .entry(node.file.raw())
            .or_default()
            .nodes
            .push(node_index);
    }
    for (edge_index, edge) in graph.inner().edges.iter().enumerate() {
        let from_file = node_files.get(&edge.from).copied().unwrap_or(edge.span.file);
        let Some(to_file) = node_files.get(&edge.to).copied() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("callgraph target {} has no persisted node", edge.to.raw()),
            ));
        };
        partition_ordinals
            .entry(from_file.raw())
            .or_default()
            .outgoing
            .push(edge_index);
        partition_ordinals
            .entry(to_file.raw())
            .or_default()
            .incoming
            .push(edge_index);
    }
    for (binding_index, binding) in graph.local_binding_records().iter().enumerate() {
        let Some(file) = node_files.get(&binding.caller).copied() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "callgraph callable binding caller {} has no persisted node",
                    binding.caller.raw()
                ),
            ));
        };
        partition_ordinals
            .entry(file.raw())
            .or_default()
            .local_bindings
            .push(binding_index);
    }
    for (site_index, site) in graph.unresolved_workspace_site_records().iter().enumerate() {
        let Some(file) = node_files.get(&site.caller).copied() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unresolved workspace caller {} has no persisted node",
                    site.caller.raw()
                ),
            ));
        };
        partition_ordinals
            .entry(file.raw())
            .or_default()
            .unresolved_workspace_sites
            .push(site_index);
    }
    identities.sort_unstable_by_key(|(function, _)| function.raw());
    let partition_files = partition_ordinals.keys().copied().collect::<Vec<_>>();
    let name_bucket_keys = name_bucket_ordinals.keys().copied().collect::<Vec<_>>();
    drop(node_files);
    let metadata = CallgraphMetadata {
        version: CALLGRAPH_CACHE_VERSION,
        matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
        files: current_source_fingerprints(db),
        dependency_metadata_fingerprint: dependency_metadata_fingerprint_for_sidecar(path),
        build_fingerprint: crate::build_fingerprint_hash(),
        partition_files,
        name_bucket_keys,
    };
    let pipeline_hash = metadata_pipeline_hash(&metadata);
    let entry_count = FIXED_ENTRY_COUNT
        .saturating_add(partition_ordinals.len())
        .saturating_add(name_bucket_ordinals.len());
    let writer =
        FactStoreWriter::create_with_capacity(path, CALLGRAPH_TABLE_ID, pipeline_hash, entry_count, 0, 0)
            .map_err(factstore_io)?;
    let metadata_bytes = wire::encode(&metadata).map_err(invalid_wire)?;
    writer
        .add_owned(METADATA_KEY, CALLGRAPH_CACHE_VERSION as u64, metadata_bytes)
        .map_err(factstore_io)?;
    writer
        .add_streamed(
            IDENTITY_TABLE_KEY,
            CALLGRAPH_CACHE_VERSION as u64,
            move |output| wire::encode_to_writer(output, &identities).map_err(invalid_wire),
        )
        .map_err(factstore_io)?;
    // Exact-name strings can dominate large Java monorepos. Retain only
    // compact node ordinals globally; materialize, persist, and free one hash
    // bucket before moving to the next.
    for (key, ordinals) in name_bucket_ordinals {
        let mut entries = BTreeMap::<String, Vec<FuncId>>::new();
        for (node_index, qualified) in ordinals {
            let node = &graph.nodes()[node_index];
            let name = if qualified {
                node.qualified_name
                    .as_deref()
                    .expect("qualified-name ordinal must reference a qualified node")
            } else {
                node.name.as_ref()
            };
            entries.entry(name.to_string()).or_default().push(node.func);
        }
        let entries = entries
            .into_iter()
            .map(|(name, mut functions)| {
                functions.sort_unstable_by_key(|function| function.raw());
                functions.dedup();
                (name, functions)
            })
            .collect();
        let bucket = CallgraphNameBucket { entries };
        writer
            .add_streamed(key, name_bucket_body_hash(key), move |output| {
                wire::encode_to_writer(output, &bucket).map_err(invalid_wire)
            })
            .map_err(factstore_io)?;
    }
    for (file, ordinals) in partition_ordinals {
        let mut partition = CallgraphFilePartition {
            file: FileId::new(file),
            nodes: ordinals
                .nodes
                .into_iter()
                .map(|index| graph.nodes()[index].clone())
                .collect(),
            outgoing: ordinals
                .outgoing
                .into_iter()
                .map(|index| graph.inner().edges[index].clone())
                .collect(),
            incoming: ordinals
                .incoming
                .into_iter()
                .map(|index| graph.inner().edges[index].clone())
                .collect(),
            local_bindings: ordinals
                .local_bindings
                .into_iter()
                .map(|index| graph.local_binding_records()[index].clone())
                .collect(),
            unresolved_workspace_sites: ordinals
                .unresolved_workspace_sites
                .into_iter()
                .map(|index| graph.unresolved_workspace_site_records()[index])
                .collect(),
        };
        sort_partition(&mut partition);
        writer
            .add_streamed(
                file_partition_key(file),
                partition_body_hash(file),
                move |output| wire::encode_to_writer(output, &partition).map_err(invalid_wire),
            )
            .map_err(factstore_io)?;
    }
    writer.finish().map_err(factstore_io)?;
    // The current artifact is durable before cleanup starts. Cache migration
    // is best-effort: an inability to remove an obsolete file must not turn a
    // successfully persisted compiler graph into an analysis failure.
    let _ = prune_obsolete_callgraph_sidecars(path);
    Ok(())
}

fn prune_obsolete_callgraph_sidecars(current_path: &Path) -> std::io::Result<()> {
    let Some(cache_dir) = current_path.parent() else {
        return Ok(());
    };
    for entry in std::fs::read_dir(cache_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path() == current_path {
            continue;
        }
        let Some(version) = callgraph_sidecar_version(&entry.file_name()) else {
            continue;
        };
        if version < CALLGRAPH_CACHE_VERSION {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn callgraph_sidecar_version(file_name: &std::ffi::OsStr) -> Option<u32> {
    let file_name = file_name.to_str()?;
    let version_and_extension = file_name.strip_prefix("callgraph.v")?;
    let (version, extension) = version_and_extension.split_once('.')?;
    (!extension.is_empty()).then_some(())?;
    version.parse().ok()
}

/// Load and validate the exact current graph while preserving the concrete
/// miss/decode error for compiler warm-up orchestration.
pub(crate) fn load_callgraph_sidecar_checked(
    path: &Path,
    db: &AnalyzerDb,
) -> std::io::Result<ResolvedCallGraph> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    if current_source_fingerprints(db) != metadata.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    decode_graph(&reader, &metadata)
}

/// Validate exact workspace freshness without reading the graph payload.
pub(crate) fn validate_callgraph_sidecar_for_db(path: &Path, db: &AnalyzerDb) -> std::io::Result<()> {
    let (_reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    if current_source_fingerprints(db) != metadata.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    Ok(())
}

/// Validate that a callgraph sidecar is structurally readable and was
/// produced by the current callgraph/matcher pipeline. This exhaustive
/// validator decodes the graph payload; warm-up uses the metadata-only exact
/// workspace validator above.
pub fn validate_callgraph_sidecar_file(path: &Path) -> std::io::Result<usize> {
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    let graph = decode_graph(&reader, &metadata)?;
    Ok(graph.inner().edges.len())
}

/// Exhaustively validate a callgraph sidecar against an explicit source set.
pub fn validate_callgraph_sidecar_file_with_source_fingerprints<I, P>(
    path: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    validate_callgraph_sidecar_metadata_with_source_fingerprints(path, fingerprints)?;
    let (reader, metadata) = open_sidecar(path)?;
    let graph = decode_graph(&reader, &metadata)?;
    Ok(graph.inner().edges.len())
}

/// Validate callgraph schema, compiler inputs, and source identity without
/// decoding the graph payload.
///
/// Query-time graph loading still decodes and validates the exact payload.
/// Cache planning uses this metadata-only contract so deciding whether a
/// multi-gigabyte artifact is reusable does not itself materialize it.
pub fn validate_callgraph_sidecar_metadata_with_source_fingerprints<I, P>(
    path: &Path,
    fingerprints: I,
) -> std::io::Result<()>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let (reader, metadata) = open_sidecar(path)?;
    validate_metadata(path, &metadata)?;
    let mut current: Vec<(String, u64)> = fingerprints
        .into_iter()
        .map(|(path, hash)| (path.as_ref().display().to_string(), hash))
        .collect();
    current.sort();
    if current != metadata.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    drop(reader);
    Ok(())
}

fn open_sidecar(path: &Path) -> std::io::Result<(FactStoreReader, CallgraphMetadata)> {
    let reader = FactStoreReader::open_relaxed(path).map_err(factstore_io)?;
    if reader.header().table_id != CALLGRAPH_TABLE_ID {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar factstore table mismatch",
        ));
    }
    if !reader.contains_key(METADATA_KEY) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar metadata is missing",
        ));
    }
    let hit = reader.get(METADATA_KEY).map_err(factstore_io)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar metadata is missing",
        )
    })?;
    if hit.body_hash != CALLGRAPH_CACHE_VERSION as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar metadata body version mismatch",
        ));
    }
    let metadata: CallgraphMetadata = wire::decode(&hit.payload).map_err(invalid_wire)?;
    let expected_entries = FIXED_ENTRY_COUNT
        .saturating_add(metadata.partition_files.len())
        .saturating_add(metadata.name_bucket_keys.len());
    if reader.len() != expected_entries
        || !reader.contains_key(IDENTITY_TABLE_KEY)
        || metadata
            .partition_files
            .iter()
            .any(|file| !reader.contains_key(file_partition_key(*file)))
        || metadata
            .name_bucket_keys
            .iter()
            .any(|key| !reader.contains_key(*key))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar entry layout mismatch",
        ));
    }
    if reader.header().pipeline_hash != metadata_pipeline_hash(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar pipeline fingerprint mismatch",
        ));
    }
    Ok((reader, metadata))
}

fn decode_identities(reader: &FactStoreReader) -> std::io::Result<Vec<(FuncId, FileId)>> {
    let mut payload = reader
        .payload_reader(IDENTITY_TABLE_KEY)
        .map_err(factstore_io)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "callgraph sidecar identity table is missing",
            )
        })?;
    if payload.body_hash != CALLGRAPH_CACHE_VERSION as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar identity-table body version mismatch",
        ));
    }
    let identities = wire::decode_from_reader(&mut payload).map_err(invalid_wire)?;
    let mut trailing = [0u8; 1];
    if payload.read(&mut trailing)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar identity table has trailing bytes",
        ));
    }
    Ok(identities)
}

fn decode_name_bucket(reader: &FactStoreReader, key: u64) -> std::io::Result<CallgraphNameBucket> {
    let hit = reader.get(key).map_err(factstore_io)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph name bucket is missing",
        )
    })?;
    if hit.body_hash != name_bucket_body_hash(key) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph name bucket body version mismatch",
        ));
    }
    let bucket: CallgraphNameBucket = wire::decode(&hit.payload).map_err(invalid_wire)?;
    if bucket.entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || bucket.entries.iter().any(|(name, functions)| {
            name_bucket_key(name) != key
                || functions.is_empty()
                || functions.windows(2).any(|pair| pair[0].raw() >= pair[1].raw())
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph name bucket is not canonical",
        ));
    }
    Ok(bucket)
}

fn decode_partition(reader: &FactStoreReader, file: u32) -> std::io::Result<CallgraphFilePartition> {
    let hit = reader
        .get(file_partition_key(file))
        .map_err(factstore_io)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("callgraph file partition {file} is missing"),
            )
        })?;
    if hit.body_hash != partition_body_hash(file) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("callgraph file partition {file} body version mismatch"),
        ));
    }
    let partition: CallgraphFilePartition = wire::decode(&hit.payload).map_err(invalid_wire)?;
    if partition.file.raw() != file {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("callgraph file partition key/payload mismatch: {file}"),
        ));
    }
    if partition.nodes.iter().any(|node| node.file != partition.file) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("callgraph file partition {file} contains a foreign callable node"),
        ));
    }
    Ok(partition)
}

fn decode_graph(
    reader: &FactStoreReader,
    metadata: &CallgraphMetadata,
) -> std::io::Result<ResolvedCallGraph> {
    let identities = decode_identities(reader)?;
    if identities
        .windows(2)
        .any(|pair| pair[0].0.raw() >= pair[1].0.raw())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph identity table is not strictly sorted",
        ));
    }
    let mut nodes = Vec::with_capacity(identities.len());
    let mut edges = Vec::new();
    let mut local_bindings = Vec::new();
    let mut unresolved_workspace_sites = Vec::new();
    for file in &metadata.partition_files {
        let partition = decode_partition(reader, *file)?;
        nodes.extend(partition.nodes);
        edges.extend(partition.outgoing);
        local_bindings.extend(partition.local_bindings);
        unresolved_workspace_sites.extend(partition.unresolved_workspace_sites);
    }
    nodes.sort_unstable_by_key(|node| node.func.raw());
    let decoded_identities = nodes
        .iter()
        .map(|node| (node.func, node.file))
        .collect::<Vec<_>>();
    if decoded_identities != identities {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph identity table does not match file-partitioned callable nodes",
        ));
    }
    let nodes_by_id = nodes
        .iter()
        .map(|node| (node.func, node))
        .collect::<AHashMap<_, _>>();
    for key in &metadata.name_bucket_keys {
        for (name, functions) in decode_name_bucket(reader, *key)?.entries {
            for function in functions {
                let Some(node) = nodes_by_id.get(&function) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "callgraph name bucket references unknown function {}",
                            function.raw()
                        ),
                    ));
                };
                if node.name.as_ref() != name.as_str()
                    && node.qualified_name.as_deref() != Some(name.as_str())
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "callgraph name bucket maps {name:?} to mismatched function {}",
                            function.raw()
                        ),
                    ));
                }
            }
        }
    }
    Ok(ResolvedCallGraph::from_persisted_parts(
        nodes,
        edges,
        local_bindings,
        unresolved_workspace_sites,
    ))
}

fn validate_metadata(path: &Path, metadata: &CallgraphMetadata) -> std::io::Result<()> {
    if metadata.version != CALLGRAPH_CACHE_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "callgraph sidecar version mismatch: file={} expected={}",
                metadata.version, CALLGRAPH_CACHE_VERSION
            ),
        ));
    }
    if metadata.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar matcher policy fingerprint mismatch",
        ));
    }
    if metadata.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar dependency metadata fingerprint mismatch",
        ));
    }
    if metadata.partition_files.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph partition file table is not strictly sorted",
        ));
    }
    if metadata
        .name_bucket_keys
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || metadata
            .name_bucket_keys
            .iter()
            .any(|key| key & !KEY_PAYLOAD_MASK != NAME_BUCKET_KEY_BASE)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph name-bucket key table is not canonical",
        ));
    }
    Ok(())
}

fn metadata_pipeline_hash(metadata: &CallgraphMetadata) -> u64 {
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(b"bonsai-callgraph-sidecar-v20");
    hasher.absorb_separator();
    hasher.absorb(&metadata.version.to_le_bytes());
    hasher.absorb(&metadata.matcher_policy_fingerprint.to_le_bytes());
    hasher.absorb(&metadata.dependency_metadata_fingerprint.to_le_bytes());
    // Bind the header to the recorded producer so metadata tampering cannot
    // preserve the artifact hash. This is an integrity/provenance field, not
    // a comparison against the currently running binary.
    hasher.absorb(&metadata.build_fingerprint.to_le_bytes());
    for (path, content_hash) in &metadata.files {
        hasher.absorb(path.as_bytes());
        hasher.absorb_separator();
        hasher.absorb(&content_hash.to_le_bytes());
        hasher.absorb_separator();
    }
    for file in &metadata.partition_files {
        hasher.absorb(&file.to_le_bytes());
        hasher.absorb_separator();
    }
    for key in &metadata.name_bucket_keys {
        hasher.absorb(&key.to_le_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

fn file_partition_key(file: u32) -> u64 {
    FILE_PARTITION_KEY_BASE | u64::from(file)
}

fn partition_body_hash(file: u32) -> u64 {
    (u64::from(CALLGRAPH_CACHE_VERSION) << 32) | u64::from(file)
}

fn name_bucket_key(name: &str) -> u64 {
    NAME_BUCKET_KEY_BASE | (fnv1a_bytes64(name.as_bytes()) & KEY_PAYLOAD_MASK)
}

fn name_bucket_body_hash(key: u64) -> u64 {
    (u64::from(CALLGRAPH_CACHE_VERSION) << 32) ^ key
}

fn sort_partition(partition: &mut CallgraphFilePartition) {
    let edge_key = |edge: &CallEdge| {
        (
            edge.from.raw(),
            edge.to.raw(),
            edge.span.file.raw(),
            edge.span.start,
            edge.span.end,
            edge.kind as u8,
            edge.precision.rank(),
        )
    };
    partition.outgoing.sort_unstable_by_key(edge_key);
    partition.incoming.sort_unstable_by_key(edge_key);
    partition.nodes.sort_unstable_by_key(|node| node.func.raw());
    partition.nodes.dedup_by_key(|node| node.func.raw());
    partition.local_bindings.sort();
    partition.local_bindings.dedup();
    partition.unresolved_workspace_sites.sort_unstable();
    partition.unresolved_workspace_sites.dedup();
}

fn current_source_fingerprints(db: &AnalyzerDb) -> Vec<(String, u64)> {
    let mut files = Vec::new();
    for file in db.vfs().all_files() {
        let Ok(snapshot) = db.vfs().snapshot(file) else {
            continue;
        };
        let Ok(path) = db.vfs().path(file) else {
            continue;
        };
        files.push((
            path.to_string_lossy().into_owned(),
            fnv1a_bytes64(snapshot.text.as_bytes()),
        ));
    }
    files.sort();
    files
}

fn invalid_wire(error: impl std::error::Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn factstore_io(error: bonsai_factstore::FactStoreError) -> std::io::Error {
    match error {
        bonsai_factstore::FactStoreError::Io(error) => error,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_callgraph::{EdgeKind, EdgeProvenance};
    use bonsai_common::{Precision, Span};
    use bonsai_lang_api::{DeclKind, LanguageRegistry};
    use bonsai_vfs::Vfs;

    fn node(function: u32, file: u32, name: &str) -> CallGraphNode {
        CallGraphNode {
            func: FuncId::new(function),
            name: name.into(),
            qualified_name: None,
            kind: DeclKind::Function,
            file: FileId::new(file),
            name_span: Span::new(FileId::new(file), 0, name.len() as u64),
        }
    }

    fn edge(from: u32, to: u32, caller_file: u32, precision: Precision) -> CallEdge {
        CallEdge {
            from: FuncId::new(from),
            to: FuncId::new(to),
            span: Span::new(FileId::new(caller_file), 10, 14),
            kind: EdgeKind::Direct,
            precision,
            provenance: EdgeProvenance::direct_symbol(),
        }
    }

    fn empty_db() -> AnalyzerDb {
        AnalyzerDb::new(Arc::new(Vfs::new()), Arc::new(LanguageRegistry::new()))
    }

    #[test]
    fn successful_schema_migration_prunes_only_older_callgraph_sidecars() {
        let root = tempfile::tempdir().expect("tempdir");
        let cache_dir = root.path().join(".bonsai");
        std::fs::create_dir(&cache_dir).expect("create cache dir");
        let current = cache_dir.join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"));
        let older_factstore = cache_dir.join(format!("callgraph.v{}.factstore", CALLGRAPH_CACHE_VERSION - 1));
        let older_wire = cache_dir.join(format!("callgraph.v{}.msgpack", CALLGRAPH_CACHE_VERSION - 2));
        let newer = cache_dir.join(format!("callgraph.v{}.factstore", CALLGRAPH_CACHE_VERSION + 1));
        let unrelated = cache_dir.join("idg.v11.factstore");
        for path in [&current, &older_factstore, &older_wire, &newer, &unrelated] {
            std::fs::write(path, b"fixture").expect("write fixture");
        }

        prune_obsolete_callgraph_sidecars(&current).expect("prune obsolete sidecars");

        assert!(current.is_file());
        assert!(!older_factstore.exists());
        assert!(!older_wire.exists());
        assert!(newer.is_file(), "a newer binary may still need its artifact");
        assert!(unrelated.is_file());
    }

    #[test]
    fn sidecar_version_parser_rejects_unversioned_and_extensionless_names() {
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("callgraph.v12.msgpack")),
            Some(12)
        );
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("callgraph.msgpack")),
            None
        );
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("callgraph.v12")),
            None
        );
        assert_eq!(
            callgraph_sidecar_version(std::ffi::OsStr::new("idg.v12.factstore")),
            None
        );
    }

    #[test]
    fn producer_identity_is_provenance_not_semantic_freshness() {
        let root = tempfile::tempdir().expect("tempdir");
        let cache_dir = root.path().join(".bonsai");
        std::fs::create_dir(&cache_dir).expect("create cache dir");
        let path = cache_dir.join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"));
        let metadata = CallgraphMetadata {
            version: CALLGRAPH_CACHE_VERSION,
            matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
            files: Vec::new(),
            dependency_metadata_fingerprint: dependency_metadata_fingerprint_for_sidecar(&path),
            build_fingerprint: crate::build_fingerprint_hash() ^ 1,
            partition_files: Vec::new(),
            name_bucket_keys: Vec::new(),
        };

        validate_metadata(&path, &metadata)
            .expect("an unrelated producer build must not invalidate exact compiler inputs");
    }

    #[test]
    fn partitioned_sidecar_round_trips_and_queries_exact_graph_regions() {
        let root = tempfile::tempdir().expect("tempdir");
        let cache_dir = root.path().join(".bonsai");
        std::fs::create_dir(&cache_dir).expect("create cache dir");
        let path = cache_dir.join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.factstore"));
        let nodes = vec![
            node(1, 1, "start"),
            node(2, 2, "middle"),
            node(3, 3, "end"),
            node(4, 4, "unrelated_start"),
            node(5, 5, "unrelated_end"),
            node(6, 6, "diagnostic_only_target"),
        ];
        let edges = vec![
            edge(1, 2, 1, Precision::Exact),
            edge(2, 3, 2, Precision::Narrowed),
            edge(4, 5, 4, Precision::Exact),
            edge(1, 6, 1, Precision::OverApproximate),
        ];
        let graph = ResolvedCallGraph::from_persisted_parts(
            nodes,
            edges,
            vec![CallGraphLocalBinding {
                caller: FuncId::new(2),
                name: "callback".into(),
                target: FuncId::new(3),
            }],
            vec![UnresolvedWorkspaceCallSite {
                caller: FuncId::new(2),
                span: Span::new(FileId::new(2), 20, 24),
            }],
        );
        let db = empty_db();
        save_callgraph_sidecar(&path, &db, Arc::new(graph)).expect("save partitioned graph");

        let decoded = load_callgraph_sidecar_checked(&path, &db).expect("load complete graph");
        assert_eq!(decoded.nodes().len(), 6);
        assert_eq!(decoded.inner().edges.len(), 4);
        assert_eq!(decoded.local_binding_records().len(), 1);
        assert_eq!(decoded.unresolved_workspace_site_records().len(), 1);

        let service = CallgraphQueryService::open_checked(&path, &db).expect("open query service");
        for raw in 1..=6 {
            let function = FuncId::new(raw);
            let resident_callees = decoded
                .callees_of(function)
                .map(call_edge_semantic_tuple)
                .collect::<Vec<_>>();
            let mut partitioned_callees = Vec::new();
            service.visit_callees(function, &mut |edge| {
                partitioned_callees.push(call_edge_semantic_tuple(edge));
            });
            assert_eq!(partitioned_callees, resident_callees);

            let resident_callers = decoded
                .callers_of(function)
                .map(call_edge_semantic_tuple)
                .collect::<Vec<_>>();
            let mut partitioned_callers = Vec::new();
            service.visit_callers(function, &mut |edge| {
                partitioned_callers.push(call_edge_semantic_tuple(edge));
            });
            assert_eq!(partitioned_callers, resident_callers);
        }
        let mut partitioned_bindings = Vec::new();
        service.visit_local_callable_bindings(&mut |caller, alias, target| {
            partitioned_bindings.push((caller, alias.to_string(), target));
        });
        assert_eq!(
            partitioned_bindings,
            decoded
                .local_callable_bindings()
                .map(|(caller, alias, target)| (caller, alias.to_string(), target))
                .collect::<Vec<_>>()
        );
        service.check_error().expect("partitioned relation remains valid");
        assert_eq!(
            service
                .callable_nodes_named("start")
                .expect("query exact callable name")
                .iter()
                .map(|node| node.func)
                .collect::<Vec<_>>(),
            vec![FuncId::new(1)]
        );
        let called = service
            .functions_with_semantic_callers(&[
                FuncId::new(1),
                FuncId::new(2),
                FuncId::new(3),
                FuncId::new(4),
                FuncId::new(5),
                FuncId::new(6),
            ])
            .expect("query incoming partitions");
        assert_eq!(
            called,
            [FuncId::new(2), FuncId::new(3), FuncId::new(5)]
                .into_iter()
                .collect()
        );
        assert_eq!(
            service
                .summary_rows()
                .expect("summarize exact partitions")
                .into_iter()
                .map(|row| (row.function.raw(), row.callers, row.outgoing))
                .collect::<Vec<_>>(),
            vec![(1, 0, 1), (2, 1, 1), (3, 1, 0), (4, 0, 1), (5, 1, 0), (6, 0, 0),],
            "summary degrees must deduplicate semantic endpoints and exclude over-approximate edges"
        );

        let mut visited_files = Vec::new();
        let mut visited_outgoing = Vec::new();
        let mut visited_unresolved = Vec::new();
        service
            .visit_partitions(|file, _nodes, outgoing, _incoming, unresolved| {
                visited_files.push(file);
                visited_outgoing.extend(outgoing.iter().map(|edge| (edge.from, edge.to)));
                visited_unresolved.extend(unresolved.iter().copied());
            })
            .expect("visit exact graph partitions");
        assert_eq!(
            visited_files,
            (1..=6).map(FileId::new).collect::<Vec<_>>(),
            "partition traversal must be canonical and exhaustive"
        );
        assert_eq!(
            visited_outgoing,
            vec![
                (FuncId::new(1), FuncId::new(2)),
                (FuncId::new(1), FuncId::new(6)),
                (FuncId::new(2), FuncId::new(3)),
                (FuncId::new(4), FuncId::new(5)),
            ]
        );
        assert_eq!(
            visited_unresolved,
            vec![UnresolvedWorkspaceCallSite {
                caller: FuncId::new(2),
                span: Span::new(FileId::new(2), 20, 24),
            }]
        );

        let reachable = service
            .materialize_reachable(&[FuncId::new(1)])
            .expect("query outgoing fixed point");
        assert_eq!(reachable.inner().edges.len(), 3);
        assert!(reachable
            .nodes()
            .iter()
            .all(|node| node.func.raw() <= 3 || node.func.raw() == 6));
        assert!(reachable
            .nodes()
            .iter()
            .all(|node| node.func.raw() != 4 && node.func.raw() != 5));
        assert_eq!(reachable.local_binding_records().len(), 1);
        assert_eq!(reachable.unresolved_workspace_site_records().len(), 1);

        let between = service
            .materialize_between(&[FuncId::new(1)], &[FuncId::new(3)])
            .expect("query exact source-to-target slice");
        assert_eq!(
            between
                .inner()
                .edges
                .iter()
                .map(|edge| (edge.from, edge.to))
                .collect::<Vec<_>>(),
            vec![(FuncId::new(1), FuncId::new(2)), (FuncId::new(2), FuncId::new(3)),]
        );
        assert_eq!(
            between.nodes().iter().map(|node| node.func).collect::<Vec<_>>(),
            vec![FuncId::new(1), FuncId::new(2), FuncId::new(3)]
        );
        assert_eq!(between.local_binding_records().len(), 1);
        assert_eq!(between.unresolved_workspace_site_records().len(), 1);

        let direct = service
            .materialize_direct_between(&[FuncId::new(1)], &[FuncId::new(2), FuncId::new(3)])
            .expect("query every direct minimum-hop path");
        assert_eq!(
            direct
                .inner()
                .edges
                .iter()
                .map(|edge| (edge.from, edge.to))
                .collect::<Vec<_>>(),
            vec![(FuncId::new(1), FuncId::new(2))]
        );
        assert_eq!(
            direct.nodes().iter().map(|node| node.func).collect::<Vec<_>>(),
            vec![FuncId::new(1), FuncId::new(2)]
        );

        let disconnected = service
            .materialize_between(&[FuncId::new(1)], &[FuncId::new(5)])
            .expect("query disconnected source-to-target slice");
        assert!(disconnected.nodes().is_empty());
        assert!(disconnected.inner().edges.is_empty());
    }

    fn call_edge_semantic_tuple(edge: &CallEdge) -> (FuncId, FuncId, Span, EdgeKind, Precision, String, u8) {
        (
            edge.from,
            edge.to,
            edge.span,
            edge.kind,
            edge.precision,
            edge.provenance.resolver_stage().to_string(),
            edge.provenance.confidence(),
        )
    }
}
