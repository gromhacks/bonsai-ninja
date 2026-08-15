//! Process resource detection and memory-aware compiler scheduling.
//!
//! Memory limits are scheduling inputs only. They may reduce the number of
//! parser, lowering, or serialization jobs in flight, but must never reduce
//! the source-file set, graph scope, fixed-point closure, or rendered facts.

use std::{
    ops::Range,
    sync::{Condvar, Mutex, MutexGuard, OnceLock},
};

const BYTES_PER_MIB: u64 = 1024 * 1024;
const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;
const SYNTAX_UNIT_TRANSIENT_BYTES: u64 = 768 * BYTES_PER_MIB;
const SYNTAX_RESIDENT_RESERVE_BYTES: u64 = 512 * BYTES_PER_MIB;
const COMPILER_UNIT_TRANSIENT_BYTES: u64 = BYTES_PER_GIB;
const COMPILER_RESIDENT_RESERVE_BYTES: u64 = 2 * BYTES_PER_GIB;
// Call resolution retains the same immutable symbol/path indexes regardless
// of worker count. Each worker owns only one file's resolver caches, decoded
// compiler object, and edge buffer. An exact 30,055-file Elasticsearch build
// measured 2.58 GiB RSS with ten concurrent resolvers, leaving roughly
// 430 MiB inside the 3 GiB production budget; the earlier 512 MiB estimate
// serialized the same graph behind two workers and doubled cold latency.
// Keep the measured per-worker allowance distinct from parser/lowering
// arenas: this changes concurrency only, never files, edges, or resolution.
const CALLGRAPH_RESOLVER_UNIT_TRANSIENT_BYTES: u64 = 96 * BYTES_PER_MIB;
const CALLGRAPH_RESOLVER_RESIDENT_RESERVE_BYTES: u64 = 2 * BYTES_PER_GIB;
// Retrieval retains its compact snapshot builder and the resolved graph while
// workers decode one exact compiler object into file-local candidate terms.
// Elasticsearch measured 2.17 GiB RSS with ten workers, leaving more than
// 850 MiB in a 3 GiB budget. Keep a separate named profile so future changes
// to either resolver or candidate representations cannot silently couple
// their schedules.
const CANDIDATE_INDEX_UNIT_TRANSIENT_BYTES: u64 = 96 * BYTES_PER_MIB;
const CANDIDATE_INDEX_RESIDENT_RESERVE_BYTES: u64 = 2 * BYTES_PER_GIB;
const SEMANTIC_QUERY_TRANSIENT_BYTES: u64 = 384 * BYTES_PER_MIB;
// An entry-rooted query cannot escape into arbitrary callers and its sparse
// worklists spill independently. Elasticsearch's exact 12,355-entry inspect
// gate measures ~80 MiB of incremental RSS per concurrent rooted closure;
// retain 128 MiB for allocator/page-cache variance. Generic rule-matched
// sources keep the heavier profile above because they intentionally propagate
// into every resolved caller.
const ROOTED_SEMANTIC_QUERY_TRANSIENT_BYTES: u64 = 128 * BYTES_PER_MIB;
// Rooted closures read persisted IDG relations through reclaimable file-backed
// pages. Charging those pages as permanent live RSS makes concurrency depend
// on whichever relation happened to be touched most recently and serialized
// Elasticsearch's exact inspect query behind one worker. Reserve the measured
// non-reclaimable compiler/linkage/output working set instead; the remaining
// budget schedules bounded sparse closure frontiers. Subject to available CPU
// parallelism, a 3 GiB machine admits up to ten 128 MiB closures, a 2 GiB
// machine up to two, and a 1 GiB machine remains safely serial. This changes
// scheduling only.
const ROOTED_SEMANTIC_QUERY_RESIDENT_RESERVE_BYTES: u64 = 7 * BYTES_PER_GIB / 4;
const SEMANTIC_QUERY_MIN_RESERVE_BYTES: u64 = 768 * BYTES_PER_MIB;
const WEIGHTED_COMPILER_UNIT_BASE_BYTES: u64 = 64 * BYTES_PER_MIB;
const WEIGHTED_COMPILER_SOURCE_AMPLIFICATION: u64 = 40;
const WEIGHTED_COMPILER_MIN_HEADROOM_BYTES: u64 = 128 * BYTES_PER_MIB;
// Retain one quarter of the process budget for allocator variance, immutable
// graph growth after the schedule is chosen, and platform runtime overhead.
// Elasticsearch's 22.5M-edge IDG measured only 18 MiB below a 3 GiB budget
// with the former one-fifth reserve; that margin was not portable across
// allocators or kernels. This changes batch width only—never compiler work.
const WEIGHTED_COMPILER_HEADROOM_DIVISOR: u64 = 4;
const WEIGHTED_SYNTAX_HEADROOM_BYTES: u64 = 384 * BYTES_PER_MIB;
const SOURCE_INGESTION_COPY_AMPLIFICATION: u64 = 2;
const SOURCE_INGESTION_MIN_HEADROOM_BYTES: u64 = 128 * BYTES_PER_MIB;

/// Return the effective memory limit available to the analyzer process.
///
/// `BONSAI_MEMORY_BUDGET_MB` may lower the detected host/container limit but
/// can never raise it. The detector uses the smaller of physical memory and a
/// Linux cgroup v1/v2 limit when those values are available. Unsupported
/// platforms return `None` unless an explicit budget is configured, which
/// leaves callers on CPU-based scheduling instead of guessing a semantic
/// limit.
#[must_use]
pub fn effective_memory_limit_bytes() -> Option<u64> {
    static DETECTED: OnceLock<Option<u64>> = OnceLock::new();
    *DETECTED.get_or_init(|| min_present(configured_memory_limit_bytes(), detect_memory_limit_bytes()))
}

/// Bound a compiler phase's worker count by both CPU parallelism and memory.
///
/// `reserved_bytes` covers state already retained by the phase, while
/// `bytes_per_worker` estimates the largest transient owned by one worker.
/// The result is always at least one: a low-memory machine performs the same
/// work serially rather than silently dropping compiler facts.
#[must_use]
pub fn memory_bounded_worker_count(cpu_workers: usize, bytes_per_worker: u64, reserved_bytes: u64) -> usize {
    worker_count_for_limit(
        cpu_workers,
        bytes_per_worker,
        reserved_bytes,
        effective_memory_limit_bytes(),
    )
}

/// Bound concurrent Tree-sitter/compiler units using the shared production
/// memory profile.
///
/// Parsing, lowering, call resolution, IDG transfer, and candidate indexing
/// all temporarily own roughly the same shape: one file/segment's CST or
/// lowered IR plus output buffers. Keeping one profile prevents an early phase
/// from overcommitting memory that a later phase already schedules safely. A
/// 3 GiB process budget therefore executes one exact unit at a time; larger
/// machines gain parallelism without changing analyzed files or emitted facts.
#[must_use]
pub fn compiler_worker_count(cpu_workers: usize) -> usize {
    compiler_worker_count_for_limit(cpu_workers, effective_memory_limit_bytes())
}

/// Bound exact call-resolution concurrency by its measured per-file working
/// set rather than the heavier parser/lowering profile.
///
/// Resolver workers share immutable compiler headers and class indexes. The
/// memory budget changes only the number of file-local caches in flight;
/// every caller and edge is still resolved.
#[must_use]
pub fn callgraph_worker_count(cpu_workers: usize) -> usize {
    callgraph_worker_count_for_limit(cpu_workers, effective_memory_limit_bytes())
}

/// Bound exact retrieval-candidate projection concurrency.
///
/// Candidate workers decode adapter-lowered compiler objects and emit only
/// file-local terms. The compact workspace snapshot is retained by the
/// coordinator, so this uses its own measured resource profile rather than a
/// parser arena's deliberately heavier estimate.
#[must_use]
pub fn candidate_index_worker_count(cpu_workers: usize) -> usize {
    candidate_index_worker_count_for_limit(cpu_workers, effective_memory_limit_bytes())
}

/// Bound independent exact semantic closures by the process's current
/// resident graph plus a measured spill/worklist allowance per query.
///
/// Callers should invoke this after hydrating shared immutable query indexes.
/// A constrained process runs the same entries serially; more memory changes
/// only concurrency, never graph scope or fixed-point completion.
#[must_use]
pub fn semantic_query_worker_count(cpu_workers: usize) -> usize {
    let resident = current_process_resident_bytes()
        .unwrap_or(SEMANTIC_QUERY_MIN_RESERVE_BYTES)
        .max(SEMANTIC_QUERY_MIN_RESERVE_BYTES);
    memory_bounded_worker_count(cpu_workers, SEMANTIC_QUERY_TRANSIENT_BYTES, resident)
}

/// Bound independent entry-rooted semantic closures by their non-reclaimable
/// resident profile.
///
/// Persisted IDG relation pages are file-backed and reclaimable, so live RSS
/// is not a stable measure of memory committed by this phase. This is a
/// scheduling distinction, not a semantic shortcut: each worker still runs
/// one complete context-matched fixed point, and constrained hosts execute the
/// identical entry sequence with less concurrency.
#[must_use]
pub fn rooted_semantic_query_worker_count(cpu_workers: usize) -> usize {
    rooted_semantic_query_worker_count_for_limit(cpu_workers, effective_memory_limit_bytes())
}

fn rooted_semantic_query_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    worker_count_for_limit(
        cpu_workers,
        ROOTED_SEMANTIC_QUERY_TRANSIENT_BYTES,
        ROOTED_SEMANTIC_QUERY_RESIDENT_RESERVE_BYTES,
        limit,
    )
}

/// Partition source units into deterministic, memory-weighted parallel
/// batches.
///
/// Unlike a single worst-case cost per worker, this accounts for the actual
/// byte size of each compilation unit. Small files can compile concurrently;
/// a very large file automatically runs alone. The returned ranges cover every
/// input exactly once and preserve source order, so this is purely a resource
/// schedule and cannot alter compiler semantics.
#[must_use]
pub fn compiler_weighted_batches(source_bytes: &[u64], cpu_workers: usize) -> Vec<Range<usize>> {
    compiler_weighted_batches_for_limit_and_resident(
        source_bytes,
        cpu_workers.max(1),
        effective_memory_limit_bytes(),
        current_process_resident_bytes(),
    )
}

/// Partition Tree-sitter frontend units by their measured source sizes and
/// the process's current resident working set.
///
/// Unlike [`syntax_worker_count`], this scheduler can safely keep several
/// small files in flight while isolating a large file. Every returned range
/// covers the input exactly once; memory changes batching only.
#[must_use]
pub fn syntax_weighted_batches(source_bytes: &[u64], cpu_workers: usize) -> Vec<Range<usize>> {
    syntax_weighted_batches_for_limit_and_resident(
        source_bytes,
        cpu_workers,
        effective_memory_limit_bytes(),
        current_process_resident_bytes(),
    )
}

/// Choose a continuous Tree-sitter worker width from the largest actual
/// source units in a phase.
///
/// This is the non-barrier companion to [`syntax_weighted_batches`]. A caller
/// that can stream results directly may submit its complete worklist to one
/// pool: sizing against the largest `N` units proves that every possible set
/// of concurrently scheduled files fits the same live-memory envelope. The
/// returned width is always at least one, so memory changes scheduling only.
#[must_use]
pub fn syntax_worker_count_for_sources(source_bytes: &[u64], cpu_workers: usize) -> usize {
    syntax_worker_count_for_sources_and_limit(
        source_bytes,
        cpu_workers,
        effective_memory_limit_bytes(),
        current_process_resident_bytes(),
    )
}

/// Continuous memory-weighted admission for exact syntax/compiler work.
///
/// Unlike a single worst-case pool width, this gate lets many small units run
/// together while preventing large units from exceeding the same detected
/// working-memory envelope. It controls concurrency only: every caller still
/// submits every unit to its work-stealing pool.
#[derive(Debug)]
pub struct SyntaxMemoryPermitPool {
    capacity_bytes: Option<u64>,
    used_bytes: Mutex<u64>,
    available: Condvar,
}

impl SyntaxMemoryPermitPool {
    /// Build a gate from the current process resident set and configured or
    /// detected memory limit.
    #[must_use]
    pub fn for_current_process() -> Self {
        Self::with_capacity(syntax_working_memory_bytes(
            effective_memory_limit_bytes(),
            current_process_resident_bytes(),
        ))
    }

    fn with_capacity(capacity_bytes: Option<u64>) -> Self {
        Self {
            capacity_bytes,
            used_bytes: Mutex::new(0),
            available: Condvar::new(),
        }
    }

    /// Wait until the exact source unit fits, then retain its permit until the
    /// returned guard is dropped. An oversize unit consumes the whole budget
    /// and therefore runs alone rather than being skipped or split.
    #[must_use]
    pub fn acquire(&self, source_bytes: u64) -> SyntaxMemoryPermit<'_> {
        let Some(capacity) = self.capacity_bytes else {
            return SyntaxMemoryPermit {
                pool: self,
                admitted_bytes: 0,
            };
        };
        let admitted_bytes = weighted_compiler_unit_bytes(source_bytes).min(capacity);
        let mut used = lock_unpoisoned(&self.used_bytes);
        while *used > 0 && used.saturating_add(admitted_bytes) > capacity {
            used = wait_unpoisoned(&self.available, used);
        }
        *used = used.saturating_add(admitted_bytes);
        SyntaxMemoryPermit {
            pool: self,
            admitted_bytes,
        }
    }

    /// Admit one exact source unit immediately when it fits the current
    /// working-memory envelope.
    ///
    /// Callers with ordered output pipelines use this to fill idle worker
    /// slots without blocking the thread that must consume completed units
    /// and release their permits. An oversize unit is admitted when the pool
    /// is otherwise empty, matching [`Self::acquire`].
    #[must_use]
    pub fn try_acquire(&self, source_bytes: u64) -> Option<SyntaxMemoryPermit<'_>> {
        let Some(capacity) = self.capacity_bytes else {
            return Some(SyntaxMemoryPermit {
                pool: self,
                admitted_bytes: 0,
            });
        };
        let admitted_bytes = weighted_compiler_unit_bytes(source_bytes).min(capacity);
        let mut used = lock_unpoisoned(&self.used_bytes);
        if *used > 0 && used.saturating_add(admitted_bytes) > capacity {
            return None;
        }
        *used = used.saturating_add(admitted_bytes);
        Some(SyntaxMemoryPermit {
            pool: self,
            admitted_bytes,
        })
    }
}

/// RAII admission returned by [`SyntaxMemoryPermitPool::acquire`].
#[derive(Debug)]
pub struct SyntaxMemoryPermit<'a> {
    pool: &'a SyntaxMemoryPermitPool,
    admitted_bytes: u64,
}

impl Drop for SyntaxMemoryPermit<'_> {
    fn drop(&mut self) {
        if self.admitted_bytes == 0 {
            return;
        }
        let mut used = lock_unpoisoned(&self.pool.used_bytes);
        *used = used.saturating_sub(self.admitted_bytes);
        self.pool.available.notify_all();
    }
}

fn syntax_working_memory_bytes(limit: Option<u64>, resident_bytes: Option<u64>) -> Option<u64> {
    limit.map(|limit| {
        let headroom = WEIGHTED_SYNTAX_HEADROOM_BYTES.min(limit.saturating_sub(1));
        let resident = resident_bytes.unwrap_or(SYNTAX_RESIDENT_RESERVE_BYTES);
        limit.saturating_sub(resident).saturating_sub(headroom).max(1)
    })
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wait_unpoisoned<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
    condvar
        .wait(guard)
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Partition raw source reads into deterministic memory-bounded windows.
///
/// Workspace ingestion retains one source copy in the VFS and temporarily
/// owns the concurrently read `String`s until that window is published in
/// path order. Unlike a parser unit, a raw read has no fixed AST arena, so its
/// schedule is governed by actual bytes rather than an arbitrary file count.
/// Every file is still read exactly once; constrained machines use more
/// windows and larger machines avoid thousands of tiny Rayon barriers.
#[must_use]
pub fn source_ingestion_batches(source_bytes: &[u64], cpu_workers: usize) -> Vec<Range<usize>> {
    source_ingestion_batches_for_limit_and_resident(
        source_bytes,
        cpu_workers,
        effective_memory_limit_bytes(),
        current_process_resident_bytes(),
    )
}

fn source_ingestion_batches_for_limit_and_resident(
    source_bytes: &[u64],
    cpu_workers: usize,
    limit: Option<u64>,
    resident_bytes: Option<u64>,
) -> Vec<Range<usize>> {
    let Some(limit) = limit else {
        return weighted_batches_for_working_set(source_bytes, cpu_workers, None);
    };
    let headroom = (limit / WEIGHTED_COMPILER_HEADROOM_DIVISOR)
        .max(SOURCE_INGESTION_MIN_HEADROOM_BYTES)
        .min(limit.saturating_sub(1));
    let resident = resident_bytes.unwrap_or(limit / 2);
    let raw_window_bytes = limit
        .saturating_sub(resident)
        .saturating_sub(headroom)
        .checked_div(SOURCE_INGESTION_COPY_AMPLIFICATION)
        .unwrap_or(1)
        .max(1);

    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < source_bytes.len() {
        let mut end = start;
        let mut batch_bytes = 0_u64;
        while end < source_bytes.len()
            && (end == start || batch_bytes.saturating_add(source_bytes[end]) <= raw_window_bytes)
        {
            batch_bytes = batch_bytes.saturating_add(source_bytes[end]);
            end += 1;
        }
        batches.push(start..end);
        start = end;
    }
    batches
}

fn syntax_worker_count_for_sources_and_limit(
    source_bytes: &[u64],
    cpu_workers: usize,
    limit: Option<u64>,
    resident_bytes: Option<u64>,
) -> usize {
    let cpu_workers = cpu_workers.max(1);
    if source_bytes.is_empty() {
        return 1;
    }
    let Some(limit) = limit else {
        return cpu_workers.min(source_bytes.len()).max(1);
    };
    let headroom = WEIGHTED_SYNTAX_HEADROOM_BYTES.min(limit.saturating_sub(1));
    let resident = resident_bytes.unwrap_or(SYNTAX_RESIDENT_RESERVE_BYTES);
    let working_bytes = limit.saturating_sub(resident).saturating_sub(headroom).max(1);
    let mut largest_units = source_bytes
        .iter()
        .copied()
        .map(weighted_compiler_unit_bytes)
        .collect::<Vec<_>>();
    largest_units.sort_unstable_by(|left, right| right.cmp(left));

    let mut admitted = 0usize;
    let mut admitted_bytes = 0_u64;
    for unit_bytes in largest_units.into_iter().take(cpu_workers) {
        if admitted > 0 && admitted_bytes.saturating_add(unit_bytes) > working_bytes {
            break;
        }
        admitted_bytes = admitted_bytes.saturating_add(unit_bytes);
        admitted += 1;
    }
    admitted.max(1)
}

fn syntax_weighted_batches_for_limit_and_resident(
    source_bytes: &[u64],
    cpu_workers: usize,
    limit: Option<u64>,
    resident_bytes: Option<u64>,
) -> Vec<Range<usize>> {
    let working_bytes = syntax_working_memory_bytes(limit, resident_bytes);
    weighted_batches_for_working_set(source_bytes, cpu_workers, working_bytes)
}

#[cfg(test)]
fn compiler_weighted_batches_for_limit(
    source_bytes: &[u64],
    cpu_workers: usize,
    limit: Option<u64>,
) -> Vec<Range<usize>> {
    compiler_weighted_batches_for_limit_and_resident(source_bytes, cpu_workers, limit, None)
}

fn compiler_weighted_batches_for_limit_and_resident(
    source_bytes: &[u64],
    cpu_workers: usize,
    limit: Option<u64>,
    resident_bytes: Option<u64>,
) -> Vec<Range<usize>> {
    let cpu_workers = cpu_workers.max(1);
    let working_bytes = limit.map(|limit| weighted_working_memory_bytes(limit, resident_bytes));
    weighted_batches_for_working_set(source_bytes, cpu_workers, working_bytes)
}

fn weighted_batches_for_working_set(
    source_bytes: &[u64],
    cpu_workers: usize,
    working_bytes: Option<u64>,
) -> Vec<Range<usize>> {
    let cpu_workers = cpu_workers.max(1);
    let mut batches = Vec::new();
    let mut start = 0usize;
    while start < source_bytes.len() {
        let mut end = start;
        let mut batch_bytes = 0_u64;
        while end < source_bytes.len() && end - start < cpu_workers {
            let unit_bytes = weighted_compiler_unit_bytes(source_bytes[end]);
            if end > start
                && working_bytes.is_some_and(|budget| batch_bytes.saturating_add(unit_bytes) > budget)
            {
                break;
            }
            batch_bytes = batch_bytes.saturating_add(unit_bytes);
            end += 1;
        }
        // Even a compilation unit larger than the detected working set must
        // run once: splitting an AST would change language semantics.
        if end == start {
            end += 1;
        }
        batches.push(start..end);
        start = end;
    }
    batches
}

fn weighted_working_memory_bytes(limit: u64, resident_bytes: Option<u64>) -> u64 {
    let headroom = (limit / WEIGHTED_COMPILER_HEADROOM_DIVISOR)
        .max(WEIGHTED_COMPILER_MIN_HEADROOM_BYTES)
        .min(limit.saturating_sub(1));
    // If this platform cannot report RSS, retain the earlier conservative
    // half-budget assumption in addition to safety headroom. On supported
    // platforms, account for the real resolver/graph state already resident
    // when the schedule is constructed.
    let resident_bytes = resident_bytes.unwrap_or(limit / 2);
    limit
        .saturating_sub(resident_bytes)
        .saturating_sub(headroom)
        .max(1)
}

fn weighted_compiler_unit_bytes(source_bytes: u64) -> u64 {
    WEIGHTED_COMPILER_UNIT_BASE_BYTES
        .saturating_add(source_bytes.saturating_mul(WEIGHTED_COMPILER_SOURCE_AMPLIFICATION))
}

/// Bound the lighter Tree-sitter validation/lowering frontend.
///
/// Syntax validation releases each completed file unit immediately and does
/// not retain the semantic resolver/graph state covered by
/// [`compiler_worker_count`]. Its separately measured profile permits useful
/// parallel parsing on constrained machines while remaining governed by the
/// same detected process budget and exact-work contract.
#[must_use]
pub fn syntax_worker_count(cpu_workers: usize) -> usize {
    syntax_worker_count_for_limit_and_resident(
        cpu_workers,
        effective_memory_limit_bytes(),
        current_process_resident_bytes(),
    )
}

fn compiler_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    worker_count_for_limit(
        cpu_workers,
        COMPILER_UNIT_TRANSIENT_BYTES,
        COMPILER_RESIDENT_RESERVE_BYTES,
        limit,
    )
}

fn callgraph_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    worker_count_for_limit(
        cpu_workers,
        CALLGRAPH_RESOLVER_UNIT_TRANSIENT_BYTES,
        CALLGRAPH_RESOLVER_RESIDENT_RESERVE_BYTES,
        limit,
    )
}

fn candidate_index_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    worker_count_for_limit(
        cpu_workers,
        CANDIDATE_INDEX_UNIT_TRANSIENT_BYTES,
        CANDIDATE_INDEX_RESIDENT_RESERVE_BYTES,
        limit,
    )
}

#[cfg(test)]
fn syntax_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    syntax_worker_count_for_limit_and_resident(cpu_workers, limit, None)
}

fn syntax_worker_count_for_limit_and_resident(
    cpu_workers: usize,
    limit: Option<u64>,
    resident_bytes: Option<u64>,
) -> usize {
    let reserved_bytes = resident_bytes
        .map(|resident| resident.max(SYNTAX_RESIDENT_RESERVE_BYTES))
        .unwrap_or(SYNTAX_RESIDENT_RESERVE_BYTES);
    worker_count_for_limit(cpu_workers, SYNTAX_UNIT_TRANSIENT_BYTES, reserved_bytes, limit)
}

fn worker_count_for_limit(
    cpu_workers: usize,
    bytes_per_worker: u64,
    reserved_bytes: u64,
    limit: Option<u64>,
) -> usize {
    let cpu_workers = cpu_workers.max(1);
    let Some(limit) = limit else {
        return cpu_workers;
    };
    let bytes_per_worker = bytes_per_worker.max(1);
    let memory_workers = limit.saturating_sub(reserved_bytes) / bytes_per_worker;
    cpu_workers.min(usize::try_from(memory_workers).unwrap_or(usize::MAX).max(1))
}

fn configured_memory_limit_bytes() -> Option<u64> {
    std::env::var("BONSAI_MEMORY_BUDGET_MB")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .and_then(|mib| mib.checked_mul(BYTES_PER_MIB))
        .filter(|bytes| *bytes > 0)
}

fn detect_memory_limit_bytes() -> Option<u64> {
    let physical = physical_memory_bytes();
    #[cfg(target_os = "linux")]
    {
        return min_present(physical, linux_cgroup_memory_limit_bytes());
    }
    #[cfg(not(target_os = "linux"))]
    physical
}

#[cfg(target_os = "linux")]
fn physical_memory_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib = meminfo.lines().find_map(|line| {
        let value = line.strip_prefix("MemTotal:")?.trim();
        value.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    kib.checked_mul(1024)
}

/// Return the current process resident set size when the host exposes it.
///
/// This is an observation helper for memory-aware scheduling and opt-in
/// diagnostics. It must never be used to admit, skip, or cap semantic work.
/// On macOS the kernel value is read through `ps`, so hot paths should cache
/// the result or call it only behind a diagnostic gate.
#[cfg(target_os = "linux")]
pub fn current_process_resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib = status.lines().find_map(|line| {
        let value = line.strip_prefix("VmRSS:")?.trim();
        value.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    kib.checked_mul(1024)
}

/// Return the current process resident set size when the host exposes it.
///
/// This is an observation helper for memory-aware scheduling and opt-in
/// diagnostics. It must never be used to admit, skip, or cap semantic work.
/// On macOS the kernel value is read through `ps`, so hot paths should cache
/// the result or call it only behind a diagnostic gate.
#[cfg(target_os = "macos")]
pub fn current_process_resident_bytes() -> Option<u64> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .flatten()?
        .checked_mul(1024)
}

/// Return the current process resident set size when the host exposes it.
///
/// This is an observation helper for memory-aware scheduling and opt-in
/// diagnostics. It must never be used to admit, skip, or cap semantic work.
/// On macOS the kernel value is read through `ps`, so hot paths should cache
/// the result or call it only behind a diagnostic gate.
#[cfg(target_os = "windows")]
pub fn current_process_resident_bytes() -> Option<u64> {
    let query = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &query])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .flatten()
}

/// Return the current process resident set size when the host exposes it.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub const fn current_process_resident_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn physical_memory_bytes() -> Option<u64> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .flatten()
}

#[cfg(target_os = "windows")]
fn physical_memory_bytes() -> Option<u64> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
        ])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .flatten()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const fn physical_memory_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn linux_cgroup_memory_limit_bytes() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    linux_cgroup_limit_paths(&cgroup)
        .iter()
        .filter_map(|path| read_numeric_limit(path))
        .min()
}

#[cfg(any(target_os = "linux", test))]
fn linux_cgroup_limit_paths(cgroup: &str) -> Vec<std::path::PathBuf> {
    use std::path::{Component, Path, PathBuf};

    fn nested_limit_path(root: &Path, cgroup_path: &str, file: &str) -> PathBuf {
        let mut path = root.to_path_buf();
        for component in Path::new(cgroup_path).components() {
            if let Component::Normal(component) = component {
                path.push(component);
            }
        }
        path.push(file);
        path
    }

    let v2_root = Path::new("/sys/fs/cgroup");
    let v1_root = Path::new("/sys/fs/cgroup/memory");
    let mut paths = vec![v2_root.join("memory.max"), v1_root.join("memory.limit_in_bytes")];
    for line in cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let Some(_hierarchy) = fields.next() else {
            continue;
        };
        let Some(controllers) = fields.next() else {
            continue;
        };
        let Some(cgroup_path) = fields.next() else {
            continue;
        };
        if controllers.is_empty() {
            paths.push(nested_limit_path(v2_root, cgroup_path, "memory.max"));
        } else if controllers.split(',').any(|controller| controller == "memory") {
            paths.push(nested_limit_path(v1_root, cgroup_path, "memory.limit_in_bytes"));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(any(target_os = "linux", test))]
fn read_numeric_limit(path: &std::path::Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("max") {
        return None;
    }
    raw.parse::<u64>().ok().filter(|value| *value > 0)
}

fn min_present(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        callgraph_worker_count_for_limit, candidate_index_worker_count_for_limit,
        compiler_weighted_batches_for_limit, compiler_weighted_batches_for_limit_and_resident,
        compiler_worker_count_for_limit, min_present, rooted_semantic_query_worker_count_for_limit,
        source_ingestion_batches_for_limit_and_resident, syntax_weighted_batches_for_limit_and_resident,
        syntax_worker_count_for_limit, syntax_worker_count_for_limit_and_resident,
        syntax_worker_count_for_sources_and_limit, weighted_compiler_unit_bytes, worker_count_for_limit,
        SyntaxMemoryPermitPool, BYTES_PER_GIB,
    };
    use super::{linux_cgroup_limit_paths, read_numeric_limit};

    #[test]
    fn configured_budget_cannot_raise_a_detected_machine_limit() {
        assert_eq!(min_present(Some(16), Some(3)), Some(3));
        assert_eq!(min_present(Some(2), Some(3)), Some(2));
    }

    #[test]
    fn worker_count_never_becomes_a_semantic_zero() {
        assert_eq!(worker_count_for_limit(16, u64::MAX, u64::MAX, Some(1)), 1);
    }

    #[test]
    fn worker_count_never_exceeds_cpu_parallelism() {
        assert_eq!(worker_count_for_limit(3, 1, 0, None), 3);
    }

    #[test]
    fn three_gib_budget_reduces_transient_concurrency_not_work() {
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(worker_count_for_limit(32, GIB / 2, GIB, Some(3 * GIB)), 4);
    }

    #[test]
    fn rooted_queries_use_the_measured_lighter_concurrency_profile() {
        assert_eq!(
            rooted_semantic_query_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)),
            10
        );
        assert_eq!(
            rooted_semantic_query_worker_count_for_limit(32, Some(2 * BYTES_PER_GIB)),
            2
        );
        assert_eq!(
            rooted_semantic_query_worker_count_for_limit(32, Some(BYTES_PER_GIB)),
            1,
            "a constrained host must execute the same closures serially"
        );
    }

    #[test]
    fn three_gib_budget_serializes_exact_compiler_units() {
        assert_eq!(compiler_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)), 1);
        assert_eq!(compiler_worker_count_for_limit(32, Some(8 * BYTES_PER_GIB)), 6);
        assert_eq!(compiler_worker_count_for_limit(2, None), 2);
    }

    #[test]
    fn three_gib_budget_keeps_ten_measured_call_resolvers_in_flight() {
        assert_eq!(callgraph_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)), 10);
        assert_eq!(callgraph_worker_count_for_limit(32, Some(2 * BYTES_PER_GIB)), 1);
        assert_eq!(callgraph_worker_count_for_limit(3, None), 3);
    }

    #[test]
    fn three_gib_budget_keeps_ten_measured_candidate_workers_in_flight() {
        assert_eq!(
            candidate_index_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)),
            10
        );
        assert_eq!(
            candidate_index_worker_count_for_limit(32, Some(2 * BYTES_PER_GIB)),
            1
        );
        assert_eq!(candidate_index_worker_count_for_limit(3, None), 3);
    }

    #[test]
    fn three_gib_budget_keeps_measured_syntax_parallelism() {
        assert_eq!(syntax_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)), 3);
        assert_eq!(syntax_worker_count_for_limit(2, Some(3 * BYTES_PER_GIB)), 2);
        assert_eq!(syntax_worker_count_for_limit(32, Some(BYTES_PER_GIB)), 1);
    }

    #[test]
    fn syntax_workers_subtract_the_live_compiler_working_set() {
        assert_eq!(
            syntax_worker_count_for_limit_and_resident(32, Some(3 * BYTES_PER_GIB), Some(2 * BYTES_PER_GIB),),
            1
        );
        assert_eq!(
            syntax_worker_count_for_limit_and_resident(32, Some(8 * BYTES_PER_GIB), Some(2 * BYTES_PER_GIB),),
            8
        );
    }

    #[test]
    fn weighted_batches_cover_every_unit_and_isolate_large_files() {
        let mib = 1024 * 1024;
        let batches =
            compiler_weighted_batches_for_limit(&[mib, mib, 100 * mib, mib], 8, Some(3 * BYTES_PER_GIB));
        assert_eq!(batches, vec![0..2, 2..3, 3..4]);
        assert_eq!(batches.iter().map(|range| range.len()).sum::<usize>(), 4);
    }

    #[test]
    fn weighted_batches_are_cpu_bounded_without_a_memory_limit() {
        assert_eq!(
            compiler_weighted_batches_for_limit(&[1, 1, 1, 1, 1], 2, None),
            vec![0..2, 2..4, 4..5]
        );
    }

    #[test]
    fn weighted_batches_subtract_resident_state_and_safety_headroom() {
        assert_eq!(
            compiler_weighted_batches_for_limit_and_resident(
                &[1; 10],
                8,
                Some(3 * BYTES_PER_GIB),
                Some(2 * BYTES_PER_GIB),
            ),
            vec![0..3, 3..6, 6..9, 9..10]
        );
    }

    #[test]
    fn weighted_compiler_batches_do_not_collapse_small_files_to_one_worker() {
        assert_eq!(
            compiler_weighted_batches_for_limit_and_resident(
                &[1; 32],
                8,
                Some(3 * BYTES_PER_GIB),
                Some(512 * 1024 * 1024),
            ),
            vec![0..8, 8..16, 16..24, 24..32]
        );
    }

    #[test]
    fn weighted_syntax_batches_keep_small_files_parallel_beside_large_resident_state() {
        assert_eq!(
            syntax_weighted_batches_for_limit_and_resident(
                &[1; 10],
                8,
                Some(3 * BYTES_PER_GIB),
                Some(2 * BYTES_PER_GIB),
            ),
            vec![0..8, 8..10]
        );
    }

    #[test]
    fn continuous_syntax_width_accounts_for_largest_possible_concurrent_units() {
        let mib = 1024 * 1024;
        assert_eq!(
            syntax_worker_count_for_sources_and_limit(
                &[mib, mib, 20 * mib, mib],
                4,
                Some(3 * BYTES_PER_GIB),
                Some(BYTES_PER_GIB),
            ),
            4,
        );
        assert_eq!(
            syntax_worker_count_for_sources_and_limit(
                &[40 * mib, 40 * mib, mib, mib],
                4,
                Some(3 * BYTES_PER_GIB),
                Some(BYTES_PER_GIB),
            ),
            1,
            "the two largest compiler units cannot overlap inside the live budget",
        );
    }

    #[test]
    fn continuous_weighted_permits_keep_small_units_parallel_and_bound_total_memory() {
        let capacity = 2 * weighted_compiler_unit_bytes(1);
        let permits = std::sync::Arc::new(SyntaxMemoryPermitPool::with_capacity(Some(capacity)));
        let first = permits.acquire(1);
        let second = permits.acquire(1);
        let peer = std::sync::Arc::clone(&permits);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _third = peer.acquire(1);
            started_tx.send(()).expect("report acquired permit");
        });

        assert!(
            started_rx
                .recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "a third unit must wait while the weighted capacity is full"
        );
        drop(first);
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("released capacity admits the waiting exact unit");
        drop(second);
        waiter.join().expect("weighted permit worker");
    }

    #[test]
    fn nonblocking_weighted_admission_preserves_capacity_and_forward_progress() {
        let unit = weighted_compiler_unit_bytes(1);
        let permits = SyntaxMemoryPermitPool::with_capacity(Some(2 * unit));
        let first = permits.acquire(1);
        let second = permits.try_acquire(1).expect("second exact unit fits");
        assert!(
            permits.try_acquire(1).is_none(),
            "a continuous producer must not block its ordered consumer when capacity is full"
        );
        drop(first);
        let replacement = permits
            .try_acquire(1)
            .expect("released exact unit admits replacement work");
        drop(second);
        drop(replacement);

        let oversize = permits
            .try_acquire(u64::MAX)
            .expect("an oversize exact compiler unit runs alone");
        assert!(permits.try_acquire(1).is_none());
        drop(oversize);
    }

    #[test]
    fn source_ingestion_windows_cover_all_bytes_without_a_file_count_cap() {
        let mib = 1024 * 1024;
        let source_bytes = vec![mib; 900];
        let batches = source_ingestion_batches_for_limit_and_resident(
            &source_bytes,
            8,
            Some(3 * BYTES_PER_GIB),
            Some(512 * mib),
        );
        assert_eq!(batches, vec![0..896, 896..900]);
        assert_eq!(batches.iter().map(std::ops::Range::len).sum::<usize>(), 900);
    }

    #[test]
    fn source_ingestion_falls_back_to_cpu_windows_without_memory_detection() {
        assert_eq!(
            source_ingestion_batches_for_limit_and_resident(&[1; 5], 2, None, None),
            vec![0..2, 2..4, 4..5]
        );
    }

    #[test]
    fn nested_cgroup_v1_and_v2_paths_are_detected_without_path_escape() {
        let paths = linux_cgroup_limit_paths(
            "0::/kubepods.slice/pod-1\n7:cpu,memory:/docker/container-2\n8:cpu:/ignored\n",
        );
        assert!(paths.contains(&"/sys/fs/cgroup/kubepods.slice/pod-1/memory.max".into()));
        assert!(paths.contains(&"/sys/fs/cgroup/memory/docker/container-2/memory.limit_in_bytes".into()));
        assert!(!paths
            .iter()
            .any(|path| path.to_string_lossy().contains("ignored")));

        let escaped = linux_cgroup_limit_paths("0::/../../outside\n");
        assert!(escaped.contains(&"/sys/fs/cgroup/outside/memory.max".into()));
    }

    #[test]
    fn cgroup_numeric_limit_parser_rejects_unbounded_and_zero_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let limit = dir.path().join("memory.max");
        std::fs::write(&limit, "max\n").expect("write unbounded limit");
        assert_eq!(read_numeric_limit(&limit), None);
        std::fs::write(&limit, "0\n").expect("write zero limit");
        assert_eq!(read_numeric_limit(&limit), None);
        std::fs::write(&limit, "3145728\n").expect("write numeric limit");
        assert_eq!(read_numeric_limit(&limit), Some(3_145_728));
    }
}
