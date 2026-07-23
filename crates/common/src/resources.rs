//! Process resource detection and memory-aware compiler scheduling.
//!
//! Memory limits are scheduling inputs only. They may reduce the number of
//! parser, lowering, or serialization jobs in flight, but must never reduce
//! the source-file set, graph scope, fixed-point closure, or rendered facts.

use std::{ops::Range, sync::OnceLock};

const BYTES_PER_MIB: u64 = 1024 * 1024;
const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;
const SYNTAX_UNIT_TRANSIENT_BYTES: u64 = 768 * BYTES_PER_MIB;
const SYNTAX_RESIDENT_RESERVE_BYTES: u64 = 512 * BYTES_PER_MIB;
const COMPILER_UNIT_TRANSIENT_BYTES: u64 = BYTES_PER_GIB;
const COMPILER_RESIDENT_RESERVE_BYTES: u64 = 2 * BYTES_PER_GIB;
const WEIGHTED_COMPILER_UNIT_BASE_BYTES: u64 = 64 * BYTES_PER_MIB;
const WEIGHTED_COMPILER_SOURCE_AMPLIFICATION: u64 = 40;
const WEIGHTED_COMPILER_MIN_HEADROOM_BYTES: u64 = 128 * BYTES_PER_MIB;
const WEIGHTED_COMPILER_HEADROOM_DIVISOR: u64 = 5;

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
    let cpu_workers = compiler_worker_count(cpu_workers);
    compiler_weighted_batches_for_limit_and_resident(
        source_bytes,
        cpu_workers,
        effective_memory_limit_bytes(),
        current_process_resident_bytes(),
    )
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
    syntax_worker_count_for_limit(cpu_workers, effective_memory_limit_bytes())
}

fn compiler_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    worker_count_for_limit(
        cpu_workers,
        COMPILER_UNIT_TRANSIENT_BYTES,
        COMPILER_RESIDENT_RESERVE_BYTES,
        limit,
    )
}

fn syntax_worker_count_for_limit(cpu_workers: usize, limit: Option<u64>) -> usize {
    worker_count_for_limit(
        cpu_workers,
        SYNTAX_UNIT_TRANSIENT_BYTES,
        SYNTAX_RESIDENT_RESERVE_BYTES,
        limit,
    )
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

#[cfg(target_os = "linux")]
fn current_process_resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib = status.lines().find_map(|line| {
        let value = line.strip_prefix("VmRSS:")?.trim();
        value.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    kib.checked_mul(1024)
}

#[cfg(target_os = "macos")]
fn current_process_resident_bytes() -> Option<u64> {
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

#[cfg(target_os = "windows")]
fn current_process_resident_bytes() -> Option<u64> {
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

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
const fn current_process_resident_bytes() -> Option<u64> {
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
    let v2 = read_numeric_limit("/sys/fs/cgroup/memory.max");
    let v1 = read_numeric_limit("/sys/fs/cgroup/memory/memory.limit_in_bytes");
    min_present(v2, v1)
}

#[cfg(target_os = "linux")]
fn read_numeric_limit(path: &str) -> Option<u64> {
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
        compiler_weighted_batches_for_limit, compiler_weighted_batches_for_limit_and_resident,
        compiler_worker_count_for_limit, min_present, syntax_worker_count_for_limit, worker_count_for_limit,
        BYTES_PER_GIB,
    };

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
    fn three_gib_budget_serializes_exact_compiler_units() {
        assert_eq!(compiler_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)), 1);
        assert_eq!(compiler_worker_count_for_limit(32, Some(8 * BYTES_PER_GIB)), 6);
        assert_eq!(compiler_worker_count_for_limit(2, None), 2);
    }

    #[test]
    fn three_gib_budget_keeps_measured_syntax_parallelism() {
        assert_eq!(syntax_worker_count_for_limit(32, Some(3 * BYTES_PER_GIB)), 3);
        assert_eq!(syntax_worker_count_for_limit(2, Some(3 * BYTES_PER_GIB)), 2);
        assert_eq!(syntax_worker_count_for_limit(32, Some(BYTES_PER_GIB)), 1);
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
            vec![0..6, 6..10]
        );
    }
}
