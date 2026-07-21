//! Process resource detection and memory-aware compiler scheduling.
//!
//! Memory limits are scheduling inputs only. They may reduce the number of
//! parser, lowering, or serialization jobs in flight, but must never reduce
//! the source-file set, graph scope, fixed-point closure, or rendered facts.

use std::sync::OnceLock;

const BYTES_PER_MIB: u64 = 1024 * 1024;
const BYTES_PER_GIB: u64 = 1024 * 1024 * 1024;
const SYNTAX_UNIT_TRANSIENT_BYTES: u64 = 768 * BYTES_PER_MIB;
const SYNTAX_RESIDENT_RESERVE_BYTES: u64 = 512 * BYTES_PER_MIB;
const COMPILER_UNIT_TRANSIENT_BYTES: u64 = BYTES_PER_GIB;
const COMPILER_RESIDENT_RESERVE_BYTES: u64 = 2 * BYTES_PER_GIB;

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
}
