//! Build-time fingerprint for the analyzer pipeline.
//!
//! Every IDG / dataflow / value-flow / flow-ids / taint-graph
//! sidecar folds `BONSAI_BUILD_FINGERPRINT` into its on-disk
//! `pipeline_hash`. The fingerprint changes whenever the local git
//! HEAD moves OR the working tree is dirty — so an upgraded binary
//! cannot accidentally reuse sidecars produced by a different
//! analysis version, even if the per-sidecar manual semantic-version
//! constant wasn't bumped. This converts the previous "remember to
//! bump 6 scattered `*_CACHE_VERSION` constants" foot-gun into a
//! single automated guarantee.
//!
//! When git is unavailable (vendored source build, no `.git`), the
//! fingerprint falls back to `CARGO_PKG_VERSION` + an "ungitted"
//! tag — still better than no automatic invalidation, since version
//! bumps still flip the value.

use std::process::Command;

fn main() {
    // Re-run when git refs/index move so the fingerprint stays
    // current across commits, staging, and checkout. Cargo skips
    // build.rs re-execution when nothing observable changed.
    let git_dir = locate_git_dir();
    if let Some(dir) = &git_dir {
        println!("cargo:rerun-if-changed={}/HEAD", dir.display());
        println!("cargo:rerun-if-changed={}/index", dir.display());
        // Packed refs (`git gc`-style repos) — re-run if it moves.
        let packed = dir.join("packed-refs");
        if packed.exists() {
            println!("cargo:rerun-if-changed={}", packed.display());
        }
    }
    println!("cargo:rerun-if-env-changed=BONSAI_BUILD_FINGERPRINT_OVERRIDE");

    // Override hook for reproducible builds: if the env var is set,
    // use it verbatim (allows release engineers to pin a deterministic
    // fingerprint per release artifact).
    if let Ok(override_value) = std::env::var("BONSAI_BUILD_FINGERPRINT_OVERRIDE") {
        emit_fingerprint(&override_value);
        return;
    }

    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());

    let head = run_git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "ungitted".to_string());
    let dirty = run_git(&["status", "--porcelain"]).map_or(String::new(), |out| out);
    let dirty_marker = if dirty.trim().is_empty() { "clean" } else { "dirty" };
    let dirty_hash = fnv1a64(dirty.as_bytes());

    // Compose deterministically so two builds at the same commit with
    // identical dirty state produce identical fingerprints.
    let fingerprint = format!("{}@{}:{}:{:016x}", pkg_version, head, dirty_marker, dirty_hash);
    emit_fingerprint(&fingerprint);
}

/// Emit the fingerprint string and its 64-bit hash as `rustc-env` vars
/// so they're available to library code via `env!("BONSAI_BUILD_FINGERPRINT_HASH")`.
fn emit_fingerprint(value: &str) {
    let hash = fnv1a64(value.as_bytes());
    println!("cargo:rustc-env=BONSAI_BUILD_FINGERPRINT={value}");
    println!("cargo:rustc-env=BONSAI_BUILD_FINGERPRINT_HASH={hash:016x}");
}

/// Run `git <args>` and capture stdout; returns `None` on any failure
/// (git missing, non-zero exit, non-UTF-8 output) so the caller can
/// fall back to a non-git fingerprint without aborting the build.
fn run_git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8(out.stdout).ok()?;
    Some(stdout.trim().to_string())
}

/// Find the repo's `.git` dir by walking up from `CARGO_MANIFEST_DIR`.
/// Submodule case (`.git` is a file, not a dir) intentionally returns
/// `None` — the build falls back to the ungitted fingerprint.
fn locate_git_dir() -> Option<std::path::PathBuf> {
    let start = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let mut path: std::path::PathBuf = start.into();
    // Bound the walk — bonsai's deepest crate is four levels under
    // the repo root; 8 leaves headroom for nested workspaces.
    for _ in 0..8 {
        let candidate = path.join(".git");
        if candidate.join("HEAD").exists() {
            return Some(candidate);
        }
        if !path.pop() {
            break;
        }
    }
    None
}

/// Tiny FNV-1a 64-bit — kept inline so build.rs has no external deps.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}
