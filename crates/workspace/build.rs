//! Build-time fingerprint for the analyzer pipeline.
//!
//! Presentation/export metadata and compiler-artifact provenance retain
//! `BONSAI_BUILD_FINGERPRINT`. Semantic sidecars bind their exact compiler
//! inputs and semantic ABI independently, so unrelated binary changes do not
//! invalidate valid facts. The producer fingerprint identifies the release
//! version and Git commit; it is not a substitute for semantic cache keys.
//!
//! When git is unavailable (vendored source build, no `.git`), the
//! fingerprint falls back to `CARGO_PKG_VERSION` + an "ungitted"
//! tag — still better than no automatic invalidation, since version
//! bumps still flip the value.

use std::{path::PathBuf, process::Command};

fn main() {
    emit_git_rerun_inputs();
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
    let fingerprint = format!("{pkg_version}@{head}");
    emit_fingerprint(&fingerprint);
}

/// Watch both Git's administrative files and the resolved symbolic HEAD ref.
///
/// Watching `.git/HEAD` alone misses ordinary commits because that file keeps
/// containing `ref: refs/heads/<branch>` while the referenced file changes.
/// `git rev-parse --git-path` also handles worktrees and submodules whose
/// `.git` entry is a redirection file rather than a directory.
fn emit_git_rerun_inputs() {
    for name in ["HEAD", "packed-refs"] {
        if let Some(path) = git_path(name) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if let Some(head_ref) = run_git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git_path(&head_ref) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn git_path(name: &str) -> Option<PathBuf> {
    let raw = run_git(&["rev-parse", "--git-path", name])?;
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(repo_root()?.join(path))
    }
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
    let mut command = Command::new("git");
    command.args(args);
    if let Some(root) = repo_root() {
        command.current_dir(root);
    }
    let out = command.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8(out.stdout).ok()?;
    Some(stdout.trim().to_string())
}

fn repo_root() -> Option<PathBuf> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    manifest.parent()?.parent().map(PathBuf::from)
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
