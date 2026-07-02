//! Build-time fingerprint for retrieval sidecars.
//!
//! Retrieval sidecars are candidate indexes, but stale candidates can still
//! make query frontends spend time in the wrong scope. Fold the same analyzer
//! build fingerprint used by workspace semantic sidecars into the retrieval
//! pipeline hash so upgraded or dirty binaries do not reuse older candidate
//! indexes.

use std::{path::PathBuf, process::Command};

fn main() {
    emit_source_rerun_inputs();

    let git_dir = locate_git_dir();
    if let Some(dir) = &git_dir {
        println!("cargo:rerun-if-changed={}/HEAD", dir.display());
        println!("cargo:rerun-if-changed={}/index", dir.display());
        let packed = dir.join("packed-refs");
        if packed.exists() {
            println!("cargo:rerun-if-changed={}", packed.display());
        }
    }
    println!("cargo:rerun-if-env-changed=BONSAI_BUILD_FINGERPRINT_OVERRIDE");

    if let Ok(override_value) = std::env::var("BONSAI_BUILD_FINGERPRINT_OVERRIDE") {
        emit_fingerprint(&override_value);
        return;
    }

    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let head = run_git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "ungitted".to_string());
    let dirty = run_git(&["status", "--porcelain"]).map_or(String::new(), |out| out);
    let dirty_marker = if dirty.trim().is_empty() { "clean" } else { "dirty" };
    let dirty_hash = fnv1a64(dirty.as_bytes());
    let fingerprint = format!("{}@{}:{}:{:016x}", pkg_version, head, dirty_marker, dirty_hash);
    emit_fingerprint(&fingerprint);
}

fn emit_source_rerun_inputs() {
    let Some(root) = repo_root() else {
        return;
    };
    for relative in ["Cargo.toml", "Cargo.lock", "crates"] {
        let path = root.join(relative);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn emit_fingerprint(value: &str) {
    let hash = fnv1a64(value.as_bytes());
    println!("cargo:rustc-env=BONSAI_BUILD_FINGERPRINT={value}");
    println!("cargo:rustc-env=BONSAI_BUILD_FINGERPRINT_HASH={hash:016x}");
}

fn run_git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8(out.stdout).ok()?;
    Some(stdout.trim().to_string())
}

fn locate_git_dir() -> Option<std::path::PathBuf> {
    let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
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

fn repo_root() -> Option<PathBuf> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    manifest.parent()?.parent().map(PathBuf::from)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}
