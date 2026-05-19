//! Shared dependency metadata classification used by cache fingerprints.
//!
//! Dependency manifest and lockfile changes can alter semantic resolution
//! without changing source files. Every cache layer should classify those files
//! identically so stale dependency context is not reused as complete analysis.

use bonsai_hash::fnv1a_bytes64;
use std::io;
use std::path::{Path, PathBuf};

/// Content fingerprint for one dependency metadata file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyMetadataFingerprint {
    /// Workspace-relative path, normalized with `/` separators.
    pub relative_path: String,
    /// Stable FNV-1a digest of the file bytes.
    pub content_hash: u64,
}

/// Returns true when a directory should be skipped while scanning for
/// dependency metadata.
pub fn dependency_metadata_dir_skipped(name: &str) -> bool {
    matches!(
        name,
        "node_modules"
            | "vendor"
            | "bower_components"
            | "target"
            | ".git"
            | ".bonsai"
            | "dist"
            | "build"
            | "out"
            | ".next"
            | ".nuxt"
            | "__pycache__"
            | "coverage"
            | ".coverage"
            | ".venv"
            | "venv"
    )
}

/// Returns true when a file name is dependency metadata that can affect
/// semantic resolution, dependency discovery, or rulepack applicability.
pub fn is_dependency_metadata_file(name: &str) -> bool {
    if matches!(
        name,
        "BUILD"
            | "BUILD.bazel"
            | "Cargo.toml"
            | "Cargo.lock"
            | "Cartfile"
            | "Cartfile.resolved"
            | "CMakeLists.txt"
            | "Gemfile"
            | "Gemfile.lock"
            | "Makefile"
            | "MODULE.bazel"
            | "Package.resolved"
            | "Package.swift"
            | "Pipfile"
            | "Pipfile.lock"
            | "Podfile"
            | "Podfile.lock"
            | "WORKSPACE"
            | "WORKSPACE.bazel"
            | "bower.json"
            | "bun.lock"
            | "bun.lockb"
            | "build.gradle"
            | "build.gradle.kts"
            | "composer.json"
            | "composer.lock"
            | "deno.json"
            | "deno.jsonc"
            | "deno.lock"
            | "go.mod"
            | "go.sum"
            | "go.work"
            | "go.work.sum"
            | "gradle.lockfile"
            | "gradle.properties"
            | "mix.exs"
            | "mix.lock"
            | "package-lock.json"
            | "package.json"
            | "packages.config"
            | "pnpm-lock.yaml"
            | "pnpm-workspace.yaml"
            | "pom.xml"
            | "poetry.lock"
            | "project.clj"
            | "pyproject.toml"
            | "rebar.config"
            | "rebar.lock"
            | "requirements.txt"
            | "settings.gradle"
            | "settings.gradle.kts"
            | "stack.yaml"
            | "stack.yaml.lock"
            | "uv.lock"
            | "yarn.lock"
    ) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    let ext = Path::new(name).extension().and_then(|ext| ext.to_str());
    (lower.starts_with("requirements") && extension_is(ext, "txt"))
        || extension_is(ext, "csproj")
        || extension_is(ext, "fsproj")
        || extension_is(ext, "vbproj")
        || extension_is(ext, "sln")
        || extension_is(ext, "slnx")
        || extension_is(ext, "props")
        || extension_is(ext, "targets")
        || extension_is(ext, "gemspec")
        || extension_is(ext, "cabal")
}

fn extension_is(ext: Option<&str>, expected: &str) -> bool {
    ext.is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}

/// Walk every dependency manifest and lockfile under `root`.
///
/// This traversal is intentionally not depth-limited. Large monorepos can put
/// semantic dependency metadata many levels below the workspace root, and a
/// cache freshness check that misses those files can replay stale callgraph,
/// taint, export, or pagination results. Symlinks and known dependency/build
/// output directories are skipped so the walk remains bounded by the actual
/// workspace tree.
pub fn walk_dependency_metadata_files(
    root: &Path,
    mut visit: impl FnMut(&Path, &str) -> io::Result<()>,
) -> io::Result<()> {
    let stable_root = stable_root_path(root);
    let mut stack = vec![stable_root.clone()];
    while let Some(dir) = stack.pop() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(err) => return Err(err),
        };
        for entry in read_dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            if file_type.is_symlink() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if file_type.is_dir() {
                if dependency_metadata_dir_skipped(name) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if file_type.is_file() && is_dependency_metadata_file(name) {
                let rel = stable_relative_path(&stable_root, &path);
                visit(&path, &rel)?;
            }
        }
    }
    Ok(())
}

/// Collect content fingerprints for every dependency metadata file under
/// `root`.
pub fn collect_dependency_metadata_fingerprints(
    root: &Path,
) -> io::Result<Vec<DependencyMetadataFingerprint>> {
    let mut out = Vec::new();
    walk_dependency_metadata_files(root, |path, rel| {
        let bytes = std::fs::read(path)?;
        out.push(DependencyMetadataFingerprint {
            relative_path: rel.to_string(),
            content_hash: fnv1a_bytes64(&bytes),
        });
        Ok(())
    })?;
    Ok(out)
}

fn stable_root_path(root: &Path) -> PathBuf {
    root.canonicalize()
        .ok()
        .or_else(|| {
            if root.is_absolute() {
                Some(root.to_path_buf())
            } else {
                std::env::current_dir().ok().map(|cwd| cwd.join(root))
            }
        })
        .unwrap_or_else(|| root.to_path_buf())
}

fn stable_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
#[path = "dependency_metadata_tests.rs"]
mod tests;
