//! Disk-change detection for long-lived SDK projects.
//!
//! This module owns frontend freshness only. Source meaning remains entirely
//! in the workspace/Tree-sitter pipeline.

use ahash::AHashSet;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

/// Exact candidate index for Git worktrees.
///
/// Git already maintains the compiler input change index for tracked and
/// non-ignored untracked files. Reusing it avoids recursively `stat`-ing every
/// source before each long-lived SDK query. The previous dirty set is retained
/// so transitions back to a clean worktree are still observed relative to the
/// in-memory snapshot. Any command or parse failure disables this optimization
/// and the caller falls back to a complete workspace reconciliation.
#[derive(Debug)]
pub(crate) struct GitChangeOracle {
    repository_root: PathBuf,
    workspace_root: PathBuf,
    previous_dirty: AHashSet<PathBuf>,
    retry_paths: AHashSet<PathBuf>,
    ignore_control_stamps: Vec<(PathBuf, Option<DiskFileStamp>)>,
}

pub(crate) struct GitChanges {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) reconcile_workspace: bool,
}

impl GitChangeOracle {
    pub(crate) fn discover(root: &Path) -> Option<Self> {
        let workspace_root = root.canonicalize().ok()?;
        let output = Command::new("git")
            .arg("-C")
            .arg(&workspace_root)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let repository_root = PathBuf::from(os_string_from_bytes(trim_ascii_line(&output.stdout)));
        let repository_root = repository_root.canonicalize().ok()?;
        if !workspace_root.starts_with(&repository_root) {
            return None;
        }
        let ignore_control_paths = git_ignore_control_paths(&workspace_root);
        let mut ignore_control_stamps = Vec::with_capacity(ignore_control_paths.len());
        for path in ignore_control_paths {
            ignore_control_stamps.push((path.clone(), disk_file_stamp(&path).ok()?));
        }
        let mut oracle = Self {
            repository_root,
            workspace_root,
            previous_dirty: AHashSet::new(),
            retry_paths: AHashSet::new(),
            ignore_control_stamps,
        };
        oracle.previous_dirty = oracle.read_current_dirty().ok()?;
        Some(oracle)
    }

    pub(crate) fn candidates(&mut self) -> std::io::Result<GitChanges> {
        let mut reconcile_workspace = false;
        for (path, observed) in &mut self.ignore_control_stamps {
            let current = disk_file_stamp(path)?;
            if *observed != current {
                *observed = current;
                reconcile_workspace = true;
            }
        }
        if reconcile_workspace {
            self.refresh_ignore_control_stamps()?;
        }
        let current = self.read_current_dirty()?;
        let mut candidates = current.clone();
        candidates.extend(self.previous_dirty.iter().cloned());
        candidates.extend(self.retry_paths.iter().cloned());
        self.previous_dirty = current;
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort();
        reconcile_workspace |= candidates.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| matches!(name, ".gitignore" | ".ignore" | ".bonsaiignore"))
        });
        Ok(GitChanges {
            paths: candidates,
            reconcile_workspace,
        })
    }

    pub(crate) fn retain_retry(&mut self, path: &Path) {
        self.retry_paths.insert(path.to_path_buf());
    }

    pub(crate) fn clear_retry(&mut self, path: &Path) {
        self.retry_paths.remove(path);
    }

    fn refresh_ignore_control_stamps(&mut self) -> std::io::Result<()> {
        let paths = git_ignore_control_paths(&self.workspace_root);
        let mut stamps = Vec::with_capacity(paths.len());
        for path in paths {
            stamps.push((path.clone(), disk_file_stamp(&path)?));
        }
        self.ignore_control_stamps = stamps;
        Ok(())
    }

    fn read_current_dirty(&self) -> std::io::Result<AHashSet<PathBuf>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args([
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--",
                ".",
            ])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "git status failed with {}",
                output.status
            )));
        }

        let mut paths = AHashSet::new();
        let mut records = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty());
        while let Some(record) = records.next() {
            if record.len() < 4 || record[2] != b' ' {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid git porcelain-v1 record",
                ));
            }
            let status = &record[..2];
            self.insert_repo_relative_path(&mut paths, &record[3..]);
            if status.contains(&b'R') || status.contains(&b'C') {
                let Some(origin) = records.next() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "git rename/copy record is missing its origin",
                    ));
                };
                self.insert_repo_relative_path(&mut paths, origin);
            }
        }
        Ok(paths)
    }

    fn insert_repo_relative_path(&self, paths: &mut AHashSet<PathBuf>, raw: &[u8]) {
        let path = self.repository_root.join(os_string_from_bytes(raw));
        if path.starts_with(&self.workspace_root) {
            paths.insert(path);
        }
    }
}

fn git_ignore_control_paths(workspace_root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for git_path in ["info/exclude", "config", "config.worktree"] {
        if let Some(path) = git_reported_path(workspace_root, &["rev-parse", "--git-path", git_path]) {
            paths.push(path);
        }
    }
    if let Some(path) = git_reported_path(
        workspace_root,
        &["config", "--path", "--get", "core.excludesFile"],
    ) {
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    paths
}

fn git_reported_path(workspace_root: &Path, args: &[&str]) -> Option<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = trim_ascii_line(&output.stdout);
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(os_string_from_bytes(raw));
    Some(if path.is_absolute() {
        path
    } else {
        workspace_root.join(path)
    })
}

fn trim_ascii_line(mut bytes: &[u8]) -> &[u8] {
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(unix)]
fn os_string_from_bytes(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt as _;
    OsString::from_vec(bytes.to_vec())
}

#[cfg(not(unix))]
fn os_string_from_bytes(bytes: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(bytes).into_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiskFileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    change_seconds: i64,
    change_nanoseconds: i64,
    device: u64,
    inode: u64,
}

pub(crate) fn disk_file_stamp(path: &Path) -> std::io::Result<Option<DiskFileStamp>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    let (change_seconds, change_nanoseconds, device, inode) = {
        use std::os::unix::fs::MetadataExt as _;
        (
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.dev(),
            metadata.ino(),
        )
    };
    #[cfg(not(unix))]
    let (change_seconds, change_nanoseconds, device, inode) = (0, 0, 0, 0);
    Ok(Some(DiskFileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        change_seconds,
        change_nanoseconds,
        device,
        inode,
    }))
}
