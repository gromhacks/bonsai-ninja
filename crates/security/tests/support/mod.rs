use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) fn repo_root() -> PathBuf {
    let mut root = std::env::current_dir().expect("cwd");
    root.push("../..");
    root.canonicalize().expect("repo root")
}

/// Select a CLI built from the current checkout. Cross-crate integration
/// tests do not receive Cargo's binary path automatically, so prefer an
/// explicit override, then the newest debug/release artifact. A stale binary
/// is an error: silently exercising an older rulepack schema gives false-green
/// security coverage.
pub(crate) fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("BONSAI_TEST_BIN").map(PathBuf::from) {
        assert!(
            path.is_file(),
            "BONSAI_TEST_BIN does not name a file: {}",
            path.display()
        );
        assert_binary_is_fresh(&path);
        return Some(path);
    }

    let root = repo_root();
    let selected = [
        root.join("target/debug/bonsai-ninja"),
        root.join("target/release/bonsai-ninja"),
    ]
    .into_iter()
    .filter(|path| path.is_file())
    .max_by_key(|path| path.metadata().and_then(|metadata| metadata.modified()).ok())?;
    assert_binary_is_fresh(&selected);
    Some(selected)
}

fn assert_binary_is_fresh(binary: &Path) {
    let Ok(binary_mtime) = binary.metadata().and_then(|metadata| metadata.modified()) else {
        return;
    };
    let root = repo_root();
    let newest_input = [
        newest_mtime(&root.join("crates"), &["rs"]),
        newest_mtime(&root.join("security-patterns"), &["yml", "yaml"]),
    ]
    .into_iter()
    .flatten()
    .max();
    if let Some(newest_input) = newest_input {
        assert!(
            binary_mtime >= newest_input,
            "stale bonsai-ninja test binary: {} is older than compiler/rulepack source; rebuild the CLI or set BONSAI_TEST_BIN",
            binary.display()
        );
    }
}

fn newest_mtime(root: &Path, extensions: &[&str]) -> Option<SystemTime> {
    let mut newest = None;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some("tests") {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
            {
                continue;
            }
            if !path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extensions.contains(&extension))
            {
                continue;
            }
            if let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) {
                newest = Some(newest.map_or(modified, |current: SystemTime| current.max(modified)));
            }
        }
    }
    newest
}
