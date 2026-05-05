//! Persistent rendered-page cache for CLI pagination.
//!
//! Pagination cursors are useful only if turning the page is cheap. The
//! row/flow analysis has already happened on page 1, so page 2 should
//! not reopen a large workspace and recompute the same report. This
//! module stores fully rendered pages under `.bonsai/page-cache.v2`
//! keyed by the normalized command line (with `--page` removed) and a
//! cheap workspace freshness fingerprint.

use crate::{out_count, paging};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{hash_map::DefaultHasher, BTreeSet};
use std::hash::{Hash, Hasher};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static PAGE_CACHE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static CAPTURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

const EAGER_PAGE_LIMIT: u64 = 32;
const RENDER_CACHE_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CachedPage {
    pub number: u64,
    pub cursor: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PageCacheFile {
    version: u32,
    binary_version: String,
    workspace_fingerprint: u64,
    normalized_argv_hash: u64,
    pages: Vec<CachedPage>,
}

pub(crate) fn write(s: &str) -> bool {
    CAPTURE.with(|slot| {
        if let Some(buf) = slot.borrow_mut().as_mut() {
            buf.push_str(s);
            true
        } else {
            false
        }
    })
}

pub(crate) fn captured_bytes() -> Option<usize> {
    CAPTURE.with(|slot| slot.borrow().as_ref().map(String::len))
}

pub(crate) fn capture<F>(f: F) -> anyhow::Result<String>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    CAPTURE.with(|slot| {
        assert!(slot.borrow().is_none(), "nested CLI page capture");
        *slot.borrow_mut() = Some(String::new());
    });
    let result = f();
    let captured = CAPTURE.with(|slot| slot.borrow_mut().take().unwrap_or_default());
    result.map(|()| captured)
}

pub(crate) fn emit_cached_text(text: &str) -> anyhow::Result<()> {
    let mut h = std::io::stdout().lock();
    h.write_all(text.as_bytes())?;
    out_count::add_counting(text, false);
    Ok(())
}

pub(crate) fn replay_if_hit(workspace: &Path) -> anyhow::Result<bool> {
    if requested_page_arg().is_none() {
        return Ok(false);
    }
    let Some(cache) = read_cache(workspace)? else {
        return Ok(false);
    };
    if !cache_is_fresh(workspace, &cache)? {
        return Ok(false);
    }
    let Some(page) = requested_page(&cache.pages) else {
        return Ok(false);
    };
    emit_cached_text(&page.text)?;
    Ok(true)
}

pub(crate) fn save_pages(workspace: &Path, pages: Vec<CachedPage>) -> anyhow::Result<()> {
    if pages.is_empty() {
        return Ok(());
    }
    let dir = cache_dir(workspace);
    std::fs::create_dir_all(&dir)?;
    let cache = PageCacheFile {
        version: RENDER_CACHE_VERSION,
        binary_version: binary_cache_fingerprint().to_string(),
        workspace_fingerprint: workspace_fingerprint(workspace)?,
        normalized_argv_hash: normalized_argv_hash(),
        pages,
    };
    let path = cache_path(workspace);
    // Per-thread / per-call unique tmp suffix so concurrent renders
    // in the same PID don't collide on the rename. Atomic counter +
    // pid is sufficient for any plausible thread count.
    let counter = PAGE_CACHE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}.{counter:x}.tmp", std::process::id()));
    {
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        tmp_file.write_all(&serde_json::to_vec(&cache)?)?;
        // Per docs/contributing/design-patterns.mdx::Lossless Caches: a partially
        // written cache file must not survive a crash and replay
        // truncated text on the next page request.
        tmp_file.sync_all()?;
    }
    if let Err(err) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err.into());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}

pub(crate) fn eager_window(current_page: u64, total_pages: u64) -> BTreeSet<u64> {
    let mut pages = BTreeSet::new();
    if total_pages == 0 {
        return pages;
    }
    let current = current_page.clamp(1, total_pages);
    let end = current
        .saturating_add(EAGER_PAGE_LIMIT.saturating_sub(1))
        .min(total_pages);
    for page in current..=end {
        pages.insert(page);
    }
    if current > 1 {
        for page in 1..=EAGER_PAGE_LIMIT.min(total_pages) {
            pages.insert(page);
        }
    }
    pages
}

pub(crate) fn emit_paged_text<T, C, R>(
    workspace: &Path,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: C,
    mut render_page: R,
) -> anyhow::Result<()>
where
    T: Clone,
    C: Fn(&T) -> u64,
    R: FnMut(&[T], &paging::PageInfo, &paging::PagingConfig) -> anyhow::Result<()>,
{
    let (_, current_info) = paging::paginate(rows, cfg, command, filters_hash, &row_cost_bytes);
    let current_page = current_info.page_number;
    let mut cached_pages = Vec::new();
    for page_number in eager_window(current_page, current_info.total_pages) {
        let mut page_cfg = cfg.clone();
        if page_number != current_page {
            page_cfg.page = paging::PageArg::Number(page_number);
        }
        let (slice, info) = paging::paginate(rows, &page_cfg, command, filters_hash, &row_cost_bytes);
        let text = capture(|| render_page(&slice, &info, &page_cfg))?;
        cached_pages.push(CachedPage {
            number: info.page_number,
            cursor: info.cursor,
            text,
        });
    }
    if let Err(e) = save_pages(workspace, cached_pages.clone()) {
        tracing::debug!("page cache save failed: {e}");
    }
    if let Some(page) = cached_pages.iter().find(|p| p.number == current_page) {
        emit_cached_text(&page.text)?;
    }
    Ok(())
}

fn requested_page(pages: &[CachedPage]) -> Option<&CachedPage> {
    requested_page_arg().and_then(|arg| page_for_arg(pages, &arg))
}

fn requested_page_arg() -> Option<String> {
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--page" {
            return args.next();
        }
        if let Some(value) = arg.strip_prefix("--page=") {
            return Some(value.to_string());
        }
    }
    None
}

fn page_for_arg<'a>(pages: &'a [CachedPage], raw: &str) -> Option<&'a CachedPage> {
    if let Some(n) = parse_page_number(raw) {
        return pages.iter().find(|p| p.number == n);
    }
    if raw.starts_with("P:") {
        return pages.iter().find(|p| p.cursor == raw);
    }
    None
}

fn parse_page_number(raw: &str) -> Option<u64> {
    let n = raw.parse::<u64>().ok()?;
    (n >= 1).then_some(n)
}

fn read_cache(workspace: &Path) -> anyhow::Result<Option<PageCacheFile>> {
    let path = cache_path(workspace);
    let Ok(bytes) = std::fs::read(path) else {
        return Ok(None);
    };
    let Ok(cache) = serde_json::from_slice::<PageCacheFile>(&bytes) else {
        return Ok(None);
    };
    if cache.version != RENDER_CACHE_VERSION
        || cache.binary_version != binary_cache_fingerprint()
        || cache.normalized_argv_hash != normalized_argv_hash()
    {
        return Ok(None);
    }
    Ok(Some(cache))
}

fn binary_cache_fingerprint() -> &'static str {
    option_env!("BONSAI_BUILD_FINGERPRINT").unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn cache_is_fresh(workspace: &Path, cache: &PageCacheFile) -> anyhow::Result<bool> {
    Ok(cache.workspace_fingerprint == workspace_fingerprint(workspace)?)
}

fn cache_dir(workspace: &Path) -> PathBuf {
    bonsai_common::workspace_bonsai_dir(workspace).join("page-cache.v2")
}

fn cache_path(workspace: &Path) -> PathBuf {
    cache_dir(workspace).join(format!("{:016x}.json", normalized_argv_hash()))
}

fn normalized_argv_hash() -> u64 {
    let mut h = DefaultHasher::new();
    normalized_argv_without_page().hash(&mut h);
    h.finish()
}

fn normalized_argv_without_page() -> Vec<String> {
    let mut out = Vec::new();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--page" {
            let _ = args.next();
            continue;
        }
        if arg.starts_with("--page=") {
            continue;
        }
        out.push(arg);
    }
    out
}

fn workspace_fingerprint(root: &Path) -> anyhow::Result<u64> {
    // Per docs/contributing/design-patterns.mdx::Lossless Caches — cached and
    // uncached results must be bit-for-bit equal. The dataflow
    // sidecar invalidates by file content hash; the page cache must
    // do the same so an mtime-preserving rewrite (cp -p, git
    // checkout, rsync) cannot leave a stale rendered page over a
    // refreshed dataflow graph.
    let mut entries = Vec::new();
    collect_file_fingerprints(root, root, &mut entries)?;
    entries.sort();
    let mut h = DefaultHasher::new();
    root.canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .hash(&mut h);
    for item in entries {
        item.hash(&mut h);
    }
    Ok(h.finish())
}

fn collect_file_fingerprints(root: &Path, dir: &Path, out: &mut Vec<String>) -> anyhow::Result<()> {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name == ".git" || file_name == ".bonsai" || file_name == "target" {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_file_fingerprints(root, &path, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let md = match entry.metadata() {
            Ok(md) => md,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let rel = path.strip_prefix(root).unwrap_or(&path).display();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %error,
                    "page-cache fingerprint skipped unreadable file"
                );
                continue;
            }
        };
        let hash = page_cache_content_hash(&bytes);
        out.push(format!("{rel}\0{}\0{hash:016x}", md.len()));
    }
    Ok(())
}

/// FNV-1a 64-bit, the same digest the dataflow sidecar uses
/// (`crates/workspace/src/dataflow.rs::content_hash`). Both call
/// into `bonsai_hash` so the two caches' invalidation stays in
/// lock-step automatically.
fn page_cache_content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

#[cfg(test)]
mod tests {
    use super::workspace_fingerprint;
    use std::path::PathBuf;

    fn tempdir(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("bonsai-page-cache-{name}-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).expect("create temp dir");
        path
    }

    #[test]
    fn workspace_fingerprint_changes_when_indexed_file_changes() {
        let root = tempdir("content-change");
        let file = root.join("app.py");
        std::fs::write(&file, "print('a')\n").expect("write app");
        let before = workspace_fingerprint(&root).expect("fingerprint before");
        std::fs::write(&file, "print('b')\n").expect("rewrite app");
        let after = workspace_fingerprint(&root).expect("fingerprint after");
        std::fs::remove_dir_all(&root).ok();

        assert_ne!(before, after);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_fingerprint_skips_symlinked_directories() {
        let root = tempdir("symlink-root");
        let outside = tempdir("symlink-outside");
        std::fs::write(root.join("app.py"), "print('root')\n").expect("write root app");
        std::fs::write(outside.join("external.py"), "print('outside')\n").expect("write outside app");
        std::os::unix::fs::symlink(&outside, root.join("linked")).expect("create symlink dir");

        let before = workspace_fingerprint(&root).expect("fingerprint before");
        std::fs::write(outside.join("external.py"), "print('changed')\n").expect("rewrite outside app");
        let after = workspace_fingerprint(&root).expect("fingerprint after");
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();

        assert_eq!(before, after);
    }
}
