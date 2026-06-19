//! Persistent rendered-page cache for CLI pagination.
//!
//! Pagination cursors are useful only if turning the page is cheap. The
//! row/flow analysis has already happened on page 1, so page 2 should
//! not reopen a large workspace and recompute the same report. This
//! module stores fully rendered pages under `.bonsai/page-cache.v5`
//! keyed by the normalized command line (with `--page` removed) and
//! source/rulepack/dependency freshness fingerprints.

use crate::{out_count, output, paging, progress};
use bonsai_common::dependency_metadata::collect_dependency_metadata_fingerprints;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::UNIX_EPOCH;

static PAGE_CACHE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static REMEMBERED_WORKSPACE_FINGERPRINT: OnceLock<
    Mutex<Option<(PathBuf, bonsai_sdk::WorkspaceContentFingerprint)>>,
> = OnceLock::new();

thread_local! {
    static CAPTURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

const EAGER_PAGE_LIMIT: u64 = 4;
const RENDER_CACHE_VERSION: u32 = 6;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CachedPage {
    pub number: u64,
    pub cursor: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WorkspaceMetadataFingerprint {
    files: usize,
    digest: u64,
}

/// Hard ceiling on a cached command payload. The payload exists so a
/// re-invocation can re-render without re-running analysis; past this
/// size the save/reload memory cost outweighs the re-run it avoids,
/// so larger payloads are simply not cached. This bound is what keeps
/// huge-corpus reports from exhausting memory at render time.
const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PageCacheFile {
    version: u32,
    binary_version: String,
    matcher_policy_fingerprint: u128,
    workspace_fingerprint: bonsai_sdk::WorkspaceContentFingerprint,
    workspace_metadata_fingerprint: WorkspaceMetadataFingerprint,
    dependency_metadata_fingerprint: u64,
    rulepack_fingerprint: Option<u64>,
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
    if output::write_raw_counted(text) {
        return Ok(());
    }
    let mut h = std::io::stdout().lock();
    h.write_all(text.as_bytes())?;
    out_count::add_counting(text, false);
    Ok(())
}

pub(crate) fn remember_workspace_fingerprint(
    workspace: &Path,
    fingerprint: bonsai_sdk::WorkspaceContentFingerprint,
) {
    let stable_workspace = stable_root_path(workspace);
    *REMEMBERED_WORKSPACE_FINGERPRINT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("page-cache fingerprint lock") = Some((stable_workspace, fingerprint));
}

fn remembered_workspace_fingerprint(workspace: &Path) -> Option<bonsai_sdk::WorkspaceContentFingerprint> {
    let stable_workspace = stable_root_path(workspace);
    REMEMBERED_WORKSPACE_FINGERPRINT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("page-cache fingerprint lock")
        .as_ref()
        .and_then(|(remembered_root, fingerprint)| {
            (remembered_root == &stable_workspace).then_some(*fingerprint)
        })
}

/// `--no-cache` / `BONSAI_NO_CACHE` disables the rendered-page cache
/// entirely: no replay, no payload reuse, no saves. The flag is the
/// documented escape hatch for stale state, so an argv-keyed replay
/// (the flag is part of the key!) must not serve a previous
/// `--no-cache` run's output back.
fn cache_disabled() -> bool {
    *crate::NO_CACHE.get().unwrap_or(&false)
}

pub(crate) fn replay_if_hit(workspace: &Path) -> anyhow::Result<bool> {
    if cache_disabled() || requested_page_arg().is_none() {
        return Ok(false);
    }
    let bar = progress::spinner("validating rendered page cache");
    let Some(cache) = read_cache(workspace)? else {
        bar.finish_and_clear();
        return Ok(false);
    };
    if !cache_is_fresh(workspace, &cache)? {
        bar.finish_and_clear();
        return Ok(false);
    }
    let Some(page) = requested_page(&cache.pages) else {
        bar.finish_and_clear();
        return Ok(false);
    };
    bar.finish_and_clear();
    emit_cached_text(&page.text)?;
    Ok(true)
}

pub(crate) fn save_pages(workspace: &Path, pages: Vec<CachedPage>) -> anyhow::Result<()> {
    save_pages_value(workspace, pages)
}

/// A payload cached under an explicit SEMANTIC key rather than the
/// command line. The key is computed by the caller from only the
/// inputs that change the result (for taint-analysis: the source/sink/
/// severity/etc. filters + content + rulepack), so output-shaping
/// flags — format, paging, `--contains` — reuse this entry instead of
/// re-running the analysis. Freshness is verified the same way as the
/// page cache (binary / matcher-policy / workspace-content / rulepack).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyedPayloadFile {
    version: u32,
    binary_version: String,
    matcher_policy_fingerprint: u128,
    workspace_fingerprint: bonsai_sdk::WorkspaceContentFingerprint,
    dependency_metadata_fingerprint: u64,
    rulepack_fingerprint: Option<u64>,
    semantic_key: u64,
    kind: String,
    /// Pre-serialized payload JSON (a string, never a `Value` tree).
    value: String,
}

fn keyed_payload_path(workspace: &Path, semantic_key: u64) -> PathBuf {
    cache_dir(workspace).join(format!("payload.{semantic_key:016x}.json"))
}

/// Persist `payload` under `semantic_key`. No-op when caching is
/// disabled or the payload exceeds [`MAX_PAYLOAD_BYTES`] (a cache miss
/// next time, never a correctness problem).
pub(crate) fn save_keyed_payload<T: Serialize>(
    workspace: &Path,
    semantic_key: u64,
    kind: &str,
    payload: &T,
) -> anyhow::Result<()> {
    if cache_disabled() {
        return Ok(());
    }
    let value = serde_json::to_string(payload)?;
    if value.len() > MAX_PAYLOAD_BYTES {
        tracing::debug!(
            "skipping {kind} keyed payload: {} bytes exceeds {MAX_PAYLOAD_BYTES} cap",
            value.len()
        );
        return Ok(());
    }
    let dir = cache_dir(workspace);
    std::fs::create_dir_all(&dir)?;
    let file = KeyedPayloadFile {
        version: RENDER_CACHE_VERSION,
        binary_version: binary_cache_fingerprint().to_string(),
        matcher_policy_fingerprint: bonsai_common::MATCHER_POLICY_FINGERPRINT,
        workspace_fingerprint: match remembered_workspace_fingerprint(workspace) {
            Some(fingerprint) => fingerprint,
            None => workspace_fingerprint(workspace)?,
        },
        dependency_metadata_fingerprint: dependency_metadata_fingerprint(workspace)?,
        rulepack_fingerprint: rulepack_fingerprint_for_command(workspace)?,
        semantic_key,
        kind: kind.to_string(),
        value,
    };
    atomic_write_json(&keyed_payload_path(workspace, semantic_key), &file)
}

/// Read the payload stored under `semantic_key`/`kind` when it is fresh
/// against the current binary, rulepack, and workspace content.
pub(crate) fn read_keyed_payload<T: DeserializeOwned>(
    workspace: &Path,
    semantic_key: u64,
    kind: &str,
) -> anyhow::Result<Option<T>> {
    if cache_disabled() {
        return Ok(None);
    }
    let path = keyed_payload_path(workspace, semantic_key);
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Ok(None);
    };
    if current_exe_is_newer_than_cache(&metadata) {
        return Ok(None);
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(None);
    };
    let Ok(file) = serde_json::from_slice::<KeyedPayloadFile>(&bytes) else {
        return Ok(None);
    };
    if file.version != RENDER_CACHE_VERSION
        || file.binary_version != binary_cache_fingerprint()
        || file.matcher_policy_fingerprint != bonsai_common::MATCHER_POLICY_FINGERPRINT
        || file.semantic_key != semantic_key
        || file.kind != kind
    {
        return Ok(None);
    }
    let fresh = file.workspace_fingerprint == workspace_fingerprint(workspace)?
        && file.dependency_metadata_fingerprint == dependency_metadata_fingerprint(workspace)?
        && file.rulepack_fingerprint == rulepack_fingerprint_for_command(workspace)?;
    if !fresh {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&file.value)?))
}

/// Atomically write `value` as JSON to `path` via a temp file + rename,
/// fsync'd so a crash can't leave a torn cache file. Shared by the page
/// cache and the keyed-payload store.
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let counter = PAGE_CACHE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}.{counter:x}.tmp", std::process::id()));
    {
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        tmp_file.write_all(&serde_json::to_vec(value)?)?;
        tmp_file.sync_all()?;
    }
    if let Err(err) = std::fs::rename(&tmp, path) {
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

fn save_pages_value(workspace: &Path, pages: Vec<CachedPage>) -> anyhow::Result<()> {
    if cache_disabled() || pages.is_empty() {
        return Ok(());
    }
    let dir = cache_dir(workspace);
    std::fs::create_dir_all(&dir)?;
    let cache = PageCacheFile {
        version: RENDER_CACHE_VERSION,
        binary_version: binary_cache_fingerprint().to_string(),
        matcher_policy_fingerprint: bonsai_common::MATCHER_POLICY_FINGERPRINT,
        workspace_fingerprint: match remembered_workspace_fingerprint(workspace) {
            Some(fingerprint) => fingerprint,
            None => workspace_fingerprint(workspace)?,
        },
        workspace_metadata_fingerprint: workspace_metadata_fingerprint(workspace)?,
        dependency_metadata_fingerprint: dependency_metadata_fingerprint(workspace)?,
        rulepack_fingerprint: rulepack_fingerprint_for_command(workspace)?,
        normalized_argv_hash: normalized_argv_hash(),
        pages,
    };
    // Per docs/contributing/design-patterns.mdx::Lossless Caches: a
    // partially written cache file must not survive a crash and replay
    // truncated text on the next page request — `atomic_write_json`
    // fsyncs a temp file then renames.
    atomic_write_json(&cache_path(workspace), &cache)
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
    T: Clone + serde::Serialize,
    C: Fn(&T) -> u64,
    R: FnMut(&[T], &paging::PageInfo, &paging::PagingConfig) -> anyhow::Result<()>,
{
    // Secondary `--contains` / `--not-contains` filters run here, the
    // shared funnel for every row-based command's text AND json paths.
    // Drop the non-matching rows before pagination so page counts,
    // budgets, and cursors all reflect the filtered set. The filter is
    // part of the normalized argv, so the saved pages key correctly.
    let secondary = crate::filter::active();
    let filtered_storage: Option<Vec<T>> = secondary.is_active().then(|| {
        let mut kept = rows.to_vec();
        secondary.retain(&mut kept);
        kept
    });
    let rows: &[T] = filtered_storage.as_deref().unwrap_or(rows);
    let (_, current_info) = paging::paginate(rows, cfg, command, filters_hash, &row_cost_bytes);
    let current_page = current_info.page_number;
    let mut cached_pages = Vec::new();
    let render_label = format!("rendering {command} page");
    let render_bar = progress::spinner(&render_label);
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
    render_bar.finish_and_clear();
    let cache_bar = progress::spinner("saving rendered page cache");
    if let Err(e) = save_pages(workspace, cached_pages.clone()) {
        tracing::debug!("page cache save failed: {e}");
    }
    cache_bar.finish_and_clear();
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
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Ok(None);
    };
    if current_exe_is_newer_than_cache(&metadata) {
        return Ok(None);
    }
    let Ok(bytes) = std::fs::read(path) else {
        return Ok(None);
    };
    let Ok(cache) = serde_json::from_slice::<PageCacheFile>(&bytes) else {
        return Ok(None);
    };
    if cache.version != RENDER_CACHE_VERSION
        || cache.binary_version != binary_cache_fingerprint()
        || cache.matcher_policy_fingerprint != bonsai_common::MATCHER_POLICY_FINGERPRINT
        || cache.normalized_argv_hash != normalized_argv_hash()
    {
        return Ok(None);
    }
    Ok(Some(cache))
}

fn binary_cache_fingerprint() -> &'static str {
    option_env!("BONSAI_BUILD_FINGERPRINT").unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn current_exe_is_newer_than_cache(cache_metadata: &std::fs::Metadata) -> bool {
    let Ok(cache_modified) = cache_metadata.modified() else {
        return false;
    };
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Ok(exe_meta) = std::fs::metadata(exe) else {
        return false;
    };
    let Ok(exe_modified) = exe_meta.modified() else {
        return false;
    };
    exe_modified > cache_modified
}

fn cache_is_fresh(workspace: &Path, cache: &PageCacheFile) -> anyhow::Result<bool> {
    Ok(
        cache.workspace_metadata_fingerprint == workspace_metadata_fingerprint(workspace)?
            && cache.dependency_metadata_fingerprint == dependency_metadata_fingerprint(workspace)?
            && cache.rulepack_fingerprint == rulepack_fingerprint_for_command(workspace)?,
    )
}

fn cache_dir(workspace: &Path) -> PathBuf {
    bonsai_common::workspace_bonsai_dir(workspace).join("page-cache.v5")
}

fn cache_path(workspace: &Path) -> PathBuf {
    cache_dir(workspace).join(format!("{:016x}.json", normalized_argv_hash()))
}

fn normalized_argv_hash() -> u64 {
    let mut h = bonsai_hash::Hasher::new();
    for arg in normalized_argv_without_page() {
        h.absorb(arg.as_bytes());
        h.absorb_separator();
    }
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
        if arg == "--output-path" {
            let _ = args.next();
            continue;
        }
        if arg.starts_with("--output-path=") {
            continue;
        }
        out.push(arg);
    }
    out
}

pub(crate) fn current_command_without_page_hint(fallback: &str) -> String {
    let args = normalized_argv_without_page();
    if args.is_empty() {
        return fallback.to_string();
    }
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push("bonsai-ninja".to_string());
    parts.extend(args.into_iter().map(shell_quote_arg));
    parts.join(" ")
}

fn shell_quote_arg(arg: String) -> String {
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | ':' | '=' | ','))
    {
        arg
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn workspace_fingerprint(root: &Path) -> anyhow::Result<bonsai_sdk::WorkspaceContentFingerprint> {
    // Rendered CLI output is derived from indexed source files, dependency
    // metadata, rulepacks, and command args. Use the SDK's supported-source
    // fingerprint so first-page cache saves do not recursively re-read every
    // file in large workspaces after analysis has already completed.
    bonsai_sdk::workspace_source_fingerprint_from_disk(root)
}

fn workspace_metadata_fingerprint(root: &Path) -> anyhow::Result<WorkspaceMetadataFingerprint> {
    let stable_root = stable_root_path(root);
    let registry = bonsai_adapters::all_languages_registry();
    let include_minified = include_minified_sources();
    let mut builder = ignore::WalkBuilder::new(&stable_root);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(true)
        .parents(true)
        .ignore(true)
        .add_custom_ignore_filename(".bonsaiignore");
    builder.filter_entry(move |entry| include_minified || !path_looks_minified(entry.path()));

    let mut entries = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if ignore_error_is_missing_or_denied(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let path = entry.path();
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if registry.adapter_for_extension(ext).is_none() {
            continue;
        }
        if !include_minified_sources() && path_looks_minified(path) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if ignore_error_is_missing_or_denied(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let modified_ns = metadata_modified_nanos(&metadata);
        let rel = stable_relative_path(&stable_root, path);
        entries.push(format!("{rel}\0{:016x}\0{:032x}", metadata.len(), modified_ns));
    }
    let files = entries.len();
    Ok(WorkspaceMetadataFingerprint {
        files,
        digest: fingerprint_entries(entries),
    })
}

fn include_minified_sources() -> bool {
    std::env::var("BONSAI_INCLUDE_MINIFIED")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
}

fn ignore_error_is_missing_or_denied(error: &ignore::Error) -> bool {
    error.io_error().is_some_and(|io_error| {
        matches!(
            io_error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        )
    })
}

fn path_looks_minified(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains(".min.") || lower.ends_with(".min.js") || lower.ends_with(".min.css")
        })
}

fn metadata_modified_nanos(metadata: &std::fs::Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

/// FNV-1a 64-bit, the same digest the dataflow sidecar uses
/// (`crates/workspace/src/dataflow.rs::content_hash`). Both call
/// into `bonsai_hash` so the two caches' invalidation stays in
/// lock-step automatically.
fn page_cache_content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

fn rulepack_fingerprint_for_command(workspace: &Path) -> anyhow::Result<Option<u64>> {
    let root = explicit_rules_dir_arg().or_else(|| bonsai_sdk::Bonsai::discover_rulepack_root(workspace));
    root.map(|path| content_tree_fingerprint(&path, rulepack_dir_skipped))
        .transpose()
}

fn explicit_rules_dir_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--rules-dir" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg.strip_prefix("--rules-dir=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn dependency_metadata_fingerprint(root: &Path) -> anyhow::Result<u64> {
    let entries = collect_dependency_metadata_fingerprints(root)?;
    Ok(fingerprint_entries(
        entries
            .into_iter()
            .map(|entry| format!("{}\0{:016x}", entry.relative_path, entry.content_hash))
            .collect(),
    ))
}

fn content_tree_fingerprint(root: &Path, skip_dir: fn(&str) -> bool) -> anyhow::Result<u64> {
    let stable_root = stable_root_path(root);
    let mut entries = Vec::new();
    collect_regular_file_fingerprints(&stable_root, &stable_root, &mut entries, skip_dir)?;
    let mut h = bonsai_hash::Hasher::new();
    h.absorb(if stable_root.is_dir() {
        b"dir-exists"
    } else {
        b"dir-missing"
    });
    h.absorb_separator();
    let entries_digest = fingerprint_entries(entries);
    h.absorb(&entries_digest.to_le_bytes());
    Ok(h.finish())
}

fn collect_regular_file_fingerprints(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
    skip_dir: fn(&str) -> bool,
) -> anyhow::Result<()> {
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
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                if skip_dir(name) {
                    continue;
                }
            }
            collect_regular_file_fingerprints(root, &path, out, skip_dir)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let rel = stable_relative_path(root, &path);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        out.push(format!("{rel}\0{:016x}", page_cache_content_hash(&bytes)));
    }
    Ok(())
}

fn fingerprint_entries(mut entries: Vec<String>) -> u64 {
    entries.sort();
    let mut h = bonsai_hash::Hasher::new();
    for entry in entries {
        h.absorb(entry.as_bytes());
        h.absorb_separator();
    }
    h.finish()
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

fn rulepack_dir_skipped(name: &str) -> bool {
    matches!(name, ".git" | ".bonsai" | "target")
}

#[cfg(test)]
#[path = "page_cache_tests.rs"]
mod tests;
