//! Persistent rendered-page cache for CLI pagination.
//!
//! Pagination cursors are useful only if turning the page is cheap. The
//! row/flow analysis has already happened on page 1, so page 2 should
//! not reopen a large workspace and recompute the same report. This
//! module stores fully rendered pages under the external workspace cache's
//! `page-cache.v5` directory
//! keyed by the normalized command line (with `--page` removed) and
//! source/rulepack/dependency freshness fingerprints.

use crate::{out_count, output, paging, progress};
use bonsai_common::{
    dependency_metadata::collect_dependency_metadata_fingerprints, wire, write_atomic_bytes,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

static REMEMBERED_WORKSPACE_FINGERPRINT: OnceLock<
    Mutex<Option<(PathBuf, bonsai_sdk::WorkspaceContentFingerprint)>>,
> = OnceLock::new();

fn lock_remembered_workspace_fingerprint(
) -> MutexGuard<'static, Option<(PathBuf, bonsai_sdk::WorkspaceContentFingerprint)>> {
    REMEMBERED_WORKSPACE_FINGERPRINT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

thread_local! {
    static CAPTURE: RefCell<Option<String>> = const { RefCell::new(None) };
}

// Page boundaries and semantic command planning are part of the cached
// rendering contract. Version 12 invalidates payloads produced before
// explicit out-of-range pages failed closed and before the full-result token
// estimate became stable across every page.
// Version 13 stores only the page the caller requested. Earlier versions
// eagerly formatted neighboring pages, multiplying render cost for commands
// whose exact analysis had already completed.
const RENDER_CACHE_VERSION: u32 = 14;

/// Stable structural ids are hashes of rendered chains, so the id alone
/// cannot be inverted into the target declaration that made the query
/// narrow. Remember the originating syntax query when `inspect` emits an
/// `F:`/`G:` id. `show` can then reopen the exact scoped compiler query
/// instead of probing the unrelated security engine or enumerating every
/// callable in a large workspace.
const STRUCTURAL_ID_HINTS_KEY: u64 = 0x5354_5255_4354_4944;
const STRUCTURAL_ID_HINTS_KIND: &str = "structural-id-hints-v2";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct StructuralIdHint {
    pub(crate) query: String,
    pub(crate) regex: bool,
    pub(crate) kind_filter: Vec<String>,
    pub(crate) from: Option<String>,
    pub(crate) from_kind: Option<String>,
    pub(crate) to: Option<String>,
    pub(crate) to_kind: Option<String>,
    pub(crate) file: Option<String>,
    pub(crate) in_fn: Option<String>,
}

/// Upper bound on remembered structural ids. One `inspect-graph` run on a
/// large workspace emits thousands of ids; without a bound the registry grew
/// past 40MB and every id-emitting command re-read and rewrote all of it.
/// Eviction is by insertion order (oldest first), so the ids a user can
/// still see in a recent terminal always resolve.
const STRUCTURAL_ID_HINTS_MAX_ENTRIES: usize = 50_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StructuralIdHints {
    by_id: std::collections::BTreeMap<String, StructuralIdHint>,
    /// Insertion sequence per id (monotonic); absent for entries written by
    /// older binaries, which then evict first.
    #[serde(default)]
    sequence: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    next_sequence: u64,
}

impl StructuralIdHints {
    fn remember(&mut self, id: &str, hint: &StructuralIdHint) -> bool {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let existing = self.by_id.get(id);
        if existing == Some(hint) {
            // Refresh recency so a re-emitted id outlives stale ones.
            self.sequence.insert(id.to_string(), sequence);
            return false;
        }
        self.by_id.insert(id.to_string(), hint.clone());
        self.sequence.insert(id.to_string(), sequence);
        true
    }

    fn evict_to_bound(&mut self) {
        if self.by_id.len() <= STRUCTURAL_ID_HINTS_MAX_ENTRIES {
            return;
        }
        let mut order: Vec<(u64, String)> = self
            .by_id
            .keys()
            .map(|id| (self.sequence.get(id).copied().unwrap_or(0), id.clone()))
            .collect();
        order.sort_unstable();
        let excess = self.by_id.len() - STRUCTURAL_ID_HINTS_MAX_ENTRIES;
        for (_, id) in order.into_iter().take(excess) {
            self.by_id.remove(&id);
            self.sequence.remove(&id);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CachedPage {
    pub number: u64,
    pub total_pages: u64,
    pub cursor: String,
    pub text: String,
}

/// Hard ceiling on a serialized cache file. The cache is an optional
/// acceleration only: larger reports are still analyzed and rendered, but
/// are not persisted. The same bound is checked before reading so a corrupt
/// or hostile workspace cache cannot force an unbounded allocation before
/// its freshness fields are validated.
const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    max_bytes: usize,
    exceeded: bool,
}

impl BoundedJsonBuffer {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(64 * 1024)),
            max_bytes,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedJsonBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "rendered cache exceeds its persistence bound",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PageCacheFile {
    version: u32,
    binary_version: String,
    matcher_policy_fingerprint: u128,
    workspace_fingerprint: bonsai_sdk::WorkspaceContentFingerprint,
    dependency_metadata_fingerprint: u64,
    rulepack_fingerprint: Option<u64>,
    normalized_argv_hash: u64,
    command: String,
    filters_hash: u64,
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
    *lock_remembered_workspace_fingerprint() = Some((stable_workspace, fingerprint));
}

fn remembered_workspace_fingerprint(workspace: &Path) -> Option<bonsai_sdk::WorkspaceContentFingerprint> {
    let stable_workspace = stable_root_path(workspace);
    lock_remembered_workspace_fingerprint()
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
    if cache_disabled() {
        return Ok(false);
    }
    let stage = progress::ScopedSpinner::new("validating rendered page cache");
    let Some(cache) = read_cache(workspace)? else {
        stage.finish();
        return Ok(false);
    };
    if !cache_is_fresh(workspace, &cache)? {
        stage.finish();
        return Ok(false);
    }
    let Some(page) = requested_page(&cache) else {
        stage.finish();
        return Ok(false);
    };
    stage.finish();
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "replaying rendered {} page {}/{}",
        cache.command,
        page.number,
        page.total_pages
    );
    paging::write_last_cursor(&cache.command, cache.filters_hash, &page.cursor);
    emit_cached_text(&page.text)?;
    Ok(true)
}

pub(crate) fn save_pages(
    workspace: &Path,
    command: &str,
    filters_hash: u64,
    pages: Vec<CachedPage>,
) -> anyhow::Result<()> {
    save_pages_value(workspace, command, filters_hash, pages)
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
    /// Length and digest of the sibling `.bin` blob holding the value.
    blob_len: u64,
    blob_digest: u64,
}

fn keyed_payload_path(workspace: &Path, semantic_key: u64) -> PathBuf {
    cache_dir(workspace).join(format!("payload.{semantic_key:016x}.json"))
}

/// The binary blob that accompanies a JSON envelope (`*.json` → `*.bin`).
fn blob_path_for(envelope: &Path) -> PathBuf {
    envelope.with_extension("bin")
}

/// Read a bounded binary blob and verify its recorded length and digest.
fn read_blob(path: &Path, expected_len: u64, expected_digest: u64, max_bytes: usize) -> Option<Vec<u8>> {
    if expected_len > max_bytes as u64 {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() != expected_len {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(expected_len).ok()?);
    file.take(expected_len.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 != expected_len || bonsai_hash::fnv1a_bytes64(&bytes) != expected_digest {
        return None;
    }
    Some(bytes)
}

/// Encode `value` for a payload blob, honouring the byte bound.
fn encode_blob_bounded<T: Serialize>(value: &T, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
    // Map encoding: fields are named, so values with optional/skipped
    // fields decode regardless of which fields were present.
    let bytes = with_cache_fields(|| wire::encode_struct_map(value))?;
    Ok((bytes.len() <= max_bytes).then_some(bytes))
}

/// Complete row sets are larger than rendered pages (a large workspace lists
/// hundreds of thousands of definitions), so they get their own bound and a
/// per-workspace retention of the most recently used sets.
const MAX_ROWS_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
const ROWS_PAYLOAD_RETENTION: usize = 24;

/// One command's complete semantic row set for one set of semantic filters.
/// Rows are stored as native JSON (no string wrapping) so a large set is
/// parsed once.
#[derive(Serialize, Deserialize)]
struct RowsPayloadFile {
    version: u32,
    binary_version: String,
    matcher_policy_fingerprint: u128,
    workspace_fingerprint: bonsai_sdk::WorkspaceContentFingerprint,
    dependency_metadata_fingerprint: u64,
    command: String,
    filters_hash: u64,
    /// Analysis-completeness reasons observed while collecting (for example
    /// files with syntax errors). A replay must report them exactly like the
    /// run that collected the rows.
    #[serde(default)]
    analysis_incomplete_reasons: Vec<String>,
    /// Length and digest of the sibling `.bin` blob holding the rows.
    blob_len: u64,
    blob_digest: u64,
}

/// A replayed complete row set with the completeness facts it was collected
/// under.
pub(crate) struct RowsPayload<T> {
    pub(crate) rows: Vec<T>,
    pub(crate) analysis_incomplete_reasons: Vec<String>,
}

fn rows_payload_key(command: &str, filters_hash: u64) -> u64 {
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(b"rows-payload");
    hasher.absorb(command.as_bytes());
    hasher.absorb(&filters_hash.to_le_bytes());
    hasher.finish()
}

fn rows_payload_path(workspace: &Path, command: &str, filters_hash: u64) -> PathBuf {
    cache_dir(workspace).join(format!(
        "rows.{:016x}.json",
        rows_payload_key(command, filters_hash)
    ))
}

/// The complete row set a browse command computed for `filters_hash`, when
/// it is still fresh for the current sources and binary. Views (page turns,
/// formats, text filters) start from these rows instead of re-collecting.
pub(crate) fn read_rows_payload<T: DeserializeOwned>(
    workspace: &Path,
    command: &str,
    filters_hash: u64,
) -> anyhow::Result<Option<RowsPayload<T>>> {
    if cache_disabled() {
        return Ok(None);
    }
    let path = rows_payload_path(workspace, command, filters_hash);
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Ok(None);
    };
    if current_exe_is_newer_than_cache(&metadata) {
        return Ok(None);
    }
    let started = std::time::Instant::now();
    let Some(file) = read_json_cache_file::<RowsPayloadFile>(&path) else {
        return Ok(None);
    };
    if file.version != RENDER_CACHE_VERSION
        || file.binary_version != binary_cache_fingerprint()
        || file.matcher_policy_fingerprint != bonsai_common::MATCHER_POLICY_FINGERPRINT
        || file.command != command
        || file.filters_hash != filters_hash
    {
        return Ok(None);
    }
    let fresh = file.workspace_fingerprint == workspace_fingerprint(workspace)?
        && file.dependency_metadata_fingerprint == dependency_metadata_fingerprint(workspace)?;
    if !fresh {
        return Ok(None);
    }
    let Some(blob) = read_blob(
        &blob_path_for(&path),
        file.blob_len,
        file.blob_digest,
        MAX_ROWS_PAYLOAD_BYTES,
    ) else {
        return Ok(None);
    };
    let rows: Vec<T> = match wire::decode(&blob) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::debug!("{command} rows payload blob decode failed: {error}");
            return Ok(None);
        }
    };
    // Touch so retention keeps recently used sets.
    let _ = std::fs::File::open(&path).and_then(|f| f.set_modified(std::time::SystemTime::now()));
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "{command} rows payload hit: {:.3}s rows={} bytes={}",
        started.elapsed().as_secs_f64(),
        rows.len(),
        blob.len()
    );
    Ok(Some(RowsPayload {
        rows,
        analysis_incomplete_reasons: file.analysis_incomplete_reasons,
    }))
}

/// Persist a command's complete row set. Failures are logged, never fatal:
/// the rendered result does not depend on the cache.
pub(crate) fn save_rows_payload<T: Serialize>(
    workspace: &Path,
    command: &str,
    filters_hash: u64,
    rows: &[T],
    analysis_incomplete_reasons: &[String],
) {
    if cache_disabled() {
        return;
    }
    let result: anyhow::Result<()> = (|| {
        let dir = cache_dir(workspace);
        std::fs::create_dir_all(&dir)?;
        let workspace_fingerprint = match remembered_workspace_fingerprint(workspace) {
            Some(fingerprint) => fingerprint,
            None => workspace_fingerprint(workspace)?,
        };
        let started = std::time::Instant::now();
        let Some(blob) = encode_blob_bounded(&rows, MAX_ROWS_PAYLOAD_BYTES)? else {
            bonsai_diagnostics::debug_log!(
                "page-cache",
                "skipping {command} rows payload: exceeds {MAX_ROWS_PAYLOAD_BYTES} bytes"
            );
            return Ok(());
        };
        let envelope_path = rows_payload_path(workspace, command, filters_hash);
        write_atomic_bytes(&blob_path_for(&envelope_path), &blob)?;
        let file = RowsPayloadFile {
            version: RENDER_CACHE_VERSION,
            binary_version: binary_cache_fingerprint().to_string(),
            matcher_policy_fingerprint: bonsai_common::MATCHER_POLICY_FINGERPRINT,
            workspace_fingerprint,
            dependency_metadata_fingerprint: dependency_metadata_fingerprint(workspace)?,
            command: command.to_string(),
            filters_hash,
            analysis_incomplete_reasons: analysis_incomplete_reasons.to_vec(),
            blob_len: blob.len() as u64,
            blob_digest: bonsai_hash::fnv1a_bytes64(&blob),
        };
        atomic_write_json(&envelope_path, &file)?;
        bonsai_diagnostics::debug_log!(
            "page-cache",
            "{command} rows payload saved: {:.3}s rows={} bytes={}",
            started.elapsed().as_secs_f64(),
            rows.len(),
            blob.len()
        );
        prune_rows_payloads(&dir);
        Ok(())
    })();
    if let Err(error) = result {
        tracing::debug!("{command} rows payload save failed: {error}");
    }
}

/// Keep the most recently used row sets; the rest are rebuilt on demand.
fn prune_rows_payloads(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("rows.") && name.ends_with(".json")) {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    if files.len() <= ROWS_PAYLOAD_RETENTION {
        return;
    }
    files.sort();
    let excess = files.len() - ROWS_PAYLOAD_RETENTION;
    for (_, path) in files.into_iter().take(excess) {
        let _ = std::fs::remove_file(blob_path_for(&path));
        let _ = std::fs::remove_file(path);
    }
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
    save_keyed_payload_with_bound(workspace, semantic_key, kind, payload, MAX_PAYLOAD_BYTES)
}

/// Complete query reports (an inspect-graph report over a hub name carries
/// hundreds of thousands of flows) are worth far more than the default bound;
/// retention keeps the payload directory bounded instead.
pub(crate) const MAX_REPORT_PAYLOAD_BYTES: usize = 1024 * 1024 * 1024;
const KEYED_PAYLOAD_RETENTION: usize = 48;
/// Total bytes of keyed payload blobs kept per workspace; the oldest are
/// dropped first once the budget is exceeded.
const KEYED_PAYLOAD_BUDGET_BYTES: u64 = 3 * 1024 * 1024 * 1024;

pub(crate) fn save_keyed_payload_with_bound<T: Serialize>(
    workspace: &Path,
    semantic_key: u64,
    kind: &str,
    payload: &T,
    max_bytes: usize,
) -> anyhow::Result<()> {
    if cache_disabled() {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let Some(blob) = encode_blob_bounded(payload, max_bytes)? else {
        bonsai_diagnostics::debug_log!(
            "page-cache",
            "skipping {kind} keyed payload: encoded value exceeds {max_bytes} byte bound"
        );
        return Ok(());
    };
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "{kind} keyed payload encoded: {:.3}s bytes={}",
        started.elapsed().as_secs_f64(),
        blob.len()
    );
    let dir = cache_dir(workspace);
    std::fs::create_dir_all(&dir)?;
    let envelope_path = keyed_payload_path(workspace, semantic_key);
    write_atomic_bytes(&blob_path_for(&envelope_path), &blob)?;
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
        blob_len: blob.len() as u64,
        blob_digest: bonsai_hash::fnv1a_bytes64(&blob),
    };
    atomic_write_json(&envelope_path, &file)?;
    prune_keyed_payloads(&dir);
    Ok(())
}

/// Keep the most recently written keyed payloads; older complete objects are
/// rebuilt on demand.
fn prune_keyed_payloads(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf, u64)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("payload.") && name.ends_with(".json")) {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            let blob_len = std::fs::metadata(blob_path_for(&entry.path()))
                .map(|meta| meta.len())
                .unwrap_or(0);
            Some((modified, entry.path(), blob_len))
        })
        .collect();
    let total: u64 = files.iter().map(|(_, _, len)| *len).sum();
    if files.len() <= KEYED_PAYLOAD_RETENTION && total <= KEYED_PAYLOAD_BUDGET_BYTES {
        return;
    }
    // Oldest first; drop until both the count and the byte budget hold.
    files.sort();
    let mut remaining = files.len();
    let mut total = total;
    for (_, path, len) in files {
        if remaining <= KEYED_PAYLOAD_RETENTION && total <= KEYED_PAYLOAD_BUDGET_BYTES {
            break;
        }
        let _ = std::fs::remove_file(blob_path_for(&path));
        let _ = std::fs::remove_file(path);
        remaining -= 1;
        total = total.saturating_sub(len);
    }
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
    let Some(file) = read_json_cache_file::<KeyedPayloadFile>(&path) else {
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
    let started = std::time::Instant::now();
    let Some(blob) = read_blob(
        &blob_path_for(&path),
        file.blob_len,
        file.blob_digest,
        MAX_REPORT_PAYLOAD_BYTES,
    ) else {
        return Ok(None);
    };
    let decoded: T = match wire::decode(&blob) {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!("{kind} keyed payload blob decode failed: {error}");
            return Ok(None);
        }
    };
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "{kind} keyed payload hit: {:.3}s bytes={}",
        started.elapsed().as_secs_f64(),
        blob.len()
    );
    Ok(Some(decoded))
}

/// Persist query provenance for structural ids emitted by one exact inspect
/// report. This is an optional acceleration cache: failure or an oversized
/// registry never changes analysis results, and all entries are invalidated
/// by the same binary/workspace/dependency fingerprints as rendered pages.
pub(crate) fn remember_structural_id_hints<'a>(
    workspace: &Path,
    ids: impl IntoIterator<Item = &'a str>,
    hint: StructuralIdHint,
) {
    if cache_disabled() {
        return;
    }
    let mut registry = match read_keyed_payload::<StructuralIdHints>(
        workspace,
        STRUCTURAL_ID_HINTS_KEY,
        STRUCTURAL_ID_HINTS_KIND,
    ) {
        Ok(Some(registry)) => registry,
        Ok(None) => StructuralIdHints::default(),
        Err(error) => {
            tracing::debug!("structural id hint cache read failed: {error}");
            StructuralIdHints::default()
        }
    };
    let mut changed = false;
    for id in ids {
        if !matches!(id.split_once(':'), Some(("F" | "G" | "T", body)) if !body.is_empty()) {
            continue;
        }
        changed |= registry.remember(id, &hint);
    }
    if changed {
        registry.evict_to_bound();
        if let Err(error) = save_keyed_payload(
            workspace,
            STRUCTURAL_ID_HINTS_KEY,
            STRUCTURAL_ID_HINTS_KIND,
            &registry,
        ) {
            tracing::debug!("structural id hint cache save failed: {error}");
        }
    }
}

/// Return the fresh originating query for an emitted structural id.
pub(crate) fn structural_id_hint(workspace: &Path, id: &str) -> anyhow::Result<Option<StructuralIdHint>> {
    Ok(
        read_keyed_payload::<StructuralIdHints>(
            workspace,
            STRUCTURAL_ID_HINTS_KEY,
            STRUCTURAL_ID_HINTS_KIND,
        )?
        .and_then(|registry| registry.by_id.get(id).cloned()),
    )
}

thread_local! {
    static CACHE_FIELDS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `skip_serializing_if` predicate for fields that exist only to replay a
/// cached report (hydration plans, function ids, cost estimates): hidden
/// from every user-facing JSON document, emitted only while a payload is
/// being written.
pub(crate) fn hide_cache_only<T>(_: &T) -> bool {
    !CACHE_FIELDS.with(std::cell::Cell::get)
}

fn with_cache_fields<R>(f: impl FnOnce() -> R) -> R {
    let previous = CACHE_FIELDS.with(|flag| flag.replace(true));
    let result = f();
    CACHE_FIELDS.with(|flag| flag.set(previous));
    result
}

/// Atomically write `value` as JSON to `path` via a temp file + rename,
/// fsync'd so a crash can't leave a torn cache file. Shared by the page
/// cache and the keyed-payload store.
fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    // The keyed-payload value is bounded by its own writer; the envelope
    // itself is bounded by the largest bound any writer may use.
    let Some(bytes) =
        serialize_json_bounded(value, MAX_REPORT_PAYLOAD_BYTES.saturating_add(MAX_PAYLOAD_BYTES))?
    else {
        bonsai_diagnostics::debug_log!(
            "page-cache",
            "skipping rendered cache file: serialized value exceeds the cache bound"
        );
        return Ok(());
    };
    write_atomic_bytes(path, &bytes).map_err(Into::into)
}

fn serialize_json_bounded<T: Serialize>(value: &T, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
    let mut output = BoundedJsonBuffer::new(max_bytes);
    match serde_json::to_writer(&mut output, value) {
        Ok(()) => Ok(Some(output.bytes)),
        Err(_) if output.exceeded => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn save_pages_value(
    workspace: &Path,
    command: &str,
    filters_hash: u64,
    pages: Vec<CachedPage>,
) -> anyhow::Result<()> {
    // The rendered-page cache exists to make repeated requests and page
    // turns cheap. Every report is cached even when it fits one page: a
    // corridor that fits one page still costs the whole query to recompute,
    // and a security inventory that fits one page still costs a workspace
    // open before its keyed payload can be read. Replaying the rendered
    // page skips both.
    if cache_disabled() || pages.is_empty() {
        return Ok(());
    }
    let dir = cache_dir(workspace);
    std::fs::create_dir_all(&dir)?;
    let workspace_fingerprint = match remembered_workspace_fingerprint(workspace) {
        Some(fingerprint) => fingerprint,
        None => workspace_fingerprint(workspace)?,
    };
    let dependency_metadata_fingerprint = dependency_metadata_fingerprint(workspace)?;
    let rulepack_fingerprint = rulepack_fingerprint_for_command(workspace)?;
    let mut by_number = BTreeMap::new();
    if let Some(existing) = read_cache(workspace)? {
        let same_report = existing.command == command
            && existing.filters_hash == filters_hash
            && existing.workspace_fingerprint == workspace_fingerprint
            && existing.dependency_metadata_fingerprint == dependency_metadata_fingerprint
            && existing.rulepack_fingerprint == rulepack_fingerprint;
        if same_report {
            by_number.extend(existing.pages.into_iter().map(|page| (page.number, page)));
        }
    }
    // Newly rendered bytes win if this process refreshed a page already in
    // the on-demand cache. No unrequested page is formatted or synthesized.
    by_number.extend(pages.into_iter().map(|page| (page.number, page)));
    let cache = PageCacheFile {
        version: RENDER_CACHE_VERSION,
        binary_version: binary_cache_fingerprint().to_string(),
        matcher_policy_fingerprint: bonsai_common::MATCHER_POLICY_FINGERPRINT,
        workspace_fingerprint,
        dependency_metadata_fingerprint,
        rulepack_fingerprint,
        normalized_argv_hash: normalized_argv_hash(),
        command: command.to_string(),
        filters_hash,
        pages: by_number.into_values().collect(),
    };
    // Per docs/contributing/design-patterns.mdx::Lossless Caches: a
    // partially written cache file must not survive a crash and replay
    // truncated text on the next page request — `atomic_write_json`
    // fsyncs a temp file then renames.
    atomic_write_json(&cache_path(workspace), &cache)
}

pub(crate) fn requested_page_window(current_page: u64, total_pages: u64) -> BTreeSet<u64> {
    let mut pages = BTreeSet::new();
    if total_pages == 0 {
        return pages;
    }
    pages.insert(current_page.clamp(1, total_pages));
    pages
}

/// Query reports up to this many pages are rendered and cached in full on
/// the first request, so every later page is a replay.
const FULL_RENDER_PAGE_LIMIT: u64 = 12;

/// The pages a query report (browse, inspect-graph) renders now: the
/// requested page, the page after it (so `--page next` replays), and every
/// page of a short report. A page render costs milliseconds next to the
/// query that produced the rows; long reports still render on demand.
pub(crate) fn query_report_page_window(current_page: u64, total_pages: u64) -> BTreeSet<u64> {
    let mut pages = BTreeSet::new();
    if total_pages == 0 {
        return pages;
    }
    let current = current_page.clamp(1, total_pages);
    if total_pages <= FULL_RENDER_PAGE_LIMIT {
        pages.extend(1..=total_pages);
        return pages;
    }
    pages.insert(current);
    if current < total_pages {
        pages.insert(current + 1);
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
    render_page: R,
) -> anyhow::Result<()>
where
    T: Clone + serde::Serialize,
    C: Fn(&T) -> u64,
    R: FnMut(&[T], &paging::PageInfo, &paging::PagingConfig) -> anyhow::Result<()>,
{
    emit_paged_text_inner(
        workspace,
        rows,
        cfg,
        command,
        filters_hash,
        row_cost_bytes,
        render_page,
        true,
    )
}

/// Paginate rows whose caller has already applied the global secondary
/// filter to its complete canonical render object. This prevents the shared
/// pager from filtering a thinner compiler row a second time and dropping a
/// result whose match lives in derived code/signature/flow evidence.
pub(crate) fn emit_paged_text_prefiltered<T, C, R>(
    workspace: &Path,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: C,
    render_page: R,
) -> anyhow::Result<()>
where
    T: Clone + serde::Serialize,
    C: Fn(&T) -> u64,
    R: FnMut(&[T], &paging::PageInfo, &paging::PagingConfig) -> anyhow::Result<()>,
{
    emit_paged_text_inner(
        workspace,
        rows,
        cfg,
        command,
        filters_hash,
        row_cost_bytes,
        render_page,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_paged_text_inner<T, C, R>(
    workspace: &Path,
    rows: &[T],
    cfg: &paging::PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: C,
    mut render_page: R,
    apply_secondary_filter: bool,
) -> anyhow::Result<()>
where
    T: Clone + serde::Serialize,
    C: Fn(&T) -> u64,
    R: FnMut(&[T], &paging::PageInfo, &paging::PagingConfig) -> anyhow::Result<()>,
{
    let paging_started = std::time::Instant::now();
    // Secondary `--contains` / `--not-contains` filters run here, the
    // shared funnel for every row-based command's text AND json paths.
    // Drop the non-matching rows before pagination so page counts,
    // budgets, and cursors all reflect the filtered set. The filter is
    // part of the normalized argv, so the saved pages key correctly.
    let secondary = crate::filter::active();
    let filtered_storage: Option<Vec<T>> = (apply_secondary_filter && secondary.is_active()).then(|| {
        let mut kept = rows.to_vec();
        secondary.retain(&mut kept);
        kept
    });
    let rows: &[T] = filtered_storage.as_deref().unwrap_or(rows);
    let (_, current_info) = paging::paginate(rows, cfg, command, filters_hash, &row_cost_bytes)?;
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "{command} pagination planned: {:.3}s rows={} pages={}",
        paging_started.elapsed().as_secs_f64(),
        rows.len(),
        current_info.total_pages
    );
    let current_page = current_info.page_number;
    let mut cached_pages = Vec::new();
    let render_label = format!("rendering {command} page");
    let render_stage = progress::ScopedSpinner::new(&render_label);
    for page_number in query_report_page_window(current_page, current_info.total_pages) {
        let mut page_cfg = cfg.clone();
        if page_number != current_page {
            page_cfg.page = paging::PageArg::Number(page_number);
        }
        let (slice, info) = paging::paginate(rows, &page_cfg, command, filters_hash, &row_cost_bytes)?;
        let text = capture(|| render_page(&slice, &info, &page_cfg))?;
        cached_pages.push(CachedPage {
            number: info.page_number,
            total_pages: info.total_pages,
            cursor: info.cursor,
            text,
        });
    }
    render_stage.finish();
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "{command} requested page rendered: {:.3}s pages={}",
        paging_started.elapsed().as_secs_f64(),
        cached_pages.len()
    );
    let cache_stage = progress::ScopedSpinner::new("saving rendered page cache");
    let save_started = std::time::Instant::now();
    if let Err(e) = save_pages(workspace, command, filters_hash, cached_pages.clone()) {
        tracing::debug!("page cache save failed: {e}");
    }
    cache_stage.finish();
    bonsai_diagnostics::debug_log!(
        "page-cache",
        "{command} page cache saved: {:.3}s total={:.3}s",
        save_started.elapsed().as_secs_f64(),
        paging_started.elapsed().as_secs_f64()
    );
    // Cache publication must not replace the user's actual current page in
    // `--page next` history.
    paging::write_last_cursor(command, filters_hash, &current_info.cursor);
    if let Some(page) = cached_pages.iter().find(|p| p.number == current_page) {
        emit_cached_text(&page.text)?;
    }
    Ok(())
}

fn requested_page(cache: &PageCacheFile) -> Option<&CachedPage> {
    let Some(arg) = requested_page_arg() else {
        return cache.pages.iter().find(|page| page.number == 1);
    };
    if arg.eq_ignore_ascii_case("next") {
        let current = paging::last_cursor(&cache.command, cache.filters_hash)?;
        return page_after_cursor(&cache.pages, &current);
    }
    page_for_arg(&cache.pages, &arg)
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

fn page_after_cursor<'a>(pages: &'a [CachedPage], cursor: &str) -> Option<&'a CachedPage> {
    let current = pages.iter().position(|page| page.cursor == cursor)?;
    pages.get(current + 1)
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
    let Some(cache) = read_json_cache_file::<PageCacheFile>(&path) else {
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

fn read_json_cache_file<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() > MAX_PAYLOAD_BYTES as u64 {
        tracing::debug!(
            "ignoring rendered cache file {}: {} bytes exceeds {MAX_PAYLOAD_BYTES} cache bound",
            path.display(),
            metadata.len()
        );
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_PAYLOAD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn binary_cache_fingerprint() -> &'static str {
    bonsai_sdk::analyzer_build_fingerprint()
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
    Ok(cache.workspace_fingerprint == workspace_fingerprint(workspace)?
        && cache.dependency_metadata_fingerprint == dependency_metadata_fingerprint(workspace)?
        && cache.rulepack_fingerprint == rulepack_fingerprint_for_command(workspace)?)
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

/// Flags that cannot change the rendered bytes: page selection, output
/// destination (every spelling), and stderr-only / scheduling switches. They
/// are dropped from the rendered-page key so toggling them replays the same
/// page instead of recomputing it.
const KEY_NEUTRAL_FLAGS_WITH_VALUE: &[&str] = &[
    "--page",
    "--output-path",
    "--output",
    "-o",
    "--debug",
    "--memory-budget",
];
const KEY_NEUTRAL_FLAGS: &[&str] = &["--no-progress"];

fn normalized_argv_without_page() -> Vec<String> {
    let mut out = Vec::new();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if KEY_NEUTRAL_FLAGS_WITH_VALUE.contains(&arg.as_str()) {
            let _ = args.next();
            continue;
        }
        if KEY_NEUTRAL_FLAGS_WITH_VALUE
            .iter()
            .any(|flag| flag.starts_with("--") && arg.starts_with(&format!("{flag}=")))
        {
            continue;
        }
        if KEY_NEUTRAL_FLAGS.contains(&arg.as_str()) {
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
    // Git is only an exact freshness proof for the manifest's previously
    // content-hashed compiler inputs. Any mismatch falls back to the complete
    // filesystem/content walk in the SDK.
    bonsai_sdk::workspace_source_fingerprint_for_cache_validation_with_minified(
        root,
        crate::include_minified_sources(),
    )
}

/// FNV-1a 64-bit, the same digest the dataflow sidecar uses
/// (`crates/workspace/src/dataflow.rs::content_hash`). Both call
/// into `bonsai_hash` so the two caches' invalidation stays in
/// lock-step automatically.
fn page_cache_content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

fn rulepack_fingerprint_for_command(workspace: &Path) -> anyhow::Result<Option<u64>> {
    if !command_uses_rulepack() {
        return Ok(None);
    }
    let root = explicit_rules_dir_arg().or_else(|| bonsai_sdk::Bonsai::discover_rulepack_root(workspace));
    root.map(|path| content_tree_fingerprint(&path, rulepack_dir_skipped))
        .transpose()
}

fn command_uses_rulepack() -> bool {
    #[cfg(test)]
    {
        true
    }
    #[cfg(not(test))]
    {
        std::env::args_os().any(|arg| arg == "security")
    }
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
