//! Map a browse-row location to the flow IDs whose upstream chains
//! end in the row's enclosing function.
//!
//! Every browse command (`defs`, `calls`, `imports`, `vars`,
//! `strings`, `args`, `classes`, `refs`, `search`) surfaces a row
//! at `(file, line)`. [`FlowAnnotator::labels_for`] returns the
//! pre-computed `F:<16-hex>` ids for that row's enclosing function
//! — the same IDs `inspect` emits, so a user can paste one into
//! `inspect --flow F:<16-hex>` to expand the chain.
//!
//! The per-function id set is built lazily by
//! [`bonsai_workspace::flow_ids::FlowIdCache::labels_for_func`],
//! so this struct answers "which function is this location inside?"
//! and then reads the shared cache. Hub functions may return a
//! bounded prefix with a trailing ellipsis. Renderers must surface
//! that as incomplete flow-label evidence; `inspect --query ... --all`
//! is the full expansion surface.

use bonsai_common::{FileId, FuncId};
use bonsai_workspace::Workspace;
use parking_lot::Mutex;
use std::sync::OnceLock;

/// Line-accurate resolver from `(file_path, line)` to flow-id
/// labels. One instance per CLI invocation; per-row calls are O(1)
/// in the workspace flow-id cache.
pub struct FlowAnnotator<'ws> {
    ws: &'ws Workspace,
    /// Lazy `path-string → FileId` index, populated on first use.
    file_by_path: OnceLock<ahash::AHashMap<String, FileId>>,
    /// Per-file function line-range cache, populated on demand by
    /// `func_ranges_for_file`.
    func_ranges_by_file: Mutex<ahash::AHashMap<FileId, Vec<FuncLineRange>>>,
}

/// One callable decl's line range within a file. `width` is the
/// span length in bytes — used to pick the narrowest enclosing
/// function when ranges nest.
#[derive(Clone)]
struct FuncLineRange {
    start_line: u32,
    end_line: u32,
    width: u64,
    func: FuncId,
}

impl<'ws> FlowAnnotator<'ws> {
    /// Build a new annotator. Indexes are lazy — first call
    /// pays the indexing cost.
    #[must_use]
    pub fn new(ws: &'ws Workspace) -> Self {
        Self {
            ws,
            file_by_path: OnceLock::new(),
            func_ranges_by_file: Mutex::new(ahash::AHashMap::new()),
        }
    }

    /// Compact display string for a row at `(file_path, line)`.
    /// Space-joined `F:<16-hex>` ids with a trailing `…` when the
    /// enclosing function's chain enumeration hit its budget;
    /// empty when the row isn't inside any indexed function or no
    /// upstream caller exists.
    pub fn labels_for(&self, file_path: &str, line: u32) -> String {
        let Some(func) = self.enclosing_func(file_path, line) else {
            return String::new();
        };
        let ids = self
            .ws
            .flow_ids()
            .labels_for_func(func, self.ws.db(), self.ws.vfs());
        if ids.is_empty() {
            return String::new();
        }
        let mut s = ids.join(" ");
        if self.ws.flow_ids().was_truncated(func) {
            s.push('…');
        }
        s
    }

    /// Look up flow labels by SYMBOL NAME. Used by browse rows
    /// whose "enclosing function" is actually the symbol itself
    /// — e.g. an import statement (`from .x import foo`) which
    /// lives at module scope but logically belongs to every flow
    /// that terminates in `foo`. Returns the same space-joined
    /// `F:<16-hex>` format as `labels_for`.
    pub fn labels_for_symbol(&self, symbol_name: &str) -> String {
        let Some(func) = self.ws.lookup_function(symbol_name) else {
            return String::new();
        };
        let ids = self
            .ws
            .flow_ids()
            .labels_for_func(func, self.ws.db(), self.ws.vfs());
        if ids.is_empty() {
            return String::new();
        }
        let mut s = ids.join(" ");
        if self.ws.flow_ids().was_truncated(func) {
            s.push('…');
        }
        s
    }

    /// Linear scan through the file's function ranges. Ranges are
    /// pre-sorted narrowest-first so the first hit is the tightest
    /// enclosing scope.
    fn enclosing_func(&self, file_path: &str, line: u32) -> Option<FuncId> {
        let file_id = *self.file_by_path().get(file_path)?;
        self.func_ranges_for_file(file_id)
            .iter()
            .find(|range| line >= range.start_line && line <= range.end_line)
            .map(|range| range.func)
    }

    /// Lazy `path → FileId` map. Build once, share across calls.
    fn file_by_path(&self) -> &ahash::AHashMap<String, FileId> {
        self.file_by_path.get_or_init(|| {
            let global = self.ws.db().global_index();
            let mut files = ahash::AHashMap::new();
            for file in global.all_files() {
                if let Ok(path) = self.ws.vfs().path(file) {
                    files.insert(path.display().to_string(), file);
                }
            }
            files
        })
    }

    /// Cached lookup of a file's function ranges. First call
    /// computes; subsequent calls hit the in-memory cache.
    fn func_ranges_for_file(&self, file_id: FileId) -> Vec<FuncLineRange> {
        if let Some(hit) = self.func_ranges_by_file.lock().get(&file_id).cloned() {
            return hit;
        }
        let computed = self.compute_func_ranges_for_file(file_id);
        self.func_ranges_by_file.lock().insert(file_id, computed.clone());
        computed
    }

    /// Compute the function/method/constructor line ranges for a
    /// single file. Output is sorted narrowest-first so callers
    /// can take the first matching range as the tightest scope.
    fn compute_func_ranges_for_file(&self, file_id: FileId) -> Vec<FuncLineRange> {
        let Ok(snap) = self.ws.vfs().snapshot(file_id) else {
            return Vec::new();
        };
        let map = bonsai_common::cached_span_map(file_id, snap.version, snap.text.as_ref());
        let global = self.ws.db().global_index();
        let mut ranges = Vec::new();
        for decl in global.decls_in(file_id) {
            if !matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) || decl.span.file != file_id
            {
                continue;
            }
            ranges.push(FuncLineRange {
                start_line: map.line_col(decl.span.start).line,
                end_line: map.line_col(decl.span.end).line,
                width: decl.span.end.saturating_sub(decl.span.start),
                func: FuncId::new(decl.symbol.raw()),
            });
        }
        // Pick the narrowest enclosing function/method/constructor
        // first, so a nested function or method beats a wider scope.
        ranges.sort_by_key(|range| range.width);
        ranges
    }
}
