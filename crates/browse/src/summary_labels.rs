//! Map a browse-row location to stable ids for its enclosing symbol summary.
//!
//! Every browse command (`defs`, `calls`, `imports`, `vars`,
//! `strings`, `args`, `classes`, `refs`, `search`) surfaces a row
//! at `(file, line)`. [`SummaryAnnotator::labels_for`] returns the
//! pre-computed `F:<16-hex>` id for that row's enclosing function — the same
//! identity `inspect` emits for its bounded compiler evidence packet.
//!
//! The per-function id set is built lazily by
//! [`bonsai_workspace::flow_ids::FlowIdCache::id_for_func`], so this
//! struct answers "which function is this location inside?" and then reads
//! the shared cache. It never walks or enumerates graph paths.

use bonsai_common::{FileId, FuncId};
use bonsai_workspace::Workspace;
use parking_lot::Mutex;
use std::sync::OnceLock;

/// Line-accurate resolver from `(file_path, line)` to symbol-summary
/// ids. One instance per CLI invocation; per-row calls are O(1) in the
/// workspace stable-id cache.
pub struct SummaryAnnotator<'ws> {
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
    name: String,
}

impl<'ws> SummaryAnnotator<'ws> {
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
    /// Space-joined `F:<16-hex>` ids, or empty when the row is not inside an
    /// indexed callable.
    pub fn labels_for(&self, file_path: &str, line: u32) -> String {
        let Some(func) = self.enclosing_range(file_path, line).map(|range| range.func) else {
            return String::new();
        };
        let id = self.ws.flow_ids().id_for_func(func, self.ws.db(), self.ws.vfs());
        id.to_string()
    }

    /// Exact compiler-owned callable name enclosing a rendered source line.
    /// The same per-file header ranges back the flow-label lookup, so table
    /// renderers do not decompress one body for every displayed row.
    #[must_use]
    pub fn enclosing_function_name(&self, file_path: &str, line: u32) -> Option<String> {
        self.enclosing_range(file_path, line)
            .map(|range| range.name.clone())
    }

    /// Look up summary ids by symbol name. Used by browse rows
    /// whose "enclosing function" is actually the symbol itself
    /// — e.g. an import statement (`from .x import foo`) which
    /// lives at module scope but logically belongs to the callable `foo`.
    /// Returns the same space-joined
    /// `F:<16-hex>` format as `labels_for`.
    pub fn labels_for_symbol(&self, symbol_name: &str) -> String {
        let global = self.ws.compiler_header_index();
        // CONTEXTLESS_LOOKUP_JUSTIFICATION: this is display annotation, not
        // semantic dispatch. The imported compiler spelling is matched
        // exactly against declaration names, and every executable overload
        // is retained. Declaration-only prototypes are used only when no
        // executable definition exists, so split header/implementation
        // languages do not lose their summary merely because the bare name
        // is intentionally ambiguous to the resolver.
        let mut candidates = global
            .find_by_name(symbol_name)
            .iter()
            .filter_map(|symbol| {
                let decl = global.decl_of(*symbol)?;
                (decl.name == symbol_name
                    && matches!(
                        decl.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    ))
                .then_some((FuncId::new(symbol.raw()), decl.body_span.is_some()))
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return String::new();
        }
        let has_executable = candidates.iter().any(|(_, executable)| *executable);
        if has_executable {
            candidates.retain(|(_, executable)| *executable);
        }
        let mut ids = candidates
            .into_iter()
            .map(|(func, _)| {
                self.ws
                    .flow_ids()
                    .id_for_func(func, self.ws.db(), self.ws.vfs())
                    .to_string()
            })
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        ids.join(" ")
    }

    /// Linear scan through the file's function ranges. Ranges are
    /// pre-sorted narrowest-first so the first hit is the tightest
    /// enclosing scope.
    fn enclosing_range(&self, file_path: &str, line: u32) -> Option<FuncLineRange> {
        let file_id = *self.file_by_path().get(file_path)?;
        self.func_ranges_for_file(file_id)
            .iter()
            .find(|range| line >= range.start_line && line <= range.end_line)
            .cloned()
    }

    /// Lazy `path → FileId` map. Build once, share across calls.
    fn file_by_path(&self) -> &ahash::AHashMap<String, FileId> {
        self.file_by_path.get_or_init(|| {
            let global = self.ws.compiler_header_index();
            let mut files = ahash::AHashMap::new();
            for file in global.all_files() {
                if let Ok(path) = self.ws.vfs().path(file) {
                    files.insert(
                        crate::common::workspace_relative_path(self.ws, &path.display().to_string()),
                        file,
                    );
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
        let map = bonsai_common::cached_span_map_arc(file_id, snap.version, &snap.text);
        let global = self.ws.compiler_header_index();
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
                name: decl.name.clone(),
            });
        }
        // Pick the narrowest enclosing function/method/constructor
        // first, so a nested function or method beats a wider scope.
        ranges.sort_by_key(|range| range.width);
        ranges
    }
}

#[cfg(test)]
mod tests {
    use super::SummaryAnnotator;

    #[test]
    fn symbol_labels_prefer_executable_definition_over_same_named_prototype() {
        let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
        ws.vfs().write(
            "Service.h",
            "@interface Service\n- (id)loadValue:(id)value;\n@end\n",
        );
        ws.vfs().write(
            "Service.m",
            "#import \"Service.h\"\n@implementation Service\n- (id)loadValue:(id)value { return value; }\n@end\n",
        );

        let labels = SummaryAnnotator::new(&ws).labels_for_symbol("loadValue");
        let ids = labels.split_whitespace().collect::<Vec<_>>();
        assert_eq!(
            ids.len(),
            1,
            "a prototype and its definition describe one executable summary: {labels}"
        );
        assert!(ids[0].starts_with("F:") && ids[0].len() == 18);
    }
}
