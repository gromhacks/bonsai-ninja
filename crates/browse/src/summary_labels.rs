//! Map a browse-row location to stable ids for its enclosing symbol summary.
//!
//! Every browse command (`defs`, `calls`, `imports`, `vars`,
//! `strings`, `args`, `classes`, `refs`, `search`) surfaces a row
//! at `(file, line, column)`. [`SummaryAnnotator::labels_at`] returns the
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
use std::sync::Arc;

/// Exact source-location resolver to symbol-summary ids. Header ranges are
/// cached per workspace revision; edits invalidate paths and symbol ordinals.
pub struct SummaryAnnotator<'ws> {
    ws: &'ws Workspace,
    cache: Mutex<AnnotationCache>,
}

#[derive(Default)]
struct AnnotationCache {
    revision: Option<u64>,
    file_by_path: ahash::AHashMap<String, FileId>,
    ranges: ahash::AHashMap<FileId, Arc<Vec<FuncLineRange>>>,
}

/// Half-open callable extent in one-based byte coordinates. Sharing the
/// cached array avoids cloning every declaration name for every rendered row.
#[derive(Clone)]
struct FuncLineRange {
    start: (u32, u32),
    end: (u32, u32),
    last_line: u32,
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
            cache: Mutex::new(AnnotationCache::default()),
        }
    }

    /// Compact display string for a row at `(file_path, line)`.
    /// Space-joined `F:<16-hex>` ids, or empty when the row is not inside an
    /// indexed callable.
    pub fn labels_for(&self, file_path: &str, line: u32) -> String {
        self.labels_at(file_path, line, 0)
    }

    /// Summary at an exact byte column. Column zero requests the legacy
    /// line-only lookup, which returns no claim for ambiguous sibling scopes.
    pub fn labels_at(&self, file_path: &str, line: u32, column: u32) -> String {
        let Some(func) = self
            .enclosing_range(file_path, line, column)
            .map(|range| range.func)
        else {
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
        self.enclosing_function_name_at(file_path, line, 0)
    }

    /// Callable owning an exact source location, excluding the end boundary.
    #[must_use]
    pub fn enclosing_function_name_at(&self, file_path: &str, line: u32, column: u32) -> Option<String> {
        self.enclosing_range(file_path, line, column)
            .map(|range| range.name)
    }

    /// Exact stable callable identity enclosing a rendered source line.
    /// Browse projections use this when they need to join a row to resolved
    /// callgraph edges; the name-only helper above remains the presentation
    /// surface for human-readable tables.
    #[must_use]
    pub fn enclosing_function_id(&self, file_path: &str, line: u32) -> Option<FuncId> {
        self.enclosing_function_id_at(file_path, line, 0)
    }

    /// Stable callable identity at an exact one-based byte coordinate.
    #[must_use]
    pub fn enclosing_function_id_at(&self, file_path: &str, line: u32, column: u32) -> Option<FuncId> {
        self.enclosing_range(file_path, line, column)
            .map(|range| range.func)
    }

    /// Direct callable members of the exact type declaration at this location.
    /// Same-spelled methods in other types or files are not related evidence.
    pub fn class_member_ids_at(&self, file: &str, line: u32, column: u32) -> Vec<FuncId> {
        let Some(file) = crate::common::workspace_file_id(self.ws, file) else {
            return Vec::new();
        };
        let Some(map) = self.ws.db().span_map(file) else {
            return Vec::new();
        };
        let headers = self.ws.compiler_header_index();
        let mut candidates = headers.decls_in(file).iter().filter(|decl| {
            let at = map.line_col(decl.name_span.start);
            matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Class
                    | bonsai_lang_api::DeclKind::Struct
                    | bonsai_lang_api::DeclKind::Interface
                    | bonsai_lang_api::DeclKind::Trait
                    | bonsai_lang_api::DeclKind::Enum
            ) && at.line == line
                && at.column == column
        });
        let Some(owner) = candidates.next() else {
            return Vec::new();
        };
        if candidates.next().is_some() {
            return Vec::new();
        }
        headers
            .decls_in(file)
            .iter()
            .filter(|decl| {
                decl.parent == Some(owner.symbol)
                    && matches!(
                        decl.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    )
            })
            .map(|decl| FuncId::new(decl.symbol.raw()))
            .collect()
    }

    pub fn labels_for_class_at(&self, file: &str, line: u32, column: u32) -> String {
        let mut ids = self
            .class_member_ids_at(file, line, column)
            .into_iter()
            .map(|func| {
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
    fn enclosing_range(&self, file_path: &str, line: u32, column: u32) -> Option<FuncLineRange> {
        if line == 0 {
            return None;
        }
        let ranges = self.ranges_for_path(file_path)?;
        let mut candidates = ranges.iter().filter(|range| {
            if column == 0 {
                line >= range.start.0 && line <= range.last_line
            } else {
                range.start <= (line, column) && (line, column) < range.end
            }
        });
        let best = candidates.next()?;
        // A line crossing two sibling functions does not identify either.
        // Equal-range competing symbols likewise have no unique owner.
        if candidates.any(|other| {
            other.start > best.start
                || other.end < best.end
                || (other.start == best.start && other.end == best.end && other.func != best.func)
        }) {
            return None;
        }
        Some(best.clone())
    }

    fn ranges_for_path(&self, file_path: &str) -> Option<Arc<Vec<FuncLineRange>>> {
        let mut cache = self.cache.lock();
        let revision = self.ws.vfs().revision();
        if cache.revision != Some(revision) {
            cache.file_by_path.clear();
            cache.ranges.clear();
            let global = self.ws.compiler_header_index();
            for file in global.all_files() {
                if let Ok(path) = self.ws.vfs().path(file) {
                    cache.file_by_path.insert(
                        crate::common::workspace_relative_path(self.ws, &path.display().to_string()),
                        file,
                    );
                    cache.file_by_path.insert(path.display().to_string(), file);
                }
            }
            cache.revision = Some(revision);
        }
        let file = *cache.file_by_path.get(file_path)?;
        Some(Arc::clone(cache.ranges.entry(file).or_insert_with(|| {
            Arc::new(self.compute_func_ranges_for_file(file))
        })))
    }

    /// Compute the function/method/constructor line ranges for a
    /// single file. Output is sorted narrowest-first so callers
    /// can take the first matching range as the tightest scope.
    fn compute_func_ranges_for_file(&self, file_id: FileId) -> Vec<FuncLineRange> {
        let Some(map) = self.ws.db().span_map(file_id) else {
            return Vec::new();
        };
        let global = self.ws.compiler_header_index();
        let mut ranges = Vec::new();
        for decl in global.decls_in(file_id) {
            if !matches!(
                decl.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            ) || decl.span.file != file_id
                || decl.span.is_empty()
            {
                continue;
            }
            let start = map.line_col(decl.span.start);
            let end = map.line_col(decl.span.end);
            ranges.push(FuncLineRange {
                start: (start.line, start.column),
                end: (end.line, end.column),
                last_line: map.line_col(decl.span.end - 1).line,
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
    fn same_line_siblings_and_end_boundaries_use_exact_columns() {
        let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
        let source = "function alpha() { return 'first'; } function beta() { return 'second'; } outside();\n";
        ws.vfs().write("app.js", source);
        let annotator = SummaryAnnotator::new(&ws);
        let column = |needle| u32::try_from(source.find(needle).unwrap() + 1).unwrap();
        assert_eq!(
            annotator
                .enclosing_function_name_at("app.js", 1, column("first"))
                .as_deref(),
            Some("alpha")
        );
        assert_eq!(
            annotator
                .enclosing_function_name_at("app.js", 1, column("second"))
                .as_deref(),
            Some("beta")
        );
        assert_eq!(
            annotator
                .enclosing_function_name_at("app.js", 1, column(" outside"))
                .as_deref(),
            Some("__module__")
        );
        assert_eq!(annotator.enclosing_function_name("app.js", 1), None);
        assert_ne!(
            annotator.labels_at("app.js", 1, column("first")),
            annotator.labels_at("app.js", 1, column("second"))
        );
    }

    #[test]
    fn class_summary_ids_follow_exact_parent_symbols_not_method_names() {
        let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
        let source = "class Alpha { run() { return 1; } } class Beta { run() { return 2; } }\n";
        ws.vfs().write("app.js", source);
        ws.vfs()
            .write("other.js", "class Gamma { run() { return 3; } }\n");
        let ann = SummaryAnnotator::new(&ws);
        let at = |name| u32::try_from(source.find(name).unwrap() + 1).unwrap();
        let alpha = ann.labels_for_class_at("app.js", 1, at("Alpha"));
        let beta = ann.labels_for_class_at("app.js", 1, at("Beta"));
        assert_eq!(alpha.split_whitespace().count(), 1);
        assert_eq!(beta.split_whitespace().count(), 1);
        assert_ne!(alpha, beta);
        assert_eq!(alpha, ann.labels_at("app.js", 1, at("return 1")));
        assert_eq!(beta, ann.labels_at("app.js", 1, at("return 2")));
    }

    #[test]
    fn annotation_cache_follows_saved_edits_and_new_files() {
        let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
        ws.vfs().write("app.js", "function first() { return 1; }\n");
        let annotator = SummaryAnnotator::new(&ws);
        assert_eq!(
            annotator.enclosing_function_name_at("app.js", 1, 20).as_deref(),
            Some("first")
        );
        ws.apply_edit(
            std::path::Path::new("app.js"),
            "function later() { return 2; }\n".to_string(),
        );
        ws.apply_edit(
            std::path::Path::new("added.js"),
            "function added() { return 3; }\n".to_string(),
        );
        assert_eq!(
            annotator.enclosing_function_name_at("app.js", 1, 20).as_deref(),
            Some("later")
        );
        assert_eq!(
            annotator.enclosing_function_name_at("added.js", 1, 20).as_deref(),
            Some("added")
        );
    }

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
