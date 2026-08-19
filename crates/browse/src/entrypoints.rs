//! `bonsai-ninja entrypoints` data layer.
//!
//! Entry points are callable declarations that have no resolved
//! semantic in-workspace callers. This is intentionally rulepack-free:
//! it is a deterministic callgraph root view for code navigation.

use crate::common::{
    best_textual_relevance_key, file_path_matches_filter, format_span, make_name_filter,
    source_files_small_first, textual_relevance_key,
};
use bonsai_common::FuncId;
use bonsai_lang_api::{DeclKind, MODULE_DECL_NAME};
use bonsai_workspace::Workspace;
use rayon::prelude::*;
use serde::Serialize;

/// Filter bundle for [`entrypoints`].
#[derive(Copy, Clone, Default, Debug)]
pub struct EntryPointsFilters<'a> {
    /// `--kind function|method|constructor`
    pub kind: Option<&'a str>,
    /// `--file substring` against the decl's source path.
    pub file: Option<&'a str>,
    /// `--name substring` (or regex when `regex` is true). Matches
    /// short and qualified names.
    pub name: Option<&'a str>,
    /// Treat `name` as a regex instead of a substring.
    pub regex: bool,
}

/// One row of `entrypoints` output.
#[derive(Serialize, Clone, Debug)]
pub struct EntryPointOut {
    pub name: String,
    pub qualified_name: Option<String>,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub params: Vec<String>,
    pub callees: Vec<String>,
    pub reason: String,
}

/// Collect callable declarations with no semantic caller in the
/// resolved callgraph.
pub fn entrypoints(ws: &Workspace, f: &EntryPointsFilters<'_>) -> Result<Vec<EntryPointOut>, regex::Error> {
    let global = if let Some(file_filter) = f.file {
        let files = ws
            .vfs()
            .all_files()
            .into_iter()
            .filter(|file| {
                ws.vfs()
                    .path(*file)
                    .is_ok_and(|path| file_path_matches_filter(ws, &path.to_string_lossy(), file_filter))
            })
            .collect::<Vec<_>>();
        ws.compiler_header_index_for_files(&files)
    } else {
        ws.compiler_header_index()
    };
    let name_match = make_name_filter(f.name, f.regex)?;
    let mut candidates = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            // Adapters use a synthetic function to own executable module-scope
            // statements. It is a compiler container, not a callable users can
            // select or invoke, so it must not appear in the public root
            // inventory even though its lowered declaration kind is Function.
            if decl.name == MODULE_DECL_NAME || !is_callable_entry_kind(decl.kind) {
                continue;
            }
            let kind = format!("{:?}", decl.kind).to_lowercase();
            if f.kind
                .is_some_and(|needle| !kind.contains(&needle.to_lowercase()))
            {
                continue;
            }
            let path = format_span(&decl.name_span, ws).0;
            if f.file
                .is_some_and(|needle| !file_path_matches_filter(ws, &path, needle))
            {
                continue;
            }
            let qualified_matches = decl.qualified_name.as_deref().is_some_and(&name_match);
            if !name_match(&decl.name) && !qualified_matches {
                continue;
            }
            let func = FuncId::new(decl.symbol.raw());
            candidates.push((func, decl));
        }
    }
    let called = ws.functions_with_semantic_callers(
        &candidates
            .iter()
            .map(|(function, _)| *function)
            .collect::<Vec<_>>(),
    );
    let roots_by_file = candidates
        .into_iter()
        .filter(|(func, _)| !called.contains(func))
        .fold(
            ahash::AHashMap::<bonsai_common::FileId, Vec<&bonsai_lang_api::Decl>>::default(),
            |mut by_file, (_, decl)| {
                by_file.entry(decl.span.file).or_default().push(decl);
                by_file
            },
        );
    let root_files = source_files_small_first(ws)
        .into_iter()
        .filter_map(|file| roots_by_file.get(&file).map(|decls| (file, decls)))
        .collect::<Vec<_>>();
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
    let mut out = root_files
        .par_iter()
        .flat_map_iter(|(file, decls)| {
            let source_bytes = ws
                .vfs()
                .snapshot(*file)
                .map_or(0, |snapshot| snapshot.text.len() as u64);
            let _memory_permit = memory_permits.acquire(source_bytes);
            // Open one validated adapter-attribution directory per file and
            // read only its root-function frames. This avoids both repeated
            // directory reads and decompression of unrequested sibling
            // functions on entrypoint-heavy projects.
            let spans = decls.iter().map(|decl| decl.span).collect::<Vec<_>>();
            let attributions = ws.db().compiler_function_attributions_uncached(*file, &spans);
            let mut per_file = Vec::with_capacity(decls.len());
            for (decl, attribution) in decls.iter().zip(attributions) {
                let kind = format!("{:?}", decl.kind).to_lowercase();
                let (path, line, column) = format_span(&decl.name_span, ws);
                let callees = attribution.map_or_else(Vec::new, |function| {
                    function.calls.into_iter().map(|call| call.name).collect()
                });
                per_file.push(EntryPointOut {
                    name: decl.name.clone(),
                    qualified_name: decl.qualified_name.clone(),
                    kind,
                    file: path,
                    line,
                    column,
                    params: decl.params.clone(),
                    callees,
                    reason: "no_semantic_callers".to_string(),
                });
            }
            per_file.into_iter()
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        entrypoint_relevance_key(a, f)
            .cmp(&entrypoint_relevance_key(b, f))
            .then_with(|| {
                a.kind
                    .cmp(&b.kind)
                    .then_with(|| a.name.cmp(&b.name))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.column.cmp(&b.column))
            })
    });
    Ok(out)
}

fn entrypoint_relevance_key(row: &EntryPointOut, f: &EntryPointsFilters<'_>) -> ((u8, usize), (u8, usize)) {
    let kind = f.kind.filter(|_| !f.regex).map_or((u8::MAX, usize::MAX), |kind| {
        textual_relevance_key(&row.kind, Some(kind), false)
    });
    let name = f.name.filter(|_| !f.regex).map_or((u8::MAX, usize::MAX), |name| {
        best_textual_relevance_key(
            [Some(row.name.as_str()), row.qualified_name.as_deref()]
                .into_iter()
                .flatten(),
            Some(name),
            false,
        )
    });
    (kind, name)
}

fn is_callable_entry_kind(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::LanguageRegistry;
    use std::sync::Arc;

    #[test]
    fn entrypoint_callees_share_one_exact_file_attribution_projection() {
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let ws = Workspace::new(registry);
        ws.vfs().write(
            "main.py".to_string(),
            Arc::<str>::from(
                "def leaf(value):\n    return value\n\ndef root(value):\n    first = leaf(value)\n    return leaf(first)\n\ndef root_two(value):\n    return leaf(value)\n",
            ),
        );

        let rows = entrypoints(
            &ws,
            &EntryPointsFilters {
                name: Some("root"),
                ..EntryPointsFilters::default()
            },
        )
        .expect("entrypoints");

        assert_eq!(rows.len(), 2);
        let file = ws.vfs().all_files()[0];
        let exact = ws.db().decl_index_uncached(file).expect("exact Python IR");
        for row in &rows {
            let root = exact
                .defs
                .iter()
                .find(|decl| decl.name == row.name)
                .expect("root declaration");
            let body_callees = crate::common::collect_callee_names(&root.flow_events);
            assert_eq!(row.callees, body_callees);
            assert!(row.callees.iter().all(|callee| callee == "leaf"));
        }
        assert_eq!(
            ws.stats().cached_decl_indexes,
            0,
            "broad entrypoint inventory must not retain per-file compiler bodies"
        );
    }
}
