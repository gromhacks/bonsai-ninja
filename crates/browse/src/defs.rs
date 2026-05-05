//! `bonsai-ninja defs` data layer.
//!
//! Returns every declaration (function / method / class / struct /
//! enum / trait / interface / constructor) in the workspace,
//! filtered by the requested predicates.

use crate::common::{collect_callees, format_span, make_name_filter};
use bonsai_lang_api::RefKind;
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`defs`]. All fields are optional; any
/// `None` skips that filter. `regex` controls how `name` is
/// interpreted.
#[derive(Copy, Clone, Default, Debug)]
pub struct DefsFilters<'a> {
    /// `--kind function|class|struct|enum|trait|interface|method|constructor|...`
    pub kind: Option<&'a str>,
    /// `--file substring` against the decl's source path.
    pub file: Option<&'a str>,
    /// `--name substring` (or regex when `regex` is true).
    pub name: Option<&'a str>,
    /// `--has-callee X` — only keep decls whose body calls `X`.
    pub has_callee: Option<&'a str>,
    /// `--has-decorator X` — only keep decls in a file whose
    /// decorators include `X` (file-scoped, not span-scoped).
    pub has_decorator: Option<&'a str>,
    /// `--has-param X` — only keep decls with a parameter named `X`.
    pub has_param: Option<&'a str>,
    /// Treat `name` as a regex instead of a substring.
    pub regex: bool,
}

/// One row of `defs` output. Field names match the JSON schema the
/// CLI emits.
#[derive(Serialize, Clone, Debug)]
pub struct DefOut {
    pub name: String,
    pub qualified_name: Option<String>,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub params: Vec<String>,
}

/// Collect every declaration matching the filters.
///
/// Sorted by `(file, line)` for stable output. The caller renders
/// the result as JSON or a table; the SDK contract is just the
/// `Vec<DefOut>`.
pub fn defs(ws: &Workspace, f: &DefsFilters<'_>) -> Result<Vec<DefOut>, regex::Error> {
    use rayon::prelude::*;
    let global = ws.db().global_index();
    let name_match = make_name_filter(f.name, f.regex)?;
    let files: Vec<_> = global.all_files().collect();
    // Parallel per-file fan-out. Each file produces an independent
    // Vec<DefOut>; rayon merges them into one. Deterministic output
    // comes from the explicit sort after collection — sort key is
    // `(file, line)` which uniquely identifies a decl location.
    // `fold` + `reduce` so each rayon worker accumulates into one
    // hot Vec, then a final merge. Avoids the per-file allocation
    // cost that hurts hub-name browse queries.
    let mut out: Vec<DefOut> = files
        .par_iter()
        .fold(Vec::new, |mut acc, &file| {
            // Decorators are file-scoped refs; build the per-file
            // list once instead of re-scanning per decl.
            let decorators_on_file: Option<Vec<String>> = global.file_index(file).map(|idx| {
                idx.refs
                    .iter()
                    .filter(|reference| reference.kind == RefKind::Decorator)
                    .map(|reference| reference.name.clone())
                    .collect()
            });
            for decl in global.decls_in(file) {
                let (path, line, column) = format_span(&decl.name_span, ws);
                if f.file.is_some_and(|needle| !path.contains(needle)) {
                    continue;
                }
                let kind_str = format!("{:?}", decl.kind).to_lowercase();
                if f.kind.is_some_and(|k| !kind_str.contains(&k.to_lowercase())) {
                    continue;
                }
                if !name_match(&decl.name) {
                    continue;
                }
                if let Some(needle) = f.has_callee {
                    let mut callees: Vec<String> = Vec::new();
                    collect_callees(&decl.flow_events, &mut callees);
                    if !callees.iter().any(|callee| callee.contains(needle)) {
                        continue;
                    }
                }
                if let Some(needle) = f.has_decorator {
                    let decorators = decorators_on_file.as_deref().unwrap_or(&[]);
                    if !decorators.iter().any(|name| name.contains(needle)) {
                        continue;
                    }
                }
                if let Some(needle) = f.has_param {
                    if !decl.params.iter().any(|param| param.contains(needle)) {
                        continue;
                    }
                }
                acc.push(DefOut {
                    name: decl.name.clone(),
                    qualified_name: decl.qualified_name.clone(),
                    kind: kind_str,
                    file: path,
                    line,
                    column,
                    params: decl.params.clone(),
                });
            }
            acc
        })
        .reduce(Vec::new, |mut larger, mut smaller| {
            if smaller.len() > larger.len() {
                std::mem::swap(&mut larger, &mut smaller);
            }
            larger.extend(smaller);
            larger
        });
    // Group by kind first (function / method / class / struct / …) so
    // all rows of a kind sit together, then alphabetical within each
    // group. File / line break ties on same-name shadowing.
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    Ok(out)
}
