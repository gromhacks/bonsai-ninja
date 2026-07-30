//! `bonsai-ninja defs` data layer.
//!
//! Returns every declaration (function / method / class / struct /
//! enum / trait / interface / constructor) in the workspace,
//! filtered by the requested predicates.

use crate::common::{
    best_textual_relevance_key, collect_callees, file_path_matches_filter, format_span, make_name_filter,
    textual_relevance_key,
};
use bonsai_workspace::{decl_decorator_names, Workspace};
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
    /// `--has-decorator X` — only keep decls with an attached
    /// decorator/annotation whose full name or segment contains `X`.
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
    let global = ws.compiler_linkage_index();
    let needs_exact_body = f.has_callee.is_some() || f.has_decorator.is_some();
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
            let exact_index = needs_exact_body
                .then(|| ws.db().decl_index_uncached(file))
                .flatten();
            let decls = exact_index
                .as_ref()
                .map_or_else(|| global.decls_in(file), |index| index.defs.as_slice());
            for decl in decls {
                let (path, line, column) = format_span(&decl.name_span, ws);
                if f.file
                    .is_some_and(|needle| !file_path_matches_filter(ws, &path, needle))
                {
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
                    let decorators = exact_index
                        .as_ref()
                        .map(|idx| decl_decorator_names(ws, file, idx, decl.span, decl.name_span))
                        .unwrap_or_default();
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
        def_relevance_key(a, f)
            .cmp(&def_relevance_key(b, f))
            .then_with(|| {
                a.kind
                    .cmp(&b.kind)
                    .then_with(|| a.name.cmp(&b.name))
                    .then_with(|| a.file.cmp(&b.file))
                    .then_with(|| a.line.cmp(&b.line))
            })
    });
    Ok(out)
}

fn def_relevance_key(row: &DefOut, f: &DefsFilters<'_>) -> ((u8, usize), (u8, usize)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_decorator_filters_to_the_attached_declaration() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            r#"
class App:
    def route(self, path):
        def deco(fn):
            return fn
        return deco

app = App()

@app.route("/x")
def decorated(request):
    return request

def helper(request):
    return request
"#,
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = defs(
            &ws,
            &DefsFilters {
                has_decorator: Some("route"),
                ..DefsFilters::default()
            },
        )
        .expect("defs");
        let names: Vec<_> = rows.iter().map(|row| row.name.as_str()).collect();

        assert_eq!(names, vec!["decorated"], "decorator filter leaked: {rows:?}");
    }

    #[test]
    fn decorator_names_include_qualified_text_and_segments() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            r#"
app = object()

@app.route("/x")
def decorated(request):
    return request
"#,
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
        let file = ws.vfs().all_files().into_iter().next().expect("file");
        let index = ws.db().decl_index(file).expect("decl index");
        let decl = index
            .defs
            .iter()
            .find(|decl| decl.name == "decorated")
            .expect("decorated decl");

        let names = decl_decorator_names(&ws, file, &index, decl.span, decl.name_span);

        assert!(names.iter().any(|name| name == "app.route"), "{names:?}");
        assert!(names.iter().any(|name| name == "app"), "{names:?}");
        assert!(names.iter().any(|name| name == "route"), "{names:?}");
    }
}
