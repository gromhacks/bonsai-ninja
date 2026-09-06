//! `bonsai-ninja classes` data layer.
//!
//! Returns every type declaration the adapter recognises as a
//! class-like construct: `class`, `struct`, `trait`, `interface`,
//! `enum`. Each row carries the type's directly owned methods
//! so callers can answer "which classes implement
//! `serialize`?" without a separate query.

use crate::common::{
    best_textual_relevance_key, file_path_matches_filter, format_span, make_name_filter,
    textual_relevance_key,
};
use bonsai_lang_api::DeclKind;
use bonsai_workspace::Workspace;
use serde::{Deserialize, Serialize};

/// Filter bundle for [`classes`].
#[derive(Copy, Clone, Default, Debug)]
pub struct ClassesFilters<'a> {
    /// `--name X` — substring (or regex) over the class name.
    pub name: Option<&'a str>,
    /// `--file substring` against the declaring file's path.
    pub file: Option<&'a str>,
    /// `--kind class|struct|trait|interface|enum` — exact
    /// (case-insensitive) match against the [`DeclKind`].
    pub kind: Option<&'a str>,
    /// `--has-method X` — only keep types whose method list
    /// contains a name with `X` as substring.
    pub has_method: Option<&'a str>,
    /// `--min-methods N` — only keep types with at least `N`
    /// declared methods.
    pub min_methods: Option<usize>,
    /// Treat `name` as a regex instead of a substring.
    pub regex: bool,
}

/// One row of `classes` output.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClassOut {
    pub name: String,
    /// Lowercased [`DeclKind`] tag — `"class"`, `"struct"`,
    /// `"trait"`, `"interface"`, or `"enum"`.
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// `methods.len()` cached on the row so JSON consumers can
    /// sort / filter without re-counting.
    pub method_count: usize,
    /// Names of every directly owned method, constructor, or function.
    /// Order is source-position-stable; nested types own their own methods.
    pub methods: Vec<String>,
}

/// Collect every class-like declaration matching the filters.
/// Sorted by `(file, line, name)` for deterministic output.
pub fn classes(ws: &Workspace, f: &ClassesFilters<'_>) -> Result<Vec<ClassOut>, regex::Error> {
    use rayon::prelude::*;
    // Class inventory needs declaration ownership only. Loading call linkage
    // here made a one-name query inflate the complete Elasticsearch semantic
    // index even though no call edge can affect the result.
    let global = ws.compiler_header_index();
    let name_match = make_name_filter(f.name, f.regex)?;
    let files: Vec<_> = global.all_files().collect();
    let mut out: Vec<ClassOut> = files
        .par_iter()
        .flat_map_iter(|&file| {
            let mut per_file: Vec<ClassOut> = Vec::new();
            let file_path = ws.vfs().path(file).map_or_else(
                |_| "<unknown>".to_string(),
                |path| path.to_string_lossy().into_owned(),
            );
            if f.file
                .is_some_and(|needle| !file_path_matches_filter(ws, &file_path, needle))
            {
                return per_file.into_iter();
            }
            let decls = global.decls_in(file);
            let mut members_by_parent = ahash::AHashMap::<_, Vec<_>>::new();
            for member in decls {
                if matches!(
                    member.kind,
                    DeclKind::Method | DeclKind::Constructor | DeclKind::Function
                ) {
                    if let Some(parent) = member.parent {
                        members_by_parent.entry(parent).or_default().push(member);
                    }
                }
            }
            for members in members_by_parent.values_mut() {
                members.sort_by_key(|member| member.span);
            }
            for class in decls {
                if !matches!(
                    class.kind,
                    DeclKind::Class
                        | DeclKind::Struct
                        | DeclKind::Trait
                        | DeclKind::Interface
                        | DeclKind::Enum
                ) {
                    continue;
                }
                let kind_str = format!("{:?}", class.kind).to_lowercase();
                if f.kind.is_some_and(|kind| !kind_str.eq_ignore_ascii_case(kind)) {
                    continue;
                }
                if !name_match(&class.name) {
                    continue;
                }
                // Methods are callable decls whose adapter-emitted
                // parent points at this class. Browse uses the same
                // semantic ownership fact as callgraph/security.
                let members = members_by_parent
                    .get(&class.symbol)
                    .map_or(&[][..], Vec::as_slice);
                if let Some(needle) = f.has_method {
                    if !members.iter().any(|member| member.name.contains(needle)) {
                        continue;
                    }
                }
                if let Some(min_count) = f.min_methods {
                    if members.len() < min_count {
                        continue;
                    }
                }
                let (path, line, column) = format_span(&class.name_span, ws);
                per_file.push(ClassOut {
                    name: class.name.clone(),
                    kind: kind_str,
                    file: path,
                    line,
                    column,
                    method_count: members.len(),
                    methods: members.iter().map(|member| member.name.clone()).collect(),
                });
            }
            per_file.into_iter()
        })
        .collect();
    // Group by kind (class / struct / trait / interface / enum) so
    // each kind clusters, then alphabetical by name, then file/line
    // for disambiguation.
    out.sort_by(|a, b| {
        class_relevance_key(a, f)
            .cmp(&class_relevance_key(b, f))
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

fn class_relevance_key(row: &ClassOut, f: &ClassesFilters<'_>) -> ((u8, usize), (u8, usize), (u8, usize)) {
    let kind = f.kind.map_or((u8::MAX, usize::MAX), |kind| {
        textual_relevance_key(&row.kind, Some(kind), false)
    });
    let name = f.name.filter(|_| !f.regex).map_or((u8::MAX, usize::MAX), |name| {
        textual_relevance_key(&row.name, Some(name), false)
    });
    let method = f.has_method.map_or((u8::MAX, usize::MAX), |method| {
        best_textual_relevance_key(row.methods.iter().map(String::as_str), Some(method), false)
    });
    (kind, name, method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_kinds_are_exact_and_member_lists_follow_compiler_ownership() {
        let ws = Workspace::new(bonsai_adapters::all_languages_registry());
        ws.vfs().write(
            "types.js",
            "class Alpha { first() {} second() {} } class Beta { third() {} }\n",
        );
        let rows = classes(
            &ws,
            &ClassesFilters {
                kind: Some("CLASS"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "Alpha");
        assert_eq!(rows[0].methods, ["first", "second"]);
        assert_eq!(rows[1].methods, ["third"]);
        assert!(rows[0].column < rows[1].column);
        assert!(classes(
            &ws,
            &ClassesFilters {
                kind: Some("ass"),
                ..Default::default()
            }
        )
        .unwrap()
        .is_empty());
    }
}
