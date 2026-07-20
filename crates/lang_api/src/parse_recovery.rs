//! Grammar recovery backed by compiler/preprocessor facts.
//!
//! Tree-sitter intentionally parses source before a C-family preprocessor has
//! expanded object-like macros. A declaration marker such as a visibility or
//! calling-convention macro can therefore occupy the grammar's type slot and
//! turn the real return type into an `ERROR` node even though the translation
//! unit is valid. This module derives reachable macro names from `#include`
//! and `#define` directives, then identifies only those macro tokens that sit
//! in a declaration prefix proven malformed by the concrete syntax tree.
//!
//! Recovery edits are same-width masks. The recovered tree's byte ranges stay
//! aligned with the original source, so every downstream span and source slice
//! remains exact. Macro bodies are never guessed or hard-coded.

use ahash::{AHashMap, AHashSet};
use bonsai_vfs::{FileSnapshot, Vfs};
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Tree};

/// A same-width parser-buffer normalization used for a recovery parse.
/// Original source is never modified, so accepted trees retain exact spans
/// and every adapter still reads the user's original bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ParseRecoveryEdit {
    pub start_byte: usize,
    pub end_byte: usize,
    action: ParseRecoveryAction,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum ParseRecoveryAction {
    Mask,
    UppercaseAscii,
}

/// Exact syntax-damage score for a concrete Tree-sitter tree.
///
/// The first component counts every `ERROR` and missing node; the second
/// totals the source bytes covered by them. The tuple ordering therefore
/// prefers fewer damaged constructs, then the narrower recovery when counts
/// tie. The walk is exhaustive and shared by grammar selection and recovery.
#[must_use]
pub fn syntax_damage_score(tree: &Tree) -> (usize, usize) {
    let mut count = 0usize;
    let mut covered_bytes = 0usize;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let is_error = node.is_error();
        if is_error || node.is_missing() {
            count += 1;
            covered_bytes = covered_bytes.saturating_add(node.end_byte().saturating_sub(node.start_byte()));
        }
        if !is_error {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.has_error() || child.is_missing() {
                    stack.push(child);
                }
            }
        }
    }
    (count, covered_bytes)
}

impl ParseRecoveryEdit {
    #[must_use]
    pub const fn new(start_byte: usize, end_byte: usize) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::Mask,
        }
    }

    /// Uppercase one ASCII byte in the parser buffer. This is intentionally
    /// narrower than general source replacement: adapters use it only to
    /// disambiguate a contextual keyword from an identifier production while
    /// downstream node text continues to come from the unchanged source.
    #[must_use]
    pub const fn uppercase_ascii(byte_offset: usize) -> Self {
        Self {
            start_byte: byte_offset,
            end_byte: byte_offset + 1,
            action: ParseRecoveryAction::UppercaseAscii,
        }
    }

    /// Apply this normalization to a same-length parser buffer.
    ///
    /// Returns `true` only when the edit is valid and changes the buffer.
    pub fn apply_to(self, original: &str, recovered: &mut [u8]) -> bool {
        if self.start_byte >= self.end_byte
            || self.end_byte > recovered.len()
            || recovered.len() != original.len()
            || !original.is_char_boundary(self.start_byte)
            || !original.is_char_boundary(self.end_byte)
        {
            return false;
        }
        match self.action {
            ParseRecoveryAction::Mask => {
                let mut changed = false;
                for byte in &mut recovered[self.start_byte..self.end_byte] {
                    if *byte != b'\n' && *byte != b'\r' {
                        changed |= *byte != b' ';
                        *byte = b' ';
                    }
                }
                changed
            }
            ParseRecoveryAction::UppercaseAscii => {
                let byte = &mut recovered[self.start_byte];
                if !byte.is_ascii_lowercase() {
                    return false;
                }
                byte.make_ascii_uppercase();
                true
            }
        }
    }
}

/// Derive declaration-macro recovery edits for one C-family syntax tree.
///
/// Definitions are collected only from the current source and headers that
/// its preprocessor include graph can resolve unambiguously in the workspace.
/// Function-like macros are intentionally excluded: masking only their name
/// would leave argument tokens behind and would not preserve program shape.
#[must_use]
pub fn c_family_declaration_macro_recovery_edits(
    snapshot: &FileSnapshot,
    vfs: &Vfs,
    tree: &Tree,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let macros = reachable_object_macros(snapshot, vfs);
    if macros.is_empty() {
        return Vec::new();
    }

    let source = snapshot.text.as_bytes();
    let mut edits = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() {
            if let Some(container) = declaration_prefix_container(node) {
                let prefix_end = node.start_byte().min(source.len());
                let prefix_start = container.start_byte().min(prefix_end);
                collect_defined_identifier_ranges(source, prefix_start, prefix_end, &macros, &mut edits);
            }
            continue;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.has_error() || child.is_missing() {
                stack.push(child);
            }
        }
    }

    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

fn declaration_prefix_container(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            // An error below executable syntax is not declaration metadata.
            "compound_statement"
            | "expression_statement"
            | "argument_list"
            | "initializer_list"
            | "return_statement" => return None,
            "function_definition"
            | "declaration"
            | "field_declaration"
            | "type_definition"
            | "template_declaration"
            | "class_specifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier" => {
                let boundary = parent
                    .child_by_field_name("declarator")
                    .or_else(|| parent.child_by_field_name("name"))
                    .or_else(|| parent.child_by_field_name("body"))
                    .map_or(parent.end_byte(), |child| child.start_byte());
                return (node.end_byte() <= boundary).then_some(parent);
            }
            _ => node = parent,
        }
    }
    None
}

fn collect_defined_identifier_ranges(
    source: &[u8],
    start: usize,
    end: usize,
    macros: &AHashSet<String>,
    edits: &mut Vec<ParseRecoveryEdit>,
) {
    let mut cursor = start;
    while cursor < end {
        if !is_identifier_start(source[cursor]) {
            cursor += 1;
            continue;
        }
        let token_start = cursor;
        cursor += 1;
        while cursor < end && is_identifier_continue(source[cursor]) {
            cursor += 1;
        }
        let Ok(name) = std::str::from_utf8(&source[token_start..cursor]) else {
            continue;
        };
        if macros.contains(name) && !line_is_preprocessor_directive(source, token_start) {
            edits.push(ParseRecoveryEdit::new(token_start, cursor));
        }
    }
}

fn line_is_preprocessor_directive(source: &[u8], offset: usize) -> bool {
    let line_start = source[..offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    source[line_start..offset]
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'#')
}

fn reachable_object_macros(snapshot: &FileSnapshot, vfs: &Vfs) -> AHashSet<String> {
    let files: Vec<_> = vfs
        .all_files()
        .into_iter()
        .filter_map(|file| {
            let path = vfs.path(file).ok()?;
            Some((file, path))
        })
        .collect();
    let mut path_to_file = AHashMap::new();
    for (file, path) in &files {
        path_to_file.insert(path.as_ref().clone(), *file);
    }

    let mut macros = AHashSet::new();
    let mut visited = AHashSet::new();
    let mut pending = vec![(snapshot.file_id, snapshot.path.as_ref().clone())];
    while let Some((file, path)) = pending.pop() {
        if !visited.insert(file) {
            continue;
        }
        let Ok(current) = vfs.snapshot(file) else {
            continue;
        };
        let directives = preprocessor_directives(&current.text);
        macros.extend(directives.object_macros);
        for include in directives.includes {
            if let Some((included_file, included_path)) =
                resolve_include(&path, &include, &files, &path_to_file)
            {
                pending.push((included_file, included_path));
            }
        }
    }
    macros
}

#[derive(Default)]
struct PreprocessorDirectives {
    object_macros: Vec<String>,
    includes: Vec<PathBuf>,
}

fn preprocessor_directives(source: &str) -> PreprocessorDirectives {
    let mut facts = PreprocessorDirectives::default();
    for line in source.lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(definition) = directive_argument(rest, "define") {
            let name_len = definition
                .as_bytes()
                .iter()
                .take_while(|byte| is_identifier_continue(**byte))
                .count();
            if name_len == 0 || !is_identifier_start(definition.as_bytes()[0]) {
                continue;
            }
            // No whitespace between the identifier and `(` means a
            // function-like macro under the C preprocessor grammar.
            if definition.as_bytes().get(name_len) == Some(&b'(') {
                continue;
            }
            facts.object_macros.push(definition[..name_len].to_string());
        } else if let Some(argument) = directive_argument(rest, "include") {
            let argument = argument.trim_start();
            let path = if let Some(quoted) = argument.strip_prefix('"') {
                quoted.split_once('"').map(|(path, _)| path)
            } else if let Some(angled) = argument.strip_prefix('<') {
                angled.split_once('>').map(|(path, _)| path)
            } else {
                None
            };
            if let Some(path) = path.filter(|path| !path.is_empty()) {
                facts.includes.push(PathBuf::from(path));
            }
        }
    }
    facts
}

fn directive_argument<'a>(line: &'a str, directive: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(directive)?;
    rest.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        .then_some(rest.trim_start())
}

fn resolve_include(
    including_path: &Path,
    include: &Path,
    files: &[(bonsai_common::FileId, std::sync::Arc<PathBuf>)],
    path_to_file: &AHashMap<PathBuf, bonsai_common::FileId>,
) -> Option<(bonsai_common::FileId, PathBuf)> {
    if let Some(parent) = including_path.parent() {
        let local = parent.join(include);
        if let Some(file) = path_to_file.get(&local).copied() {
            return Some((file, local));
        }
    }

    let mut matches = files
        .iter()
        .filter(|(_, path)| path.ends_with(include))
        .map(|(file, path)| (*file, path.as_ref().clone()));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

const fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

const fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocessor_facts_distinguish_object_and_function_macros() {
        let facts = preprocessor_directives(
            "#define API extern \"C\"\n#define CALL(x) x\n#include \"api/detail.h\"\n",
        );
        assert_eq!(facts.object_macros, vec!["API"]);
        assert_eq!(facts.includes, vec![PathBuf::from("api/detail.h")]);
    }

    #[test]
    fn recovery_edits_preserve_width_and_original_source() {
        let source = "API var\n";
        let mut recovered = source.as_bytes().to_vec();
        assert!(ParseRecoveryEdit::new(0, 3).apply_to(source, &mut recovered));
        assert!(ParseRecoveryEdit::uppercase_ascii(4).apply_to(source, &mut recovered));
        assert_eq!(std::str::from_utf8(&recovered).unwrap(), "    Var\n");
        assert_eq!(source, "API var\n");
    }
}
