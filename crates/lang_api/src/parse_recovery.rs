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
//! remains exact. Macro bodies are never guessed or hard-coded. Adapters may
//! declare variadic read builtins whose pointer type operand Tree-sitter
//! represents as an expression plus an `ERROR` node; recovery masks only the
//! pointer declarator token proven by that CST shape.

use ahash::AHashSet;
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
    damaged_descendant_owner: Option<(usize, usize)>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum ParseRecoveryAction {
    Mask,
    UppercaseAscii,
    ReplaceAscii(&'static [u8]),
}

/// Exact syntax-damage score for a concrete Tree-sitter tree.
///
/// The first component totals source bytes inside errors that are not covered
/// by a valid named descendant; the second counts every concrete error or
/// missing node. Tuple ordering therefore preserves the greatest amount of
/// compiler-visible source before using error count as a tie-breaker.
///
/// Tree-sitter may wrap an otherwise structured translation unit in one
/// whole-file `ERROR` node. Treating that wrapper's complete byte range as
/// damaged makes every recovery candidate tie even when one restores a lost
/// function. For an error container, valid named children subtract their
/// exact non-overlapping ranges from the damage total, while nested
/// ERROR/MISSING children are measured recursively. Unnamed tokens inside an
/// error remain damaged: their grammar role has not been established.
#[must_use]
pub fn syntax_damage_score(tree: &Tree) -> (usize, usize) {
    let mut count = 0usize;
    let mut covered_bytes = 0usize;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let is_error = node.is_error();
        if node.is_missing() {
            count += 1;
            continue;
        }
        if is_error {
            count += 1;
            let mut covered_until = node.start_byte();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let carries_damage = child.is_missing() || child.has_error();
                if carries_damage || child.is_named() {
                    covered_bytes =
                        covered_bytes.saturating_add(child.start_byte().saturating_sub(covered_until));
                    if carries_damage {
                        stack.push(child);
                    }
                    covered_until = covered_until.max(child.end_byte());
                }
            }
            covered_bytes = covered_bytes.saturating_add(node.end_byte().saturating_sub(covered_until));
            continue;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.has_error() || child.is_missing() {
                stack.push(child);
            }
        }
    }
    // A grammar may expose a hidden missing production through the root damage
    // flag without making that node iterable through Tree-sitter's public API.
    // Keep the damage count non-zero so a clean grammar/recovery candidate can
    // win, but do not pretend the hidden zero-width production covers the
    // entire file.
    if count == 0 && tree.root_node().has_error() {
        (0, 1)
    } else {
        (covered_bytes, count)
    }
}

/// Adapter-owned spelling for one conditional-compilation grammar.
///
/// The shared recovery algorithm understands balanced optional regions, but
/// it deliberately does not own any language's directive inventory.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConditionalDirectiveSyntax {
    /// Opening directives whose suffix must contain a condition.
    pub openings_with_condition: &'static [&'static str],
    /// Alternative directives whose suffix must contain a condition.
    pub alternatives_with_condition: &'static [&'static str],
    /// Alternative directives that accept no argument.
    pub alternatives_without_condition: &'static [&'static str],
    /// Closing directive that accepts no argument.
    pub closing: &'static str,
    /// Adapter-owned line/block comment prefixes accepted after a no-argument
    /// directive.
    pub trailing_comment_prefixes: &'static [&'static str],
    /// Grammar-owned comment and literal nodes in which directive-looking
    /// text is ordinary data. The shared scanner checks the exact
    /// Tree-sitter ancestor chain at the directive marker; it never guesses
    /// language string/comment syntax from raw bytes.
    pub non_directive_node_kinds: &'static [&'static str],
}

/// Mask directive lines around branch-free conditional-compilation regions.
///
/// Retaining the optional tokens models the conservative union of build
/// configurations. Regions with any alternative directive are never
/// flattened because adjacent alternatives are not one source program. The
/// shared parser still requires the recovery tree to contain strictly less
/// syntax damage.
#[must_use]
pub fn branch_free_conditional_recovery_edits(
    snapshot: &FileSnapshot,
    tree: &Tree,
    syntax: ConditionalDirectiveSyntax,
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let mut stack = Vec::<ConditionalRegion>::new();
    let mut edits = Vec::new();
    for (start, end, line) in source_lines_with_ranges(snapshot.text.as_ref()) {
        let directive = line.trim_start();
        let directive_start = start + line.len().saturating_sub(directive.len());
        if directive_is_inside_non_directive_node(tree, directive_start, syntax.non_directive_node_kinds) {
            continue;
        }
        if syntax
            .openings_with_condition
            .iter()
            .any(|prefix| directive_with_condition(directive, prefix))
        {
            stack.push(ConditionalRegion {
                if_start: start,
                if_end: end,
                has_alternative: false,
            });
        } else if syntax
            .alternatives_with_condition
            .iter()
            .any(|prefix| directive_with_condition(directive, prefix))
            || syntax
                .alternatives_without_condition
                .iter()
                .any(|prefix| directive_without_argument(directive, prefix, syntax.trailing_comment_prefixes))
        {
            if let Some(region) = stack.last_mut() {
                region.has_alternative = true;
            }
        } else if directive_without_argument(directive, syntax.closing, syntax.trailing_comment_prefixes) {
            let Some(region) = stack.pop() else {
                continue;
            };
            if !region.has_alternative {
                edits.push(ParseRecoveryEdit::new(region.if_start, region.if_end));
                edits.push(ParseRecoveryEdit::new(start, end));
            }
        }
    }
    edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
    edits.dedup();
    edits
}

fn directive_is_inside_non_directive_node(
    tree: &Tree,
    byte: usize,
    non_directive_node_kinds: &[&str],
) -> bool {
    if non_directive_node_kinds.is_empty() || byte >= tree.root_node().end_byte() {
        return false;
    }
    let Some(mut node) = tree
        .root_node()
        .descendant_for_byte_range(byte, byte.saturating_add(1))
    else {
        return false;
    };
    loop {
        if non_directive_node_kinds.contains(&node.kind()) {
            return true;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

struct ConditionalRegion {
    if_start: usize,
    if_end: usize,
    has_alternative: bool,
}

fn source_lines_with_ranges(source: &str) -> impl Iterator<Item = (usize, usize, &str)> {
    let mut offset = 0usize;
    source.split_inclusive('\n').map(move |line| {
        let start = offset;
        offset += line.len();
        (start, offset, line)
    })
}

fn directive_with_condition(line: &str, prefix: &str) -> bool {
    line.strip_prefix(prefix)
        .is_some_and(|condition| condition.starts_with(char::is_whitespace) && !condition.trim().is_empty())
}

fn directive_without_argument(line: &str, prefix: &str, comment_prefixes: &[&str]) -> bool {
    line.strip_prefix(prefix)
        .is_some_and(|rest| directive_has_no_argument(rest, comment_prefixes))
}

fn directive_has_no_argument(rest: &str, comment_prefixes: &[&str]) -> bool {
    let rest = rest.trim_start();
    rest.is_empty() || comment_prefixes.iter().any(|prefix| rest.starts_with(prefix))
}

impl ParseRecoveryEdit {
    #[must_use]
    pub const fn new(start_byte: usize, end_byte: usize) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::Mask,
            damaged_descendant_owner: None,
        }
    }

    /// Mask one compiler-proven token inside a syntactically damaged
    /// production. The adapter must derive the range from concrete frontend
    /// or preprocessor facts; the parser additionally requires strictly less
    /// damage and preservation of every unrelated clean compiler node.
    #[must_use]
    pub const fn mask_damaged_descendant(start_byte: usize, end_byte: usize) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::Mask,
            damaged_descendant_owner: Some((start_byte, end_byte)),
        }
    }

    /// Mask one prefix inside a larger clean descendant that is wholly owned
    /// by an enclosing error production.
    ///
    /// Some grammars parse a qualified construct as one clean node but accept
    /// only its unqualified terminal in the intended production. The adapter
    /// supplies the exact CST owner span so monotonic recovery may reclassify
    /// that subtree while still protecting every disjoint compiler node.
    #[must_use]
    pub const fn mask_damaged_descendant_prefix(
        start_byte: usize,
        end_byte: usize,
        owner_start_byte: usize,
        owner_end_byte: usize,
    ) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::Mask,
            damaged_descendant_owner: Some((owner_start_byte, owner_end_byte)),
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
            damaged_descendant_owner: None,
        }
    }

    /// Uppercase one contextual-keyword byte inside a clean node that is
    /// wholly owned by an enclosing error production. See
    /// [`Self::replace_damaged_descendant_ascii`].
    #[must_use]
    pub const fn uppercase_damaged_descendant_ascii(byte_offset: usize) -> Self {
        Self {
            start_byte: byte_offset,
            end_byte: byte_offset + 1,
            action: ParseRecoveryAction::UppercaseAscii,
            damaged_descendant_owner: Some((byte_offset, byte_offset + 1)),
        }
    }

    /// Replace one parser-buffer token with a shorter or equal-length ASCII
    /// grammar keyword and pad the remaining bytes with spaces.
    ///
    /// Adapters use this only after proving a compiler macro's syntactic role
    /// from its surrounding CST. Original source remains authoritative.
    #[must_use]
    pub const fn replace_ascii(start_byte: usize, end_byte: usize, replacement: &'static [u8]) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::ReplaceAscii(replacement),
            damaged_descendant_owner: None,
        }
    }

    /// Replace a clean descendant that is wholly owned by an enclosing
    /// Tree-sitter error production.
    ///
    /// This narrowly supports valid syntax whose current grammar parses one
    /// non-executable subexpression cleanly inside a damaged type/declaration
    /// node. The parser still requires the edit to cover that exact descendant
    /// and to reduce syntax damage; clean nodes outside an error ancestor stay
    /// protected by the monotonic recovery contract.
    #[must_use]
    pub const fn replace_damaged_descendant_ascii(
        start_byte: usize,
        end_byte: usize,
        replacement: &'static [u8],
    ) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::ReplaceAscii(replacement),
            damaged_descendant_owner: Some((start_byte, end_byte)),
        }
    }

    /// Replace one token inside a larger CST-proven damaged production.
    ///
    /// This is the replacement analogue of
    /// [`Self::mask_damaged_descendant_prefix`]. It is reserved for adapters
    /// whose raw damaged tree proves the complete owner region and whose
    /// same-width replacement leaves every unrelated compiler node intact.
    /// The parser independently requires strictly less syntax damage before
    /// accepting the recovered tree.
    #[must_use]
    pub const fn replace_damaged_descendant_prefix_ascii(
        start_byte: usize,
        end_byte: usize,
        replacement: &'static [u8],
        owner_start_byte: usize,
        owner_end_byte: usize,
    ) -> Self {
        Self {
            start_byte,
            end_byte,
            action: ParseRecoveryAction::ReplaceAscii(replacement),
            damaged_descendant_owner: Some((owner_start_byte, owner_end_byte)),
        }
    }

    #[must_use]
    pub const fn allows_damaged_descendant_replacement(self) -> bool {
        self.damaged_descendant_owner.is_some()
    }

    #[must_use]
    pub const fn damaged_descendant_owner(self) -> Option<(usize, usize)> {
        self.damaged_descendant_owner
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
            ParseRecoveryAction::ReplaceAscii(replacement) => {
                let target = &mut recovered[self.start_byte..self.end_byte];
                if replacement.is_empty()
                    || replacement.len() > target.len()
                    || !replacement.iter().all(u8::is_ascii)
                    || target.iter().any(|byte| matches!(*byte, b'\n' | b'\r'))
                {
                    return false;
                }
                let before = target.to_vec();
                target.fill(b' ');
                target[..replacement.len()].copy_from_slice(replacement);
                target != before
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
    variadic_read_builtins: &[&str],
) -> Vec<ParseRecoveryEdit> {
    if !tree.root_node().has_error() {
        return Vec::new();
    }

    let source = snapshot.text.as_bytes();
    let mut edits = Vec::new();
    collect_variadic_pointer_type_recovery_edits(source, tree, variadic_read_builtins, &mut edits);

    let macros = reachable_object_macros(snapshot, vfs);
    bonsai_diagnostics::debug_log!(
        "parse-recovery",
        "file={} reachable_object_macros={}",
        snapshot.path.display(),
        macros.len()
    );
    if macros.is_empty() {
        edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
        edits.dedup();
        return edits;
    }

    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() {
            if let Some(container) = declaration_prefix_container(node) {
                let prefix_end = node.start_byte().min(source.len());
                let prefix_start = container.start_byte().min(prefix_end);
                collect_defined_identifier_ranges(source, prefix_start, prefix_end, &macros, &mut edits);
            }
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

/// Recover the standardized C-family `va_arg(list, pointer_type)` form.
///
/// Tree-sitter parses the type head (`char`) as an expression and leaves the
/// pointer declarator (`*`) as an `ERROR` sibling. Masking only that sibling
/// yields a valid same-width recovery tree while downstream text and spans
/// continue to address the original type operand. No arbitrary call or
/// malformed value expression is accepted by this recovery.
fn collect_variadic_pointer_type_recovery_edits(
    source: &[u8],
    tree: &Tree,
    variadic_read_builtins: &[&str],
    edits: &mut Vec<ParseRecoveryEdit>,
) {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_error() && variadic_pointer_type_error(node, source, variadic_read_builtins) {
            edits.push(ParseRecoveryEdit::new(node.start_byte(), node.end_byte()));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.has_error() || child.is_missing() {
                stack.push(child);
            }
        }
    }
}

fn variadic_pointer_type_error(node: Node<'_>, source: &[u8], variadic_read_builtins: &[&str]) -> bool {
    let Some(fragment) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    if !fragment.contains(&b'*')
        || fragment
            .iter()
            .any(|byte| *byte != b'*' && !byte.is_ascii_whitespace())
    {
        return false;
    }

    let Some(arguments) = node.parent().filter(|parent| parent.kind() == "argument_list") else {
        return false;
    };
    let has_list_and_type_before_error = {
        let mut cursor = arguments.walk();
        arguments
            .named_children(&mut cursor)
            .filter(|child| child.end_byte() <= node.start_byte())
            .take(2)
            .count()
            == 2
    };
    if !has_list_and_type_before_error {
        return false;
    }

    let Some(call) = arguments
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
    else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    source
        .get(function.start_byte()..function.end_byte())
        .and_then(|name| std::str::from_utf8(name).ok())
        .is_some_and(|name| variadic_read_builtins.contains(&name))
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
            edits.push(ParseRecoveryEdit::mask_damaged_descendant(token_start, cursor));
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
    reachable_preprocessor_context(snapshot, vfs).0
}

/// Stable digest of exact C-family source/header context consumed by parser
/// recovery. This is adapter-facing compiler identity, not security meaning.
#[must_use]
pub fn c_family_preprocessor_context_fingerprint(snapshot: &FileSnapshot, vfs: &Vfs) -> u64 {
    reachable_preprocessor_context(snapshot, vfs).1
}

fn reachable_preprocessor_context(snapshot: &FileSnapshot, vfs: &Vfs) -> (AHashSet<String>, u64) {
    let mut macros = AHashSet::new();
    let mut visited = AHashSet::new();
    let mut pending = vec![(snapshot.file_id, snapshot.path.as_ref().clone())];
    let mut context = Vec::new();
    while let Some((file, path)) = pending.pop() {
        if !visited.insert(file) {
            continue;
        }
        let current = if file == snapshot.file_id {
            snapshot.clone()
        } else {
            let Ok(current) = vfs.snapshot(file) else {
                continue;
            };
            current
        };
        let directives = preprocessor_directives(&current.text);
        context.push((path.clone(), current.version, current.text.clone()));
        macros.extend(directives.object_macros);
        for include in directives.includes {
            if let Some((included_file, included_path)) = resolve_include(vfs, &path, &include) {
                pending.push((included_file, included_path));
            }
        }
    }
    context.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = bonsai_hash::Hasher::new();
    for (path, version, text) in context {
        hasher.absorb(path.to_string_lossy().as_bytes());
        hasher.absorb_separator();
        hasher.absorb(&version.to_le_bytes());
        hasher.absorb_separator();
        hasher.absorb(text.as_bytes());
        hasher.absorb_separator();
    }
    (macros, hasher.finish())
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
    vfs: &Vfs,
    including_path: &Path,
    include: &Path,
) -> Option<(bonsai_common::FileId, PathBuf)> {
    if let Some(parent) = including_path.parent() {
        let local = parent.join(include);
        if let Some(file) = vfs.lookup(&local) {
            return Some((file, local));
        }
    }
    vfs.unique_file_ending_with(include)
        .map(|(file, path)| (file, path.as_ref().clone()))
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
        assert!(ParseRecoveryEdit::replace_ascii(4, 7, b"fn").apply_to(source, &mut recovered));
        assert_eq!(std::str::from_utf8(&recovered).unwrap(), "    fn \n");
        assert_eq!(source, "API var\n");
    }

    #[test]
    fn syntax_damage_scores_concrete_error_nodes() {
        let source = "def f():\n    @@@\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::kit::language_from_pack("python").expect("Python grammar"))
            .expect("set Python grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse malformed Python fixture");

        assert!(tree.root_node().has_error());
        let (covered_bytes, count) = syntax_damage_score(&tree);
        assert!(count > 0, "syntax damage must count a concrete error node");
        assert!(
            covered_bytes > 0,
            "syntax damage must retain its concrete byte extent"
        );
        assert!(covered_bytes <= source.len());
    }

    #[test]
    fn syntax_damage_never_prefers_one_whole_source_error_over_local_damage() {
        let language = crate::kit::language_from_pack("c").expect("C grammar");
        let parse = |source: &str| {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&language).expect("set C grammar");
            parser.parse(source, None).expect("parse C damage fixture")
        };
        let local = parse("int ok(void) { return 0; }\n@@@\nint also_ok(void) { return 1; }\n");
        let collapsed = parse("def not_c():\n    return {'broken': [1, 2}\n");

        assert!(local.root_node().has_error());
        assert!(collapsed.root_node().has_error());
        assert!(
            syntax_damage_score(&local) < syntax_damage_score(&collapsed),
            "localized syntax damage must preserve more compiler evidence: local={:?}, collapsed={:?}",
            syntax_damage_score(&local),
            syntax_damage_score(&collapsed)
        );
    }

    #[test]
    fn syntax_damage_recurses_through_named_children_that_carry_errors() {
        let source =
            "#if MODE\nint value(int x) { if (x)\n#else\nint value(int x) {\n#endif\nreturn (1 + );\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::kit::language_from_pack("c").expect("C grammar"))
            .expect("set C grammar");
        let tree = parser.parse(source, None).expect("parse damage fixture");
        let mut stack = vec![tree.root_node()];
        let mut has_nested_named_damage = false;
        let mut concrete_count = 0usize;
        while let Some(node) = stack.pop() {
            concrete_count += usize::from(node.is_error() || node.is_missing());
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                has_nested_named_damage |=
                    node.is_error() && child.is_named() && child.has_error() && !child.is_error();
                stack.push(child);
            }
        }
        assert!(
            has_nested_named_damage,
            "fixture must retain named damage below an ERROR container"
        );
        assert_eq!(
            syntax_damage_score(&tree).1,
            concrete_count,
            "the recovery score must enumerate nested concrete damage rather than treating its named container as clean"
        );
    }
}
