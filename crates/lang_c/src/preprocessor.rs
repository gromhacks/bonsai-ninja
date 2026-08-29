//! Lexical C preprocessor structure.
//!
//! This module owns directive boundaries and conditional nesting only. It does
//! not interpret declarations, expand macros, normalize source, or lower
//! Tree-sitter facts. Every range addresses the original source bytes.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct ByteRange {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConditionalDirectiveKind {
    If,
    Ifdef,
    Ifndef,
    Elif,
    Elifdef,
    Elifndef,
    Else,
    Endif,
}

impl ConditionalDirectiveKind {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "if" => Self::If,
            "ifdef" => Self::Ifdef,
            "ifndef" => Self::Ifndef,
            "elif" => Self::Elif,
            "elifdef" => Self::Elifdef,
            "elifndef" => Self::Elifndef,
            "else" => Self::Else,
            "endif" => Self::Endif,
            _ => return None,
        })
    }

    const fn requires_argument(self) -> bool {
        matches!(
            self,
            Self::If | Self::Ifdef | Self::Ifndef | Self::Elif | Self::Elifdef | Self::Elifndef
        )
    }

    const fn requires_identifier_argument(self) -> bool {
        matches!(self, Self::Ifdef | Self::Ifndef | Self::Elifdef | Self::Elifndef)
    }

    const fn is_opening(self) -> bool {
        matches!(self, Self::If | Self::Ifdef | Self::Ifndef)
    }

    const fn is_alternative(self) -> bool {
        matches!(self, Self::Elif | Self::Elifdef | Self::Elifndef | Self::Else)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectiveStatus {
    Valid,
    MissingArgument,
    UnexpectedArgument,
    UnmatchedAlternative,
    UnmatchedClose,
    DuplicateElse,
    ElifAfterElse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectiveFact {
    pub(crate) kind: ConditionalDirectiveKind,
    /// One contiguous original-source range covering the complete logical
    /// directive, including continuation lines and its terminal newline.
    pub(crate) logical_span: ByteRange,
    /// Exact original-source ranges for every physical line occupied by the
    /// logical directive.
    pub(crate) physical_line_spans: Vec<ByteRange>,
    pub(crate) name_span: ByteRange,
    pub(crate) argument_span: Option<ByteRange>,
    pub(crate) status: DirectiveStatus,
    pub(crate) group: Option<usize>,
    pub(crate) branch: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConditionalBranch {
    pub(crate) directive: usize,
    pub(crate) condition_span: Option<ByteRange>,
    pub(crate) body_span: ByteRange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConditionalGroup {
    pub(crate) opening_directive: usize,
    pub(crate) closing_directive: Option<usize>,
    pub(crate) parent_group: Option<usize>,
    pub(crate) parent_branch: Option<usize>,
    pub(crate) branches: Vec<ConditionalBranch>,
    pub(crate) span: Option<ByteRange>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PreprocessorDiagnosticKind {
    MissingArgument,
    UnexpectedArgument,
    UnmatchedAlternative,
    UnmatchedClose,
    DuplicateElse,
    ElifAfterElse,
    UnclosedConditional,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreprocessorDiagnostic {
    pub(crate) kind: PreprocessorDiagnosticKind,
    pub(crate) span: ByteRange,
    pub(crate) directive: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PreprocessorMap {
    pub(crate) directives: Vec<DirectiveFact>,
    pub(crate) groups: Vec<ConditionalGroup>,
    pub(crate) diagnostics: Vec<PreprocessorDiagnostic>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LexicalState {
    Code,
    LineComment,
    BlockComment,
    String,
    Character,
}

#[derive(Copy, Clone, Debug)]
struct OpenGroup {
    group: usize,
    saw_else: bool,
}

#[derive(Copy, Clone, Debug)]
struct ParsedDirective {
    kind: ConditionalDirectiveKind,
    name_span: ByteRange,
    argument_span: Option<ByteRange>,
    syntax_status: DirectiveStatus,
}

impl PreprocessorMap {
    #[must_use]
    pub(crate) fn parse(source: &str) -> Self {
        let bytes = source.as_bytes();
        let directive_ranges = directive_logical_ranges(bytes);
        let mut map = Self::default();
        let mut stack = Vec::<OpenGroup>::new();

        for logical_span in directive_ranges {
            let Some(parsed) = parse_conditional_directive(bytes, logical_span) else {
                continue;
            };
            let directive = map.directives.len();
            map.directives.push(DirectiveFact {
                kind: parsed.kind,
                logical_span,
                physical_line_spans: physical_line_spans(bytes, logical_span),
                name_span: parsed.name_span,
                argument_span: parsed.argument_span,
                status: parsed.syntax_status,
                group: None,
                branch: None,
            });

            if parsed.syntax_status != DirectiveStatus::Valid {
                map.push_status_diagnostic(directive, parsed.syntax_status);
                continue;
            }

            if parsed.kind.is_opening() {
                let parent_group = stack.last().map(|open| open.group);
                let parent_branch = stack.last().and_then(|open| {
                    map.groups
                        .get(open.group)
                        .and_then(|group| group.branches.len().checked_sub(1))
                });
                let group = map.groups.len();
                map.groups.push(ConditionalGroup {
                    opening_directive: directive,
                    closing_directive: None,
                    parent_group,
                    parent_branch,
                    branches: vec![ConditionalBranch {
                        directive,
                        condition_span: parsed.argument_span,
                        body_span: ByteRange {
                            start: logical_span.end,
                            end: bytes.len(),
                        },
                    }],
                    span: None,
                });
                map.directives[directive].group = Some(group);
                map.directives[directive].branch = Some(0);
                stack.push(OpenGroup {
                    group,
                    saw_else: false,
                });
                continue;
            }

            if parsed.kind.is_alternative() {
                let Some(open) = stack.last_mut() else {
                    map.set_status(directive, DirectiveStatus::UnmatchedAlternative);
                    continue;
                };
                if parsed.kind == ConditionalDirectiveKind::Else {
                    if open.saw_else {
                        map.directives[directive].group = Some(open.group);
                        map.set_status(directive, DirectiveStatus::DuplicateElse);
                        continue;
                    }
                    open.saw_else = true;
                } else if open.saw_else {
                    map.directives[directive].group = Some(open.group);
                    map.set_status(directive, DirectiveStatus::ElifAfterElse);
                    continue;
                }

                let group = &mut map.groups[open.group];
                if let Some(previous) = group.branches.last_mut() {
                    previous.body_span.end = logical_span.start;
                }
                let branch = group.branches.len();
                group.branches.push(ConditionalBranch {
                    directive,
                    condition_span: parsed.argument_span,
                    body_span: ByteRange {
                        start: logical_span.end,
                        end: bytes.len(),
                    },
                });
                map.directives[directive].group = Some(open.group);
                map.directives[directive].branch = Some(branch);
                continue;
            }

            debug_assert_eq!(parsed.kind, ConditionalDirectiveKind::Endif);
            let Some(open) = stack.pop() else {
                map.set_status(directive, DirectiveStatus::UnmatchedClose);
                continue;
            };
            let group = &mut map.groups[open.group];
            if let Some(branch) = group.branches.last_mut() {
                branch.body_span.end = logical_span.start;
            }
            group.closing_directive = Some(directive);
            group.span = Some(ByteRange {
                start: map.directives[group.opening_directive].logical_span.start,
                end: logical_span.end,
            });
            map.directives[directive].group = Some(open.group);
        }

        for open in stack {
            let opening = map.groups[open.group].opening_directive;
            map.diagnostics.push(PreprocessorDiagnostic {
                kind: PreprocessorDiagnosticKind::UnclosedConditional,
                span: map.directives[opening].logical_span,
                directive: opening,
            });
        }
        map
    }

    /// Exact directive-line spans for balanced conditional groups that have
    /// one branch and therefore no mutually exclusive alternative.
    ///
    /// Retaining that branch is a concrete preprocessing configuration, not a
    /// merge of incompatible token streams.  Callers may use these spans to
    /// build a same-width Tree-sitter projection, but declarations and flow
    /// still have to come from the resulting CST. Malformed or unclosed
    /// groups never contribute recovery spans.
    #[must_use]
    pub(crate) fn branch_free_directive_spans(&self) -> Vec<ByteRange> {
        let mut spans = Vec::new();
        for group in &self.groups {
            if group.branches.len() != 1 {
                continue;
            }
            let Some(closing) = group.closing_directive else {
                continue;
            };
            let opening = group.opening_directive;
            if self.directives[opening].status != DirectiveStatus::Valid
                || self.directives[closing].status != DirectiveStatus::Valid
            {
                continue;
            }
            spans.push(self.directives[opening].logical_span);
            spans.push(self.directives[closing].logical_span);
        }
        spans.sort_by_key(|span| (span.start, span.end));
        spans.dedup();
        spans
    }

    fn set_status(&mut self, directive: usize, status: DirectiveStatus) {
        self.directives[directive].status = status;
        self.push_status_diagnostic(directive, status);
    }

    fn push_status_diagnostic(&mut self, directive: usize, status: DirectiveStatus) {
        let kind = match status {
            DirectiveStatus::Valid => return,
            DirectiveStatus::MissingArgument => PreprocessorDiagnosticKind::MissingArgument,
            DirectiveStatus::UnexpectedArgument => PreprocessorDiagnosticKind::UnexpectedArgument,
            DirectiveStatus::UnmatchedAlternative => PreprocessorDiagnosticKind::UnmatchedAlternative,
            DirectiveStatus::UnmatchedClose => PreprocessorDiagnosticKind::UnmatchedClose,
            DirectiveStatus::DuplicateElse => PreprocessorDiagnosticKind::DuplicateElse,
            DirectiveStatus::ElifAfterElse => PreprocessorDiagnosticKind::ElifAfterElse,
        };
        self.diagnostics.push(PreprocessorDiagnostic {
            kind,
            span: self.directives[directive].logical_span,
            directive,
        });
    }
}

/// Locate directive logical lines with one source-linear lexical pass.
fn directive_logical_ranges(source: &[u8]) -> Vec<ByteRange> {
    let mut ranges = Vec::new();
    let mut state = LexicalState::Code;
    let mut directive_start = None;
    let mut only_trivia = true;
    let mut cursor = 0usize;
    while cursor < source.len() {
        if let Some(end) = escaped_newline_end(source, cursor) {
            cursor = end;
            continue;
        }

        if let Some(newline_end) = newline_end(source, cursor) {
            if let Some(start) = directive_start.take() {
                ranges.push(ByteRange {
                    start,
                    end: newline_end,
                });
            }
            if state == LexicalState::LineComment {
                state = LexicalState::Code;
            }
            only_trivia = true;
            cursor = newline_end;
            continue;
        }

        match state {
            LexicalState::Code => {
                if source.get(cursor..cursor + 2) == Some(b"//") {
                    state = LexicalState::LineComment;
                    cursor += 2;
                } else if source.get(cursor..cursor + 2) == Some(b"/*") {
                    state = LexicalState::BlockComment;
                    cursor += 2;
                } else if source[cursor] == b'"' {
                    state = LexicalState::String;
                    only_trivia = false;
                    cursor += 1;
                } else if source[cursor] == b'\'' {
                    state = LexicalState::Character;
                    only_trivia = false;
                    cursor += 1;
                } else if source[cursor] == b'#' && only_trivia && directive_start.is_none() {
                    directive_start = Some(cursor);
                    only_trivia = false;
                    cursor += 1;
                } else {
                    if !source[cursor].is_ascii_whitespace() {
                        only_trivia = false;
                    }
                    cursor += 1;
                }
            }
            LexicalState::LineComment => cursor += 1,
            LexicalState::BlockComment => {
                if source.get(cursor..cursor + 2) == Some(b"*/") {
                    state = LexicalState::Code;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            LexicalState::String => {
                if source[cursor] == b'\\' {
                    cursor = (cursor + 2).min(source.len());
                } else {
                    if source[cursor] == b'"' {
                        state = LexicalState::Code;
                    }
                    cursor += 1;
                }
            }
            LexicalState::Character => {
                if source[cursor] == b'\\' {
                    cursor = (cursor + 2).min(source.len());
                } else {
                    if source[cursor] == b'\'' {
                        state = LexicalState::Code;
                    }
                    cursor += 1;
                }
            }
        }
    }
    if let Some(start) = directive_start {
        ranges.push(ByteRange {
            start,
            end: source.len(),
        });
    }
    ranges
}

fn parse_conditional_directive(source: &[u8], span: ByteRange) -> Option<ParsedDirective> {
    let mut cursor = LogicalCursor::new(source, span.start + 1, span.end);
    cursor.skip_trivia();
    let (name, name_span) = cursor.identifier()?;
    let kind = ConditionalDirectiveKind::from_name(name.as_str())?;
    cursor.skip_trivia();
    let argument_span = cursor.remaining_token_span();
    let syntax_status = if kind.requires_argument() && argument_span.is_none() {
        DirectiveStatus::MissingArgument
    } else if kind.requires_identifier_argument()
        && !argument_span.is_some_and(|argument| logical_range_is_single_identifier(source, argument))
    {
        DirectiveStatus::UnexpectedArgument
    } else if kind.requires_argument() {
        DirectiveStatus::Valid
    } else if argument_span.is_some() {
        DirectiveStatus::UnexpectedArgument
    } else {
        DirectiveStatus::Valid
    };
    Some(ParsedDirective {
        kind,
        name_span,
        argument_span,
        syntax_status,
    })
}

fn logical_range_is_single_identifier(source: &[u8], span: ByteRange) -> bool {
    let mut cursor = LogicalCursor::new(source, span.start, span.end);
    cursor.skip_trivia();
    if cursor.identifier().is_none() {
        return false;
    }
    cursor.skip_trivia();
    cursor.cursor == span.end
}

struct LogicalCursor<'a> {
    source: &'a [u8],
    cursor: usize,
    end: usize,
}

impl<'a> LogicalCursor<'a> {
    const fn new(source: &'a [u8], cursor: usize, end: usize) -> Self {
        Self { source, cursor, end }
    }

    fn skip_trivia(&mut self) {
        loop {
            if self.cursor >= self.end {
                return;
            }
            if let Some(end) = escaped_newline_end(self.source, self.cursor) {
                self.cursor = end.min(self.end);
            } else if self.source[self.cursor].is_ascii_whitespace() {
                self.cursor += 1;
            } else if self.source.get(self.cursor..self.cursor + 2) == Some(b"/*") {
                self.cursor = self.source[self.cursor + 2..self.end]
                    .windows(2)
                    .position(|pair| pair == b"*/")
                    .map_or(self.end, |relative| self.cursor + relative + 4);
            } else if self.source.get(self.cursor..self.cursor + 2) == Some(b"//") {
                self.cursor = self.end;
            } else {
                return;
            }
        }
    }

    fn identifier(&mut self) -> Option<(String, ByteRange)> {
        if self.cursor >= self.end || !is_identifier_start(self.source[self.cursor]) {
            return None;
        }
        let start = self.cursor;
        let mut value = String::new();
        let mut last_end = start;
        while self.cursor < self.end {
            if let Some(end) = escaped_newline_end(self.source, self.cursor) {
                self.cursor = end.min(self.end);
                continue;
            }
            let byte = self.source[self.cursor];
            if !is_identifier_continue(byte) {
                break;
            }
            value.push(char::from(byte));
            self.cursor += 1;
            last_end = self.cursor;
        }
        Some((value, ByteRange { start, end: last_end }))
    }

    fn remaining_token_span(&mut self) -> Option<ByteRange> {
        self.skip_trivia();
        let start = self.cursor;
        if start >= self.end {
            return None;
        }

        let mut cursor = self.cursor;
        let mut last_token_end = None;
        while cursor < self.end {
            if let Some(end) = escaped_newline_end(self.source, cursor) {
                cursor = end.min(self.end);
                continue;
            }
            if self.source[cursor].is_ascii_whitespace() {
                cursor += 1;
                continue;
            }
            if self.source.get(cursor..cursor + 2) == Some(b"//") {
                break;
            }
            if self.source.get(cursor..cursor + 2) == Some(b"/*") {
                cursor = self.source[cursor + 2..self.end]
                    .windows(2)
                    .position(|pair| pair == b"*/")
                    .map_or(self.end, |relative| cursor + relative + 4);
                continue;
            }
            last_token_end = Some(cursor + 1);
            cursor += 1;
        }
        last_token_end.map(|end| ByteRange { start, end })
    }
}

fn physical_line_spans(source: &[u8], logical: ByteRange) -> Vec<ByteRange> {
    let mut spans = Vec::new();
    let mut start = logical.start;
    let mut cursor = logical.start;
    while cursor < logical.end {
        if let Some(end) = newline_end(source, cursor) {
            spans.push(ByteRange { start, end });
            start = end;
            cursor = end;
        } else {
            cursor += 1;
        }
    }
    if start < logical.end {
        spans.push(ByteRange {
            start,
            end: logical.end,
        });
    }
    spans
}

fn escaped_newline_end(source: &[u8], cursor: usize) -> Option<usize> {
    (source.get(cursor) == Some(&b'\\'))
        .then(|| newline_end(source, cursor + 1))
        .flatten()
}

fn newline_end(source: &[u8], cursor: usize) -> Option<usize> {
    match source.get(cursor) {
        Some(b'\n') => Some(cursor + 1),
        Some(b'\r') if source.get(cursor + 1) == Some(&b'\n') => Some(cursor + 2),
        Some(b'\r') => Some(cursor + 1),
        _ => None,
    }
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

    fn kinds(map: &PreprocessorMap) -> Vec<ConditionalDirectiveKind> {
        map.directives.iter().map(|fact| fact.kind).collect()
    }

    #[test]
    fn nested_groups_retain_parent_branch_and_exact_bodies() {
        let source = "#if OUTER\nouter_a\n#ifdef INNER\ninner_a\n#else\ninner_b\n#endif\n#elif OTHER\nouter_b\n#else\nouter_c\n#endif\n";
        let map = PreprocessorMap::parse(source);

        assert!(map.diagnostics.is_empty(), "{map:#?}");
        assert_eq!(map.groups.len(), 2);
        let outer = &map.groups[0];
        let inner = &map.groups[1];
        assert_eq!(outer.branches.len(), 3);
        assert_eq!(inner.branches.len(), 2);
        assert_eq!(inner.parent_group, Some(0));
        assert_eq!(inner.parent_branch, Some(0));
        assert_eq!(outer.closing_directive, Some(6));
        assert_eq!(inner.closing_directive, Some(3));
        assert_eq!(
            &source[inner.branches[0].body_span.start..inner.branches[0].body_span.end],
            "inner_a\n"
        );
        assert_eq!(
            &source[inner.branches[1].body_span.start..inner.branches[1].body_span.end],
            "inner_b\n"
        );
        assert_eq!(
            outer.span,
            Some(ByteRange {
                start: 0,
                end: source.len()
            })
        );
    }

    #[test]
    fn every_supported_directive_kind_is_recognized() {
        let source =
            "#if A\n#elif B\n#elifdef C\n#elifndef D\n#else\n#endif\n#ifdef E\n#endif\n#ifndef F\n#endif\n";
        let map = PreprocessorMap::parse(source);
        assert!(map.diagnostics.is_empty(), "{map:#?}");
        assert_eq!(
            kinds(&map),
            [
                ConditionalDirectiveKind::If,
                ConditionalDirectiveKind::Elif,
                ConditionalDirectiveKind::Elifdef,
                ConditionalDirectiveKind::Elifndef,
                ConditionalDirectiveKind::Else,
                ConditionalDirectiveKind::Endif,
                ConditionalDirectiveKind::Ifdef,
                ConditionalDirectiveKind::Endif,
                ConditionalDirectiveKind::Ifndef,
                ConditionalDirectiveKind::Endif,
            ]
        );
    }

    #[test]
    fn crlf_whitespace_comments_and_logical_continuations_keep_exact_spans() {
        let source = " \t#  if defined(A) && \\\r\n defined(B) /* tail */\r\nvalue\r\n\t#endif // done\r\n";
        let opening_text = "#  if defined(A) && \\\r\n defined(B) /* tail */\r\n";
        let map = PreprocessorMap::parse(source);
        assert!(map.diagnostics.is_empty(), "{map:#?}");
        assert_eq!(map.directives.len(), 2);
        let opening = &map.directives[0];
        assert_eq!(
            opening.logical_span,
            ByteRange {
                start: 2,
                end: 2 + opening_text.len(),
            }
        );
        assert_eq!(opening.physical_line_spans.len(), 2);
        assert_eq!(&source[opening.name_span.start..opening.name_span.end], "if");
        let argument = opening.argument_span.expect("conditional expression span");
        assert_eq!(
            &source[argument.start..argument.end],
            "defined(A) && \\\r\n defined(B)"
        );
        assert_eq!(
            &source[opening.logical_span.start..opening.logical_span.end],
            opening_text
        );
        assert_eq!(
            &source[map.directives[1].logical_span.start..map.directives[1].logical_span.end],
            "#endif // done\r\n"
        );
    }

    #[test]
    fn comment_string_character_and_line_comment_spellings_are_not_directives() {
        let source = "/* #if HIDDEN */\nconst char *s = \"#endif\";\nchar c = '#'; // #if ALSO_HIDDEN\n/* prefix */ #if VISIBLE\n#endif\n";
        let map = PreprocessorMap::parse(source);
        assert_eq!(
            kinds(&map),
            [ConditionalDirectiveKind::If, ConditionalDirectiveKind::Endif]
        );
        assert!(map.diagnostics.is_empty(), "{map:#?}");
    }

    #[test]
    fn backslash_newline_can_continue_a_directive_name_and_argument() {
        let source = "#i\\\nf FLAG && \\\n MORE\n#en\\\ndif\n";
        let map = PreprocessorMap::parse(source);
        assert_eq!(
            kinds(&map),
            [ConditionalDirectiveKind::If, ConditionalDirectiveKind::Endif]
        );
        assert!(map.diagnostics.is_empty(), "{map:#?}");
        assert_eq!(map.directives[0].physical_line_spans.len(), 3);
        assert_eq!(map.directives[1].physical_line_spans.len(), 2);
    }

    #[test]
    fn continuations_do_not_turn_code_or_line_comments_into_directive_prefixes() {
        let source = "int value = \\\n+#if NOT_A_DIRECTIVE\n// comment \\\n+#endif\n#if VISIBLE\n#endif\n";
        let map = PreprocessorMap::parse(source);
        assert_eq!(
            kinds(&map),
            [ConditionalDirectiveKind::If, ConditionalDirectiveKind::Endif,]
        );
        assert!(map.diagnostics.is_empty(), "{map:#?}");
    }

    #[test]
    fn unmatched_close_is_retained_and_diagnosed() {
        let map = PreprocessorMap::parse("#endif\n");
        assert_eq!(map.directives.len(), 1);
        assert_eq!(map.directives[0].status, DirectiveStatus::UnmatchedClose);
        assert_eq!(
            map.diagnostics[0].kind,
            PreprocessorDiagnosticKind::UnmatchedClose
        );
    }

    #[test]
    fn unclosed_conditional_retains_the_open_group_and_diagnostic() {
        let source = "#if ENABLED\nvalue\n";
        let map = PreprocessorMap::parse(source);

        assert_eq!(map.directives.len(), 1);
        assert_eq!(map.directives[0].status, DirectiveStatus::Valid);
        assert_eq!(map.groups.len(), 1);
        assert_eq!(map.groups[0].closing_directive, None);
        assert_eq!(map.groups[0].span, None);
        assert_eq!(map.groups[0].branches[0].body_span.end, source.len());
        assert_eq!(
            map.diagnostics[0].kind,
            PreprocessorDiagnosticKind::UnclosedConditional
        );
    }

    #[test]
    fn endif_with_tokens_does_not_guess_a_close() {
        let map = PreprocessorMap::parse("#if ENABLED\n#endif junk\n");
        assert_eq!(map.directives[1].status, DirectiveStatus::UnexpectedArgument);
        assert_eq!(map.groups[0].closing_directive, None);
        assert_eq!(
            map.diagnostics.iter().map(|diag| diag.kind).collect::<Vec<_>>(),
            [
                PreprocessorDiagnosticKind::UnexpectedArgument,
                PreprocessorDiagnosticKind::UnclosedConditional,
            ]
        );
    }

    #[test]
    fn duplicate_else_is_retained_without_creating_a_branch() {
        let map = PreprocessorMap::parse("#if A\n#else\n#else\n#endif\n");
        assert_eq!(map.directives[2].status, DirectiveStatus::DuplicateElse);
        assert_eq!(map.directives[2].group, Some(0));
        assert_eq!(map.groups[0].branches.len(), 2);
        assert_eq!(map.diagnostics[0].kind, PreprocessorDiagnosticKind::DuplicateElse);
    }

    #[test]
    fn elif_after_else_is_retained_without_creating_a_branch() {
        let map = PreprocessorMap::parse("#if A\n#else\n#elif B\n#endif\n");
        assert_eq!(map.directives[2].status, DirectiveStatus::ElifAfterElse);
        assert_eq!(map.directives[2].group, Some(0));
        assert_eq!(map.groups[0].branches.len(), 2);
        assert_eq!(map.diagnostics[0].kind, PreprocessorDiagnosticKind::ElifAfterElse);
    }

    #[test]
    fn missing_condition_and_unmatched_alternative_are_retained() {
        let map = PreprocessorMap::parse("#if /* none */\n#else\n");
        assert_eq!(map.directives[0].status, DirectiveStatus::MissingArgument);
        assert_eq!(map.directives[1].status, DirectiveStatus::UnmatchedAlternative);
        assert_eq!(
            map.diagnostics.iter().map(|diag| diag.kind).collect::<Vec<_>>(),
            [
                PreprocessorDiagnosticKind::MissingArgument,
                PreprocessorDiagnosticKind::UnmatchedAlternative,
            ]
        );
    }

    #[test]
    fn macro_condition_directives_require_exactly_one_identifier() {
        let map =
            PreprocessorMap::parse("#ifdef ONE TWO\n#ifndef 123\n#elifdef VALID\n#elifndef ALSO_VALID\n");
        assert_eq!(
            map.directives.iter().map(|fact| fact.status).collect::<Vec<_>>(),
            [
                DirectiveStatus::UnexpectedArgument,
                DirectiveStatus::UnexpectedArgument,
                DirectiveStatus::UnmatchedAlternative,
                DirectiveStatus::UnmatchedAlternative,
            ]
        );
        assert_eq!(map.groups.len(), 0, "malformed opens must not mutate nesting");
    }

    #[test]
    fn branch_free_recovery_spans_exclude_alternatives_and_malformed_groups() {
        let source =
            "#if OUTER\n#ifdef INNER\nvalue\n#endif\n#endif\n#if CHOICE\na\n#else\nb\n#endif\n#if UNCLOSED\n";
        let map = PreprocessorMap::parse(source);
        let spans = map.branch_free_directive_spans();
        let recovered = spans
            .iter()
            .map(|span| &source[span.start..span.end])
            .collect::<Vec<_>>();

        assert_eq!(
            recovered,
            ["#if OUTER\n", "#ifdef INNER\n", "#endif\n", "#endif\n"]
        );
        assert!(
            recovered
                .iter()
                .all(|directive| !directive.contains("CHOICE") && !directive.contains("UNCLOSED")),
            "alternative and malformed groups must not become recovery projections"
        );
    }
}
