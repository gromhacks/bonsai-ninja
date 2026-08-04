//! Tree-sitter-backed ANSI syntax highlighting for CLI source snippets.
//!
//! Highlighting consumes each adapter's production grammar and classifies
//! parsed nodes through grammar metadata. It therefore cannot drift onto a
//! second parsing stack or mistake source text for syntax.

use crate::theme::Theme;
use ahash::AHashMap;
use bonsai_lang_api::FragmentParseContext;
use once_cell::sync::OnceCell;
use tree_sitter::{Language, Node, Parser};

/// Immutable per-language grammars shared by all renderers. Mutable parser
/// state remains local to each highlight call.
pub(crate) struct SyntaxHighlightCache {
    languages: AHashMap<String, Language>,
    fragment_contexts: AHashMap<String, FragmentParseContext>,
    extension_languages: AHashMap<String, String>,
}

pub(crate) fn syntax_highlight_cache() -> &'static SyntaxHighlightCache {
    static CACHE: OnceCell<SyntaxHighlightCache> = OnceCell::new();
    CACHE.get_or_init(SyntaxHighlightCache::build)
}

impl SyntaxHighlightCache {
    fn build() -> Self {
        let mut languages = AHashMap::new();
        let mut fragment_contexts = AHashMap::new();
        let mut extension_languages = AHashMap::new();
        for adapter in bonsai_adapters::all_adapters() {
            for extension in adapter.file_extensions() {
                let synthetic_path = std::path::PathBuf::from(format!("source.{extension}"));
                let grammar_name = adapter.grammar_name_for_path(&synthetic_path).to_string();
                let Ok(language) = adapter.tree_sitter_language_for_path(&synthetic_path) else {
                    continue;
                };
                extension_languages.insert((*extension).to_string(), grammar_name.clone());
                fragment_contexts.insert(grammar_name.clone(), adapter.fragment_parse_context());
                languages.insert(grammar_name, language);
            }
        }
        Self {
            languages,
            fragment_contexts,
            extension_languages,
        }
    }

    pub(crate) fn syntax_for_extension(&self, extension: &str) -> Option<&Language> {
        self.languages.get(self.language_name_for_extension(extension)?)
    }

    fn language_name_for_extension(&self, extension: &str) -> Option<&str> {
        self.extension_languages.get(extension).map(String::as_str)
    }

    pub(crate) fn highlight(&self, code: &str, extension: &str, theme: Theme) -> String {
        let Some(language_name) = self.language_name_for_extension(extension) else {
            return code.to_string();
        };
        let Some(language) = self.syntax_for_extension(extension) else {
            return code.to_string();
        };
        let context = self
            .fragment_contexts
            .get(language_name)
            .copied()
            .unwrap_or_default();
        let mut parser = Parser::new();
        if parser.set_language(language).is_err() {
            return code.to_string();
        }
        let wrapped;
        let (source, source_offset) = if context.prefix.is_empty() && context.suffix.is_empty() {
            (code, 0)
        } else {
            wrapped = format!("{}{code}{}", context.prefix, context.suffix);
            (wrapped.as_str(), context.prefix.len())
        };
        let Some(tree) = parser.parse(source.as_bytes(), None) else {
            return code.to_string();
        };
        render_tree(code, tree.root_node(), theme, source_offset).unwrap_or_else(|| code.to_string())
    }
}

fn render_tree(code: &str, root: Node<'_>, theme: Theme, source_offset: usize) -> Option<String> {
    let mut ranges = semantic_ranges(root);
    let source_end = source_offset.checked_add(code.len())?;
    ranges.retain_mut(|range| {
        range.start = range.start.max(source_offset);
        range.end = range.end.min(source_end);
        if range.end <= range.start {
            return false;
        }
        range.start -= source_offset;
        range.end -= source_offset;
        true
    });
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut out = String::with_capacity(code.len().saturating_add(code.len() / 3));
    let mut cursor = 0usize;
    for range in ranges {
        if range.start < cursor || range.end <= range.start || code.len() < range.end {
            continue;
        }
        out.push_str(code.get(cursor..range.start)?);
        let (red, green, blue) = tone_color(theme, range.tone);
        use std::fmt::Write as _;
        write!(out, "\x1b[38;2;{red};{green};{blue}m").ok()?;
        out.push_str(code.get(range.start..range.end)?);
        out.push_str("\x1b[0m");
        cursor = range.end;
    }
    out.push_str(code.get(cursor..)?);
    Some(out)
}

/// Iterative CST walk: nesting depth cannot overflow the Rust stack, and no
/// node/byte budget can silently truncate highlighting on generated files.
fn semantic_ranges(root: Node<'_>) -> Vec<SemanticRange> {
    let mut ranges = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.end_byte() <= node.start_byte() {
            continue;
        }
        if let Some(tone) = whole_node_tone(node.kind()) {
            ranges.push(SemanticRange::new(node, tone));
            continue;
        }
        if node.child_count() == 0 {
            ranges.push(SemanticRange::new(node, leaf_tone(node)));
            continue;
        }
        let mut cursor = node.walk();
        let children = node.children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    ranges
}

/// Literal/comment nodes own their complete span, including delimiters. These
/// categories come from grammar node kinds rather than the source bytes.
fn whole_node_tone(kind: &str) -> Option<SyntaxTone> {
    let kind = kind.to_ascii_lowercase();
    if kind.contains("comment") {
        Some(SyntaxTone::Comment)
    } else if kind.contains("string")
        || kind.contains("heredoc")
        || kind.contains("character_literal")
        || kind == "char_literal"
    {
        Some(SyntaxTone::String)
    } else if kind.contains("number")
        || kind.contains("integer")
        || kind.contains("float")
        || kind.contains("decimal")
    {
        Some(SyntaxTone::Constant)
    } else {
        None
    }
}

fn leaf_tone(node: Node<'_>) -> SyntaxTone {
    let kind = node.kind().to_ascii_lowercase();
    if !node.is_named() {
        return if kind.chars().any(char::is_alphanumeric) {
            SyntaxTone::Keyword
        } else {
            SyntaxTone::Punctuation
        };
    }
    let parent_kind = node.parent().map(|parent| parent.kind().to_ascii_lowercase());
    let field = node_field_name(node).unwrap_or_default().to_ascii_lowercase();
    if field.contains("type")
        || parent_kind
            .as_deref()
            .is_some_and(|parent| parent.contains("type") || parent.contains("class"))
    {
        SyntaxTone::Type
    } else if field.contains("function")
        || field.contains("method")
        || field.contains("callee")
        || parent_kind
            .as_deref()
            .is_some_and(|parent| parent.contains("call") && field == "name")
    {
        SyntaxTone::Function
    } else if field.contains("property") || field.contains("field") || field.contains("member") {
        SyntaxTone::Property
    } else if parent_kind
        .as_deref()
        .is_some_and(|parent| parent.contains("tag"))
    {
        SyntaxTone::Tag
    } else if kind.contains("constant") {
        SyntaxTone::Constant
    } else {
        SyntaxTone::Variable
    }
}

fn node_field_name(node: Node<'_>) -> Option<&'static str> {
    let parent = node.parent()?;
    (0..parent.child_count()).find_map(|index| {
        let index = u32::try_from(index).ok()?;
        (parent.child(index) == Some(node))
            .then(|| parent.field_name_for_child(index))
            .flatten()
    })
}

fn tone_color(theme: Theme, tone: SyntaxTone) -> (u8, u8, u8) {
    match (theme, tone) {
        (Theme::EarthyDark, SyntaxTone::Comment) => (120, 110, 96),
        (Theme::EarthyDark, SyntaxTone::Constant) => (214, 154, 91),
        (Theme::EarthyDark, SyntaxTone::Function) => (217, 195, 141),
        (Theme::EarthyDark, SyntaxTone::Keyword) => (188, 132, 61),
        (Theme::EarthyDark, SyntaxTone::String) => (152, 170, 110),
        (Theme::EarthyDark, SyntaxTone::Type) => (160, 181, 168),
        (Theme::EarthyDark, SyntaxTone::Tag) => (196, 118, 90),
        (Theme::EarthyDark, SyntaxTone::Property) => (185, 168, 124),
        (Theme::EarthyDark, SyntaxTone::Punctuation) => (139, 130, 110),
        (Theme::EarthyDark, SyntaxTone::Variable) => (205, 196, 174),
        (Theme::Dracula, SyntaxTone::Comment) => (98, 114, 164),
        (Theme::Dracula, SyntaxTone::Constant) => (189, 147, 249),
        (Theme::Dracula, SyntaxTone::Function) => (80, 250, 123),
        (Theme::Dracula, SyntaxTone::Keyword) => (255, 121, 198),
        (Theme::Dracula, SyntaxTone::String) => (241, 250, 140),
        (Theme::Dracula, SyntaxTone::Type) => (139, 233, 253),
        (Theme::Dracula, SyntaxTone::Tag) => (255, 85, 85),
        (Theme::Dracula, SyntaxTone::Property) => (255, 184, 108),
        (Theme::Dracula, SyntaxTone::Punctuation | SyntaxTone::Variable) => (248, 248, 242),
        (Theme::RetroAmber, SyntaxTone::Comment) => (110, 74, 0),
        (Theme::RetroAmber, SyntaxTone::Constant) => (255, 176, 0),
        (Theme::RetroAmber, SyntaxTone::Function) => (230, 154, 0),
        (Theme::RetroAmber, SyntaxTone::Keyword) => (255, 196, 64),
        (Theme::RetroAmber, SyntaxTone::String) => (204, 136, 0),
        (Theme::RetroAmber, SyntaxTone::Type) => (236, 164, 32),
        (Theme::RetroAmber, SyntaxTone::Tag) => (204, 68, 0),
        (Theme::RetroAmber, SyntaxTone::Property) => (232, 150, 0),
        (Theme::RetroAmber, SyntaxTone::Punctuation) => (148, 98, 0),
        (Theme::RetroAmber, SyntaxTone::Variable) => (220, 148, 0),
        (Theme::Moss, SyntaxTone::Comment) => (92, 118, 110),
        (Theme::Moss, SyntaxTone::Constant) => (130, 190, 184),
        (Theme::Moss, SyntaxTone::Function) => (138, 192, 156),
        (Theme::Moss, SyntaxTone::Keyword) => (110, 160, 204),
        (Theme::Moss, SyntaxTone::String) => (126, 178, 142),
        (Theme::Moss, SyntaxTone::Type) => (118, 188, 196),
        (Theme::Moss, SyntaxTone::Tag) => (108, 170, 180),
        (Theme::Moss, SyntaxTone::Property) => (146, 188, 170),
        (Theme::Moss, SyntaxTone::Punctuation) => (102, 132, 124),
        (Theme::Moss, SyntaxTone::Variable) => (190, 214, 202),
    }
}

#[derive(Clone, Copy)]
struct SemanticRange {
    start: usize,
    end: usize,
    tone: SyntaxTone,
}

impl SemanticRange {
    fn new(node: Node<'_>, tone: SyntaxTone) -> Self {
        Self {
            start: node.start_byte(),
            end: node.end_byte(),
            tone,
        }
    }
}

#[derive(Clone, Copy)]
enum SyntaxTone {
    Comment,
    Constant,
    Function,
    Keyword,
    String,
    Type,
    Tag,
    Property,
    Punctuation,
    Variable,
}
