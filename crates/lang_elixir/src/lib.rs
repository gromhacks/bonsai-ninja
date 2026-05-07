//! Elixir language adapter.
//!
//! Elixir's `def` and `defp` are macros, not keywords — tree-sitter-elixir
//! parses them as `call` nodes whose target is the identifier `def` or
//! `defp`. We use `call` as the function-kind and filter by the target
//! identifier in the grammar handler. Constructs with `do ... end`
//! blocks (function bodies, branches, loops) all share the `do_block`
//! grammar kind.
use bonsai_common::FileId;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    with_fn_kinds, AdapterContext, AdapterError, DeclIndex, GrammarHandler, ImportIndex, ImportScope,
    ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, Visibility,
};
use tree_sitter::{Language, Node, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("elixir");
const PACK_NAME: &str = "elixir";
// Elixir has no direct `function_definition` grammar node. Function
// definitions come through as `call` nodes with target `def` / `defp`.
// Accepting `call` as the fn-kind means the adapter treats every call
// as a potential function body; the walker then finds the actual name
// from the child identifier. This over-captures (macro calls that aren't
// definitions also match), but that's the cost of Elixir's macro-based
// syntax — precision upgrades would require a hand-rolled handler
// filtering by target.
const HANDLER: GrammarHandler = GrammarHandler {
    assignment_kinds: &["binary_operator"],
    ..with_fn_kinds(&["call"])
};

#[derive(Debug, Default, Copy, Clone)]
pub struct ElixirAdapter;

impl ElixirAdapter {
    /// Construct a stateless Elixir adapter handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for ElixirAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Elixir"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        &["ex", "exs"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities::partial_baseline()
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut decl_index = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        // Elixir privacy: `defp` is module-private, `def` is public.
        // Both lower to `call` nodes whose target identifier names
        // the macro. Walk for `defp` call spans, then mark matching
        // decls private.
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let module_spans = collect_elixir_module_spans(&tree, snapshot.text.as_bytes(), file);
            if module_spans.is_empty() {
                bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
            } else {
                apply_elixir_module_identity(&mut decl_index, &module_spans);
            }
            let private_spans = collect_elixir_defp_spans(&tree, snapshot.text.as_bytes());
            for decl in &mut decl_index.defs {
                let body_start = decl.body_span.map(|s| s.start).unwrap_or(decl.span.start);
                let body_end = decl.body_span.map(|s| s.end).unwrap_or(decl.span.end);
                // Match either by exact body-span anchor, or by an
                // enclosing span that aligns with the decl's start —
                // the walker may have anchored to either depending on
                // whether a `do` block was seen.
                if private_spans.iter().any(|(defp_start, defp_end)| {
                    *defp_start == body_start
                        || (*defp_start >= body_start
                            && *defp_end <= body_end
                            && *defp_start == decl.span.start)
                }) {
                    decl.visibility = Visibility::Module;
                }
            }
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut decl_index, ctx);
        }
        // Recognised Elixir lifecycle transitions. Elixir's
        // tree-sitter call names land as bare atoms (e.g.
        // `:gen_server.stop` reads as `:gen_server.stop`); the
        // matcher's call-name comparison strips the leading colon
        // when the rule key omits it. Bare `close`/`cancel` cover
        // ad-hoc resource APIs that follow the same convention.
        const ELIXIR_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: ":gen_server.stop",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: ":ets.delete",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "Process.exit",
                transition: "cancelled",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        for decl in &mut decl_index.defs {
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, ELIXIR_LIFECYCLE_TRANSITIONS);
        }
        decl_index
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

#[derive(Clone, Debug)]
struct ElixirModuleSpan {
    span: bonsai_common::Span,
    module: String,
}

fn collect_elixir_module_spans(tree: &Tree, src: &[u8], file: FileId) -> Vec<ElixirModuleSpan> {
    let mut raw = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        if call_target_text(&call_node, src).as_deref() != Some("defmodule") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        let mut args_cursor = args_node.walk();
        let Some(module_node) = args_node
            .named_children(&mut args_cursor)
            .find(|child| child.kind() == "alias")
        else {
            continue;
        };
        let module = node_text(&module_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        raw.push((span_of(file, &call_node), module));
    }

    raw.sort_by_key(|(span, _)| (span.start, std::cmp::Reverse(span.end)));
    let mut resolved = Vec::new();
    for (idx, (span, module)) in raw.iter().enumerate() {
        let parent = raw
            .iter()
            .enumerate()
            .filter(|(parent_idx, (parent_span, _))| {
                *parent_idx != idx
                    && parent_span.start <= span.start
                    && parent_span.end >= span.end
                    && (parent_span.start, parent_span.end) != (span.start, span.end)
            })
            .min_by_key(|(_, (parent_span, _))| parent_span.end.saturating_sub(parent_span.start))
            .and_then(|(parent_idx, _)| resolved_module_for_raw_index(parent_idx, &raw, &resolved));
        let full_module = if module.contains('.') {
            module.clone()
        } else if let Some(parent) = parent {
            format!("{parent}.{module}")
        } else {
            module.clone()
        };
        resolved.push(ElixirModuleSpan {
            span: *span,
            module: full_module,
        });
    }
    resolved
}

fn resolved_module_for_raw_index(
    raw_idx: usize,
    raw: &[(bonsai_common::Span, String)],
    resolved: &[ElixirModuleSpan],
) -> Option<String> {
    let (span, module) = raw.get(raw_idx)?;
    resolved
        .iter()
        .find(|entry| entry.span.start == span.start && entry.span.end == span.end)
        .map(|entry| entry.module.clone())
        .or_else(|| module.contains('.').then(|| module.clone()))
}

fn apply_elixir_module_identity(idx: &mut DeclIndex, modules: &[ElixirModuleSpan]) {
    for decl in &mut idx.defs {
        let Some(module) = innermost_module_for_span(modules, decl.span) else {
            continue;
        };
        let segments: Vec<String> = module.split('.').map(str::to_string).collect();
        decl.module_path = ModulePath::from_segments(segments);
        decl.qualified_name = Some(format!("{module}.{}", decl.name));
    }
}

fn innermost_module_for_span(modules: &[ElixirModuleSpan], span: bonsai_common::Span) -> Option<&str> {
    modules
        .iter()
        .filter(|module| module.span.start <= span.start && module.span.end >= span.end)
        .min_by_key(|module| module.span.end.saturating_sub(module.span.start))
        .map(|module| module.module.as_str())
}

/// Extract `alias`, `import`, `require`, `use` directives from an Elixir
/// tree into the canonical `ImportSpec` shape.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // Elixir's `alias`, `import`, `require`, `use` are all macro calls —
    // `call` nodes whose target is the corresponding identifier and whose
    // first argument is the module alias. `alias MyApp.Foo, as: F` adds
    // the alias-rename via a keywords-pair child.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(target_node) = call_node.child_by_field_name("target") else {
            continue;
        };
        let target_text = node_text(&target_node, src);
        // Filter to the four directive macros — every other call slips
        // through unchanged.
        if !matches!(target_text, "alias" | "import" | "require" | "use") {
            continue;
        }
        let Some(args_node) = call_node
            .child_by_field_name("arguments")
            .or_else(|| first_named_child_of_kind(&call_node, "arguments"))
        else {
            continue;
        };
        // First positional arg must be an `alias` (Elixir's name for a
        // module identifier like `MyApp.Foo`). Anything else is unsupported
        // (e.g. `import :erlang_module` atom form).
        let mut args_cursor = args_node.walk();
        let mut named_args = args_node.named_children(&mut args_cursor);
        let module_node = match named_args.next() {
            Some(arg) if arg.kind() == "alias" => arg,
            _ => continue,
        };
        let module = node_text(&module_node, src).to_string();
        // `as: F` rename appears as a keyword list: `keywords > pair { key, value }`.
        let alias = first_named_child_of_kind(&args_node, "keywords")
            .and_then(|keywords| first_named_child_of_kind(&keywords, "pair"))
            .and_then(|pair| {
                let key_node = pair.child_by_field_name("key")?;
                let key_text = node_text(&key_node, src).trim().trim_end_matches(':');
                if key_text == "as" {
                    pair.child_by_field_name("value")
                        .map(|value_node| node_text(&value_node, src).to_string())
                } else {
                    None
                }
            });
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module,
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn call_target_text(call_node: &Node<'_>, src: &[u8]) -> Option<String> {
    call_node
        .child_by_field_name("target")
        .or_else(|| {
            let mut cursor = call_node.walk();
            let first = call_node.named_children(&mut cursor).next();
            first
        })
        .map(|target| node_text(&target, src).trim().to_string())
}

/// Find every `defp` call site in the tree and return its byte span.
/// Adapter uses these to mark matching decls as Visibility::Module
/// (Elixir's module-private visibility).
fn collect_elixir_defp_spans(tree: &tree_sitter::Tree, src: &[u8]) -> Vec<(u64, u64)> {
    let mut defp_spans = Vec::new();
    for call_node in collect_kinds(tree, &["call"]) {
        let field_target = call_node.child_by_field_name("target");
        // Prefer the `target:` field; older grammar revisions don't expose
        // it, so fall back to the first named child.
        let target_node = match field_target {
            Some(target) => target,
            None => {
                let mut call_cursor = call_node.walk();
                let first_named = call_node.named_children(&mut call_cursor).next();
                match first_named {
                    Some(first_child) => first_child,
                    None => continue,
                }
            }
        };
        let target_text = node_text(&target_node, src).trim();
        if target_text == "defp" {
            defp_spans.push((
                u64::try_from(call_node.start_byte()).unwrap_or(u64::MAX),
                u64::try_from(call_node.end_byte()).unwrap_or(u64::MAX),
            ));
        }
    }
    defp_spans
}
