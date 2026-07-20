//! Ruby language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::kit::with_fn_kinds_and_implicit_receivers;
use bonsai_lang_api::{
    decl_index_with_handler, extract_imports_via,
    kit::{collect_kinds, first_named_child_of_kind, language_from_pack, node_text, parse_with, span_of},
    AdapterContext, AdapterError, CallArg, CallKind, DeclIndex, DeclKind, FlowEvent, GrammarHandler,
    ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities, LanguageId, ModulePath, Ref,
    RefKind, SyntaxSpecialForm,
};
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("ruby");
const PACK_NAME: &str = "ruby";
const BASE_HANDLER: GrammarHandler =
    with_fn_kinds_and_implicit_receivers(&["method", "singleton_method"], &["self", "super"], &["@"]);
const HANDLER: GrammarHandler = GrammarHandler {
    // Ruby methods return their final expression when there is no
    // explicit `return`. Surface that terminal expression as a normal
    // Return event so the shared semantic taint summaries can model
    // wrapper methods such as `def wrap(data); new(data); end`.
    constructor_names: &["initialize", "new"],
    tail_expression_returns: true,
    void_return_type_names: &[],
    // tree-sitter-ruby parses `buf += data`, `x ||= y`, `arr <<= e`
    // as `operator_assignment`, which is absent from the generic
    // assignment_kinds list (audit H24). Without it `is_assignment`
    // never matches and no Assign{target, source} is emitted, so the
    // RHS taint never binds to the target. `is_assignment` ORs with
    // GENERIC_HANDLER.assignment_kinds, so the plain `x = y`
    // (`assignment`) kind still matches via that fallback; the
    // compound arm in the kit then re-adds the LHS as a source
    // operand (read-modify-write).
    assignment_kinds: &["operator_assignment"],
    special_forms: &[SyntaxSpecialForm::BlockLoopCall],
    ..BASE_HANDLER
};

#[derive(Debug, Default, Copy, Clone)]
pub struct RubyAdapter;

impl RubyAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for RubyAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "Ruby"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.erb` (HTML/Ruby template blend) and `.rhtml` (legacy
        // Rails) are claimed alongside `.rb`. tree-sitter-ruby cannot
        // parse the HTML wrapper as Ruby — extract_declarations
        // pre-processes ERB files to mask HTML with whitespace
        // (preserving line numbers) and expose only the embedded
        // `<%= expr %>` / `<% stmt %>` Ruby blocks to the parser.
        &["rb", "erb", "rhtml"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities {
            constructor_method_names: &["initialize", "new"],
            super_receiver_tokens: &["super"],
            implicit_receiver_tokens: &["self"],
            workspace_manifest_context_extensions: &["erb", "rhtml", "haml", "slim"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        // Pure Ruby files take the standard pipeline.
        let path = ctx.vfs.path(file).ok();
        let is_erb = path
            .as_ref()
            .and_then(|p| p.extension())
            .is_some_and(|ext| ext == "erb" || ext == "rhtml");
        if !is_erb {
            let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
            if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
                idx.refs.extend(extract_ruby_static_element_key_refs(
                    &tree,
                    snapshot.text.as_bytes(),
                    file,
                ));
                // Apply Ruby's scope-marker visibility: `private`,
                // `protected`, `public` keywords inside a class body
                // change the default visibility of subsequent method
                // definitions. See `apply_ruby_scope_visibility` for
                // the exact contract this implements.
                apply_ruby_scope_visibility(&mut idx, &tree, snapshot.text.as_bytes(), file);
                for decl in &mut idx.defs {
                    inject_ruby_raise_throw_events(&mut decl.flow_events);
                    inject_ruby_super_call_events(&mut decl.flow_events, &decl.name);
                    normalize_ruby_subshell_events(&mut decl.flow_events, snapshot.text.as_bytes());
                    normalize_ruby_instance_variable_events(decl);
                }
            }
            // Per-class `bases`: `class Echo < Base` → ["Base"].
            // Ruby has only single-inheritance; mixins via `include`
            // are call statements (handled by the matcher's existing
            // include path), not parent-clauses.
            let mut block_param_names = std::collections::BTreeSet::new();
            if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
                let src = snapshot.text.as_bytes();
                block_param_names = collect_ruby_block_param_names(&tree, src);
                let bases_by_span = collect_ruby_class_bases(&tree, file, src);
                for decl in &mut idx.defs {
                    if !is_class_like(decl.kind) {
                        continue;
                    }
                    if let Some(bases) = bases_by_span.iter().find_map(|(span, name, bases)| {
                        (*span == decl.span || name == &decl.name).then_some(bases)
                    }) {
                        decl.bases = bases.clone();
                    }
                }
                inject_ruby_hash_field_assigns(&mut idx, &tree, file, src);
                inject_ruby_bare_method_arg_calls(&mut idx, &tree, file, src);
            }
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
            apply_ruby_class_semantic_identity(&mut idx);
            // Recognised Ruby lifecycle transitions. Method-style
            // `close` for files / sockets, `unlink` / `dispose` for
            // freed resources, `cancel` for async work.
            const RUBY_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
                bonsai_lang_api::LifecycleTransition {
                    call_match: "close",
                    transition: "closed",
                    arg_index: 0,
                },
                bonsai_lang_api::LifecycleTransition {
                    call_match: "unlink",
                    transition: "freed",
                    arg_index: 0,
                },
                bonsai_lang_api::LifecycleTransition {
                    call_match: "dispose",
                    transition: "freed",
                    arg_index: 0,
                },
                bonsai_lang_api::LifecycleTransition {
                    call_match: "cancel",
                    transition: "cancelled",
                    arg_index: 0,
                },
            ];
            for decl in &mut idx.defs {
                // Paren-less method calls in value position (`cmd =
                // get_input`, `v = gets`) parse as bare identifier
                // reads; promote the ones that name a method (not a
                // local or block variable) into the call-result shape so
                // taint crosses the call edge. Runs before the call-result
                // normalizer so the promoted assign is normalized too.
                rewrite_ruby_bareword_call_result_assigns(decl, &block_param_names);
                // Same promotion for tail position: `def get_input; gets;
                // end` is a call to `gets`, not an identifier read.
                inject_ruby_bare_tail_return_calls(decl, &block_param_names);
                bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
                bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, RUBY_LIFECYCLE_TRANSITIONS);
            }
            // Lift `@field = ParamType` writes captured during decl
            // collection into per-method `type_aliases`, so the
            // resolver's `type_alias_for_receiver(method, "self.field")`
            // returns the constructor-supplied type without re-walking
            // sibling decls per call site.
            // Local constructor-result receiver typing (`c = Foo.new` →
            // `c: Foo`) so `c.method(...)` carries a resolved receiver
            // type for `receiver_type_in` / `[Type, method]` rules. Ruby
            // class names are CamelCase and the constructor is the `.new`
            // method, which `constructor_call_type_name` resolves to the
            // class qualifier.
            bonsai_lang_api::apply_constructor_result_type_aliases(&mut idx);
            bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
            return idx;
        }
        // ERB files: pre-process the source so the HTML wrapper
        // becomes whitespace and only `<%= expr %>` / `<% stmt %>`
        // Ruby code remains, then run the standard pipeline against
        // the synthetic source. Whitespace masking preserves line
        // numbers so diagnostics stay accurate.
        let Some(snapshot) = ctx.vfs.snapshot(file).ok() else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let processed = preprocess_erb(&snapshot.text);
        // Parse the processed source manually with tree-sitter-ruby.
        let Ok(lang) = language_from_pack(PACK_NAME) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&lang).is_err() {
            return DeclIndex {
                file,
                ..Default::default()
            };
        }
        let Some(tree) = parser.parse(&processed, None) else {
            return DeclIndex {
                file,
                ..Default::default()
            };
        };
        // Build a DeclIndex by hand over the pre-processed source.
        // ERB expressions are module-scope Ruby snippets, so wrap
        // actionable flow events in a synthetic `__module__` decl.
        // That preserves rule constraints that depend on call args
        // (`raw @value`) instead of falling back to arg-less refs.
        let src = processed.as_bytes();
        let root = tree.root_node();
        let mut root_events = bonsai_lang_api::kit::walk_flow_events(root, file, src, &HANDLER, &[]);
        inject_ruby_raise_throw_events(&mut root_events);
        normalize_ruby_subshell_events(&mut root_events, src);
        let has_actionable_event = root_events.iter().any(|event| {
            matches!(
                event,
                bonsai_lang_api::FlowEvent::Call { .. }
                    | bonsai_lang_api::FlowEvent::Assign { .. }
                    | bonsai_lang_api::FlowEvent::Yield { .. }
                    | bonsai_lang_api::FlowEvent::Await { .. }
            )
        });
        // Recognised Ruby lifecycle transitions. Same set used for
        // pure-Ruby files; applied to ERB module-level decls below.
        const RUBY_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
            bonsai_lang_api::LifecycleTransition {
                call_match: "close",
                transition: "closed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "unlink",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "dispose",
                transition: "freed",
                arg_index: 0,
            },
            bonsai_lang_api::LifecycleTransition {
                call_match: "cancel",
                transition: "cancelled",
                arg_index: 0,
            },
        ];
        let mut defs = if has_actionable_event {
            let module_span = span_of(file, &root);
            // Synthesized container for ERB module-level code (the
            // body of `<% %>` / `<%= %>` blocks). Module-level Ruby
            // code is implicitly public — the template renderer
            // executes it when the file is processed. Marking the
            // container `Public` means the resolver's visibility
            // filter doesn't accidentally hide its FlowEvents when
            // a future caller reaches in by name.
            vec![bonsai_lang_api::Decl {
                symbol: bonsai_common::SymbolId::new(0),
                kind: bonsai_lang_api::DeclKind::Function,
                name: "__module__".to_string(),
                qualified_name: None,
                module_path: bonsai_lang_api::ModulePath::default(),
                span: module_span,
                name_span: module_span,
                visibility: bonsai_lang_api::Visibility::Public,
                parent: None,
                body_span: Some(module_span),
                flow_events: root_events,
                has_implicit_returns: true,
                params: Vec::new(),
                param_annotations: Vec::new(),
                type_aliases: Vec::new(),
                bases: Vec::new(),
                receiver_param_index: None,
                receiver_field_writes: Vec::new(),
                implicit_receiver_names: Vec::new(),
                receiver_state_sources: Vec::new(),
                return_type: None,
                is_variadic: false,
            }]
        } else {
            Vec::new()
        };
        let block_param_names = collect_ruby_block_param_names(&tree, src);
        for decl in &mut defs {
            rewrite_ruby_bareword_call_result_assigns(decl, &block_param_names);
            inject_ruby_bare_tail_return_calls(decl, &block_param_names);
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, RUBY_LIFECYCLE_TRANSITIONS);
        }
        let mut refs = bonsai_lang_api::kit::extract_call_refs(&tree, file, src);
        refs.extend(bonsai_lang_api::kit::extract_decorators(&tree, file, src));
        refs.extend(bonsai_lang_api::kit::extract_read_write_refs(&tree, file, src));
        refs.extend(extract_ruby_static_element_key_refs(&tree, src, file));
        let strings = bonsai_lang_api::kit::extract_string_literals(&tree, file, src);
        let comments = bonsai_lang_api::kit::extract_comments(&tree, file, src);
        let assignment_values =
            bonsai_lang_api::kit::extract_assignment_value_facts(&tree, file, &HANDLER, src);
        let call_receivers = bonsai_lang_api::kit::extract_call_receiver_facts(&tree, file, &HANDLER, src);
        let runtime_type_narrowings =
            bonsai_lang_api::kit::extract_runtime_type_narrowing_facts(&tree, file, &HANDLER, src);
        let branch_conditions =
            bonsai_lang_api::kit::extract_branch_condition_facts(&tree, file, &HANDLER, src);
        DeclIndex {
            file,
            defs,
            refs,
            assignment_values,
            call_receivers,
            runtime_type_narrowings,
            branch_conditions,
            aggregate_layouts: Vec::new(),
            strings,
            comments,
        }
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

fn inject_ruby_raise_throw_events(events: &mut Vec<FlowEvent>) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_ruby_raise_throw_events(then_events);
                inject_ruby_raise_throw_events(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_ruby_raise_throw_events(body);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_ruby_raise_throw_events(body);
                inject_ruby_raise_throw_events(catch_events);
                inject_ruby_raise_throw_events(finally_events);
            }
            _ => {}
        }
    }

    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        let synthetic_throw = ruby_raise_throw_event(&event);
        rewritten.push(event);
        if let Some(throw_event) = synthetic_throw {
            rewritten.push(throw_event);
        }
    }
    *events = rewritten;
}

fn inject_ruby_super_call_events(events: &mut Vec<FlowEvent>, method_name: &str) {
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                inject_ruby_super_call_events(then_events, method_name);
                inject_ruby_super_call_events(else_events, method_name);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                inject_ruby_super_call_events(body, method_name);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                inject_ruby_super_call_events(body, method_name);
                inject_ruby_super_call_events(catch_events, method_name);
                inject_ruby_super_call_events(finally_events, method_name);
            }
            _ => {}
        }
    }

    if method_name.trim().is_empty() {
        return;
    }
    let mut rewritten = Vec::with_capacity(events.len());
    for event in events.drain(..) {
        if ruby_return_is_bare_super(&event) {
            let span = match &event {
                FlowEvent::Return { span, .. } => *span,
                _ => unreachable!("guarded by ruby_return_is_bare_super"),
            };
            rewritten.push(FlowEvent::Call {
                span,
                name: format!("super.{method_name}"),
                receiver: Some("super".to_string()),
                receiver_types: Vec::new(),
                call_kind: CallKind::Method,
                args: Vec::new(),
            });
        }
        rewritten.push(event);
    }
    *events = rewritten;
}

fn ruby_return_is_bare_super(event: &FlowEvent) -> bool {
    let FlowEvent::Return { value_flow, .. } = event else {
        return false;
    };
    value_flow.place.as_deref() == Some("super")
}

fn ruby_raise_throw_event(event: &FlowEvent) -> Option<FlowEvent> {
    let FlowEvent::Call { name, args, span, .. } = event else {
        return None;
    };
    if name != "raise" {
        return None;
    }
    // `raise ExceptionClass, message` (M17): arg0 is the exception
    // class, so the thrown *value* is the message in arg1. Recognize
    // the class form by a Capitalized constant or `Foo::Bar` scope.
    let thrown_arg = match args.first() {
        Some(first) if args.len() >= 2 && ruby_is_exception_class(&first.value_text) => args.get(1),
        other => other,
    };
    // value_name is contractually a bare identifier (M18): take it
    // only from `place`, leaving compound throws such as
    // `StandardError.new(msg)` as None so the engine routes them
    // through its conservative inter-procedural branch.
    Some(FlowEvent::Throw {
        span: *span,
        value_name: thrown_arg.and_then(|arg| arg.place.clone()),
        thrown_type: None,
    })
}

/// True when an argument's text names a Ruby exception class -- a
/// Capitalized constant (`ArgumentError`) or a scope-resolved constant
/// (`Net::HTTPError`). Used to detect the two-argument
/// `raise ExceptionClass, message` form (audit M17).
fn ruby_is_exception_class(text: &str) -> bool {
    let head = text.trim().rsplit("::").next().unwrap_or("").trim();
    head.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn normalize_ruby_subshell_events(events: &mut [FlowEvent], src: &[u8]) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                args,
                span,
                call_kind,
                ..
            } if name == "`" => {
                let source_names = ruby_subshell_arg_source_names(args);
                let value_text = ruby_span_text(src, *span)
                    .filter(|text| !text.trim().is_empty())
                    .map(|text| text.trim().to_string())
                    .unwrap_or_else(|| {
                        args.iter()
                            .map(|arg| arg.value_text.trim())
                            .filter(|text| !text.is_empty())
                            .collect::<Vec<_>>()
                            .join(" ")
                    });
                *call_kind = CallKind::Function;
                *args = vec![CallArg {
                    passing_mode: Default::default(),
                    span: *span,
                    name: None,
                    value_text,
                    place: None,
                    source_names,
                }];
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                normalize_ruby_subshell_events(then_events, src);
                normalize_ruby_subshell_events(else_events, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_ruby_subshell_events(body, src);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                normalize_ruby_subshell_events(body, src);
                normalize_ruby_subshell_events(catch_events, src);
                normalize_ruby_subshell_events(finally_events, src);
            }
            _ => {}
        }
    }
}

fn ruby_subshell_arg_source_names(args: &[CallArg]) -> Vec<String> {
    let mut source_names = Vec::new();
    for arg in args {
        for name in &arg.source_names {
            if name.is_empty() || source_names.iter().any(|seen| seen == name) {
                continue;
            }
            source_names.push(name.clone());
        }
    }
    source_names
}

fn normalize_ruby_instance_variable_events(decl: &mut bonsai_lang_api::Decl) {
    for write in &mut decl.receiver_field_writes {
        write.target = normalize_ruby_instance_variable_text(&write.target);
    }
    for source in &mut decl.receiver_state_sources {
        *source = normalize_ruby_instance_variable_text(source);
    }
    normalize_ruby_instance_variable_flow_events(&mut decl.flow_events);
}

fn normalize_ruby_instance_variable_flow_events(events: &mut [FlowEvent]) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                *target = normalize_ruby_instance_variable_text(target);
                normalize_optional_ruby_instance_variable_text(source_name);
                normalize_optional_ruby_instance_variable_text(source_call);
                normalize_ruby_instance_variable_texts(source_call_args);
                normalize_ruby_instance_variable_texts(source_names);
            }
            FlowEvent::AggregateAssign {
                target, value_flow, ..
            } => {
                *target = normalize_ruby_instance_variable_text(target);
                normalize_ruby_instance_variable_expression_flow(value_flow);
            }
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                *name = normalize_ruby_instance_variable_text(name);
                normalize_optional_ruby_instance_variable_text(receiver);
                for arg in args {
                    arg.value_text = normalize_ruby_instance_variable_text(&arg.value_text);
                    normalize_optional_ruby_instance_variable_text(&mut arg.place);
                    normalize_ruby_instance_variable_texts(&mut arg.source_names);
                    enrich_ruby_instance_variable_call_arg(arg);
                }
            }
            FlowEvent::Return {
                value_name,
                value_text,
                value_flow,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(value_name);
                normalize_optional_ruby_instance_variable_text(value_text);
                normalize_ruby_instance_variable_expression_flow(value_flow);
            }
            FlowEvent::Throw { value_name, .. } => {
                normalize_optional_ruby_instance_variable_text(value_name);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(catch_param);
                normalize_ruby_instance_variable_flow_events(body);
                normalize_ruby_instance_variable_flow_events(catch_events);
                normalize_ruby_instance_variable_flow_events(finally_events);
            }
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(condition);
                normalize_ruby_instance_variable_flow_events(then_events);
                normalize_ruby_instance_variable_flow_events(else_events);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                normalize_ruby_instance_variable_flow_events(body);
            }
            FlowEvent::Yield {
                value_text,
                value_flow,
                ..
            } => {
                normalize_optional_ruby_instance_variable_text(value_text);
                normalize_ruby_instance_variable_expression_flow(value_flow);
            }
            FlowEvent::Await { value_name, .. } => {
                normalize_optional_ruby_instance_variable_text(value_name);
            }
            FlowEvent::Lifecycle { name, .. } => {
                *name = normalize_ruby_instance_variable_text(name);
            }
            FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {}
        }
    }
}

fn normalize_ruby_instance_variable_expression_flow(flow: &mut bonsai_lang_api::ExpressionFlow) {
    normalize_optional_ruby_instance_variable_text(&mut flow.place);
    normalize_ruby_instance_variable_texts(&mut flow.source_names);
    if let Some(projection) = &mut flow.projection {
        projection.base = normalize_ruby_instance_variable_text(&projection.base);
        normalize_ruby_instance_variable_texts(&mut projection.path);
    }
    for field in &mut flow.aggregate_fields {
        field.name = normalize_ruby_instance_variable_text(&field.name);
        normalize_ruby_instance_variable_expression_flow(&mut field.value);
    }
    for item in &mut flow.tuple_items {
        normalize_ruby_instance_variable_expression_flow(item);
    }
    for spread in &mut flow.spreads {
        normalize_ruby_instance_variable_expression_flow(spread);
    }
}

fn normalize_optional_ruby_instance_variable_text(value: &mut Option<String>) {
    if let Some(text) = value {
        *text = normalize_ruby_instance_variable_text(text);
    }
}

fn normalize_ruby_instance_variable_texts(values: &mut [String]) {
    for value in values {
        *value = normalize_ruby_instance_variable_text(value);
    }
}

fn enrich_ruby_instance_variable_call_arg(arg: &mut CallArg) {
    let Some(place) = ruby_normalized_instance_variable_place(&arg.value_text) else {
        return;
    };
    if arg.place.as_deref().is_none_or(str::is_empty) {
        arg.place = Some(place.clone());
    }
    if !arg.source_names.iter().any(|source| source == &place) {
        arg.source_names.push(place);
        arg.source_names.sort();
        arg.source_names.dedup();
    }
}

fn ruby_normalized_instance_variable_place(text: &str) -> Option<String> {
    let text = text.trim();
    let rest = text.strip_prefix("self.")?;
    if rest.is_empty() {
        return None;
    }
    if rest.split('.').all(ruby_identifier_part) {
        Some(text.to_string())
    } else {
        None
    }
}

fn ruby_identifier_part(part: &str) -> bool {
    let mut chars = part.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn normalize_ruby_instance_variable_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if let Some(active_quote) = quote {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }

        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            out.push(ch);
            continue;
        }

        if ch != '@' {
            out.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('@') => out.push(ch),
            Some(next) if next == '_' || next.is_ascii_alphabetic() => {
                out.push_str("self.");
                while let Some(part) = chars.peek().copied() {
                    if part == '_' || part.is_ascii_alphanumeric() {
                        out.push(part);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn inject_ruby_hash_field_assigns(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut synthesized = Vec::new();
    for assignment in collect_kinds(tree, &["assignment"]) {
        let (Some(left), Some(right)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        let target = normalize_ruby_instance_variable_text(node_text(&left, src).trim());
        if target.is_empty() || !ruby_field_target_base_is_supported(&target) {
            continue;
        }
        collect_ruby_hash_field_assigns_for_target(&target, right, file, src, &mut synthesized);
    }
    if synthesized.is_empty() {
        return;
    }

    for event in synthesized {
        let span = event.span();
        let Some(decl) = idx
            .defs
            .iter_mut()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl_span_contains(decl, span)
            })
            .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        else {
            continue;
        };
        if !decl.flow_events.iter().any(|existing| existing == &event) {
            decl.flow_events.push(event);
            decl.flow_events
                .sort_by_key(|event| (event.span().start, event.span().end));
        }
    }
}

fn ruby_field_target_base_is_supported(target: &str) -> bool {
    target
        .split('.')
        .all(|part| !part.is_empty() && part.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()))
}

fn decl_span_contains(decl: &bonsai_lang_api::Decl, span: Span) -> bool {
    let container = decl.body_span.unwrap_or(decl.span);
    container.file == span.file && container.start <= span.start && span.end <= container.end
}

fn collect_ruby_hash_field_assigns_for_target(
    target: &str,
    node: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    if node.kind() == "hash" {
        collect_ruby_hash_pair_assigns(target, node, file, src, out);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ruby_hash_field_assigns_for_target(target, child, file, src, out);
    }
}

fn collect_ruby_hash_pair_assigns(
    target: &str,
    hash: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
    out: &mut Vec<FlowEvent>,
) {
    let mut cursor = hash.walk();
    for child in hash.named_children(&mut cursor) {
        if child.kind() != "pair" {
            continue;
        }
        let Some(key) = child
            .child_by_field_name("key")
            .and_then(|key| ruby_hash_key_name(key, src))
        else {
            continue;
        };
        let Some(value) = child.child_by_field_name("value") else {
            continue;
        };
        let mut source_names = ruby_value_source_names(value, src);
        if source_names.is_empty() {
            continue;
        }
        source_names.sort();
        source_names.dedup();
        out.push(FlowEvent::Assign {
            span: span_of(file, &child),
            target: format!("{target}.{key}"),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names,
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
        });
    }
}

fn ruby_hash_key_name(key: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let raw = node_text(&key, src)
        .trim()
        .trim_start_matches(':')
        .trim_matches('"')
        .trim_matches('\'')
        .trim();
    if raw.is_empty() || !raw.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(raw.to_string())
}

fn ruby_value_source_names(node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    collect_ruby_value_source_names(node, src, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_ruby_value_source_names(node: tree_sitter::Node<'_>, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "identifier" | "constant" | "self" => {
            push_ruby_source_name(out, node_text(&node, src));
        }
        "instance_variable" => {
            push_ruby_source_name(out, &normalize_ruby_instance_variable_text(node_text(&node, src)));
        }
        "call" => {
            push_ruby_source_name(
                out,
                &normalize_ruby_instance_variable_text(node_text(&node, src).trim()),
            );
            if let Some(receiver) = node.child_by_field_name("receiver") {
                collect_ruby_value_source_names(receiver, src, out);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "arguments" {
                    collect_ruby_value_source_names(child, src, out);
                }
            }
            return;
        }
        "element_reference" => {
            if let Some(access) = ruby_element_reference_name(node, src) {
                push_ruby_source_name(out, &access);
            }
        }
        "hash_key_symbol" | "simple_symbol" | "integer" | "float" | "string_content" => {}
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ruby_value_source_names(child, src, out);
    }
}

fn ruby_element_reference_name(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let object = node
        .child_by_field_name("object")
        .map(|object| normalize_ruby_instance_variable_text(node_text(&object, src).trim()))?;
    let mut cursor = node.walk();
    let key = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "simple_symbol" || child.kind() == "string")
        .and_then(|key| ruby_hash_key_name(key, src))?;
    (!object.is_empty()).then(|| format!("{object}.{key}"))
}

fn push_ruby_source_name(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with(':')
        || value.starts_with('"')
        || value.starts_with('\'')
        || value.chars().all(|ch| ch.is_ascii_digit())
    {
        return;
    }
    if !out.iter().any(|existing| existing == value) {
        out.push(value.to_string());
    }
}

fn inject_ruby_bare_method_arg_calls(idx: &mut DeclIndex, tree: &Tree, file: FileId, src: &[u8]) {
    let mut candidates = Vec::new();
    for call in collect_kinds(tree, &["call"]) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        for arg in arguments.named_children(&mut cursor) {
            if arg.kind() != "identifier" {
                continue;
            }
            let name = node_text(&arg, src).trim();
            if !ruby_bare_method_candidate(name) {
                continue;
            }
            candidates.push((span_of(file, &arg), name.to_string()));
        }
    }
    if candidates.is_empty() {
        return;
    }

    for (span, name) in candidates {
        let Some(decl) = idx
            .defs
            .iter_mut()
            .filter(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && decl_span_contains(decl, span)
            })
            .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
        else {
            continue;
        };
        let locals = ruby_local_bindings_for_decl(decl);
        if locals.contains(name.as_str()) {
            continue;
        }
        let event = FlowEvent::Call {
            span,
            name,
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        };
        if !decl.flow_events.iter().any(|existing| existing == &event) {
            decl.flow_events.push(event);
            decl.flow_events
                .sort_by_key(|event| (event.span().start, event.span().end));
        }
    }
}

fn ruby_bare_method_candidate(name: &str) -> bool {
    !name.is_empty()
        && !matches!(
            name,
            "nil" | "true" | "false" | "self" | "super" | "yield" | "return" | "break" | "next"
        )
        && name
            .chars()
            .all(|ch| ch == '_' || ch == '!' || ch == '?' || ch.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
}

fn ruby_local_bindings_for_decl(decl: &bonsai_lang_api::Decl) -> std::collections::BTreeSet<String> {
    let mut locals: std::collections::BTreeSet<String> = decl
        .params
        .iter()
        .filter_map(|param| ruby_bare_binding_name(param))
        .collect();
    collect_ruby_local_bindings(&decl.flow_events, &mut locals);
    locals
}

fn collect_ruby_local_bindings(events: &[FlowEvent], locals: &mut std::collections::BTreeSet<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => {
                if let Some(name) = ruby_bare_binding_name(target) {
                    locals.insert(name);
                }
            }
            FlowEvent::AggregateAssign { target, .. } => {
                if let Some(name) = ruby_bare_binding_name(target) {
                    locals.insert(name);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                if let Some(param) = catch_param.as_deref().and_then(ruby_bare_binding_name) {
                    locals.insert(param);
                }
                collect_ruby_local_bindings(body, locals);
                collect_ruby_local_bindings(catch_events, locals);
                collect_ruby_local_bindings(finally_events, locals);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_ruby_local_bindings(then_events, locals);
                collect_ruby_local_bindings(else_events, locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_ruby_local_bindings(body, locals);
            }
            FlowEvent::Call { .. }
            | FlowEvent::Return { .. }
            | FlowEvent::Throw { .. }
            | FlowEvent::Yield { .. }
            | FlowEvent::Await { .. }
            | FlowEvent::Lifecycle { .. }
            | FlowEvent::Break { .. }
            | FlowEvent::Continue { .. } => {}
        }
    }
}

fn ruby_bare_binding_name(value: &str) -> Option<String> {
    let name = value.trim();
    if name.is_empty() || name.contains('.') || name.contains('[') || name.starts_with('@') {
        return None;
    }
    ruby_bare_method_candidate(name).then(|| name.to_string())
}

/// Promote paren-less method calls that sit in an assignment's value
/// position into call-result assignments.
///
/// tree-sitter-ruby parses a receiver-less, argument-less method call
/// in value position (`cmd = get_input`, `v = gets`) as a bare
/// `identifier`, syntactically identical to a local-variable read. The
/// flow walker therefore emits `cmd = get_input` as a simple-rename
/// `Assign { source_name: Some("get_input"), value_kind: Compound }`
/// with no `Call` sibling — so the IDG stitches no call edge and the
/// callee's tainted return never reaches the target. The paren form
/// (`get_input()`) instead yields `Assign { source_call: "get_input",
/// value_kind: CallResult }` plus a sibling `Call`, which taints
/// correctly.
///
/// Ruby's own disambiguation rule (the same one its parser uses): a
/// bareword is a local-variable reference iff a local of that name is
/// bound in the enclosing scope; otherwise a receiver-less bareword
/// naming a method is a method call. We apply exactly that rule —
/// rewriting a simple-rename `Assign` into the call-result shape only
/// when the RHS bareword is NOT bound as a local/param anywhere in the
/// method — and emit the sibling arg-less `Call` so the paren-less
/// form produces the identical shape to the working paren form.
///
/// FP-safety: taint reaches the target via the pre-existing
/// simple-rename path only when the RHS names a *tainted local*, which
/// must have been bound earlier and is therefore excluded by the local
/// guard (locals/params always stay reads). When the bareword is never
/// bound in the method it can carry no variable-level taint today, so
/// the rewrite is purely additive: it can introduce the (correct)
/// callee-return edge but never remove a working one. An unresolved
/// callee yields no return summary, so the engine leaves the target
/// clean — the same behaviour the paren form already exhibits.
fn rewrite_ruby_bareword_call_result_assigns(
    decl: &mut bonsai_lang_api::Decl,
    block_param_names: &std::collections::BTreeSet<String>,
) {
    // Method-wide local set (params + every assignment target). Block and
    // lambda parameters (`each do |x|`, `->(x){}`) do NOT surface as Assign
    // targets — a block variable is bound by the loop, not written — so they
    // are folded in from `block_param_names` (collected from the tree by the
    // caller). Without this, a block variable that shares a method name
    // (`each do |line| ...`, with a `def line`) is wrongly promoted to a call
    // (a false positive). Collecting method-wide rather than
    // lexically-before-use is strictly conservative: it can only keep more
    // barewords as reads, never fewer.
    let mut locals = ruby_local_bindings_for_decl(decl);
    locals.extend(block_param_names.iter().cloned());
    rewrite_ruby_bareword_assigns_in_events(&mut decl.flow_events, &locals);
}

/// Paren-less method calls in TAIL position: `def get_input; gets; end`
/// parses the bare `gets` as an identifier, so the tail-return synthesis
/// records `Return { value_name: "gets" }` and NO Call event exists — the
/// source matcher never sees a `gets` call and the wrapper's taint is
/// silently lost. Mirror of [`inject_ruby_bare_method_arg_calls`] for the
/// return position: when a Return's value is a bare word that is not a
/// local, param, or block variable, it IS a method call under Ruby
/// semantics — synthesize the Call event at the tail span so matching and
/// the call-ret→Return stitch both see it.
fn inject_ruby_bare_tail_return_calls(
    decl: &mut bonsai_lang_api::Decl,
    block_param_names: &std::collections::BTreeSet<String>,
) {
    let mut locals = ruby_local_bindings_for_decl(decl);
    locals.extend(block_param_names.iter().cloned());
    let mut sites = Vec::new();
    collect_ruby_bare_tail_call_sites(&decl.flow_events, &locals, &mut sites);
    if sites.is_empty() {
        return;
    }
    let mut changed = false;
    for (span, name) in sites {
        let event = FlowEvent::Call {
            span,
            name,
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args: Vec::new(),
        };
        if !decl.flow_events.iter().any(|existing| existing == &event) {
            decl.flow_events.push(event);
            changed = true;
        }
    }
    if changed {
        decl.flow_events
            .sort_by_key(|event| (event.span().start, event.span().end));
    }
}

fn collect_ruby_bare_tail_call_sites(
    events: &[FlowEvent],
    locals: &std::collections::BTreeSet<String>,
    out: &mut Vec<(Span, String)>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_name: Some(name),
                value_flow,
                ..
            } => {
                // Only the exact bare-word shape: the whole return value
                // is the identifier itself. Compound returns
                // (`gets.chomp`, `a + b`) already carry real Call events
                // or operand reads.
                if value_flow.place.as_deref() == Some(name.as_str())
                    && ruby_bare_method_candidate(name)
                    && !locals.contains(name.as_str())
                {
                    out.push((*span, name.clone()));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_ruby_bare_tail_call_sites(then_events, locals, out);
                collect_ruby_bare_tail_call_sites(else_events, locals, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_ruby_bare_tail_call_sites(body, locals, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_ruby_bare_tail_call_sites(body, locals, out);
                collect_ruby_bare_tail_call_sites(catch_events, locals, out);
                collect_ruby_bare_tail_call_sites(finally_events, locals, out);
            }
            _ => {}
        }
    }
}

/// Names bound as block / lambda parameters anywhere in the file
/// (`xs.each do |item|`, `xs.map { |x| }`, `->(y){}`). These shadow method
/// names inside their block, so a value-position bareword naming one must
/// stay a variable read, never be promoted to a method call. Collected
/// file-wide (a conservative over-set) so the promotion never mistakes a
/// block variable for a paren-less call.
fn collect_ruby_block_param_names(tree: &Tree, src: &[u8]) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for params in collect_kinds(tree, &["block_parameters", "lambda_parameters"]) {
        collect_ruby_param_identifiers(params, src, &mut names);
    }
    names
}

fn collect_ruby_param_identifiers(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    out: &mut std::collections::BTreeSet<String>,
) {
    if node.kind() == "identifier" {
        if let Some(name) = ruby_bare_binding_name(node_text(&node, src).trim()) {
            out.insert(name);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_ruby_param_identifiers(child, src, out);
    }
}

fn rewrite_ruby_bareword_assigns_in_events(
    events: &mut Vec<FlowEvent>,
    locals: &std::collections::BTreeSet<String>,
) {
    // Recurse into nested regions with the same method-wide local set.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_ruby_bareword_assigns_in_events(then_events, locals);
                rewrite_ruby_bareword_assigns_in_events(else_events, locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_ruby_bareword_assigns_in_events(body, locals);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_ruby_bareword_assigns_in_events(body, locals);
                rewrite_ruby_bareword_assigns_in_events(catch_events, locals);
                rewrite_ruby_bareword_assigns_in_events(finally_events, locals);
            }
            _ => {}
        }
    }

    if !events
        .iter()
        .any(|event| ruby_bareword_call_result_name(event, locals).is_some())
    {
        return;
    }
    // Preserve source order and insert each synthetic arg-less Call
    // immediately after the promoted Assign, mirroring the paren form's
    // `Assign{CallResult}` + `Call` pairing. Order-preserving, so the
    // pass is deterministic.
    let mut rewritten = Vec::with_capacity(events.len() + 1);
    for event in events.drain(..) {
        match ruby_bareword_call_result_name(&event, locals) {
            Some(call_name) => {
                let span = event.span();
                rewritten.push(promote_ruby_bareword_assign_to_call_result(event, &call_name));
                rewritten.push(FlowEvent::Call {
                    span,
                    name: call_name,
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args: Vec::new(),
                });
            }
            None => rewritten.push(event),
        }
    }
    *events = rewritten;
}

/// If `event` is a simple-rename assignment (`target = bareword`) whose
/// RHS bareword names a method rather than a bound local, return the
/// method name. `None` for anything else — the guard that keeps locals,
/// params, literals, compound RHS, and already-a-call assigns as reads.
fn ruby_bareword_call_result_name(
    event: &FlowEvent,
    locals: &std::collections::BTreeSet<String>,
) -> Option<String> {
    let FlowEvent::Assign {
        source_name: Some(name),
        source_call: None,
        source_names,
        value_kind,
        ..
    } = event
    else {
        return None;
    };
    // Simple-name RHS only: `source_name` is contractually a single bare
    // identifier and `source_names` must carry nothing beyond it (a
    // compound RHS leaves `source_name` empty). Anything else is not a
    // bare paren-less-call candidate.
    if !source_names.iter().all(|carrier| carrier == name) {
        return None;
    }
    // Never reclassify a literal, an already-resolved call, or a yield
    // RHS. A bare identifier read is Compound / Unknown / unset.
    if matches!(
        value_kind,
        Some(
            bonsai_lang_api::AssignValueKind::Literal
                | bonsai_lang_api::AssignValueKind::CallResult
                | bonsai_lang_api::AssignValueKind::YieldResult
                | bonsai_lang_api::AssignValueKind::CallableReference
        )
    ) {
        return None;
    }
    // Ruby's rule: a bareword bound as a local/param is a variable read.
    if locals.contains(name.as_str()) {
        return None;
    }
    // The bareword must have the lexical shape of a Ruby method name.
    ruby_bare_method_candidate(name).then(|| name.clone())
}

/// Rewrite a qualifying simple-rename `Assign` into the call-result
/// shape: drop the read-style `source_name` / `source_names`, set
/// `source_call` to the callee, and mark the RHS `CallResult`.
fn promote_ruby_bareword_assign_to_call_result(event: FlowEvent, call_name: &str) -> FlowEvent {
    let FlowEvent::Assign {
        span,
        target,
        declares_new_binding,
        ..
    } = event
    else {
        return event;
    };
    FlowEvent::Assign {
        span,
        target,
        source_name: None,
        source_call: Some(call_name.to_string()),
        source_call_args: Vec::new(),
        source_names: Vec::new(),
        declares_new_binding,
        value_kind: Some(bonsai_lang_api::AssignValueKind::CallResult),
    }
}

fn ruby_span_text(src: &[u8], span: Span) -> Option<&str> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    let bytes = src.get(start..end)?;
    std::str::from_utf8(bytes).ok()
}

fn apply_ruby_class_semantic_identity(idx: &mut DeclIndex) {
    let mut classes: Vec<(Span, String, bonsai_common::SymbolId)> = idx
        .defs
        .iter()
        .filter(|decl| is_class_like(decl.kind))
        .map(|decl| (decl.span, decl.name.clone(), decl.symbol))
        .collect();
    classes.sort_by_key(|(span, _, _)| span.end.saturating_sub(span.start));
    if classes.is_empty() {
        return;
    }
    for decl in &mut idx.defs {
        if is_class_like(decl.kind) {
            let mut segments = decl.module_path.segments.clone();
            segments.push(decl.name.clone());
            decl.module_path = ModulePath::from_segments(segments.iter().cloned());
            decl.qualified_name = Some(segments.join("."));
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some((_, class_name, class_symbol)) = classes
            .iter()
            .filter(|(span, _, _)| span.start <= decl.span.start && span.end >= decl.span.end)
            .min_by_key(|(span, _, _)| span.end.saturating_sub(span.start))
        else {
            continue;
        };
        decl.parent = Some(*class_symbol);
        let mut segments = decl.module_path.segments.clone();
        segments.push(class_name.clone());
        decl.module_path = ModulePath::from_segments(segments.iter().cloned());
        decl.qualified_name = Some(format!("{}.{}", segments.join("."), decl.name));
    }
}

/// Apply Ruby's scope-marker visibility to method decls. Ruby's
/// `private` / `protected` / `public` keywords (used as bare
/// statements inside a class / module body) change the default
/// visibility of subsequent `def` definitions until another marker
/// flips the scope. The keyword form `private :foo, :bar` flips a
/// specific list of names rather than a scope.
///
/// Visibility comes from real syntax. The kit's modifier-vocabulary
/// path doesn't model line-scoped visibility, so this adapter walks
/// the parsed tree directly.
fn apply_ruby_scope_visibility(idx: &mut DeclIndex, tree: &Tree, src: &[u8], file: FileId) {
    // Map (start_byte, end_byte) of each method decl in the index to
    // the span we'll patch when we find the matching tree node.
    let mut visibility_overrides: std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility> =
        std::collections::HashMap::new();
    walk_class_bodies(
        tree.root_node(),
        src,
        file,
        bonsai_lang_api::Visibility::Public,
        &mut visibility_overrides,
    );
    for decl in &mut idx.defs {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        if let Some(visibility) = visibility_overrides.get(&(decl.span.start, decl.span.end)) {
            decl.visibility = *visibility;
        }
    }
}

/// Walk the tree, find each `class` / `module` / `singleton_class`,
/// and run the scope-tracking pass over its body. Each body resets to
/// `Public` — Ruby scope markers don't bleed between sibling classes.
fn walk_class_bodies(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    file: FileId,
    inherited_scope: bonsai_lang_api::Visibility,
    out: &mut std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility>,
) {
    // Ruby tree-sitter exposes class / module / singleton bodies as
    // `body_statement` children of `class` / `module` / `singleton_class`.
    // Inside those bodies we track the current scope marker.
    match node.kind() {
        "class" | "module" | "singleton_class" => {
            let mut scope = bonsai_lang_api::Visibility::Public;
            if let Some(body) = node.child_by_field_name("body") {
                walk_body_statements(body, src, file, &mut scope, out);
            } else {
                // Fall back to scanning all named children — ts-ruby
                // grammar uses `body_statement` as a named child.
                let mut child_cursor = node.walk();
                for child in node.named_children(&mut child_cursor) {
                    if child.kind() == "body_statement" {
                        walk_body_statements(child, src, file, &mut scope, out);
                    }
                }
            }
        }
        _ => {}
    }
    // Recurse: nested classes and modules need their own scope tracking.
    let mut child_cursor = node.walk();
    for child in node.named_children(&mut child_cursor) {
        walk_class_bodies(child, src, file, inherited_scope, out);
    }
}

/// Iterate one class / module body in source order, mutating
/// `current_scope` as scope markers appear and tagging each `def` /
/// `singleton_method` with the active scope. The scope is line-relative
/// — markers only affect defs that follow them inside the same body.
fn walk_body_statements(
    body: tree_sitter::Node<'_>,
    src: &[u8],
    file: FileId,
    current_scope: &mut bonsai_lang_api::Visibility,
    out: &mut std::collections::HashMap<(u64, u64), bonsai_lang_api::Visibility>,
) {
    let mut body_cursor = body.walk();
    for stmt in body.named_children(&mut body_cursor) {
        match stmt.kind() {
            // Bare scope marker: `private` / `protected` / `public` /
            // `module_function` alone on a line flips the default for
            // subsequent defs. tree-sitter-ruby parses arg-less calls
            // to those methods as bare identifiers, not `call` nodes.
            "identifier" => {
                let text = std::str::from_utf8(&src[stmt.byte_range()]).unwrap_or("");
                match text {
                    "private" => *current_scope = bonsai_lang_api::Visibility::Private,
                    "protected" => *current_scope = bonsai_lang_api::Visibility::Protected,
                    "public" => *current_scope = bonsai_lang_api::Visibility::Public,
                    // `module_function` flips the dual-mode (private
                    // instance, public module-level). The
                    // resolver-relevant half is the public surface;
                    // model as Public.
                    "module_function" => *current_scope = bonsai_lang_api::Visibility::Public,
                    _ => {}
                }
            }
            // Modifier with arg list: `private :foo, :bar`. Tags the
            // listed methods only — does NOT flip the scope. Also
            // covers `module_function :name` (Ruby's "make `name` both
            // private instance and public module-level"), which we
            // model as a Public override on the named method, plus the
            // `attr_reader` / `attr_writer` / `attr_accessor` forms
            // which declare *new* synthetic methods that don't exist
            // as `def` decls — but if the declaration sits inside a
            // public scope region, we keep the default scope, and if
            // it sits inside a private region the kit's scope-marker
            // path already handles the surrounding visibility.
            "call" => {
                let method_node = stmt.child_by_field_name("method");
                let method_text = method_node
                    .map(|method| std::str::from_utf8(&src[method.byte_range()]).unwrap_or(""))
                    .unwrap_or("");
                let target_visibility = match method_text {
                    "private" => Some(bonsai_lang_api::Visibility::Private),
                    "protected" => Some(bonsai_lang_api::Visibility::Protected),
                    "public" => Some(bonsai_lang_api::Visibility::Public),
                    // `module_function :name` — exposes `name` as a
                    // public module-level method while keeping it
                    // private as an instance method. We tag the
                    // matching `def` Public so cross-module callers
                    // can resolve it.
                    "module_function" => Some(bonsai_lang_api::Visibility::Public),
                    _ => None,
                };
                if let Some(visibility) = target_visibility {
                    if let Some(args) = stmt.child_by_field_name("arguments") {
                        let mut arg_cursor = args.walk();
                        for arg in args.named_children(&mut arg_cursor) {
                            // Only `:name` symbols name a target; bare
                            // identifiers in the arg list are treated
                            // as locals by Ruby and ignored here.
                            if arg.kind() != "simple_symbol" {
                                continue;
                            }
                            let raw_symbol = std::str::from_utf8(&src[arg.byte_range()]).unwrap_or("");
                            let target_name = raw_symbol.trim_start_matches(':');
                            if target_name.is_empty() {
                                continue;
                            }
                            // Find a method def in this body with the
                            // same name and tag it.
                            let mut sibling_cursor = body.walk();
                            for sibling in body.named_children(&mut sibling_cursor) {
                                if sibling.kind() != "method" && sibling.kind() != "singleton_method" {
                                    continue;
                                }
                                let name_node = sibling.child_by_field_name("name");
                                let sibling_name = name_node
                                    .map(|name| std::str::from_utf8(&src[name.byte_range()]).unwrap_or(""))
                                    .unwrap_or("");
                                if sibling_name == target_name {
                                    let span = span_of(file, &sibling);
                                    out.insert((span.start, span.end), visibility);
                                }
                            }
                        }
                    }
                }
                // `module_function` with no args (bare keyword form)
                // flips the scope for subsequent defs to the dual
                // private-instance/public-module mode. From the
                // resolver's perspective the public module-level half
                // is what matters, so we treat it as a Public scope
                // flip for the rest of the body.
                if method_text == "module_function" {
                    let no_args = match stmt.child_by_field_name("arguments") {
                        None => true,
                        Some(args) => args.named_child_count() == 0,
                    };
                    if no_args {
                        *current_scope = bonsai_lang_api::Visibility::Public;
                    }
                }
            }
            "method" | "singleton_method" => {
                let span = span_of(file, &stmt);
                // Don't overwrite an explicit `private :foo` tag.
                out.entry((span.start, span.end)).or_insert(*current_scope);
            }
            _ => {}
        }
    }
}

/// True for any `DeclKind` that can carry a `bases` list. Ruby only
/// has `Class` itself, but the predicate is shared with the
/// post-processing loop and matches the shape used by the other adapters.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk Ruby `class` declarations and collect the single optional
/// superclass from the `superclass:` field. Grammar shape (verified):
///
///   `class Echo < Base; … end` →
///     (class name: (constant) superclass: (superclass (constant)) body: …)
///
/// Ruby has no interfaces and no multiple inheritance. The `include
/// SomeMixin` form is a call statement inside the body, not a parent
/// clause — the matcher's existing import / include resolution path
/// handles it elsewhere.
fn collect_ruby_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, String, Vec<String>)> {
    let mut bases_table = Vec::new();
    for class_node in collect_kinds(tree, &["class"]) {
        let class_name = class_node
            .child_by_field_name("name")
            .map(|node| node_text(&node, src).to_string())
            .unwrap_or_default();
        let mut bases: Vec<String> = Vec::new();
        if let Some(superclass_node) = class_node.child_by_field_name("superclass") {
            // `superclass` wrapper has one named child — the constant
            // / scope_resolution naming the parent.
            let mut sc_cursor = superclass_node.walk();
            for child in superclass_node.named_children(&mut sc_cursor) {
                if let Some(name) = canonical_ruby_base_name(node_text(&child, src)) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), class_name, bases));
        }
    }
    bases_table
}

/// Strip `Foo::Bar::Baz` down to the bare tail (`Baz`). Resolver
/// lookups for inherited methods key on the unqualified class name.
fn canonical_ruby_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let bare = trimmed.rsplit("::").next().unwrap_or(trimmed).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Lower Ruby's static string-key element reads into field-like compiler
/// facts. `env["QUERY_STRING"]` becomes `env.QUERY_STRING`; comments,
/// unrelated string literals, interpolated keys, and element writes do not
/// create reads. Security policy remains in the rulepack rather than in this
/// adapter.
fn extract_ruby_static_element_key_refs(tree: &Tree, src: &[u8], file: FileId) -> Vec<Ref> {
    let mut refs = Vec::new();
    for element in collect_kinds(tree, &["element_reference"]) {
        if ruby_element_reference_is_write(&element) {
            continue;
        }
        let Some(object) = element.child_by_field_name("object") else {
            continue;
        };
        let object_name = node_text(&object, src).trim();
        if object_name.is_empty() {
            continue;
        }
        let mut cursor = element.walk();
        for argument in element.named_children(&mut cursor) {
            if argument.id() == object.id() || argument.kind() != "string" {
                continue;
            }
            let mut string_cursor = argument.walk();
            let parts = argument.named_children(&mut string_cursor).collect::<Vec<_>>();
            let [content] = parts.as_slice() else {
                continue;
            };
            if content.kind() != "string_content" {
                continue;
            }
            let key = node_text(content, src).trim();
            if key.is_empty() {
                continue;
            }
            refs.push(Ref {
                span: span_of(file, content),
                name: format!("{object_name}.{key}"),
                kind: RefKind::Read,
                scope: None,
                resolved: None,
            });
        }
    }
    refs
}

fn ruby_element_reference_is_write(node: &tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(parent.kind(), "assignment" | "operator_assignment") {
        return false;
    }
    parent
        .child_by_field_name("left")
        .is_some_and(|left| left.id() == node.id())
}

/// Pre-process an ERB / RHTML template source: replace HTML wrapping
/// with spaces while preserving the embedded `<%= expr %>` and
/// `<% stmt %>` Ruby code blocks. The ERB tags themselves (`<%=`,
/// `<%`, `%>`) are also masked so tree-sitter-ruby sees only Ruby
/// code surrounded by whitespace.
///
/// Line breaks are preserved — every replacement is whitespace of
/// the same byte length, so column / line positions in the resulting
/// tree-sitter node match the original `.erb` source.
fn preprocess_erb(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    // Preserve all newlines first so blank-string regions still
    // carry line breaks into the masked output.
    for (byte_index, &byte) in bytes.iter().enumerate() {
        if byte == b'\n' || byte == b'\r' {
            out[byte_index] = byte;
        }
    }
    // Find each `<%` ... `%>` block and copy the Ruby chunk into the
    // masked output. Tag boundaries themselves stay as spaces so
    // tree-sitter-ruby sees only Ruby tokens.
    let mut cursor = 0;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b'<' && bytes[cursor + 1] == b'%' {
            // Skip optional `=` / `-` / `#` (ERB comment / silent / value).
            let tag_start = cursor;
            let mut content_start = cursor + 2;
            while content_start < bytes.len() && matches!(bytes[content_start], b'=' | b'-' | b'#') {
                content_start += 1;
            }
            // Find closing `%>`.
            let mut close_start = content_start;
            while close_start + 1 < bytes.len() {
                if bytes[close_start] == b'%' && bytes[close_start + 1] == b'>' {
                    break;
                }
                close_start += 1;
            }
            if close_start + 1 >= bytes.len() {
                // Unclosed tag — treat the rest as masked.
                break;
            }
            // Copy Ruby content [content_start..close_start] into the output.
            // ERB comments (`<%# ... %>`) — masked, not surfaced as
            // Ruby. Silent and value forms are surfaced.
            let is_comment = bytes.get(tag_start + 2).copied() == Some(b'#');
            if !is_comment {
                for content_index in content_start..close_start {
                    if bytes[content_index] != b'\n' && bytes[content_index] != b'\r' {
                        out[content_index] = bytes[content_index];
                    }
                }
            }
            // Skip past `%>` (and an optional trailing `-` for trim form).
            cursor = close_start + 2;
            if cursor < bytes.len() && bytes[cursor] == b'-' {
                cursor += 1;
            }
            continue;
        }
        cursor += 1;
    }
    // Safety: only valid-UTF8 bytes were copied (Ruby code from a
    // UTF-8 input is UTF-8). The rest is ASCII whitespace.
    match String::from_utf8(out) {
        Ok(masked) => masked,
        Err(invalid) => {
            // Fall back to lossy if a multi-byte char straddled a
            // tag boundary in a way that produced an invalid byte
            // sequence (very unlikely with the byte-level copy).
            String::from_utf8_lossy(invalid.as_bytes()).into_owned()
        }
    }
}

/// Lift every `require` / `require_relative` / `load` / `autoload`
/// call into an `ImportSpec`. Ruby has no native import keyword; these
/// method calls are the convention and the only handle the resolver has.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // tree-sitter-ruby parses each loader call as a `call` node whose
    // `method:` is the function name and whose `arguments:` carries
    // the module string.
    for call_node in collect_kinds(tree, &["call"]) {
        let Some(method_node) = call_node.child_by_field_name("method") else {
            continue;
        };
        let method = node_text(&method_node, src);
        if !matches!(method, "require" | "require_relative" | "load" | "autoload") {
            continue;
        }
        let Some(args) = call_node.child_by_field_name("arguments") else {
            continue;
        };
        let module = first_named_child_of_kind(&args, "string")
            .and_then(|string_node| first_named_child_of_kind(&string_node, "string_content"))
            .map(|content| node_text(&content, src).to_string())
            .unwrap_or_default();
        if module.is_empty() {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &call_node),
            module: module.clone(),
            alias: None,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if matches!(method, "require" | "require_relative" | "load") {
            imports.push(ImportSpec {
                span: span_of(file, &call_node),
                module: module.clone(),
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Local,
            });
            if let Some(stem) = module.rsplit(['/', '\\']).next() {
                let constant = ruby_constant_name_from_snake_case(stem);
                if !constant.is_empty() && constant != module {
                    imports.push(ImportSpec {
                        span: span_of(file, &call_node),
                        module,
                        alias: Some(constant),
                        is_wildcard: true,
                        original_name: None,
                        // Resolver-only constant binding inferred
                        // from the loader target (`user_service` ->
                        // `UserService`). The visible import row is
                        // still the require/load statement itself.
                        scope: ImportScope::Local,
                    });
                }
            }
        }
    }
    for assignment in collect_kinds(tree, &["assignment"]) {
        if inside_ruby_executable_scope(assignment) {
            continue;
        }
        let (Some(left), Some(right)) = (
            assignment.child_by_field_name("left"),
            assignment.child_by_field_name("right"),
        ) else {
            continue;
        };
        if left.kind() != "constant" || right.kind() != "constant" {
            continue;
        }
        let alias = node_text(&left, src).trim();
        let module = node_text(&right, src).trim();
        if alias.is_empty() || module.is_empty() || alias == module {
            continue;
        }
        if imports.iter().any(|import| {
            import.alias.as_deref() == Some(alias)
                && import.module == module
                && import.original_name.is_none()
        }) {
            continue;
        }
        imports.push(ImportSpec {
            span: span_of(file, &assignment),
            module: module.to_string(),
            alias: Some(alias.to_string()),
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
    }
    imports
}

fn ruby_constant_name_from_snake_case(stem: &str) -> String {
    stem.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            let mut out = String::new();
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
            out
        })
        .collect::<String>()
}

fn inside_ruby_executable_scope(node: tree_sitter::Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "method" | "singleton_method" | "block" | "do_block"
        ) {
            return true;
        }
        parent = current.parent();
    }
    false
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
