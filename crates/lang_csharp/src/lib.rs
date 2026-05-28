//! C# language adapter.
use bonsai_common::{FileId, Span};
use bonsai_lang_api::{
    collect_param_type_aliases, decl_index_with_handler, extract_imports_via,
    kit::{
        canonical_simple_type_name, collect_kinds, language_from_pack, node_text, parse_with, span_of,
        with_fn_kinds_and_implicit_receivers,
    },
    AdapterContext, AdapterError, AssignValueKind, CallKind, DeclIndex, DeclKind, FlowEvent,
    GrammarHandler, ImportIndex, ImportScope, ImportSpec, LanguageAdapter, LanguageCapabilities,
    LanguageId, TypeAliasBinding, TypeAliasVocabulary, Visibility,
};

const CSHARP_TYPE_ALIASES: TypeAliasVocabulary = TypeAliasVocabulary {
    fn_kinds: &[
        "method_declaration",
        "constructor_declaration",
        "local_function_statement",
    ],
    param_kinds: &["parameter"],
    name_field: "name",
    type_field: "type",
};

const CSHARP_DECL_KINDS: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "class_declaration",
    "struct_declaration",
    "interface_declaration",
    "record_declaration",
    "enum_declaration",
    "delegate_declaration",
    "property_declaration",
    "event_declaration",
    "field_declaration",
    "local_function_statement",
];

// C# default for type members is `private` and for top-level
// types it's `internal`, but applying that strictly when
// module_path is the file-stem fallback would block legitimate
// cross-file calls within the same project. Default to `Public`
// until real module_path coverage (namespace declarations) lands;
// tighten then.
const CSHARP_DEFAULT_VISIBILITY: Visibility = Visibility::Public;
use tree_sitter::{Language, Tree};

pub const LANG_ID: LanguageId = LanguageId::new("csharp");
const PACK_NAME: &str = "csharp";
// `accessor_declaration` is C#'s property getter/setter body. Treating
// it as a function-declaration kind gives each accessor its own Decl
// with its own flow_events so taint that flows through `string X
// { get => …; set => _x = value; }` is observed end-to-end. Without
// this the property collapses into a Field decl and accessor body
// events disappear (audit task #131). `constructor_declaration` and
// `destructor_declaration` join the set so RAII / dtor flows surface.
const HANDLER: GrammarHandler = GrammarHandler {
    constructor_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
    ..with_fn_kinds_and_implicit_receivers(
        &[
            "method_declaration",
            "local_function_statement",
            "accessor_declaration",
            "constructor_declaration",
            "destructor_declaration",
        ],
        &["this", "base"],
        &[],
    )
};

#[derive(Debug, Default, Copy, Clone)]
pub struct CSharpAdapter;

impl CSharpAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LanguageAdapter for CSharpAdapter {
    fn language_id(&self) -> LanguageId {
        LANG_ID
    }
    fn display_name(&self) -> &'static str {
        "C#"
    }
    fn file_extensions(&self) -> &'static [&'static str] {
        // `.csx` is C#'s script / interactive form — same grammar and
        // lookup semantics apply.
        &["cs", "csx"]
    }
    fn tree_sitter_language(&self) -> Result<Language, AdapterError> {
        language_from_pack(PACK_NAME)
    }
    fn capabilities(&self) -> LanguageCapabilities {
        // Exceptions: the adapter populates `Throw::thrown_type` from
        // `throw new IOException(...)` and `Try::catch_types` from
        // `catch (IOException e)`. Catch-all `catch { }` arms produce
        // an empty `catch_types` and the engine falls back to the
        // conservative seed-on-any-tainted-throw behavior.
        LanguageCapabilities {
            exceptions: bonsai_lang_api::CapabilityLevel::Exact,
            receiver_types: bonsai_lang_api::CapabilityLevel::Partial,
            constructor_method_names: bonsai_lang_api::NO_CONSTRUCTOR_METHOD_NAMES,
            super_receiver_tokens: &["base"],
            implicit_receiver_tokens: &["this"],
            ..LanguageCapabilities::partial_baseline()
        }
    }
    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        let mut idx = decl_index_with_handler(PACK_NAME, file, ctx, &HANDLER);
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            // Phase-6 return-type extraction: `T Method() {}` populates
            // `Decl.return_type` for `apply_assign_call_result_types`.
            bonsai_lang_api::populate_decl_return_types(&mut idx, &tree, src, &HANDLER);
            for decl in &mut idx.defs {
                populate_csharp_exception_types(&mut decl.flow_events, &tree, src);
            }
        }
        let pkg = parse_with(PACK_NAME, file, ctx).and_then(|(snapshot, tree)| {
            extract_csharp_namespace(tree.root_node(), snapshot.text.as_bytes())
        });
        if let Some(segments) = pkg {
            bonsai_lang_api::apply_module_path_semantic_identity(&mut idx, segments);
        } else {
            bonsai_lang_api::apply_file_stem_semantic_identity(&mut idx, ctx);
        }
        if let Some((snapshot, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = snapshot.text.as_bytes();
            let vis_map = collect_csharp_visibility(tree.root_node(), file, src);
            let alias_map = collect_param_type_aliases(&tree, file, src, &CSHARP_TYPE_ALIASES);
            // Class-level field/property type bindings extend each
            // method's `type_aliases`. A field declared as `private
            // readonly AuthService _authService = new AuthService();`
            // must be visible inside the class's methods so receiver
            // calls like `_authService.RunAdminCommand(...)` resolve
            // through the workspace's `AuthService` decl. The
            // class-scoped collection mirrors Java's pattern in
            // `lang_java` and applies symmetrically to property
            // declarations (`public Foo Bar { get; set; }` carries
            // the same `Bar : Foo` binding).
            let class_field_aliases = collect_csharp_class_field_aliases(&tree, file, src);
            // Pre-compute the parent class span for each method-like
            // decl so the per-decl pass below can patch `type_aliases`
            // without re-borrowing `idx.defs` while it's already
            // mutably borrowed.
            let class_span_for_parent: std::collections::HashMap<bonsai_common::SymbolId, Span> = idx
                .defs
                .iter()
                .filter(|candidate| is_class_like(candidate.kind))
                .map(|candidate| (candidate.symbol, candidate.span))
                .collect();
            for decl in &mut idx.defs {
                if let Some(vis) = vis_map.get(&decl.span).copied() {
                    decl.visibility = vis;
                }
                let mut aliases = alias_map.get(&decl.span).cloned().unwrap_or_default();
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    if let Some(class_span) = decl
                        .parent
                        .and_then(|parent_sym| class_span_for_parent.get(&parent_sym).copied())
                    {
                        if let Some(field_aliases) = class_field_aliases
                            .iter()
                            .find_map(|(span, list)| (*span == class_span).then_some(list))
                        {
                            for alias in field_aliases {
                                if !aliases.contains(alias) {
                                    aliases.push(alias.clone());
                                }
                            }
                        }
                    }
                }
                if !aliases.is_empty() {
                    decl.type_aliases = aliases;
                }
            }
            // Per-class `bases`: `class Echo : Base, IFoo` → ["Base", "IFoo"].
            // C# uses a single `base_list` for both class super and
            // interface impls — they're indistinguishable in syntax.
            let bases_by_span = collect_csharp_class_bases(&tree, file, src);
            for decl in &mut idx.defs {
                if !is_class_like(decl.kind) {
                    continue;
                }
                if let Some(bases) = bases_by_span
                    .iter()
                    .find_map(|(span, bases)| (*span == decl.span).then_some(bases))
                {
                    decl.bases = bases.clone();
                }
            }
        }
        for decl in &mut idx.defs {
            bonsai_lang_api::normalize_call_result_assignment_sources(&mut decl.flow_events);
            bonsai_lang_api::inject_lifecycle_events(&mut decl.flow_events, CSHARP_LIFECYCLE_TRANSITIONS);
        }
        // Synthesize implicit members of positional `record`
        // declarations (canonical constructor + component accessors) so
        // `new R(.., tainted, ..)` and `r.Comp` thread taint — C#
        // records have no grammar nodes for these. Shared with lang_java.
        if let Some((_, tree)) = parse_with(PACK_NAME, file, ctx) {
            let src = parse_with(PACK_NAME, file, ctx)
                .map(|(s, _)| s.text.as_bytes().to_vec())
                .unwrap_or_default();
            bonsai_lang_api::kit::synthesize_record_members(&mut idx, &tree, &src, file);
            // Expression-bodied properties (`X => expr;`) have no
            // accessor node, so synthesize their getter before resolving
            // bare property reads below.
            synthesize_csharp_expression_bodied_properties(&mut idx, &tree, &src, file);
            // C# constructor bodies are `block` kind — excluded from
            // the kit's `body_has_implicit_return` set — so the kit
            // emits no synthetic Return for them. Java's equivalent
            // (`constructor_body` kind) IS treated as an expression-
            // body, so each Java ctor gets a `Return{value_text=body}`
            // event whose identifier tokenization bridges param taint
            // to the return → caller's CallRet → caller's `repo`
            // allocation. Mirror that by synthesizing a ctor Return
            // whose value_text includes the body text + constructor_
            // initializer text (`: base(data)`) so params propagate
            // through the inheritance chain even when the body is
            // empty — `new AuditedRepository(envelope)` then taints
            // `repo` whole-object (Java-style), letting the existing
            // 1-level receiver-field bridge carry it.
            synthesize_csharp_constructor_implicit_returns(&mut idx, &tree, &src, file);
        }
        // Resolve bare implicit-`this` property reads. C# accesses a
        // zero-arg property/getter by its bare name (`var c = Cmd;` for
        // `string Cmd => Data.Cmd;`), which the generic walker emits as a
        // plain identifier read — so taint never flows out of the
        // property. Rewrite such reads into getter calls so the IDG
        // stitches the property's return into the assignment.
        qualify_csharp_implicit_member_reads(&mut idx);
        // Precompute `self.<field> → Type` bindings from each
        // class's constructor `receiver_field_writes` so receiver-
        // typed dispatch through stable instance state is an O(1)
        // lookup against the method's `type_aliases` instead of a
        // per-call walk over sibling decls.
        bonsai_lang_api::apply_class_field_type_aliases(&mut idx);
        idx
    }
    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        extract_imports_via(PACK_NAME, file, ctx, parse_imports)
    }
}

/// Synthesize getter `Method` decls for C# expression-bodied properties
/// (`public string Cmd => Data.Cmd;`). The grammar emits these as a
/// `property_declaration` whose body is an `arrow_expression_clause` with
/// no `accessor_declaration` child — so the HANDLER's fn-kind extraction
/// (which keys on `accessor_declaration`) produces no decl at all and the
/// property's return expression is invisible to the IDG. Mirror the
/// record-accessor synthesis: one zero-arg `Method` named after the
/// property whose single `Return` forwards the (receiver-qualified) body
/// expression, so a getter call resolves the property's value and a
/// tainted receiver field flows out through the property.
fn synthesize_csharp_expression_bodied_properties(
    index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    let mut next_symbol = index
        .defs
        .iter()
        .map(|d| d.symbol.raw())
        .max()
        .map_or(1, |m| m + 1);
    let mut synthesized: Vec<bonsai_lang_api::Decl> = Vec::new();
    for prop in collect_kinds(tree, &["property_declaration"]) {
        // Expression-bodied only: a direct `arrow_expression_clause`
        // child. Properties with an `accessor_list` (`{ get; set; }`)
        // surface their bodies through `accessor_declaration` decls.
        let mut pc = prop.walk();
        let Some(arrow) = prop
            .children(&mut pc)
            .find(|c| c.kind() == "arrow_expression_clause")
        else {
            continue;
        };
        let Some(name_node) = prop.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() {
            continue;
        }
        // Body expression = the arrow clause's last named child (the
        // node after the `=>` token).
        let mut ac = arrow.walk();
        let named: Vec<_> = arrow.children(&mut ac).filter(|c| c.is_named()).collect();
        let Some(expr) = named.last().copied() else {
            continue;
        };
        let body = node_text(&expr, src).trim().to_string();
        if body.is_empty() {
            continue;
        }
        // Qualify a bare member read against the receiver so the field
        // base resolves to `this` (`Data.Cmd` → `this.Data.Cmd`), which
        // is what the receiver-state machinery keys on.
        let qualified = if body.starts_with("this.") || body.starts_with("base.") {
            body.clone()
        } else {
            format!("this.{body}")
        };
        let Some((parent, module_path, visibility)) =
            csharp_enclosing_type_decl(index, prop, file)
        else {
            continue;
        };
        // A property with an explicit getter/field of the same name
        // already covers this; don't double-declare.
        if index
            .defs
            .iter()
            .chain(synthesized.iter())
            .any(|d| d.parent == parent && d.name == name && d.params.is_empty())
        {
            continue;
        }
        let body_span = span_of(file, &expr);
        // If the body is a simple dotted member access (`Data.Cmd` —
        // optionally prefixed with `this.`/`base.`), model it as a
        // CALL chain rather than a single 2-level field read. The
        // IDG's interprocedural receiver-field bridge is 1-level, so
        // `Cmd => Data.Cmd` modeled as `Return this.Data.Cmd` (2-
        // level read) never connects to the caller's tainted
        // `repo.Data.Cmd`. Modeling as `Call Data.Cmd(); Return
        // call-result` mirrors the Java accessor pattern
        // (`String cmd() { return data.cmd(); }`) which the bridge
        // already handles — the call resolves to the receiver-typed
        // member (e.g. the record component's synthesized accessor),
        // and that 1-level hop forwards the tainted field.
        let flow_events = if let Some((call_receiver, call_name)) =
            dotted_member_access_call_parts(&body)
        {
            // Look up the receiver's static type from sibling
            // `property_declaration` / `field_declaration` siblings in
            // the same class so the resolver can disambiguate the
            // call's `name` against the receiver's class instead of
            // resolving back to the synthesizing property itself
            // (which would self-recurse).
            let receiver_types =
                csharp_lookup_member_type(prop, &call_receiver, src).into_iter().collect();
            vec![
                FlowEvent::Call {
                    span: body_span,
                    name: call_name.clone(),
                    receiver: Some(call_receiver),
                    receiver_types,
                    call_kind: CallKind::Method,
                    args: Vec::new(),
                },
                FlowEvent::Return {
                    span: body_span,
                    value_text: Some(format!("{call_name}()")),
                    value_name: None,
                },
            ]
        } else {
            vec![FlowEvent::Return {
                span: body_span,
                value_text: Some(qualified.clone()),
                value_name: Some(qualified.clone()),
            }]
        };
        synthesized.push(bonsai_lang_api::Decl {
            symbol: bonsai_common::SymbolId::new(next_symbol),
            kind: DeclKind::Method,
            name,
            qualified_name: None,
            module_path,
            span: span_of(file, &name_node),
            name_span: span_of(file, &name_node),
            visibility,
            parent,
            body_span: Some(body_span),
            flow_events,
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: vec!["this".to_string(), "base".to_string()],
            receiver_state_sources: vec![qualified],
            return_type: None,
        });
        next_symbol += 1;
    }
    index.defs.extend(synthesized);
}

/// For each C# `constructor_declaration` whose extracted decl has
/// no `Return` event yet, synthesize one whose `value_text` includes
/// the constructor body + initializer text (`: base(data)`). The IDG
/// transfer's Return handler tokenizes that text via
/// `bridge_value_expr_to_node`, so each identifier (in particular the
/// `data` param forwarded to `base`) bridges to `Place::Return`. The
/// caller's `new R(envelope)` site then connects via the standard
/// callee-Return → caller-CallRet edge, tainting `repo` whole-object
/// — which is exactly how Java's identical mega_flow propagates
/// (Java's `constructor_body` kind falls into the kit's implicit-
/// return path automatically; C#'s `block` doesn't).
fn synthesize_csharp_constructor_implicit_returns(
    index: &mut DeclIndex,
    tree: &Tree,
    src: &[u8],
    file: FileId,
) {
    for ctor_node in collect_kinds(tree, &["constructor_declaration"]) {
        let ctor_span = span_of(file, &ctor_node);
        let Some(decl) = index.defs.iter_mut().find(|d| {
            matches!(d.kind, DeclKind::Constructor) && d.span == ctor_span
        }) else {
            continue;
        };
        if decl.flow_events.iter().any(|e| matches!(e, FlowEvent::Return { .. })) {
            continue;
        }
        // Build value_text from the constructor_initializer + body
        // texts. Concatenating both surfaces param identifiers from
        // either side (`: base(data)` or `{ Data = data; }`) so
        // tokenization can bridge them.
        let mut parts: Vec<String> = Vec::new();
        let mut cw = ctor_node.walk();
        for child in ctor_node.children(&mut cw) {
            if matches!(child.kind(), "constructor_initializer" | "block") {
                let t = node_text(&child, src).trim().to_string();
                if !t.is_empty() {
                    parts.push(t);
                }
            }
        }
        if parts.is_empty() {
            continue;
        }
        let value_text = parts.join(" ");
        let body_span = ctor_node
            .child_by_field_name("body")
            .map(|b| span_of(file, &b))
            .unwrap_or_else(|| span_of(file, &ctor_node));
        decl.flow_events.push(FlowEvent::Return {
            span: body_span,
            value_text: Some(value_text),
            value_name: None,
        });
    }
}

/// Find a sibling `property_declaration` / `field_declaration` named
/// `member` in the type that lexically encloses `prop`, returning its
/// declared (canonical) type name. Used to set `receiver_types` on a
/// synthesized member-access Call so the resolver dispatches against
/// the receiver's class — without this, `Cmd => Data.Cmd` resolves
/// `Data.Cmd` back to the same `Cmd` property and self-recurses.
fn csharp_lookup_member_type(
    prop: tree_sitter::Node<'_>,
    member: &str,
    src: &[u8],
) -> Option<String> {
    let mut cur = prop.parent();
    let mut class_node = None;
    while let Some(n) = cur {
        if matches!(
            n.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
        ) {
            class_node = Some(n);
            break;
        }
        cur = n.parent();
    }
    let class_node = class_node?;
    let body = class_node.child_by_field_name("body")?;
    let mut walker = body.walk();
    for child in body.children(&mut walker) {
        match child.kind() {
            "property_declaration" => {
                let name_node = child.child_by_field_name("name")?;
                if node_text(&name_node, src).trim() == member {
                    let type_node = child.child_by_field_name("type")?;
                    let raw = node_text(&type_node, src).trim();
                    if raw.is_empty() {
                        return None;
                    }
                    return Some(canonical_simple_type_name(raw).to_string());
                }
            }
            "field_declaration" => {
                // C# field_declaration: `Type Name [, Name2];` — the
                // type is the `type` field; the name(s) are inside
                // `variable_declaration` children.
                let Some(type_node) = child.child_by_field_name("type") else {
                    continue;
                };
                let mut cw = child.walk();
                for cc in child.children(&mut cw) {
                    if cc.kind() != "variable_declaration" {
                        continue;
                    }
                    let mut vw = cc.walk();
                    for v in cc.children(&mut vw) {
                        if v.kind() != "variable_declarator" {
                            continue;
                        }
                        if let Some(name_node) = v.child_by_field_name("name") {
                            if node_text(&name_node, src).trim() == member {
                                let raw = node_text(&type_node, src).trim();
                                if raw.is_empty() {
                                    return None;
                                }
                                return Some(canonical_simple_type_name(raw).to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// If `body` is a simple dotted member-access of identifiers
/// (`Data.Cmd`, optionally prefixed `this.`/`base.`), return
/// `(receiver, call_name)` modeling it as a method call — `Data.Cmd`
/// becomes `(receiver="Data", call_name="Data.Cmd")` so the IDG's
/// 1-level receiver-field bridge resolves it to the receiver-typed
/// member (e.g. a record component's synthesized accessor). Returns
/// `None` for any non-trivial body (call, indexer, literal, complex
/// expression) so those keep the Return-only fallback.
fn dotted_member_access_call_parts(body: &str) -> Option<(String, String)> {
    let trimmed = body.trim();
    // Strip a leading receiver qualifier; the remaining text must be a
    // pure dotted identifier path of at least two segments
    // (`A.B`/`A.B.C`/...).
    let inner = trimmed
        .strip_prefix("this.")
        .or_else(|| trimmed.strip_prefix("base."))
        .unwrap_or(trimmed);
    let segments: Vec<&str> = inner.split('.').collect();
    if segments.len() < 2 {
        return None;
    }
    for seg in &segments {
        if seg.is_empty()
            || !seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || !seg
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return None;
        }
    }
    // Receiver = everything up to the last dot; call_name = full dotted
    // form mirroring Java's `data.cmd` pattern (`receiver="data",
    // name="data.cmd"`).
    let last_dot = inner.rfind('.').unwrap();
    let receiver = inner[..last_dot].to_string();
    Some((receiver, inner.to_string()))
}

/// Resolve the type declaration (`class`/`struct`/`record`/`interface`)
/// that lexically encloses `node`, returning its symbol / module / visibility.
fn csharp_enclosing_type_decl(
    index: &DeclIndex,
    node: tree_sitter::Node<'_>,
    file: FileId,
) -> Option<(
    Option<bonsai_common::SymbolId>,
    bonsai_lang_api::ModulePath,
    Visibility,
)> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if matches!(
            n.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
        ) {
            let span = span_of(file, &n);
            return index
                .defs
                .iter()
                .find(|d| d.span == span)
                .map(|d| (Some(d.symbol), d.module_path.clone(), d.visibility));
        }
        cur = n.parent();
    }
    None
}

/// Rewrite bare reads of zero-arg member accessors (C# properties /
/// expression-bodied `=> expr` getters) into getter calls. C# reads a
/// property by its bare name (`var c = Cmd;` for `string Cmd =>
/// Data.Cmd;`), which the generic walker emits as `Assign { source_name:
/// "Cmd" }` — a plain identifier read that never connects to the
/// property's return, so taint stops at the property boundary. When the
/// bare RHS name matches a zero-arg member decl in this file and is NOT
/// a local/param of the method, convert it into a `source_call` so the
/// IDG resolves the getter and forwards its return into the assignment.
fn qualify_csharp_implicit_member_reads(index: &mut DeclIndex) {
    use std::collections::HashSet;
    let getter_names: HashSet<String> = index
        .defs
        .iter()
        .filter(|d| matches!(d.kind, DeclKind::Method) && d.params.is_empty() && !d.name.is_empty())
        .map(|d| d.name.clone())
        .collect();
    if getter_names.is_empty() {
        return;
    }
    for decl in &mut index.defs {
        if decl.flow_events.is_empty() {
            continue;
        }
        // A local binding (param or assignment target) shadows the
        // member, so those names must keep their plain-read semantics.
        let mut locals: HashSet<String> = decl.params.iter().cloned().collect();
        collect_csharp_assign_targets(&decl.flow_events, &mut locals);
        rewrite_csharp_member_reads(&mut decl.flow_events, &getter_names, &locals);
    }
}

fn collect_csharp_assign_targets(events: &[FlowEvent], out: &mut std::collections::HashSet<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => {
                if !target.is_empty() {
                    out.insert(target.trim().to_string());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_csharp_assign_targets(then_events, out);
                collect_csharp_assign_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_csharp_assign_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_csharp_assign_targets(body, out);
                collect_csharp_assign_targets(catch_events, out);
                collect_csharp_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

fn rewrite_csharp_member_reads(
    events: &mut Vec<FlowEvent>,
    getters: &std::collections::HashSet<String>,
    locals: &std::collections::HashSet<String>,
) {
    // Two-pass: first recurse into nested events (mutating their
    // inner vecs); then walk this level with an index, mutating each
    // Assign that needs qualification AND inserting an explicit Call
    // event before it so `walk_call`'s `args.is_empty()` fallback
    // tokenizes the property name into a `CallArg{idx=0}` recv-slot.
    // Without that synthetic recv-slot, `recv_slots_for_call_span`
    // returns nothing for the property's call and the interprocedural
    // receiver-field bridge can't propagate caller-receiver taint
    // into the getter's body — mirrors Java's pattern where
    // `String c = cmd();` emits both `Assign{source_call:"cmd"}` and
    // `Call{name:"cmd", call_kind:function, args:[]}`.
    for event in events.iter_mut() {
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                rewrite_csharp_member_reads(then_events, getters, locals);
                rewrite_csharp_member_reads(else_events, getters, locals);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                rewrite_csharp_member_reads(body, getters, locals);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                rewrite_csharp_member_reads(body, getters, locals);
                rewrite_csharp_member_reads(catch_events, getters, locals);
                rewrite_csharp_member_reads(finally_events, getters, locals);
            }
            _ => {}
        }
    }
    let mut idx = 0usize;
    while idx < events.len() {
        let (qualify_name, span) = match &events[idx] {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                span,
                ..
            } => {
                if source_call.is_some() {
                    (None, *span)
                } else if let Some(name) = source_name.as_deref().map(str::trim).map(str::to_string) {
                    if getters.contains(&name)
                        && !locals.contains(&name)
                        && name != target.trim()
                    {
                        (Some(name), *span)
                    } else {
                        (None, *span)
                    }
                } else {
                    (None, *span)
                }
            }
            _ => {
                idx += 1;
                continue;
            }
        };
        let Some(name) = qualify_name else {
            idx += 1;
            continue;
        };
        // Mutate the Assign in place.
        if let FlowEvent::Assign {
            source_name,
            source_call,
            source_call_args,
            source_names,
            value_kind,
            ..
        } = &mut events[idx]
        {
            *source_call = Some(name.clone());
            *source_call_args = Vec::new();
            *source_name = None;
            source_names.retain(|s| s.trim() != name);
            *value_kind = Some(AssignValueKind::CallResult);
        }
        // Insert an explicit Call event before the Assign so
        // `walk_call`'s argless fallback synthesizes the recv-slot.
        events.insert(
            idx,
            FlowEvent::Call {
                span,
                name: name.clone(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: Vec::new(),
            },
        );
        idx += 2;
    }
}

/// C# lifecycle transitions: IDisposable / CancellationTokenSource / lock release.
const CSHARP_LIFECYCLE_TRANSITIONS: &[bonsai_lang_api::LifecycleTransition] = &[
    bonsai_lang_api::LifecycleTransition {
        call_match: "Dispose",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "DisposeAsync",
        transition: "freed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Close",
        transition: "closed",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Cancel",
        transition: "cancelled",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "Release",
        transition: "unlocked",
        arg_index: 0,
    },
    bonsai_lang_api::LifecycleTransition {
        call_match: "ReleaseMutex",
        transition: "unlocked",
        arg_index: 0,
    },
];

/// Lift every `using_directive` into an `ImportSpec`. C# splits the
/// alias out of the path: `using IO = System.IO` exposes `IO` as
/// `name:` and `System.IO` as the trailing qualified path child.
fn parse_imports(tree: &Tree, src: &[u8], file: FileId) -> Vec<ImportSpec> {
    let mut imports = Vec::new();
    // `using_directive` shapes:
    //   `using System.Data;`              → qualified_name only
    //   `using static System.Math;`       → qualified_name (with `static` keyword)
    //   `using IO = System.IO;`           → name: identifier (alias) + qualified_name
    for using_node in collect_kinds(tree, &["using_directive"]) {
        let mut child_cursor = using_node.walk();
        // The path is the *last* qualified_name / identifier child that
        // isn't the alias `name:` field — this is the only shape that
        // works across all three forms above.
        let mut last_path: Option<tree_sitter::Node<'_>> = None;
        for child in using_node.named_children(&mut child_cursor) {
            if matches!(child.kind(), "qualified_name" | "identifier")
                && Some(child) != using_node.child_by_field_name("name")
            {
                last_path = Some(child);
            }
        }
        let Some(path_node) = last_path.or_else(|| using_node.child_by_field_name("name")) else {
            continue;
        };
        let module = node_text(&path_node, src).trim().to_string();
        if module.is_empty() {
            continue;
        }
        let alias = using_node
            .child_by_field_name("name")
            .map(|alias_node| node_text(&alias_node, src).to_string());
        imports.push(ImportSpec {
            span: span_of(file, &using_node),
            module: module.clone(),
            alias,
            is_wildcard: false,
            original_name: None,
            scope: ImportScope::Module,
        });
        if csharp_using_is_static(&using_node, src) {
            imports.push(ImportSpec {
                span: span_of(file, &using_node),
                module,
                alias: None,
                is_wildcard: true,
                original_name: None,
                scope: ImportScope::Local,
            });
        }
    }
    imports
}

fn csharp_using_is_static(using_node: &tree_sitter::Node<'_>, src: &[u8]) -> bool {
    node_text(using_node, src)
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| window == ["using", "static"])
}

/// Walk every C# class-like declaration and pull `(name, type)`
/// bindings from its `field_declaration` and `property_declaration`
/// children. Returns `(class_span, [TypeAliasBinding])` so the
/// per-method merge can attach a class's bindings to every method
/// nested inside it, matching the resolver's caller-decl
/// `type_aliases` lookup contract.
fn collect_csharp_class_field_aliases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<TypeAliasBinding>)> {
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "record_struct_declaration",
        "interface_declaration",
    ];
    let mut out = Vec::new();
    for class_node in collect_kinds(tree, class_kinds) {
        let mut aliases: Vec<TypeAliasBinding> = Vec::new();
        let mut work = vec![class_node];
        while let Some(node) = work.pop() {
            // Don't descend into nested classes — their own iteration
            // produces the right scope for their methods. A nested
            // class's fields are visible only to its own methods, not
            // the outer class's methods.
            if node != class_node && class_kinds.contains(&node.kind()) {
                continue;
            }
            match node.kind() {
                "field_declaration" | "event_field_declaration" => {
                    extend_aliases_from_field_or_event(node, src, &mut aliases);
                }
                "property_declaration" => {
                    if let Some(binding) = property_alias_from_node(node, src) {
                        if !aliases.contains(&binding) {
                            aliases.push(binding);
                        }
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                work.push(child);
            }
        }
        if !aliases.is_empty() {
            out.push((span_of(file, &class_node), aliases));
        }
    }
    out
}

fn extend_aliases_from_field_or_event(
    node: tree_sitter::Node<'_>,
    src: &[u8],
    aliases: &mut Vec<TypeAliasBinding>,
) {
    // C# `field_declaration` wraps a `variable_declaration` whose
    // `type` field carries the field type and whose
    // `variable_declarator` children name each binding. Multi-name
    // forms (`Foo a, b, c;`) are valid for value-type fields.
    let var_decl = node.child_by_field_name("declaration").or_else(|| {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "variable_declaration" {
                found = Some(child);
                break;
            }
        }
        found
    });
    let Some(var_decl) = var_decl else {
        return;
    };
    let Some(type_node) = var_decl.child_by_field_name("type") else {
        return;
    };
    let canonical = canonical_simple_type_name(node_text(&type_node, src));
    if canonical.is_empty() {
        return;
    }
    let mut cursor = var_decl.walk();
    for declarator in var_decl.named_children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let name_node = declarator.child_by_field_name("name").or_else(|| {
            let mut inner = declarator.walk();
            let mut found = None;
            for child in declarator.named_children(&mut inner) {
                if child.kind() == "identifier" {
                    found = Some(child);
                    break;
                }
            }
            found
        });
        let Some(name_node) = name_node else {
            continue;
        };
        let name = node_text(&name_node, src).trim().to_string();
        if name.is_empty() || name == canonical {
            continue;
        }
        let binding = TypeAliasBinding {
            name,
            type_name: canonical.clone(),
        };
        if !aliases.contains(&binding) {
            aliases.push(binding);
        }
    }
}

fn property_alias_from_node(node: tree_sitter::Node<'_>, src: &[u8]) -> Option<TypeAliasBinding> {
    let type_node = node.child_by_field_name("type")?;
    let canonical = canonical_simple_type_name(node_text(&type_node, src));
    if canonical.is_empty() {
        return None;
    }
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(&name_node, src).trim().to_string();
    if name.is_empty() || name == canonical {
        return None;
    }
    Some(TypeAliasBinding {
        name,
        type_name: canonical,
    })
}

/// C#-aware visibility collector.
///
/// Differs from the generic `collect_modifier_visibility` helper in
/// that it recognises the compound forms `protected internal` (broader
/// than either alone — caller is in the same assembly OR is a derived
/// class anywhere) and `private protected` (narrower — derived classes
/// in the same assembly only). Maps to the four-level lattice in
/// `Visibility` as follows:
///
/// - `private`            → `Private`
/// - `private protected`  → `Protected` (assembly-bounded but derived-callable)
/// - `protected`          → `Protected`
/// - `protected internal` → `Crate` (visible to whole assembly)
/// - `internal`           → `Crate`
/// - `public`             → `Public`
///
/// Visibility comes from real syntax markers; per-language
/// compound-modifier handling lives in the adapter.
fn collect_csharp_visibility(
    root: tree_sitter::Node<'_>,
    file: FileId,
    src: &[u8],
) -> std::collections::HashMap<Span, Visibility> {
    let mut visibility_by_span = std::collections::HashMap::new();
    // Iterative DFS over the whole tree. Every CSHARP_DECL_KINDS node
    // contributes one entry; nested classes / nested local functions
    // each get their own.
    let mut work_stack = vec![root];
    while let Some(node) = work_stack.pop() {
        if CSHARP_DECL_KINDS.contains(&node.kind()) {
            visibility_by_span.insert(span_of(file, &node), csharp_node_visibility(node, src));
        }
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            work_stack.push(child);
        }
    }
    visibility_by_span
}

/// Resolve a single decl's visibility from its `modifier` children.
/// Compound forms (`protected internal`, `private protected`) are
/// distinct visibility levels in C# that don't map 1:1 to either side.
fn csharp_node_visibility(node: tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut keywords: Vec<&str> = Vec::new();
    let mut child_cursor = node.walk();
    for child in node.children(&mut child_cursor) {
        if child.kind() == "modifier" {
            let text = node_text(&child, src);
            if matches!(text, "private" | "protected" | "internal" | "public") {
                keywords.push(text);
            }
        }
    }
    let has_private = keywords.contains(&"private");
    let has_protected = keywords.contains(&"protected");
    let has_internal = keywords.contains(&"internal");
    let has_public = keywords.contains(&"public");
    // `public` always wins — C# doesn't allow it to combine with the
    // other access modifiers.
    if has_public {
        return Visibility::Public;
    }
    if has_protected && has_internal {
        // `protected internal` — accessible in the whole assembly +
        // derived classes outside. Closest in the four-level lattice
        // is `Crate` (assembly-wide).
        return Visibility::Crate;
    }
    if has_private && has_protected {
        // `private protected` — derived classes in the same assembly
        // only. Closer to `Protected` than `Private` for resolver
        // narrowing purposes; assembly-bounded narrowing is the
        // module_path filter applied separately.
        return Visibility::Protected;
    }
    if has_protected {
        return Visibility::Protected;
    }
    if has_internal {
        return Visibility::Crate;
    }
    if has_private {
        return Visibility::Private;
    }
    CSHARP_DEFAULT_VISIBILITY
}

/// True for decl kinds that can carry a `bases` list (class super /
/// interface impl). Shared with the post-processing loop that copies
/// `bases_by_span` onto matching decls.
fn is_class_like(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Class | DeclKind::Interface | DeclKind::Trait | DeclKind::Struct | DeclKind::Enum
    )
}

/// Walk C# class / struct / record / interface declarations and
/// pull bare base type names from `base_list`. Grammar shape:
///
///   `class Echo : Base, IFoo, IBar { ... }` →
///     (class_declaration name: (identifier)
///        (base_list (identifier) (identifier) (identifier))
///        body: ...)
///
/// The `base_list` lists both the parent class and any implemented
/// interfaces in source order; C# does not distinguish them
/// syntactically. Generic / qualified bases collapse to the bare tail.
fn collect_csharp_class_bases(
    tree: &Tree,
    file: FileId,
    src: &[u8],
) -> Vec<(bonsai_common::Span, Vec<String>)> {
    let mut bases_table = Vec::new();
    let class_kinds = &[
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "record_struct_declaration",
        "interface_declaration",
    ];
    for class_node in collect_kinds(tree, class_kinds) {
        let mut bases: Vec<String> = Vec::new();
        let mut class_cursor = class_node.walk();
        for child in class_node.named_children(&mut class_cursor) {
            if child.kind() != "base_list" {
                continue;
            }
            let mut entry_cursor = child.walk();
            for entry in child.named_children(&mut entry_cursor) {
                let raw = node_text(&entry, src);
                if let Some(name) = canonical_csharp_base_name(raw) {
                    if !bases.iter().any(|existing| existing == &name) {
                        bases.push(name);
                    }
                }
            }
        }
        if !bases.is_empty() {
            bases_table.push((span_of(file, &class_node), bases));
        }
    }
    bases_table
}

/// Strip a base entry down to the bare type name. Drops generic
/// parameters (`Foo<T>` -> `Foo`) and namespace qualification
/// (`System.IO.Stream` -> `Stream`); the resolver keys on bare names.
fn canonical_csharp_base_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let head = trimmed.split('<').next().unwrap_or(trimmed).trim();
    let bare = head.rsplit('.').next().unwrap_or(head).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_string())
}

/// Walk `decl.flow_events` recursively and populate
/// `Throw::thrown_type` / `Try::catch_types` from the C# parse tree.
/// C# syntax:
///   throw new IOException("...")  → thrown_type: "IOException"
///   throw err                     → thrown_type: None (need data-flow)
///   `try { } catch (IOException e) { } catch (FormatException e) { }`
///                                 → `catch_types = vec!["IOException", "FormatException"]`
///   `try { } catch { }`           → `catch_types = vec![]` (catch-all)
fn populate_csharp_exception_types(
    events: &mut [bonsai_lang_api::FlowEvent],
    tree: &tree_sitter::Tree,
    src: &[u8],
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Throw {
                span, thrown_type, ..
            } => {
                if thrown_type.is_some() {
                    continue;
                }
                if let Some(node) = bonsai_lang_api::kit::node_at_span(
                    tree.root_node(),
                    *span,
                    &["throw_statement", "throw_expression"],
                ) {
                    if let Some(name) = csharp_thrown_type_for_node(node, src) {
                        *thrown_type = Some(name);
                    }
                }
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_types,
                catch_param,
                ..
            } => {
                if let Some(node) =
                    bonsai_lang_api::kit::node_at_span(tree.root_node(), *span, &["try_statement"])
                {
                    if catch_types.is_empty() {
                        *catch_types = collect_csharp_catch_types(node, src);
                    }
                    // The kit's generic catch_param extractor picks the
                    // type identifier (or qualified type) on C#'s
                    // `catch (T name)` shape. Fix in the adapter where
                    // we have the structural context.
                    if let Some(name) = collect_csharp_catch_param_name(node, src) {
                        *catch_param = Some(name);
                    }
                }
                populate_csharp_exception_types(body, tree, src);
                populate_csharp_exception_types(catch_events, tree, src);
                populate_csharp_exception_types(finally_events, tree, src);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                populate_csharp_exception_types(then_events, tree, src);
                populate_csharp_exception_types(else_events, tree, src);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                populate_csharp_exception_types(body, tree, src);
            }
            _ => {}
        }
    }
}

/// Pull the constructor type out of `throw new Foo(...)`. Returns
/// `None` for re-throws (`throw e`), where the thrown type is whatever
/// data-flow eventually proves about `e` — beyond syntactic reach.
fn csharp_thrown_type_for_node(throw_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    // throw_statement > object_creation_expression > identifier (or qualified_name)
    let mut throw_cursor = throw_node.walk();
    for child in throw_node.named_children(&mut throw_cursor) {
        if child.kind() == "object_creation_expression" {
            // Newer grammar releases expose the type via the `type:` field.
            if let Some(type_node) = child.child_by_field_name("type") {
                return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                    &type_node, src,
                )));
            }
            // Older releases inline the identifier as a named child.
            let mut type_cursor = child.walk();
            for descendant in child.named_children(&mut type_cursor) {
                if matches!(
                    descendant.kind(),
                    "identifier" | "qualified_name" | "generic_name"
                ) {
                    return Some(bonsai_lang_api::kit::canonical_simple_type_name(node_text(
                        &descendant,
                        src,
                    )));
                }
            }
        }
    }
    None
}

/// Pull the binding name out of `catch (T name)`. Returns `None` for
/// catch-all (`catch { }`) and for catch declarations that omit the
/// name (`catch (T) { }` — unusual but legal in C#).
fn collect_csharp_catch_param_name(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        let mut clause_cursor = child.walk();
        for sub in child.named_children(&mut clause_cursor) {
            if sub.kind() != "catch_declaration" {
                continue;
            }
            // The `name` field is the binding identifier; the `type`
            // field is the exception type.
            if let Some(name_node) = sub.child_by_field_name("name") {
                return Some(node_text(&name_node, src).trim().to_string());
            }
            // Fallback: rightmost named identifier after the type.
            let mut pcur = sub.walk();
            let mut last_ident: Option<tree_sitter::Node<'_>> = None;
            for n in sub.named_children(&mut pcur) {
                if n.kind() == "identifier" {
                    last_ident = Some(n);
                }
            }
            if let Some(n) = last_ident {
                return Some(node_text(&n, src).trim().to_string());
            }
        }
    }
    None
}

/// Collect the `catch (T e)` types in source order. Catch-all (`catch
/// { }`) is omitted — the engine's seed-on-any-throw path handles it.
fn collect_csharp_catch_types(try_node: tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut catch_types: Vec<String> = Vec::new();
    let mut try_cursor = try_node.walk();
    for child in try_node.named_children(&mut try_cursor) {
        if child.kind() != "catch_clause" {
            continue;
        }
        // catch_clause > catch_declaration > type
        let mut clause_cursor = child.walk();
        for sub in child.named_children(&mut clause_cursor) {
            if sub.kind() != "catch_declaration" {
                continue;
            }
            if let Some(type_node) = sub.child_by_field_name("type") {
                let name = bonsai_lang_api::kit::canonical_simple_type_name(node_text(&type_node, src));
                if !name.is_empty() && !catch_types.iter().any(|existing| existing == &name) {
                    catch_types.push(name);
                }
            }
        }
    }
    catch_types
}

/// Find the file's top-level `namespace` declaration and return its
/// dotted segments. Both block-form (`namespace Foo.Bar { ... }`) and
/// file-scoped (`namespace Foo.Bar;`) shapes resolve identically.
fn extract_csharp_namespace(root: tree_sitter::Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    let mut child_cursor = root.walk();
    for child in root.children(&mut child_cursor) {
        if !matches!(
            child.kind(),
            "namespace_declaration" | "file_scoped_namespace_declaration"
        ) {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            let text = node_text(&name_node, src);
            let segments: Vec<String> = text
                .split('.')
                .map(str::trim)
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
                .collect();
            if !segments.is_empty() {
                return Some(segments);
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
