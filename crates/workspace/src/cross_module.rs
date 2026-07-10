//! Cross-file / cross-module trace engine.
//!
//! Given a function, we walk its structured `flow_events` (produced by the
//! adapter's grammar handler). For every ordinary `Call`, we consume the
//! precomputed semantic resolved callgraph and recurse only when that graph
//! proves the target. For `Branch`, we emit a `BranchSplit` step and walk
//! both sides as separate path ids. For `Loop`, we emit `LoopEnter` /
//! `LoopExit` and walk the body once with an `Iterate` marker.
//! Higher-order callbacks are resolved by binding call-site arguments to
//! parameter names in the callee's `Decl::params`; unresolved calls are
//! recorded as incompleteness, never widened into guessed targets.

use ahash::{AHashMap, AHashSet};
use bonsai_abstract_interp::{RawStep, RawTrace, StepKind, TraceLimits};
use bonsai_callgraph::{EdgeKind, ResolvedCallGraph};
use bonsai_common::{FuncId, Precision, Span, SymbolId, TraceStepId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{
    AliasTarget, CallArg, CallKind, Decl, DeclKind, FlowEvent, LoopKind, TypeAliasBinding,
};
use bonsai_resolve::{resolve_callable_with_context, ResolveContext};

#[derive(Copy, Clone, Debug)]
pub struct CrossModuleOptions {
    pub max_depth: u16,
    pub max_steps: u32,
    pub max_branch_fanout: u16,
    pub max_loop_iters: u16,
}

impl Default for CrossModuleOptions {
    fn default() -> Self {
        Self {
            max_depth: 12,
            max_steps: 8192,
            max_branch_fanout: 4,
            max_loop_iters: 1,
        }
    }
}

impl From<CrossModuleOptions> for TraceLimits {
    fn from(o: CrossModuleOptions) -> Self {
        Self {
            max_steps: o.max_steps,
            max_call_depth: o.max_depth,
            max_loop_iters: o.max_loop_iters,
            max_branches: u32::from(o.max_branch_fanout) * 256,
        }
    }
}

pub(crate) struct CrossModuleTracer<'a> {
    db: &'a AnalyzerDb,
    call_graph: &'a ResolvedCallGraph,
    opts: CrossModuleOptions,
}

struct TraceBuilder<'a> {
    db: &'a AnalyzerDb,
    call_graph: &'a ResolvedCallGraph,
    opts: CrossModuleOptions,
    out: RawTrace,
    next_step: u32,
    next_path: u32,
    current_path: u32,
    /// Per-frame bindings: maps parameter-name -> concrete symbol its
    /// callback argument pointed at. Pushed on entry, popped on exit.
    frames: Vec<CallFrame>,
    /// Recursion guard: set of symbols currently being expanded.
    stack_set: AHashSet<SymbolId>,
}

#[derive(Default, Clone)]
struct CallFrame {
    /// parameter name -> callable symbol passed at the call site
    callbacks: AHashMap<String, SymbolId>,
    /// whole-local variable bindings (e.g. `x = some_func`)
    locals: AHashMap<String, SymbolId>,
    /// local / parameter / field receiver type bindings visible in
    /// this frame. Seeded from adapter-emitted `Decl.type_aliases`
    /// and updated from call-site parameter bindings.
    types: AHashMap<String, String>,
}

struct CallSite<'a> {
    span: Span,
    name: &'a str,
    receiver: Option<&'a str>,
    call_kind: CallKind,
    args: &'a [CallArg],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SiteResolution {
    Resolved(SymbolId),
    Ambiguous { candidates: usize },
    Unresolved,
}

fn semantic_receiver_callback_args<'a>(site: &'a CallSite<'_>) -> Vec<&'a CallArg> {
    if site.receiver.is_none() {
        return Vec::new();
    }
    let method = bonsai_lang_api::kit::short_name_of(site.name);
    match method {
        // Well-known collection/promise APIs whose first argument is a
        // callback that the call semantically invokes.
        "forEach" | "map" | "flatMap" | "filter" | "some" | "every" | "find" | "findIndex" | "reduce"
        | "reduceRight" | "sort" | "then" | "catch" | "finally" => site.args.first().into_iter().collect(),
        _ => Vec::new(),
    }
}

impl<'a> CrossModuleTracer<'a> {
    #[must_use]
    pub(crate) fn new(
        db: &'a AnalyzerDb,
        call_graph: &'a ResolvedCallGraph,
        opts: CrossModuleOptions,
    ) -> Self {
        Self { db, call_graph, opts }
    }

    pub(crate) fn trace(&self, start: SymbolId) -> RawTrace {
        let mut builder = TraceBuilder {
            db: self.db,
            call_graph: self.call_graph,
            opts: self.opts,
            out: RawTrace::default(),
            next_step: 0,
            next_path: 1,
            current_path: 1,
            frames: vec![CallFrame::default()],
            stack_set: AHashSet::new(),
        };
        builder.expand(start, &[], &[], 0);
        builder.out
    }
}

impl<'a> TraceBuilder<'a> {
    fn emit(&mut self, kind: StepKind, func: FuncId, span: Span, precision: Precision, msg: String) -> bool {
        if self.next_step >= self.opts.max_steps {
            self.out.mark_truncated("max-steps");
            return false;
        }
        self.out.steps.push(RawStep {
            id: TraceStepId::new(self.next_step),
            path_id: self.current_path,
            kind,
            span,
            func,
            precision,
            message: msg,
        });
        self.next_step += 1;
        true
    }

    fn allocate_path(&mut self) -> u32 {
        self.next_path = self.next_path.saturating_add(1);
        self.next_path
    }

    /// Expand function `symbol`. `args` / `param_names` let us bind
    /// callback-parameter values from the caller.
    fn expand(&mut self, symbol: SymbolId, args: &[CallArg], param_names: &[String], depth: u16) -> bool {
        if depth > self.opts.max_depth {
            self.out.mark_truncated("max-depth");
            return false;
        }
        if !self.stack_set.insert(symbol) {
            // Cycle: emit a truncation hint rather than recursing forever.
            return true;
        }
        let Some(decl) = self.db.global_index().decl_of(symbol).cloned() else {
            self.stack_set.remove(&symbol);
            return true;
        };
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            self.stack_set.remove(&symbol);
            return true;
        }
        let func = FuncId::new(symbol.raw());

        // Build a new frame; bind parameter names to concrete callables
        // when the argument at that position resolves to one.
        let mut frame = CallFrame {
            types: types_from_decl(&decl),
            ..Default::default()
        };
        let zip_params = if param_names.is_empty() {
            &decl.params[..]
        } else {
            param_names
        };
        for (idx, param) in zip_params.iter().enumerate() {
            // Keyword-arg match first.
            let kw = args.iter().find(|a| a.name.as_deref() == Some(param.as_str()));
            let positional = args.get(idx);
            let arg = kw.or(positional);
            if let Some(a) = arg {
                if let Some(sym) = self.resolve_callable_by_name(&a.value_text, &decl) {
                    frame.callbacks.insert(param.clone(), sym);
                }
                if let Some(type_name) = self.type_name_for_expr(&a.value_text, &decl) {
                    frame.types.insert(param.clone(), type_name);
                }
            }
        }
        self.frames.push(frame);

        if !self.emit(
            StepKind::EnterFunction,
            func,
            decl.name_span,
            Precision::Exact,
            format!("Enter function {}", decl.name),
        ) {
            self.frames.pop();
            self.stack_set.remove(&symbol);
            return false;
        }

        let ok = self.walk_events(&decl.flow_events, func, depth);

        self.emit(
            StepKind::Return,
            func,
            decl.name_span,
            Precision::Exact,
            format!("Exit {}", decl.name),
        );

        self.frames.pop();
        self.stack_set.remove(&symbol);
        ok
    }

    fn walk_events(&mut self, events: &[FlowEvent], func: FuncId, depth: u16) -> bool {
        for event in events {
            if !self.walk_event(event, func, depth) {
                return false;
            }
        }
        true
    }

    fn walk_event(&mut self, event: &FlowEvent, func: FuncId, depth: u16) -> bool {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types: _,
                call_kind,
                args,
                ..
            } => self.emit_call(
                CallSite {
                    span: *span,
                    name,
                    receiver: receiver.as_deref(),
                    call_kind: *call_kind,
                    args,
                },
                func,
                depth,
            ),
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } => {
                if !self.emit(
                    StepKind::BranchSplit,
                    func,
                    *span,
                    Precision::Exact,
                    "Branch split".into(),
                ) {
                    return false;
                }
                // Walk both branches and tag the alternate arm with a
                // distinct path id so renderers can reconstruct the split.
                let parent_path = self.current_path;
                if !self.walk_events(then_events, func, depth) {
                    return false;
                }
                if !else_events.is_empty() {
                    let else_path = self.allocate_path();
                    self.current_path = else_path;
                    if !self.emit(
                        StepKind::BranchSplit,
                        func,
                        *span,
                        Precision::Exact,
                        "Else branch".into(),
                    ) {
                        return false;
                    }
                    if !self.walk_events(else_events, func, depth) {
                        self.current_path = parent_path;
                        return false;
                    }
                    if !self.emit(
                        StepKind::Merge,
                        func,
                        *span,
                        Precision::Exact,
                        "Branch merge".into(),
                    ) {
                        self.current_path = parent_path;
                        return false;
                    }
                    self.current_path = parent_path;
                }
                if !self.emit(
                    StepKind::Merge,
                    func,
                    *span,
                    Precision::Exact,
                    "Branch merge".into(),
                ) {
                    return false;
                }
                true
            }
            FlowEvent::Loop {
                span,
                loop_kind,
                body,
            } => {
                let enter_msg = match loop_kind {
                    LoopKind::For => "Loop enter (for)",
                    LoopKind::ForEach => "Loop enter (foreach)",
                    LoopKind::While => "Loop enter (while)",
                    LoopKind::DoWhile => "Loop enter (do-while)",
                    LoopKind::Loop => "Loop enter",
                };
                if !self.emit(
                    StepKind::BranchSplit,
                    func,
                    *span,
                    Precision::Exact,
                    enter_msg.into(),
                ) {
                    return false;
                }
                // Walk body once — static unroll isn't useful; the user
                // knows the body can repeat.
                if !self.walk_events(body, func, depth) {
                    return false;
                }
                self.emit(StepKind::Merge, func, *span, Precision::Exact, "Loop exit".into())
            }
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } => {
                // Record local binding for callback resolution.
                let global = self.db.global_index();
                let caller_decl = global.decl_of(SymbolId::new(func.raw()));
                if let Some(name) = source_name {
                    if let Some(caller_decl) = caller_decl {
                        if let Some(sym) = self.resolve_callable_by_name(name, caller_decl) {
                            if let Some(frame) = self.frames.last_mut() {
                                frame.locals.insert(target.clone(), sym);
                            }
                        }
                    }
                }
                let assigned_type = caller_decl.and_then(|decl| {
                    self.infer_assigned_type(
                        decl,
                        source_name.as_deref(),
                        source_call.as_deref(),
                        source_names,
                    )
                });
                if let Some(type_name) = assigned_type {
                    if let Some(frame) = self.frames.last_mut() {
                        frame.types.insert(target.clone(), type_name);
                    }
                } else if let Some(frame) = self.frames.last_mut() {
                    if !declares_type_alias(caller_decl, target) {
                        frame.types.remove(target);
                    }
                }
                self.emit(
                    StepKind::Assign,
                    func,
                    *span,
                    Precision::Exact,
                    assignment_trace_message(
                        "Assign",
                        target,
                        source_name.as_deref(),
                        source_call.as_deref(),
                        source_call_args,
                        source_names,
                    ),
                )
            }
            FlowEvent::Return { span, .. } => {
                self.emit(StepKind::Return, func, *span, Precision::Exact, "Return".into())
            }
            FlowEvent::Throw { span, .. } => {
                self.emit(StepKind::Throw, func, *span, Precision::Exact, "Throw".into())
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if !self.emit(StepKind::BranchSplit, func, *span, Precision::Exact, "Try".into()) {
                    return false;
                }
                let parent_path = self.current_path;
                for e in body {
                    if !self.walk_event(e, func, depth) {
                        return false;
                    }
                }
                if !catch_events.is_empty() {
                    let catch_path = self.allocate_path();
                    self.current_path = catch_path;
                    for e in catch_events {
                        if !self.walk_event(e, func, depth) {
                            self.current_path = parent_path;
                            return false;
                        }
                    }
                    for e in finally_events {
                        if !self.walk_event(e, func, depth) {
                            self.current_path = parent_path;
                            return false;
                        }
                    }
                    if !self.emit(StepKind::Merge, func, *span, Precision::Exact, "Try exit".into()) {
                        self.current_path = parent_path;
                        return false;
                    }
                    self.current_path = parent_path;
                }
                for e in finally_events {
                    if !self.walk_event(e, func, depth) {
                        return false;
                    }
                }
                self.emit(StepKind::Merge, func, *span, Precision::Exact, "Try exit".into())
            }
            FlowEvent::Break { span, label } => self.emit(
                StepKind::Diagnostic,
                func,
                *span,
                Precision::Exact,
                label
                    .as_ref()
                    .map(|l| format!("Break {l}"))
                    .unwrap_or_else(|| "Break".into()),
            ),
            FlowEvent::Continue { span, label } => self.emit(
                StepKind::Diagnostic,
                func,
                *span,
                Precision::Exact,
                label
                    .as_ref()
                    .map(|l| format!("Continue {l}"))
                    .unwrap_or_else(|| "Continue".into()),
            ),
            FlowEvent::Yield { span, value_text } => self.emit(
                StepKind::Yield,
                func,
                *span,
                Precision::Exact,
                value_text
                    .as_ref()
                    .map(|t| format!("Yield {t}"))
                    .unwrap_or_else(|| "Yield".into()),
            ),
            FlowEvent::Await { span, .. } => {
                self.emit(StepKind::Await, func, *span, Precision::Exact, "Await".into())
            }
            FlowEvent::Defer { span, body } => {
                if !self.emit(
                    StepKind::BranchSplit,
                    func,
                    *span,
                    Precision::Exact,
                    "Defer".into(),
                ) {
                    return false;
                }
                for e in body {
                    if !self.walk_event(e, func, depth) {
                        return false;
                    }
                }
                true
            }
            FlowEvent::Using { span, body } => {
                if !self.emit(
                    StepKind::BranchSplit,
                    func,
                    *span,
                    Precision::Exact,
                    "Using".into(),
                ) {
                    return false;
                }
                for e in body {
                    if !self.walk_event(e, func, depth) {
                        return false;
                    }
                }
                self.emit(
                    StepKind::Merge,
                    func,
                    *span,
                    Precision::Exact,
                    "Using exit".into(),
                )
            }
            FlowEvent::Lifecycle {
                span,
                name,
                transition,
            } => self.emit(
                StepKind::Lifecycle,
                func,
                *span,
                Precision::Exact,
                format!("Lifecycle {name} -> {transition}"),
            ),
        }
    }

    fn emit_call(&mut self, site: CallSite<'_>, func: FuncId, depth: u16) -> bool {
        // Resolution order:
        //   1. Resolved semantic callgraph edge for this exact call site.
        //   2. Active call-frame parameter/local binding for context-sensitive
        //      higher-order callbacks.
        // Anything else is reported as incomplete instead of re-resolved by a
        // trace-local fallback that could disagree with the callgraph.
        let graph_resolution = self.resolve_callgraph_site(func, &site);
        let graph_sym = match graph_resolution {
            SiteResolution::Resolved(sym) if self.is_trace_expandable(sym) => Some(sym),
            SiteResolution::Resolved(_) => None,
            SiteResolution::Ambiguous { .. } | SiteResolution::Unresolved => None,
        };

        let callback_sym = if graph_sym.is_none() {
            self.frames.last().and_then(|f| {
                f.callbacks
                    .get(site.name)
                    .or_else(|| f.locals.get(site.name))
                    .copied()
                    .filter(|sym| self.is_trace_expandable(*sym))
            })
        } else {
            None
        };

        let resolved_call = graph_sym.or(callback_sym);
        let resolved_by_graph = graph_sym.is_some();
        let display_kind = site.call_kind;
        let label = match display_kind {
            CallKind::Constructor => format!("New {}", site.name),
            CallKind::Method => format!("Method call {}", site.name),
            CallKind::Macro => format!("Macro {}", site.name),
            CallKind::Indirect => format!("Indirect call {}", site.name),
            CallKind::ChannelSend => format!("Channel send {}", site.name),
            CallKind::Function => format!("Call {}", site.name),
        };

        let Some(sym) = resolved_call else {
            let call_name = site.name.trim();
            let diagnostic = match graph_resolution {
                SiteResolution::Ambiguous { candidates } => {
                    self.out
                        .mark_incomplete(format!("ambiguous-call:{call_name}:{candidates}"));
                    format!("Ambiguous call {call_name}")
                }
                SiteResolution::Resolved(_) | SiteResolution::Unresolved => {
                    self.out.mark_incomplete(format!("unresolved-call:{call_name}"));
                    format!("Unresolved call {call_name}")
                }
            };
            return self.emit(
                StepKind::Diagnostic,
                func,
                site.span,
                Precision::Exact,
                diagnostic,
            );
        };

        let precision = match display_kind {
            CallKind::Constructor => Precision::Exact,
            _ => Precision::Narrowed,
        };
        if !self.emit(StepKind::Call, func, site.span, precision, label) {
            return false;
        }

        if !self.expand(sym, site.args, &self.get_param_names(sym), depth + 1) {
            return false;
        }
        let ret_label = if display_kind == CallKind::Constructor {
            format!("Return from new {}", site.name)
        } else {
            format!("Return from {}", site.name)
        };
        if !self.emit(StepKind::Return, func, site.span, Precision::Exact, ret_label) {
            return false;
        }
        if display_kind == CallKind::Method && !resolved_by_graph {
            for arg in semantic_receiver_callback_args(&site) {
                let Some(callback) = self.resolve_callable_arg(&arg.value_text, func) else {
                    continue;
                };
                if !self.expand(callback, &[], &self.get_param_names(callback), depth + 1) {
                    return false;
                }
                if !self.emit(
                    StepKind::Return,
                    func,
                    site.span,
                    Precision::Narrowed,
                    format!("Return from callback {}", arg.value_text.trim()),
                ) {
                    return false;
                }
            }
        }
        true
    }

    fn resolve_callgraph_site(&self, caller: FuncId, site: &CallSite<'_>) -> SiteResolution {
        let mut out = Vec::new();
        let mut seen = AHashSet::new();
        let callback_arg_spans: Vec<Span> = if site.call_kind == CallKind::Method {
            semantic_receiver_callback_args(site)
                .into_iter()
                .map(|arg| arg.span)
                .collect()
        } else {
            Vec::new()
        };
        for edge in self.call_graph.callees_of(caller) {
            let same_site = edge.span == site.span
                || (edge.kind == EdgeKind::Indirect && callback_arg_spans.contains(&edge.span));
            if !edge.precision.is_semantic() || !same_site {
                continue;
            }
            if seen.insert(edge.to) {
                out.push(SymbolId::new(edge.to.raw()));
            }
        }
        match out.len() {
            0 => SiteResolution::Unresolved,
            1 => SiteResolution::Resolved(out[0]),
            candidates => SiteResolution::Ambiguous { candidates },
        }
    }

    fn is_trace_expandable(&self, symbol: SymbolId) -> bool {
        self.db.global_index().decl_of(symbol).is_some_and(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && decl.body_span.is_some()
        })
    }

    fn resolve_callable_arg(&self, raw: &str, caller: FuncId) -> Option<SymbolId> {
        let trimmed = raw.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
        if trimmed.is_empty()
            || trimmed.starts_with('"')
            || trimmed.starts_with('\'')
            || trimmed.starts_with('`')
            || trimmed.contains("=>")
        {
            return None;
        }
        let short = bonsai_lang_api::kit::short_name_of(trimmed);
        self.frames
            .last()
            .and_then(|f| {
                f.callbacks
                    .get(trimmed)
                    .or_else(|| f.callbacks.get(short))
                    .or_else(|| f.locals.get(trimmed))
                    .or_else(|| f.locals.get(short))
                    .copied()
            })
            .or_else(|| {
                let global = self.db.global_index();
                let caller_decl = global.decl_of(SymbolId::new(caller.raw()))?;
                self.resolve_callable_by_name(trimmed, caller_decl)
            })
    }

    /// Resolve a textual callable name in the caller's file/module
    /// context. This is intentionally not a bare global-name
    /// lookup: visibility, module path, import aliases, and local
    /// type facts must all flow through `ResolveContext`.
    fn resolve_callable_by_name(&self, raw: &str, caller_decl: &Decl) -> Option<SymbolId> {
        if raw.is_empty() {
            return None;
        }
        let trimmed = raw.trim().trim_start_matches('&').trim_start_matches('*');
        let global = self.db.global_index();
        let caller_file = global
            .declaring_file(caller_decl.symbol)
            .unwrap_or(caller_decl.span.file);
        let alias_map = self.alias_map_for_decl(caller_decl);
        let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(&alias_map);
        for candidate in callable_name_variants(trimmed) {
            let hits = resolve_callable_with_context(&global, &candidate, &ctx)
                .into_iter()
                .map(|func| SymbolId::new(func.raw()))
                .collect::<Vec<_>>();
            if let Some(sym) = self.best_symbol_candidate(hits, caller_decl) {
                return Some(sym);
            }
        }
        None
    }

    fn type_name_for_expr(&self, expr: &str, caller_decl: &Decl) -> Option<String> {
        let normalized = normalize_receiver_alias_text(expr);
        let tail = bonsai_lang_api::kit::short_name_of(&normalized);
        let self_tail = format!("self.{tail}");
        let this_tail = format!("this.{tail}");
        self.frames
            .last()
            .and_then(|frame| {
                frame
                    .types
                    .get(expr)
                    .or_else(|| frame.types.get(normalized.as_str()))
                    .or_else(|| frame.types.get(tail))
                    .or_else(|| frame.types.get(self_tail.as_str()))
                    .or_else(|| frame.types.get(this_tail.as_str()))
                    .cloned()
            })
            .or_else(|| {
                caller_decl
                    .type_aliases
                    .iter()
                    .find(|alias| {
                        alias.name == expr
                            || alias.name == normalized
                            || alias.name == tail
                            || alias.name == self_tail
                            || alias.name == this_tail
                    })
                    .map(|alias| alias.type_name.clone())
            })
    }

    fn infer_assigned_type(
        &self,
        caller_decl: &Decl,
        source_name: Option<&str>,
        source_call: Option<&str>,
        source_names: &[String],
    ) -> Option<String> {
        if let Some(source_name) = source_name {
            if let Some(type_name) = self.type_name_for_expr(source_name, caller_decl) {
                return Some(type_name);
            }
        }
        if let Some(call) = source_call {
            let bare = constructor_type_tail(call)?;
            return Some(bare.to_string());
        }
        if source_names.len() == 2
            && source_names[0]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_uppercase())
        {
            return Some(source_names[0].clone());
        }
        None
    }

    fn alias_map_for_decl(&self, decl: &Decl) -> AHashMap<String, AliasTarget> {
        let mut map = self
            .db
            .import_index(decl.span.file)
            .map(|imports| bonsai_lang_api::alias_map_from_imports(imports.as_ref()))
            .unwrap_or_default();
        extend_alias_map_with_declared_types(&mut map, &decl.type_aliases);
        bonsai_lang_api::extend_alias_map_with_flow_events(&mut map, &decl.flow_events);
        map.into_iter().collect()
    }

    fn best_symbol_candidate(&self, mut hits: Vec<SymbolId>, caller_decl: &Decl) -> Option<SymbolId> {
        if hits.is_empty() {
            return None;
        }
        let global = self.db.global_index();
        let vfs = self.db.vfs();
        let caller_file = global
            .declaring_file(caller_decl.symbol)
            .unwrap_or(caller_decl.span.file);
        let rank = |sym: SymbolId| {
            let decl = global.decl_of(sym);
            let file = global.declaring_file(sym).or_else(|| decl.map(|d| d.span.file));
            let same_file = file == Some(caller_file);
            let same_module = decl.is_some_and(|decl| {
                !decl.module_path.is_empty() && decl.module_path.matches(&caller_decl.module_path)
            });
            (same_file, same_module)
        };
        hits.sort_by(|a_sym, b_sym| {
            let a = global.decl_of(*a_sym);
            let b = global.decl_of(*b_sym);
            let a_file = global.declaring_file(*a_sym).or_else(|| a.map(|d| d.span.file));
            let b_file = global.declaring_file(*b_sym).or_else(|| b.map(|d| d.span.file));
            let a_same_file = a_file == Some(caller_file);
            let b_same_file = b_file == Some(caller_file);
            let a_same_module = a.is_some_and(|decl| {
                !decl.module_path.is_empty() && decl.module_path.matches(&caller_decl.module_path)
            });
            let b_same_module = b.is_some_and(|decl| {
                !decl.module_path.is_empty() && decl.module_path.matches(&caller_decl.module_path)
            });
            let a_path = a_file
                .and_then(|file| vfs.path(file).ok())
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            let b_path = b_file
                .and_then(|file| vfs.path(file).ok())
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
            b_same_file
                .cmp(&a_same_file)
                .then_with(|| b_same_module.cmp(&a_same_module))
                .then_with(|| a_path.cmp(&b_path))
                .then_with(|| {
                    a.map(|decl| decl.name_span.start)
                        .unwrap_or_default()
                        .cmp(&b.map(|decl| decl.name_span.start).unwrap_or_default())
                })
                .then_with(|| a_sym.raw().cmp(&b_sym.raw()))
        });
        let first = hits[0];
        if hits.get(1).is_some_and(|second| rank(first) == rank(*second)) {
            return None;
        }
        Some(first)
    }

    /// Parameter-name list for `sym`, or empty if the symbol isn't
    /// a known decl.
    fn get_param_names(&self, sym: SymbolId) -> Vec<String> {
        self.db
            .global_index()
            .decl_of(sym)
            .map(|decl: &Decl| decl.params.clone())
            .unwrap_or_default()
    }
}

fn callable_name_variants(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_start_matches('&').trim_start_matches('*');
    if trimmed.is_empty() {
        return Vec::new();
    }
    let short = bonsai_lang_api::kit::short_name_of(trimmed);
    let mut out = Vec::new();
    push_unique_string(&mut out, trimmed.to_string());
    if let Some(no_bang) = trimmed.strip_suffix('!') {
        push_unique_string(&mut out, no_bang.to_string());
    }
    push_unique_string(&mut out, short.to_string());
    if let Some(short_no_bang) = short.strip_suffix('!') {
        push_unique_string(&mut out, short_no_bang.to_string());
    }
    out
}

fn normalize_receiver_alias_text(text: &str) -> String {
    text.trim()
        .trim_start_matches(['&', '*'])
        .replace("->", ".")
        .trim_matches('.')
        .to_string()
}

fn constructor_type_tail(call: &str) -> Option<&str> {
    // Peel any leading constructor keyword (`new `) before extracting
    // the rightmost type segment. Other entries in
    // VALUE_TEXT_LEADING_KEYWORDS (e.g. `return `) shouldn't appear
    // here — this site receives only the call form — but iterating
    // the constant keeps the strip future-proof against new additions.
    let mut head = call.trim();
    for keyword in bonsai_common::VALUE_TEXT_LEADING_KEYWORDS {
        if let Some(rest) = head.strip_prefix(*keyword) {
            head = rest.trim();
        }
    }
    let bare = head
        .rsplit(&['.', ':'][..])
        .next()
        .unwrap_or(call)
        .trim()
        .trim_end_matches("()");
    bare.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
        .then_some(bare)
}

fn types_from_decl(decl: &Decl) -> AHashMap<String, String> {
    decl.type_aliases
        .iter()
        .map(|alias| (alias.name.clone(), alias.type_name.clone()))
        .collect()
}

fn assignment_trace_message(
    prefix: &str,
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> String {
    let rhs = assignment_trace_rhs(source_name, source_call, source_call_args, source_names);
    match rhs {
        Some(rhs) => format!("{prefix} {target} = {rhs}"),
        None => format!("{prefix} {target}"),
    }
}

fn assignment_trace_rhs(
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
) -> Option<String> {
    if let Some(name) = source_name.map(str::trim).filter(|name| !name.is_empty()) {
        return Some(name.to_string());
    }
    if let Some(call) = source_call.map(str::trim).filter(|call| !call.is_empty()) {
        return Some(if source_call_args.is_empty() {
            format!("{call}()")
        } else {
            format!("{call}({})", source_call_args.join(", "))
        });
    }
    if !source_names.is_empty() {
        return Some(source_names.join(" + "));
    }
    if !source_call_args.is_empty() {
        return Some(source_call_args.join(", "));
    }
    None
}

fn declares_type_alias(decl: Option<&Decl>, target: &str) -> bool {
    decl.is_some_and(|decl| decl.type_aliases.iter().any(|alias| alias.name == target))
}

fn extend_alias_map_with_declared_types(
    alias_map: &mut std::collections::HashMap<String, AliasTarget>,
    aliases: &[TypeAliasBinding],
) {
    for alias in aliases {
        alias_map
            .entry(alias.name.clone())
            .or_insert_with(|| AliasTarget::Type {
                type_name: alias.type_name.clone(),
            });
    }
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|seen| seen == &value) {
        out.push(value);
    }
}
