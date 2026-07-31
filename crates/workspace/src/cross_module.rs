//! Cross-file / cross-module trace engine.
//!
//! Given a function, we walk its structured `flow_events` (produced by the
//! adapter's grammar handler). For every ordinary `Call`, we consume the
//! precomputed semantic resolved callgraph and recurse only when that graph
//! proves the target. For `Branch`, we emit a `BranchSplit` step and walk
//! both sides as separate path ids. Loops and recursive calls converge over
//! canonical semantic states, so the default trace is complete without an
//! arbitrary unroll or call-depth ceiling.
//! Higher-order callbacks are resolved by binding call-site arguments to
//! parameter names in the callee's `Decl::params`; unresolved calls are
//! recorded as incompleteness, never widened into guessed targets.

use ahash::{AHashMap, AHashSet};
use bonsai_abstract_interp::{RawStep, RawTrace, StepKind, TraceLimits};
use bonsai_callgraph::{EdgeKind, ResolvedCallGraph};
use bonsai_common::{FuncId, Precision, Span, SymbolId, TraceStepId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    AliasTarget, CallArg, CallKind, Decl, DeclKind, FlowEvent, LoopKind, TypeAliasBinding,
};
use bonsai_resolve::{resolve_callable_with_context, ResolveContext};
use std::sync::Arc;

use crate::Workspace;

#[derive(Copy, Clone, Debug)]
pub struct CrossModuleOptions {
    /// Maximum call edges from the entry. `0` means no semantic depth cap.
    pub max_depth: u16,
    /// Maximum emitted semantic steps. `0` means no requested step cap.
    pub max_steps: u32,
    /// Maximum alternatives expanded at one structured split. `0` means all.
    pub max_branch_fanout: u16,
    /// Maximum distinct loop binding states evaluated. `0` means fixed point.
    pub max_loop_iters: u16,
}

impl Default for CrossModuleOptions {
    fn default() -> Self {
        Self {
            max_depth: 0,
            max_steps: 0,
            max_branch_fanout: 0,
            max_loop_iters: 0,
        }
    }
}

impl CrossModuleOptions {
    /// Presentation metadata for `bonsai_trace::finalize`. Cross-module
    /// traversal interprets zero itself as uncapped; this value is never fed
    /// to the separately bounded abstract interpreter.
    pub(crate) fn trace_metadata_limits(self) -> TraceLimits {
        TraceLimits {
            max_steps: self.max_steps,
            max_call_depth: self.max_depth,
            max_loop_iters: self.max_loop_iters,
            max_branches: u32::from(self.max_branch_fanout),
        }
    }
}

pub(crate) struct CrossModuleTracer<'a> {
    workspace: &'a Workspace,
    headers: Arc<GlobalIndex>,
    call_graph: &'a ResolvedCallGraph,
    opts: CrossModuleOptions,
}

struct TraceBuilder<'a> {
    workspace: &'a Workspace,
    headers: Arc<GlobalIndex>,
    call_graph: &'a ResolvedCallGraph,
    opts: CrossModuleOptions,
    out: RawTrace,
    next_step: u32,
    next_path: u32,
    current_path: u32,
    /// Per-frame bindings: maps parameter-name -> concrete symbol its
    /// callback argument pointed at. Pushed on entry, popped on exit.
    frames: Vec<CallFrame>,
    /// Monotone graph fixed point. The symbol alone is insufficient because
    /// the same higher-order function can be reached with different callback
    /// and receiver-type bindings.
    expanded_states: AHashSet<ExpansionState>,
    /// Exact resolved targets indexed by compiler call-site identity. A
    /// function body can be revisited under several callback/type states;
    /// its callgraph edges do not change between those states.
    resolved_site_cache: AHashMap<(FuncId, Span), Vec<ResolvedTarget>>,
    /// Contextual textual callable resolution is likewise a pure function of
    /// the caller declaration and spelling. Memoize it instead of rebuilding
    /// import/type alias maps for every abstract state.
    callable_resolution_cache: AHashMap<(SymbolId, String), Option<SymbolId>>,
}

#[derive(Default, Clone)]
struct CallFrame {
    /// parameter name -> callable symbol passed at the call site
    callbacks: AHashMap<String, AHashSet<SymbolId>>,
    /// whole-local variable bindings (e.g. `x = some_func`)
    locals: AHashMap<String, AHashSet<SymbolId>>,
    /// local / parameter / field receiver type bindings visible in
    /// this frame. Seeded from adapter-emitted `Decl.type_aliases`
    /// and updated from call-site parameter bindings.
    types: AHashMap<String, AHashSet<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ExpansionState {
    symbol: SymbolId,
    callbacks: Vec<(String, Vec<SymbolId>)>,
    types: Vec<(String, Vec<String>)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FrameState {
    callbacks: Vec<(String, Vec<SymbolId>)>,
    locals: Vec<(String, Vec<SymbolId>)>,
    types: Vec<(String, Vec<String>)>,
}

impl CallFrame {
    fn expansion_state(&self, symbol: SymbolId) -> ExpansionState {
        ExpansionState {
            symbol,
            callbacks: canonical_symbol_bindings(&self.callbacks),
            types: canonical_string_bindings(&self.types),
        }
    }

    fn state(&self) -> FrameState {
        FrameState {
            callbacks: canonical_symbol_bindings(&self.callbacks),
            locals: canonical_symbol_bindings(&self.locals),
            types: canonical_string_bindings(&self.types),
        }
    }

    fn merge_alternative(&mut self, other: &Self) {
        merge_binding_map(&mut self.callbacks, &other.callbacks);
        merge_binding_map(&mut self.locals, &other.locals);
        merge_binding_map(&mut self.types, &other.types);
    }

    fn bound_callables(&self, name: &str) -> Vec<SymbolId> {
        let mut out = AHashSet::new();
        if let Some(symbols) = self.callbacks.get(name) {
            out.extend(symbols.iter().copied());
        }
        if let Some(symbols) = self.locals.get(name) {
            out.extend(symbols.iter().copied());
        }
        let mut out: Vec<_> = out.into_iter().collect();
        out.sort_by_key(|symbol| symbol.raw());
        out
    }
}

fn canonical_symbol_bindings(
    bindings: &AHashMap<String, AHashSet<SymbolId>>,
) -> Vec<(String, Vec<SymbolId>)> {
    let mut out: Vec<_> = bindings
        .iter()
        .map(|(name, values)| {
            let mut values: Vec<_> = values.iter().copied().collect();
            values.sort_by_key(|symbol| symbol.raw());
            (name.clone(), values)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn canonical_string_bindings(bindings: &AHashMap<String, AHashSet<String>>) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<_> = bindings
        .iter()
        .map(|(name, values)| {
            let mut values: Vec<_> = values.iter().cloned().collect();
            values.sort();
            (name.clone(), values)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn merge_binding_map<T>(into: &mut AHashMap<String, AHashSet<T>>, from: &AHashMap<String, AHashSet<T>>)
where
    T: Clone + Eq + std::hash::Hash,
{
    for (name, values) in from {
        into.entry(name.clone())
            .or_default()
            .extend(values.iter().cloned());
    }
}

struct CallSite<'a> {
    span: Span,
    name: &'a str,
    call_kind: CallKind,
    args: &'a [CallArg],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ResolvedTarget {
    symbol: SymbolId,
    /// Whether this edge represents invocation of the call site's arguments.
    /// Callback edges attached to an argument span do not: the callback's own
    /// invocation parameters are supplied by the receiving API.
    bind_site_args: bool,
}

impl<'a> CrossModuleTracer<'a> {
    #[must_use]
    pub(crate) fn new(
        workspace: &'a Workspace,
        headers: Arc<GlobalIndex>,
        call_graph: &'a ResolvedCallGraph,
        opts: CrossModuleOptions,
    ) -> Self {
        Self {
            workspace,
            headers,
            call_graph,
            opts,
        }
    }

    pub(crate) fn trace(&self, start: SymbolId) -> RawTrace {
        let mut builder = TraceBuilder {
            workspace: self.workspace,
            headers: Arc::clone(&self.headers),
            call_graph: self.call_graph,
            opts: self.opts,
            out: RawTrace::default(),
            next_step: 0,
            next_path: 1,
            current_path: 1,
            frames: vec![CallFrame::default()],
            expanded_states: AHashSet::new(),
            resolved_site_cache: AHashMap::new(),
            callable_resolution_cache: AHashMap::new(),
        };
        builder.expand(start, &[], None, 0);
        builder.out
    }
}

impl<'a> TraceBuilder<'a> {
    fn emit(&mut self, kind: StepKind, func: FuncId, span: Span, precision: Precision, msg: String) -> bool {
        if self.opts.max_steps != 0 && self.next_step >= self.opts.max_steps {
            self.out.mark_truncated("max-steps");
            return false;
        }
        if self.next_step == u32::MAX {
            self.out.mark_truncated("trace-step-id-space");
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

    fn allocate_path(&mut self) -> Option<u32> {
        let Some(next) = self.next_path.checked_add(1) else {
            self.out.mark_truncated("trace-path-id-space");
            return None;
        };
        self.next_path = next;
        Some(next)
    }

    /// Expand one semantic graph state. `args` bind structured call-site
    /// values to the callee's AST-declared parameters.
    fn expand(&mut self, symbol: SymbolId, args: &[CallArg], caller: Option<FuncId>, depth: usize) -> bool {
        if self.opts.max_depth != 0 && depth > usize::from(self.opts.max_depth) {
            self.out.mark_truncated("max-depth");
            return true;
        }
        let Some(exact_decl) = self
            .workspace
            .exact_decl_with_headers(symbol, Arc::clone(&self.headers))
        else {
            return true;
        };
        let decl = &*exact_decl;
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            return true;
        }
        let func = FuncId::new(symbol.raw());

        // Build a new frame; bind parameter names to concrete callables
        // when the argument at that position resolves to one.
        let mut frame = CallFrame {
            types: types_from_decl(&decl),
            ..Default::default()
        };
        let binding_exact = caller.and_then(|func| {
            self.workspace
                .exact_decl_with_headers(SymbolId::new(func.raw()), Arc::clone(&self.headers))
        });
        let binding_decl = binding_exact.as_ref().map_or(decl, |exact| &**exact);
        for (idx, param) in decl.params.iter().enumerate() {
            // Keyword-arg match first.
            let kw = args.iter().find(|a| a.name.as_deref() == Some(param.as_str()));
            let positional = args.get(idx);
            let arg = kw.or(positional);
            if let Some(a) = arg {
                if let Some(sym) = self.resolve_callable_by_name(&a.value_text, binding_decl) {
                    frame.callbacks.entry(param.clone()).or_default().insert(sym);
                }
                frame
                    .types
                    .entry(param.clone())
                    .or_default()
                    .extend(self.type_names_for_expr(&a.value_text, binding_decl));
            }
        }
        let state = frame.expansion_state(symbol);
        if !self.expanded_states.insert(state) {
            // Reaching an already-expanded semantic state closes a recursive
            // or diamond edge. This is convergence, not truncation.
            return true;
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
        ok
    }

    fn walk_events(&mut self, events: &[FlowEvent], func: FuncId, depth: usize) -> bool {
        for event in events {
            if !self.walk_event(event, func, depth) {
                return false;
            }
        }
        true
    }

    fn walk_event(&mut self, event: &FlowEvent, func: FuncId, depth: usize) -> bool {
        match event {
            FlowEvent::Call {
                span,
                name,
                call_kind,
                args,
                ..
            } => self.emit_call(
                CallSite {
                    span: *span,
                    name,
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
                let entry_frame = self.frames.last().cloned().unwrap_or_default();
                if !self.walk_events(then_events, func, depth) {
                    return false;
                }
                let then_frame = self.frames.last().cloned().unwrap_or_default();
                let mut merged_frame = then_frame;
                if !else_events.is_empty() {
                    if self.opts.max_branch_fanout == 1 {
                        self.out.mark_truncated("max-branch-fanout");
                    } else {
                        let Some(else_path) = self.allocate_path() else {
                            return false;
                        };
                        self.current_path = else_path;
                        if let Some(frame) = self.frames.last_mut() {
                            *frame = entry_frame.clone();
                        }
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
                        let else_frame = self.frames.last().cloned().unwrap_or_default();
                        merged_frame.merge_alternative(&else_frame);
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
                } else {
                    // An if-without-else also has the path on which the body
                    // is skipped; preserve both binding states at the join.
                    merged_frame.merge_alternative(&entry_frame);
                }
                if let Some(frame) = self.frames.last_mut() {
                    *frame = merged_frame;
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
                let mut states = AHashSet::new();
                let mut iterations = 0usize;
                loop {
                    let before = self
                        .frames
                        .last()
                        .map(CallFrame::state)
                        .unwrap_or_else(|| CallFrame::default().state());
                    if !states.insert(before.clone()) {
                        break;
                    }
                    if self.opts.max_loop_iters != 0 && iterations >= usize::from(self.opts.max_loop_iters) {
                        self.out.mark_truncated("max-loop-iters");
                        break;
                    }
                    iterations += 1;
                    if !self.walk_events(body, func, depth) {
                        return false;
                    }
                    let after = self
                        .frames
                        .last()
                        .map(CallFrame::state)
                        .unwrap_or_else(|| CallFrame::default().state());
                    if after == before || states.contains(&after) {
                        break;
                    }
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
                let caller_exact = self
                    .workspace
                    .exact_decl_with_headers(SymbolId::new(func.raw()), Arc::clone(&self.headers));
                let caller_decl = caller_exact.as_ref().map(|exact| &**exact);
                let assigned_callable = source_name
                    .as_deref()
                    .and_then(|name| caller_decl.and_then(|decl| self.resolve_callable_by_name(name, decl)));
                if let Some(frame) = self.frames.last_mut() {
                    frame.locals.remove(target);
                    if let Some(symbol) = assigned_callable {
                        frame.locals.entry(target.clone()).or_default().insert(symbol);
                    }
                }
                let assigned_types = caller_decl
                    .map(|decl| self.infer_assigned_types(decl, source_name.as_deref()))
                    .unwrap_or_default();
                if !assigned_types.is_empty() {
                    if let Some(frame) = self.frames.last_mut() {
                        frame.types.insert(target.clone(), assigned_types);
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
            FlowEvent::AggregateAssign { span, target, .. } => self.emit(
                StepKind::Assign,
                func,
                *span,
                Precision::Exact,
                format!("Initialize aggregate {target}"),
            ),
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
                let entry_frame = self.frames.last().cloned().unwrap_or_default();
                for e in body {
                    if !self.walk_event(e, func, depth) {
                        return false;
                    }
                }
                for e in finally_events {
                    if !self.walk_event(e, func, depth) {
                        return false;
                    }
                }
                let mut merged_frame = self.frames.last().cloned().unwrap_or_default();
                if !catch_events.is_empty() {
                    if self.opts.max_branch_fanout == 1 {
                        self.out.mark_truncated("max-branch-fanout");
                    } else {
                        let Some(catch_path) = self.allocate_path() else {
                            return false;
                        };
                        self.current_path = catch_path;
                        if let Some(frame) = self.frames.last_mut() {
                            *frame = entry_frame;
                        }
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
                        merged_frame.merge_alternative(&self.frames.last().cloned().unwrap_or_default());
                        if !self.emit(StepKind::Merge, func, *span, Precision::Exact, "Try exit".into()) {
                            self.current_path = parent_path;
                            return false;
                        }
                        self.current_path = parent_path;
                    }
                }
                if let Some(frame) = self.frames.last_mut() {
                    *frame = merged_frame;
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
            FlowEvent::Yield { span, value_text, .. } => self.emit(
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

    fn emit_call(&mut self, site: CallSite<'_>, func: FuncId, depth: usize) -> bool {
        // Resolution order:
        //   1. Resolved semantic callgraph edge for this exact call site.
        //   2. Active call-frame parameter/local binding for context-sensitive
        //      higher-order callbacks. These bindings are unioned because a
        //      branch join can retain alternatives that the context-free graph
        //      represents with only one whole-function local binding.
        // Anything else is reported as incomplete rather than widened through
        // a workspace name inventory.
        let mut resolved_calls = self.resolve_callgraph_site(func, &site);
        if let Some(frame) = self.frames.last() {
            resolved_calls.extend(frame.bound_callables(site.name).into_iter().map(|symbol| {
                ResolvedTarget {
                    symbol,
                    bind_site_args: true,
                }
            }));
            let short = bonsai_lang_api::kit::short_name_of(site.name);
            if short != site.name {
                resolved_calls.extend(frame.bound_callables(short).into_iter().map(|symbol| {
                    ResolvedTarget {
                        symbol,
                        bind_site_args: true,
                    }
                }));
            }
        }
        resolved_calls.retain(|target| self.is_trace_expandable(target.symbol));
        resolved_calls.sort_by_key(|target| (target.symbol.raw(), !target.bind_site_args));
        resolved_calls.dedup_by_key(|target| target.symbol);
        let display_kind = site.call_kind;
        let label = match display_kind {
            CallKind::Constructor => format!("New {}", site.name),
            CallKind::Method => format!("Method call {}", site.name),
            CallKind::Macro => format!("Macro {}", site.name),
            CallKind::Operator => format!("Operator {}", site.name),
            CallKind::Indirect => format!("Indirect call {}", site.name),
            CallKind::ChannelSend => format!("Channel send {}", site.name),
            CallKind::Function => format!("Call {}", site.name),
        };

        if resolved_calls.is_empty() {
            let call_name = site.name.trim();
            self.out.mark_incomplete(format!("unresolved-call:{call_name}"));
            return self.emit(
                StepKind::Diagnostic,
                func,
                site.span,
                Precision::Exact,
                format!("Unresolved call {call_name}"),
            );
        }

        let allowed = if self.opts.max_branch_fanout == 0 {
            resolved_calls.len()
        } else {
            resolved_calls.len().min(usize::from(self.opts.max_branch_fanout))
        };
        if allowed < resolved_calls.len() {
            self.out.mark_truncated("max-branch-fanout");
            resolved_calls.truncate(allowed);
        }

        let precision = match display_kind {
            CallKind::Constructor => Precision::Exact,
            _ => Precision::Narrowed,
        };
        let ret_label = if display_kind == CallKind::Constructor {
            format!("Return from new {}", site.name)
        } else {
            format!("Return from {}", site.name)
        };
        let parent_path = self.current_path;
        if resolved_calls.len() > 1
            && !self.emit(
                StepKind::BranchSplit,
                func,
                site.span,
                Precision::Narrowed,
                format!("Call target split {}", site.name),
            )
        {
            return false;
        }
        for (idx, target) in resolved_calls.into_iter().enumerate() {
            if idx > 0 {
                let Some(path) = self.allocate_path() else {
                    return false;
                };
                self.current_path = path;
            }
            if !self.emit(StepKind::Call, func, site.span, precision, label.clone()) {
                self.current_path = parent_path;
                return false;
            }
            let args = if target.bind_site_args { site.args } else { &[] };
            if !self.expand(target.symbol, args, Some(func), depth + 1) {
                self.current_path = parent_path;
                return false;
            }
            if !self.emit(
                StepKind::Return,
                func,
                site.span,
                Precision::Exact,
                ret_label.clone(),
            ) {
                self.current_path = parent_path;
                return false;
            }
        }
        self.current_path = parent_path;
        true
    }

    fn resolve_callgraph_site(&mut self, caller: FuncId, site: &CallSite<'_>) -> Vec<ResolvedTarget> {
        let cache_key = (caller, site.span);
        if let Some(cached) = self.resolved_site_cache.get(&cache_key) {
            return cached.clone();
        }
        let mut out = Vec::new();
        let mut seen = AHashMap::new();
        let arg_spans: AHashSet<Span> = site.args.iter().map(|arg| arg.span).collect();
        for edge in self.call_graph.callees_of(caller) {
            let direct_site = edge.span == site.span;
            let callback_site = edge.kind == EdgeKind::Indirect && arg_spans.contains(&edge.span);
            let same_site = direct_site || callback_site;
            if !edge.precision.is_semantic() || !same_site {
                continue;
            }
            seen.entry(SymbolId::new(edge.to.raw()))
                .and_modify(|bind_site_args| *bind_site_args |= direct_site)
                .or_insert(direct_site);
        }
        out.extend(seen.into_iter().map(|(symbol, bind_site_args)| ResolvedTarget {
            symbol,
            bind_site_args,
        }));
        out.sort_by_key(|target| target.symbol.raw());
        self.resolved_site_cache.insert(cache_key, out.clone());
        out
    }

    fn is_trace_expandable(&self, symbol: SymbolId) -> bool {
        self.headers.decl_of(symbol).is_some_and(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && decl.body_span.is_some()
        })
    }

    /// Resolve a textual callable name in the caller's file/module
    /// context. This is intentionally not a bare global-name
    /// lookup: visibility, module path, import aliases, and local
    /// type facts must all flow through `ResolveContext`.
    fn resolve_callable_by_name(&mut self, raw: &str, caller_decl: &Decl) -> Option<SymbolId> {
        if raw.is_empty() {
            return None;
        }
        let trimmed = raw.trim();
        let cache_key = (caller_decl.symbol, trimmed.to_string());
        if let Some(cached) = self.callable_resolution_cache.get(&cache_key) {
            return *cached;
        }
        let global = &self.headers;
        let caller_file = global
            .declaring_file(caller_decl.symbol)
            .unwrap_or(caller_decl.span.file);
        let alias_map = self.alias_map_for_decl(caller_decl);
        let capabilities = self
            .workspace
            .db()
            .adapter_for(caller_file)
            .map(|adapter| adapter.capabilities())
            .unwrap_or_else(bonsai_lang_api::LanguageCapabilities::unsupported);
        let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
            .with_alias_map(&alias_map)
            .with_same_directory_unqualified_calls(capabilities.same_directory_unqualified_calls)
            .with_module_path_syntax(capabilities.module_path_syntax);
        for candidate in callable_name_variants(trimmed) {
            let hits = resolve_callable_with_context(global, &candidate, &ctx)
                .into_iter()
                .map(|func| SymbolId::new(func.raw()))
                .collect::<Vec<_>>();
            if let Some(sym) = self.best_symbol_candidate(hits, caller_decl) {
                self.callable_resolution_cache.insert(cache_key, Some(sym));
                return Some(sym);
            }
        }
        self.callable_resolution_cache.insert(cache_key, None);
        None
    }

    fn type_names_for_expr(&self, expr: &str, caller_decl: &Decl) -> AHashSet<String> {
        let normalized = expr.trim();
        let tail = bonsai_lang_api::kit::short_name_of(normalized);
        let mut aliases = vec![expr, normalized, tail];
        let mut receiver_aliases = Vec::new();
        for receiver in &caller_decl.implicit_receiver_names {
            receiver_aliases.push(format!("{receiver}.{tail}"));
        }
        if let Some(receiver_index) = caller_decl.receiver_param_index {
            if let Some(receiver) = caller_decl.params.get(receiver_index) {
                receiver_aliases.push(format!("{receiver}.{tail}"));
            }
        }
        aliases.extend(receiver_aliases.iter().map(String::as_str));
        let mut out = AHashSet::new();
        if let Some(frame) = self.frames.last() {
            for alias in &aliases {
                if let Some(types) = frame.types.get(*alias) {
                    out.extend(types.iter().cloned());
                }
            }
        }
        out.extend(
            caller_decl
                .type_aliases
                .iter()
                .filter(|binding| aliases.iter().any(|alias| binding.name == *alias))
                .map(|binding| binding.type_name.clone()),
        );
        out
    }

    fn infer_assigned_types(&self, caller_decl: &Decl, source_name: Option<&str>) -> AHashSet<String> {
        let mut out = AHashSet::new();
        if let Some(source_name) = source_name {
            out.extend(self.type_names_for_expr(source_name, caller_decl));
        }
        out
    }

    fn alias_map_for_decl(&self, decl: &Decl) -> AHashMap<String, AliasTarget> {
        let mut map = self
            .workspace
            .db()
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
        let global = &self.headers;
        let vfs = self.workspace.db().vfs();
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
}

fn callable_name_variants(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let short = bonsai_lang_api::kit::short_name_of(trimmed);
    let mut out = Vec::new();
    push_unique_string(&mut out, trimmed.to_string());
    push_unique_string(&mut out, short.to_string());
    out
}

fn types_from_decl(decl: &Decl) -> AHashMap<String, AHashSet<String>> {
    let mut out: AHashMap<String, AHashSet<String>> = AHashMap::new();
    for alias in &decl.type_aliases {
        out.entry(alias.name.clone())
            .or_default()
            .insert(alias.type_name.clone());
    }
    out
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
