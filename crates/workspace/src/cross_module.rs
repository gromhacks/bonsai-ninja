//! Cross-file / cross-module trace engine.
//!
//! Given a function, we walk its structured `flow_events` (produced by the
//! adapter's grammar handler). For every `Call`, we resolve the callee
//! across the workspace and recurse. For `Branch`, we emit a `BranchSplit`
//! step and walk both sides as separate path ids. For `Loop`, we emit
//! `LoopEnter` / `LoopExit` and walk the body once with an `Iterate` marker.
//! For `Constructor` calls we route to the class's constructor method.
//! Higher-order callbacks are resolved by binding call-site arguments to
//! parameter names in the callee's `Decl::params`.

use ahash::AHashSet;
use bonsai_abstract_interp::{RawStep, RawTrace, StepKind, TraceLimits};
use bonsai_common::{FuncId, Precision, Span, SymbolId, TraceStepId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{CallArg, CallKind, Decl, DeclKind, FlowEvent, LoopKind};

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
    opts: CrossModuleOptions,
}

struct TraceBuilder<'a> {
    db: &'a AnalyzerDb,
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
    callback_bindings: ahash::AHashMap<String, SymbolId>,
    /// whole-local variable bindings (e.g. `x = some_func`)
    local_bindings: ahash::AHashMap<String, SymbolId>,
}

struct CallSite<'a> {
    span: Span,
    name: &'a str,
    receiver: Option<&'a str>,
    call_kind: CallKind,
    args: &'a [CallArg],
}

impl<'a> CrossModuleTracer<'a> {
    #[must_use]
    pub(crate) fn new(db: &'a AnalyzerDb, opts: CrossModuleOptions) -> Self {
        Self { db, opts }
    }

    pub(crate) fn trace(&self, start: SymbolId) -> RawTrace {
        let mut builder = TraceBuilder {
            db: self.db,
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
            self.out.truncated = true;
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
            self.out.truncated = true;
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
        let mut frame = CallFrame::default();
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
                if let Some(sym) = self.resolve_callable_by_name(&a.value_text) {
                    frame.callback_bindings.insert(param.clone(), sym);
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
            decl.body_span.unwrap_or(decl.span),
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
                    Precision::OverApproximate,
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
                        Precision::OverApproximate,
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
                    Precision::OverApproximate,
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
                ..
            } => {
                // Record local binding for callback resolution.
                if let Some(name) = source_name {
                    if let Some(sym) = self.resolve_callable_by_name(name) {
                        if let Some(frame) = self.frames.last_mut() {
                            frame.local_bindings.insert(target.clone(), sym);
                        }
                    }
                }
                self.emit(
                    StepKind::Assign,
                    func,
                    *span,
                    Precision::Exact,
                    format!("Assign {target}"),
                )
            }
            FlowEvent::Return { span, .. } => {
                self.emit(StepKind::Return, func, *span, Precision::Exact, "Return".into())
            }
            FlowEvent::Throw { span, .. } => self.emit(
                StepKind::Throw,
                func,
                *span,
                Precision::OverApproximate,
                "Throw".into(),
            ),
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
                StepKind::Yield,
                func,
                *span,
                Precision::Exact,
                format!("Lifecycle {name} -> {transition}"),
            ),
        }
    }

    fn emit_call(&mut self, site: CallSite<'_>, func: FuncId, depth: u16) -> bool {
        // Resolution order:
        //   1. Active call-frame parameter binding (higher-order callback).
        //   2. Active call-frame local binding.
        //   3. Global class match -> route to that class's constructor.
        //   4. Global callable match.
        let callback_sym = self.frames.last().and_then(|f| {
            f.callback_bindings
                .get(site.name)
                .or_else(|| f.local_bindings.get(site.name))
                .copied()
        });

        let class_sym = if callback_sym.is_none() {
            self.find_class_by_name(site.name)
        } else {
            None
        };
        let class_ctor = class_sym.and_then(|c| self.find_constructor_for_class(c));

        let receiver_sym = if callback_sym.is_none() && class_ctor.is_none() {
            self.resolve_receiver_method(func, &site)
        } else {
            None
        };

        let global_sym = if callback_sym.is_none() && class_ctor.is_none() && receiver_sym.is_none() {
            self.resolve_callable_by_name(site.name)
        } else {
            None
        };

        let (resolved_call, is_ctor_route) = match (callback_sym, class_ctor, receiver_sym, global_sym) {
            (Some(s), _, _, _) => (Some(s), false),
            (_, Some(s), _, _) => (Some(s), true),
            (_, _, Some(s), _) => (Some(s), false),
            (_, _, _, Some(s)) => (Some(s), false),
            _ => (None, false),
        };

        let display_kind = if is_ctor_route {
            CallKind::Constructor
        } else {
            site.call_kind
        };
        let precision = match (resolved_call, display_kind) {
            (Some(_), CallKind::Constructor) => Precision::Exact,
            (Some(_), _) => Precision::Narrowed,
            (None, _) => Precision::Unknown,
        };

        let label = match display_kind {
            CallKind::Constructor => format!("New {}", site.name),
            CallKind::Method => format!("Method call {}", site.name),
            CallKind::Macro => format!("Macro {}", site.name),
            CallKind::Indirect => format!("Indirect call {}", site.name),
            CallKind::Function => format!("Call {}", site.name),
        };
        if !self.emit(StepKind::Call, func, site.span, precision, label) {
            return false;
        }

        if let Some(sym) = resolved_call {
            if !self.expand(sym, site.args, &self.get_param_names(sym), depth + 1) {
                return false;
            }
            let ret_label = if is_ctor_route {
                format!("Return from new {}", site.name)
            } else {
                format!("Return from {}", site.name)
            };
            if !self.emit(StepKind::Return, func, site.span, Precision::Exact, ret_label) {
                return false;
            }
        }
        if site.receiver.is_some() && display_kind == CallKind::Method {
            for arg in site.args {
                let Some(callback) = self.resolve_callable_arg(&arg.value_text) else {
                    continue;
                };
                if !self.expand(callback, &[], &self.get_param_names(callback), depth + 1) {
                    return false;
                }
                if !self.emit(
                    StepKind::Return,
                    func,
                    site.span,
                    Precision::OverApproximate,
                    format!("Return from callback {}", arg.value_text.trim()),
                ) {
                    return false;
                }
            }
        }
        true
    }

    fn resolve_receiver_method(&self, caller: FuncId, site: &CallSite<'_>) -> Option<SymbolId> {
        if site.call_kind != CallKind::Method {
            return None;
        }
        let receiver = site.receiver?;
        let global = self.db.global_index();
        let caller_decl = global.decl_of(SymbolId::new(caller.raw()))?;
        let receiver_tail = bonsai_lang_api::kit::short_name_of(receiver);
        let type_name = caller_decl
            .type_aliases
            .iter()
            .find(|alias| alias.name == receiver || alias.name == receiver_tail)
            .map(|alias| alias.type_name.as_str())?;
        let method_name = bonsai_lang_api::kit::short_name_of(site.name);
        self.find_method_in_class(type_name, method_name)
    }

    fn find_method_in_class(&self, class_name: &str, method_name: &str) -> Option<SymbolId> {
        let global = self.db.global_index();
        let class_symbols = global
            .find_by_name(class_name)
            .iter()
            .copied()
            .filter(|sym| {
                global
                    .decl_of(*sym)
                    .is_some_and(|decl| matches!(decl.kind, DeclKind::Class | DeclKind::Struct))
            })
            .collect::<Vec<_>>();
        for class_sym in class_symbols {
            let Some(class_file) = global.declaring_file(class_sym) else {
                continue;
            };
            let Some(class_decl) = global.decl_of(class_sym) else {
                continue;
            };
            for decl in global.decls_in(class_file) {
                if decl.name != method_name || !self.is_callable(decl.symbol) {
                    continue;
                }
                if decl.parent == Some(class_sym) || span_contains(class_decl.span, decl.span) {
                    return Some(decl.symbol);
                }
            }
        }
        None
    }

    fn resolve_callable_arg(&self, raw: &str) -> Option<SymbolId> {
        let trimmed = raw.trim().trim_start_matches('&').trim_start_matches('*');
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
                f.callback_bindings
                    .get(trimmed)
                    .or_else(|| f.callback_bindings.get(short))
                    .or_else(|| f.local_bindings.get(trimmed))
                    .or_else(|| f.local_bindings.get(short))
                    .copied()
            })
            .or_else(|| self.resolve_callable_by_name(trimmed))
    }

    /// Resolve a textual callable name (with optional sigil / module
    /// prefix) to one workspace symbol, deterministically.
    fn resolve_callable_by_name(&self, raw: &str) -> Option<SymbolId> {
        if raw.is_empty() {
            return None;
        }
        let trimmed = raw.trim().trim_start_matches('&').trim_start_matches('*');
        // Ruby's `!` suffix denotes mutating variants; treat them as
        // aliases for the bare name.
        let trimmed_no_bang = trimmed.strip_suffix('!').unwrap_or(trimmed);
        let short = bonsai_lang_api::kit::short_name_of(trimmed);
        let short_no_bang = short.strip_suffix('!').unwrap_or(short);
        for candidate in [trimmed, trimmed_no_bang, short, short_no_bang] {
            if let Some(sym) = self.deterministic_first_callable_by_name(candidate) {
                return Some(sym);
            }
        }
        // Fallback: scan every decl when the indexed lookup missed.
        let global = self.db.global_index();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if (decl.name == short
                    || decl.name == short_no_bang
                    || decl.name == trimmed
                    || decl.name == trimmed_no_bang)
                    && self.is_callable(decl.symbol)
                {
                    return Some(decl.symbol);
                }
            }
        }
        None
    }

    /// Pick the first callable symbol matching `name` in a
    /// deterministic order (file path, name span start, symbol id).
    /// `find_by_name` returns matches in adapter-emitted insertion
    /// order, which isn't stable across runs when names collide
    /// across translation units; pinning a sort here keeps trace
    /// expansion reproducible. Same contract as
    /// `Workspace::lookup_function_symbol`.
    fn deterministic_first_callable_by_name(&self, name: &str) -> Option<SymbolId> {
        if name.is_empty() {
            return None;
        }
        let global = self.db.global_index();
        let vfs = self.db.vfs();
        let mut hits: Vec<(SymbolId, &Decl)> = global
            .find_by_name(name)
            .iter()
            .filter_map(|sym| global.decl_of(*sym).map(|d| (*sym, d)))
            .filter(|(sym, _)| self.is_callable(*sym))
            .collect();
        hits.sort_by(|(a_sym, a), (b_sym, b)| {
            let a_path = vfs
                .path(a.span.file)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let b_path = vfs
                .path(b.span.file)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            a_path
                .cmp(&b_path)
                .then_with(|| a.name_span.start.cmp(&b.name_span.start))
                .then_with(|| a_sym.raw().cmp(&b_sym.raw()))
        });
        hits.into_iter().next().map(|(sym, _)| sym)
    }

    /// First class / struct decl in the workspace named `name`.
    fn find_class_by_name(&self, name: &str) -> Option<SymbolId> {
        let global = self.db.global_index();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if decl.name == name && matches!(decl.kind, DeclKind::Class | DeclKind::Struct) {
                    return Some(decl.symbol);
                }
            }
        }
        None
    }

    /// Locate a class's constructor, preferring an explicit
    /// `DeclKind::Constructor` and falling back to the per-language
    /// idiomatic name (`__init__`, `init`, `new`, …).
    fn find_constructor_for_class(&self, class_sym: SymbolId) -> Option<SymbolId> {
        let global = self.db.global_index();
        let class_decl = global.decl_of(class_sym)?;
        let class_file = global.declaring_file(class_sym)?;
        for decl in global.decls_in(class_file) {
            if matches!(decl.kind, DeclKind::Constructor) && span_contains(class_decl.span, decl.span) {
                return Some(decl.symbol);
            }
        }
        for decl in global.decls_in(class_file) {
            if matches!(
                decl.name.as_str(),
                "__init__" | "constructor" | "__construct" | "init" | "new"
            ) && span_contains(class_decl.span, decl.span)
            {
                return Some(decl.symbol);
            }
        }
        None
    }

    /// True iff `sym` resolves to a callable decl.
    fn is_callable(&self, sym: SymbolId) -> bool {
        self.db.global_index().decl_of(sym).is_some_and(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
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

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}
