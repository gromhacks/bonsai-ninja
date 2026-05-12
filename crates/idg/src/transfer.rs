//! Per-function transfer-function pass (Phase 2 of the IDG plan).
//!
//! Input: a `Decl` whose `flow_events` carry the adapter-emitted
//! intra-procedural facts.
//! Output: a [`TransferOutput`] holding:
//!
//! - the function's intra-procedural edges (already interned in a
//!   [`PlaceDict`] and [`NodeDict`])
//! - the call sites encountered, with enough metadata for the
//!   workspace-level Phase 3 builder to stitch cross-function edges
//! - the throw events encountered, again for Phase 3 stitching of
//!   cross-function `Throw → Catch` edges
//!
//! ## Why `TransferOutput`, not directly a segment
//!
//! A segment's identity is a *source file*, not a single function.
//! Multiple functions in one file produce multiple `TransferOutput`s
//! that get merged into one segment by the Phase 3 builder. That
//! also lets the workspace's per-function caches (DataFlow / ValueFlow)
//! reuse the same `TransferOutput` shape if needed.
//!
//! ## Mapping from FlowEvent to edges
//!
//! - `Assign { target, source_name }` → `Read(source_name) → Write(target)`
//! - `Assign { target, source_names: [a, b] }` → two edges:
//!   `Read(a) → Write(target)`, `Read(b) → Write(target)`
//! - `Assign { target, source_call: f, source_call_args: [x] }`:
//!   - `Read(x) → CallArg(site, 0)`  (caller-side, intra)
//!   - `CallRet(site) → Write(target)` (caller-side, intra; the
//!     return-from-callee edge is stitched cross-function in Phase 3)
//! - `Call { name, args }` → for each arg with a `place`:
//!   `Read(place) → CallArg(site, idx)` (intra). Phase 3 adds the
//!   `CallArg(site, idx) → callee.Param(idx)` cross edge.
//! - `Return { value_name: Some(name) }` → `Read(name) → Return`
//! - `Throw { value_name: Some(name), thrown_type }` →
//!   `Read(name) → Throw(ty)`. Phase 3 stitches the inter-function
//!   `callee.Throw(ty) → caller.Catch(ty)` edges.
//! - `Try { body, catch_events, catch_param, catch_types }`:
//!   - Walk body to collect any `Throw` events.
//!   - For each (catch_type, recorded throw of matching type) pair,
//!     emit `Throw(ty) → Catch(ty)` (intra; the catch param is
//!     populated below).
//!   - If `catch_param` is set, emit `Catch(ty) → Write(catch_param)`
//!     for each catch_type so the catch body's reads of `catch_param`
//!     resolve to the caught value.
//!   - Walk catch_events and finally_events as nested event lists.
//! - `Branch { then_events, else_events }` → walk both arms; the
//!   union of edges is the merged post-state.
//! - `Loop { body }` → walk body once; loop carries form cycles via
//!   the assignments inside (the IDG is sound under fixpoint
//!   reachability).
//! - `Defer { body }` → walk body normally; we don't separate
//!   deferred edges from immediate ones in the IDG (path
//!   sensitivity is a query-time concern, not a graph-construction
//!   one).
//! - `Yield { value_text }` → if the text is a bare identifier,
//!   `Read(name) → Place::Yield`.
//! - `Await { value_name }` → `Read(name) → Place::Await`.

use bonsai_common::{FuncId, Precision, Span};
use bonsai_factstore::{StrId, StringPoolBuilder};
use bonsai_lang_api::{CallArg, CallKind, Decl, FlowEvent};
use smallvec::SmallVec;
use std::sync::Arc;

use crate::dict::{NodeDict, PlaceDict};
use crate::edge::{IdgEdge, IdgEdgeKind};
use crate::node::NodeId;
use crate::place::{CallSiteId, Place, TypeId};

/// One call site recorded by the transfer pass for the Phase 3
/// builder to stitch cross-function edges.
#[derive(Clone, Debug)]
pub struct CallSiteRef {
    /// Stable identifier (the call's source span).
    pub site: CallSiteId,
    /// Callee name as the adapter saw it. Phase 3 resolves this
    /// against the workspace `ResolvedCallGraph` to a list of
    /// candidate `FuncId`s with their precision.
    pub callee_name: String,
    /// Receiver expression text for method calls. Used by Phase 3's
    /// receiver-type resolution.
    pub receiver: Option<String>,
    /// Adapter-derived static receiver types. Phase 3 prefers these
    /// over textual receiver inference.
    pub receiver_types: Vec<String>,
    /// Adapter's classification for this call (Free / Method /
    /// Constructor / etc.). Mirrors the FlowEvent::Call::call_kind.
    pub call_kind: CallKind,
    /// Number of arguments at the site. Phase 3 uses this to bound
    /// the param-index edges it stitches.
    pub args_count: u8,
    /// Caller-side `CallRet(site)` node interned in the function's
    /// segment. Phase 3 connects each candidate callee's
    /// `Return` node to this node.
    pub call_ret_node: NodeId,
    /// Caller-side `CallArg(site, i)` nodes per argument index.
    /// Phase 3 connects each candidate callee's `Param(i)` node to
    /// these.
    pub call_arg_nodes: SmallVec<[NodeId; 4]>,
    /// Source span of each argument expression. Used by the
    /// post-walk compound-expression bridger to wire inner-call
    /// returns into outer-call args (`Repository.search(source())`
    /// — `source()`'s CallRet bridges to `search`'s CallArg).
    pub call_arg_spans: SmallVec<[Span; 4]>,
    /// True when this call site arose from `target = callee(args)`
    /// (a `FlowEvent::Assign` with `source_call`). Phase 3's
    /// unknown-callee passthrough fires only for these — adding
    /// `CallArg → CallRet` for free-standing `Call` events would
    /// over-approximate side-effecting external calls (`fgets`,
    /// `snprintf`) whose return value doesn't carry input taint.
    pub is_assign_rhs: bool,
}

/// One throw event recorded by the transfer pass for Phase 3 to
/// stitch cross-function `Throw → Catch` edges.
#[derive(Clone, Debug)]
pub struct ThrowSite {
    /// `Throw(ty)` node in the throwing function.
    pub throw_node: NodeId,
    /// Type id of the thrown value, if known. `None` for
    /// untyped / catch-all throws — Phase 3 falls back to
    /// conservative seeding.
    pub thrown_type: Option<TypeId>,
    /// Source span of the throw.
    pub span: Span,
}

/// Output of the transfer-function pass for one function.
#[derive(Clone, Debug)]
pub struct TransferOutput {
    /// FuncId this transfer-function pass ran for.
    pub func: FuncId,
    /// Parameter names declared by this function, in declaration
    /// order. Used by Phase 3 callback-binding stitching to detect
    /// `callback(value)` calls whose callee name matches a function
    /// parameter — the stitcher then walks the callgraph for
    /// bindings into that param and emits cross-call edges.
    pub params: Vec<String>,
    /// Place dictionary local to this function. The Phase 3 builder
    /// merges it into the segment's dictionary, remapping ids.
    pub places: PlaceDict,
    /// Node dictionary local to this function.
    pub nodes: NodeDict,
    /// Intra-procedural edges (all `from` and `to` are nodes in
    /// `self.nodes`).
    pub edges: Vec<IdgEdge>,
    /// Call sites encountered, for Phase 3 stitching.
    pub call_sites: Vec<CallSiteRef>,
    /// Throw sites encountered, for Phase 3 stitching.
    pub throw_sites: Vec<ThrowSite>,
    /// Name pool used by this function's `Place::Read` /
    /// `Place::Write` / field-path / type-name interns. Embedded so
    /// the segment merge can resolve StrIds back to source-name
    /// strings and re-intern them in the segment's own name pool —
    /// without this, segment consumers can't translate `Place::Read
    /// { name: StrId }` back into "what source-level identifier?"
    /// for seed-name lookup or display.
    pub names: bonsai_factstore::StringPoolBuilder,
}

impl TransferOutput {
    /// Construct an empty output for `func`.
    #[must_use]
    pub fn new(func: FuncId) -> Self {
        Self {
            func,
            params: Vec::new(),
            places: PlaceDict::new(),
            nodes: NodeDict::new(),
            edges: Vec::new(),
            call_sites: Vec::new(),
            throw_sites: Vec::new(),
            names: bonsai_factstore::StringPoolBuilder::new(),
        }
    }
}

/// String interner shared across one segment / build invocation.
/// Wraps a [`StringPoolBuilder`] so the transfer pass and the
/// segment writer use the same name → `StrId` mapping.
#[derive(Default)]
pub struct NameInterner {
    pool: StringPoolBuilder,
}

impl NameInterner {
    /// Construct an empty interner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern `name` and return its id.
    pub fn intern(&mut self, name: &str) -> StrId {
        self.pool.intern(name)
    }

    /// Number of unique names interned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// True iff no names interned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Borrow the underlying pool — useful when persistence handles
    /// the pool serialisation.
    #[must_use]
    pub fn pool(&self) -> &StringPoolBuilder {
        &self.pool
    }

    /// Take ownership of the underlying pool, consuming the
    /// interner.
    pub fn into_pool(self) -> StringPoolBuilder {
        self.pool
    }
}

/// Run the transfer-function pass on `decl` — walk its flow events
/// and emit edges into a fresh [`TransferOutput`].
///
/// Each output owns its own name pool — [`TransferOutput::names`]
/// holds every interned source-level identifier for this function's
/// places, so the segment merge can resolve local StrIds back to
/// strings and re-intern them in the segment-level pool.
pub fn transfer_function_for(decl: &Decl) -> TransferOutput {
    let func = FuncId::new(decl.symbol.raw());
    let mut out = TransferOutput::new(func);
    out.params.clone_from(&decl.params);
    let mut ctx = TransferCtx {
        out: &mut out,
        last_writer: ahash::AHashMap::new(),
    };

    // Seed the function's `Return` place defensively. Every
    // callable has a conceptual return slot even if its body never
    // executes a `Return` event — Phase 3's cross-function
    // stitching needs the Return node to exist before it can wire
    // `callee.Return → caller.CallRet(site)` edges.
    let _ = ctx.intern_node(Place::Return);

    // Seed parameter bindings. Each param gets a synthetic
    // `Write(param_name, name_span)` representing "the param's
    // value is bound here at function entry." `last_writer` is
    // initialised so subsequent reads of the param resolve to this
    // entry-binding write — the CFG-narrowing pass emits
    // `Param(idx) → Write(param_name, entry_span)` plus per-use
    // bridges from this Write to each consumer.
    for (idx, param_name) in decl.params.iter().enumerate() {
        if param_name.is_empty() {
            continue;
        }
        let param_idx = u8::try_from(idx).unwrap_or(u8::MAX);
        let param_node = ctx.intern_node(Place::Param { idx: param_idx });
        let entry_write = ctx.write_node(param_name, decl.name_span);
        ctx.commit_writer(param_name, entry_write);
        // Param(idx) → Write(param_name, entry_span). Precision::Exact:
        // parameter binding is a structural language guarantee.
        ctx.emit(IdgEdge {
            from: param_node,
            to: entry_write,
            meta: crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraAssign,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: decl.name_span,
            },
        });
    }

    walk_events(&decl.flow_events, &mut ctx);
    bridge_compound_expression_calls(&mut ctx);
    out
}

/// Post-walk pass: wire inner-call CallRet → outer-call CallArg
/// for compound expressions like `outer(inner(x))`. The walker
/// processes both calls as siblings without knowing their
/// nesting; the adapter records each arg's source span, so we
/// can detect "inner call's site span lies inside outer arg's
/// span" and emit the bridge edge. Without this, source-result
/// inlined into a sink-call argument never surfaces as
/// tainted-arg evidence on the outer call (e.g. Java
/// `Repository.search(source())` — source's CallRet must reach
/// search's CallArg before the matcher's `arg_tainted` check
/// succeeds). Same-segment edge, IntraRead-shaped (the result
/// is read into the outer call's arg slot).
fn bridge_compound_expression_calls(ctx: &mut TransferCtx<'_>) {
    let sites = ctx.out.call_sites.clone();
    for outer in &sites {
        for (arg_idx, arg_span) in outer.call_arg_spans.iter().enumerate() {
            let outer_arg_node = match outer.call_arg_nodes.get(arg_idx) {
                Some(n) => *n,
                None => continue,
            };
            for inner in &sites {
                if std::ptr::eq(outer, inner) {
                    continue;
                }
                let inner_site_span = inner.site.0;
                if inner_site_span == *arg_span {
                    // Same-span — the adapter sometimes records
                    // both calls at the same span (the inner is
                    // the bare arg expression). Treat as a bridge.
                } else if !span_strictly_contains(*arg_span, inner_site_span) {
                    continue;
                }
                ctx.out.edges.push(IdgEdge {
                    from: inner.call_ret_node,
                    to: outer_arg_node,
                    meta: crate::edge::EdgeMeta {
                        precision: Precision::OverApproximate,
                        kind: IdgEdgeKind::IntraRead,
                        call_kind: bonsai_callgraph::EdgeKind::Direct,
                        via_span: inner_site_span,
                    },
                });
            }
        }
    }
}

/// True when `outer` strictly contains `inner` — i.e. inner is
/// fully inside outer with at least one different endpoint. Used
/// to detect compound-expression nesting.
fn span_strictly_contains(outer: Span, inner: Span) -> bool {
    if outer.file != inner.file {
        return false;
    }
    outer.start <= inner.start
        && inner.end <= outer.end
        && (outer.start != inner.start || outer.end != inner.end)
}

/// Internal walker context. Holds a mutable ref into the output;
/// passed by &mut through the recursive walkers so we don't need
/// clones. All name interning routes through `out.names` so the
/// per-function pool is the canonical source of source-name strings.
struct TransferCtx<'a> {
    out: &'a mut TransferOutput,
    /// Per-name "current writers" — the `Write` nodes that the
    /// transfer pass considers most-recent for each name in CFG
    /// order. Each entry is a small set because branch joins union
    /// the writers from both arms. The CFG-narrowing pass uses
    /// this to emit `Write(name, span_W) → consumer-node` edges
    /// instead of routing through a shared `Read(name)` node — that
    /// way a clean overwrite later in the function "kills" the
    /// earlier writer's bridge into subsequent reads.
    last_writer: ahash::AHashMap<StrId, smallvec::SmallVec<[NodeId; 4]>>,
}

impl<'a> TransferCtx<'a> {
    /// Intern a bare identifier into the per-function name pool.
    fn intern_name(&mut self, name: &str) -> StrId {
        self.out.names.intern(name)
    }

    /// Intern a `Place` and resolve it to a `NodeId` in the output's
    /// dictionaries. Convenience: chains `places.intern` +
    /// `nodes.intern(func, …)`.
    fn intern_node(&mut self, place: Place) -> NodeId {
        let pid = self.out.places.intern(place);
        self.out.nodes.intern(self.out.func, pid)
    }

    /// Look up or intern a bare-name `Place::Read` node.
    fn read_node(&mut self, name: &str) -> NodeId {
        let sid = self.intern_name(name);
        self.intern_node(Place::read(sid))
    }

    /// Emit edges from every recently-known writer of `name` to
    /// `consumer`, using `meta` for each edge. CFG narrowing: only
    /// the writers in `last_writer[name]` (the most-recent writes
    /// in CFG order) bridge to `consumer`, so a clean overwrite
    /// later in the function "kills" the earlier writer's bridge.
    /// When no writer is known (e.g. an unrooted read of an
    /// imported global), falls back to the shared `Place::Read`
    /// node so closure analysis still picks up flows seeded
    /// elsewhere.
    fn bridge_read(&mut self, name: &str, consumer: NodeId, meta: crate::edge::EdgeMeta) {
        let sid = self.intern_name(name);
        let mut writers: smallvec::SmallVec<[NodeId; 4]> =
            self.last_writer.get(&sid).cloned().unwrap_or_default();
        // Field-aware fallback: when a read of `obj.field` (or
        // `obj["field"]`) has no exact-name writer, also union in
        // every writer of the base name `obj`. Field assignments
        // commit on both the qualified path and the base (see
        // `walk_assign`'s field-write union), but reads of
        // sibling fields whose path was never explicitly written
        // still need to see the base's tainted state. Without this
        // fallback, `obj.cmd = tainted; sink(obj.user)` drops taint
        // because `obj.user` has no specific writer.
        if let Some((base, _)) = name.split_once(['.', '[']) {
            let base = base.trim();
            if !base.is_empty() && base != name {
                let base_sid = self.intern_name(base);
                if let Some(base_writers) = self.last_writer.get(&base_sid) {
                    for w in base_writers {
                        if !writers.contains(w) {
                            writers.push(*w);
                        }
                    }
                }
            }
        }
        if writers.is_empty() {
            // Unrooted read: route through the shared Read node so
            // any external taint that finds Read(name) still
            // propagates. Closure won't be over-approximated by
            // CFG-killed earlier writes because there ARE no prior
            // writes in last_writer.
            let from = self.read_node(name);
            self.emit(IdgEdge {
                from,
                to: consumer,
                meta,
            });
            return;
        }
        for writer in writers {
            self.emit(IdgEdge {
                from: writer,
                to: consumer,
                meta,
            });
        }
    }

    /// Look up or intern a `Place::Write` node for `name` at `span`.
    /// Each distinct `span` yields a distinct node so CFG-narrowing
    /// can kill earlier writes when later ones overwrite. Does NOT
    /// update `last_writer` — callers must call
    /// [`Self::commit_writer`] after they've finished emitting
    /// bridges from the prior writers (so a self-assign like
    /// `x = x` reads the *prior* x, not the about-to-be-written one).
    fn write_node(&mut self, name: &str, span: Span) -> NodeId {
        let sid = self.intern_name(name);
        self.intern_node(Place::write(sid, span))
    }

    /// Add `node` to the writer union for `name` without dropping
    /// any prior writers. Used by side-effect handlers that
    /// over-approximate (receiver-state propagation, partial
    /// updates) — the existing writer must stay live because the
    /// mutation didn't fully overwrite the slot.
    fn union_writer(&mut self, name: &str, node: NodeId) {
        let sid = self.intern_name(name);
        let writers = self.last_writer.entry(sid).or_default();
        if !writers.contains(&node) {
            writers.push(node);
        }
        let stripped = name.trim_start_matches(['$', '@', '%', '&']);
        if !stripped.is_empty() && stripped != name {
            let alias_sid = self.intern_name(stripped);
            let alias_writers = self.last_writer.entry(alias_sid).or_default();
            if !alias_writers.contains(&node) {
                alias_writers.push(node);
            }
        }
    }

    /// Mark `node` as the new most-recent writer for `name`,
    /// replacing any prior writers (clean-overwrite semantics).
    /// Also commits aliases produced by sigil-stripping (`$x`/`@x`/`%x`
    /// → `x`) so a clean overwrite of `$x` also kills `x`'s prior
    /// writer — perl-style adapters emit both forms for the same
    /// variable, and without alias-aware committing the bare-form
    /// last_writer would retain the original tainted value.
    fn commit_writer(&mut self, name: &str, node: NodeId) {
        let sid = self.intern_name(name);
        self.last_writer.insert(sid, smallvec::smallvec![node]);
        let stripped = name.trim_start_matches(['$', '@', '%', '&']);
        if !stripped.is_empty() && stripped != name {
            let alias_sid = self.intern_name(stripped);
            self.last_writer.insert(alias_sid, smallvec::smallvec![node]);
        }
    }

    /// Append an edge to the output's edge list.
    fn emit(&mut self, edge: IdgEdge) {
        self.out.edges.push(edge);
    }
}

/// Walk a slice of FlowEvents, dispatching each to its handler.
fn walk_events(events: &[FlowEvent], ctx: &mut TransferCtx<'_>) {
    for event in events {
        walk_event(event, ctx);
    }
}

/// Dispatch one FlowEvent to the appropriate handler.
fn walk_event(event: &FlowEvent, ctx: &mut TransferCtx<'_>) {
    match event {
        FlowEvent::Assign {
            span,
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
            declares_new_binding,
            value_kind,
        } => walk_assign(
            *span,
            target,
            source_name.as_deref(),
            source_call.as_deref(),
            source_call_args,
            source_names,
            *declares_new_binding,
            *value_kind,
            ctx,
        ),
        FlowEvent::Call {
            span,
            name,
            receiver,
            receiver_types,
            call_kind,
            args,
        } => walk_call(
            *span,
            name,
            receiver.as_deref(),
            receiver_types,
            *call_kind,
            args,
            ctx,
        ),
        FlowEvent::Return {
            span,
            value_name,
            value_text,
        } => {
            let return_node = ctx.intern_node(Place::Return);
            let return_meta = crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraReturn,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: *span,
            };
            let mut bridged: ahash::AHashSet<StrId> = ahash::AHashSet::default();
            if let Some(name) = value_name.as_deref() {
                if !name.is_empty() {
                    let sid = ctx.intern_name(name);
                    if bridged.insert(sid) {
                        ctx.bridge_read(name, return_node, return_meta);
                    }
                }
            }
            // Compound return expressions (`return ext(inner(x))`)
            // don't surface a `value_name` — the adapter only fills
            // `value_text` with the raw expression. Tokenising the
            // identifier names inside that text and bridging each
            // through to Place::Return mirrors the engine's
            // identifier-tokenisation fallback for return-paths;
            // without it, compound returns silently drop taint and
            // every transitive sink past such a function disappears.
            if let Some(text) = value_text.as_deref() {
                if !text.is_empty() {
                    for token in extract_identifiers_outside_strings(text) {
                        if token.is_empty() {
                            continue;
                        }
                        let sid = ctx.intern_name(&token);
                        if !bridged.insert(sid) {
                            continue;
                        }
                        ctx.bridge_read(&token, return_node, return_meta);
                    }
                }
            }
        }
        FlowEvent::Throw {
            span,
            value_name,
            thrown_type,
        } => walk_throw(*span, value_name.as_deref(), thrown_type.as_deref(), ctx),
        FlowEvent::Branch {
            span: _,
            condition,
            then_events,
            else_events,
        } => {
            // Phase-8 path-sensitive narrowing: classify the branch
            // condition. When the textual condition normalises to a
            // boolean literal (`true` / `false` / `1` / `0`), the
            // opposite arm is dead and we don't walk it. The
            // unreachable arm's writers don't enter `last_writer`,
            // so downstream taint can't flow through it. When the
            // condition is non-trivial (anything that depends on a
            // runtime value), fall through to the existing
            // SSA-style join below.
            let cond_kind = condition
                .as_deref()
                .map(classify_branch_condition)
                .unwrap_or(BranchConditionKind::Unknown);
            match cond_kind {
                BranchConditionKind::AlwaysTrue => {
                    walk_events(then_events, ctx);
                    return;
                }
                BranchConditionKind::AlwaysFalse => {
                    walk_events(else_events, ctx);
                    return;
                }
                BranchConditionKind::Unknown => {}
            }
            // SSA-style join: snapshot last_writer at branch entry,
            // walk each arm with an independent copy, then merge by
            // taking the union of writers per name. Either arm's
            // writer remains "live" for code after the join, so a
            // tainted write in one arm reaches downstream consumers
            // even if the other arm wrote a clean value.
            let entry = ctx.last_writer.clone();
            walk_events(then_events, ctx);
            let after_then = std::mem::replace(&mut ctx.last_writer, entry);
            walk_events(else_events, ctx);
            // Merge after_then into ctx.last_writer (which holds
            // after_else): per-name union.
            for (name, writers) in after_then {
                let merged = ctx.last_writer.entry(name).or_default();
                for w in writers {
                    if !merged.contains(&w) {
                        merged.push(w);
                    }
                }
            }
        }
        FlowEvent::Loop {
            span: _,
            loop_kind: _,
            body,
        } => {
            // Loop body may run zero or more times. Run the body
            // twice with last_writer accumulating across iterations
            // (fixpoint approximation): first pass establishes
            // body-end writers, second pass widens any reads in the
            // body to see those writers from a prior iteration.
            // Two passes suffice for typical patterns (loop-carried
            // accumulators, iterating over a collection); deeper
            // fixpoint convergence is unnecessary because the IDG
            // is a structural reachability graph and union is
            // monotonic.
            walk_events(body, ctx);
            walk_events(body, ctx);
        }
        FlowEvent::Try {
            span,
            body,
            catch_events,
            finally_events,
            catch_param,
            catch_types,
        } => walk_try(
            *span,
            body,
            catch_events,
            finally_events,
            catch_param.as_deref(),
            catch_types,
            ctx,
        ),
        FlowEvent::Defer { span: _, body } => walk_events(body, ctx),
        FlowEvent::Using { span: _, body } => walk_events(body, ctx),
        FlowEvent::Yield { span, value_text } => {
            if let Some(text) = value_text.as_deref() {
                let trimmed = text.trim();
                if is_bare_identifier(trimmed) {
                    let to = ctx.intern_node(Place::Yield);
                    ctx.bridge_read(
                        trimmed,
                        to,
                        crate::edge::EdgeMeta {
                            precision: Precision::Exact,
                            kind: IdgEdgeKind::IntraYield,
                            call_kind: bonsai_callgraph::EdgeKind::Direct,
                            via_span: *span,
                        },
                    );
                }
            }
        }
        FlowEvent::Await { span, value_name } => {
            if let Some(name) = value_name.as_deref() {
                if !name.is_empty() {
                    let to = ctx.intern_node(Place::Await);
                    ctx.bridge_read(
                        name,
                        to,
                        crate::edge::EdgeMeta {
                            precision: Precision::Exact,
                            kind: IdgEdgeKind::IntraAwait,
                            call_kind: bonsai_callgraph::EdgeKind::Direct,
                            via_span: *span,
                        },
                    );
                }
            }
        }
        FlowEvent::Break { .. } | FlowEvent::Continue { .. } | FlowEvent::Lifecycle { .. } => {
            // No dataflow edges from these events. Break/Continue
            // affect control flow which the IDG models as graph
            // reachability — the relevant edges live on the
            // surrounding events.
        }
    }
}

/// Walk an `Assign` event. Handles the four shapes the adapter may
/// emit: bare-name, multi-source compound, call-RHS with args, and
/// combinations.
/// Phase-8 branch-condition classification. The adapter records a
/// textual condition on `FlowEvent::Branch`; this classifier
/// normalises the spelling across languages and decides whether
/// the condition is statically true / false. Anything not in the
/// small recognised set is `Unknown` and falls through to the
/// SSA join.
///
/// Recognised statically-true literals:
///   `true`, `True`, `TRUE`, `1`
/// Recognised statically-false literals:
///   `false`, `False`, `FALSE`, `0`, `nil`, `null`, `None`
/// `!true` and `not true` flip; double-negation collapses.
#[derive(Copy, Clone, Debug)]
enum BranchConditionKind {
    AlwaysTrue,
    AlwaysFalse,
    Unknown,
}

fn classify_branch_condition(cond: &str) -> BranchConditionKind {
    let mut s = cond.trim();
    let mut negations = 0usize;
    loop {
        if let Some(rest) = s.strip_prefix("!") {
            negations += 1;
            s = rest.trim_start();
            continue;
        }
        if let Some(rest) = s.strip_prefix("not ").or_else(|| s.strip_prefix("not(")) {
            negations += 1;
            s = rest.trim_start();
            continue;
        }
        break;
    }
    // Strip surrounding parens once for `not(true)` etc.
    while s.starts_with('(') && s.ends_with(')') {
        s = &s[1..s.len() - 1];
        s = s.trim();
    }
    let kind = match s {
        "true" | "True" | "TRUE" | "1" => BranchConditionKind::AlwaysTrue,
        "false" | "False" | "FALSE" | "0" | "nil" | "null" | "None" => BranchConditionKind::AlwaysFalse,
        _ => BranchConditionKind::Unknown,
    };
    match (kind, negations % 2 == 0) {
        (BranchConditionKind::AlwaysTrue, true) => BranchConditionKind::AlwaysTrue,
        (BranchConditionKind::AlwaysTrue, false) => BranchConditionKind::AlwaysFalse,
        (BranchConditionKind::AlwaysFalse, true) => BranchConditionKind::AlwaysFalse,
        (BranchConditionKind::AlwaysFalse, false) => BranchConditionKind::AlwaysTrue,
        (BranchConditionKind::Unknown, _) => BranchConditionKind::Unknown,
    }
}

fn walk_assign(
    span: Span,
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
    _declares_new_binding: bool,
    value_kind: Option<bonsai_lang_api::AssignValueKind>,
    ctx: &mut TransferCtx<'_>,
) {
    if target.is_empty() {
        return;
    }
    // Field-write detection: targets like `obj.field` or `obj["k"]`.
    let (write_node, is_field_write) = build_target_node(target, span, ctx);

    let assign_kind = if is_field_write {
        IdgEdgeKind::IntraFieldWrite
    } else {
        IdgEdgeKind::IntraAssign
    };

    // Phase-5 const propagation: when the adapter classified the
    // RHS as a pure literal (no identifier reads), the assignment
    // is a clean overwrite. We still intern the write_node and
    // commit it (so subsequent reads bind to a fresh writer), but
    // we skip every `bridge_read` of source names / call args —
    // no live carrier flows into this write, so no edges into
    // it. The downstream effect is that `let SAFE = "literal";
    // sink(SAFE)` doesn't fire any rule, because the sink's
    // `bridge_read("SAFE")` resolves to a writer node that has
    // no incoming edge from any tainted source.
    let rhs_is_literal = matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::Literal));
    if rhs_is_literal {
        // Skip name-bridging; commit the writer as-is so reads
        // of `target` after this point see the literal write.
        ctx.commit_writer(target, write_node);
        if is_field_write {
            if let Some((base, _)) = target.split_once(['.', '[']) {
                let base = base.trim();
                if !base.is_empty() {
                    ctx.union_writer(base, write_node);
                }
            }
        }
        return;
    }

    let edge_meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: assign_kind,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };

    // Bridge each source's most-recent writer to the new target's
    // Write node. CFG narrowing: bridge_read consults
    // `last_writer[src]` so a stale earlier write of `src` doesn't
    // cross-pollute. The shared `Place::Read` node is used only as
    // a fallback when `src` has no recorded writer (unrooted reads).
    if let Some(src) = source_name {
        if !src.is_empty() {
            ctx.bridge_read(src, write_node, edge_meta);
        }
    }
    for src in source_names {
        if src.is_empty() {
            continue;
        }
        ctx.bridge_read(src, write_node, edge_meta);
    }

    // Call-RHS shape: `target = callee(args...)`. Two intra edges per
    // arg (Read(arg) → CallArg(site, idx)) plus one
    // CallRet(site) → Write(target). Phase 3 stitches the
    // CallArg → callee.Param and callee.Return → CallRet edges.
    if let Some(callee) = source_call {
        if !callee.is_empty() {
            let site = CallSiteId(span);
            let mut arg_nodes: SmallVec<[NodeId; 4]> = SmallVec::new();
            for (idx, arg) in source_call_args.iter().enumerate() {
                let arg_idx = u8::try_from(idx).unwrap_or(u8::MAX);
                let arg_node = ctx.intern_node(Place::CallArg { site, idx: arg_idx });
                arg_nodes.push(arg_node);
                if !arg.is_empty() {
                    ctx.bridge_read(
                        arg,
                        arg_node,
                        crate::edge::EdgeMeta {
                            precision: Precision::Exact,
                            kind: IdgEdgeKind::IntraRead,
                            call_kind: bonsai_callgraph::EdgeKind::Direct,
                            via_span: span,
                        },
                    );
                }
            }
            let ret_node = ctx.intern_node(Place::CallRet { site });
            ctx.emit(IdgEdge {
                from: ret_node,
                to: write_node,
                meta: edge_meta,
            });
            // Assign-RHS `source_call_args` are Strings without
            // explicit per-arg spans; use the assign's span as
            // the conservative fallback.
            let mut arg_spans: SmallVec<[Span; 4]> = SmallVec::new();
            for _ in 0..source_call_args.len() {
                arg_spans.push(span);
            }
            ctx.out.call_sites.push(CallSiteRef {
                site,
                callee_name: callee.to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args_count: u8::try_from(source_call_args.len()).unwrap_or(u8::MAX),
                call_ret_node: ret_node,
                call_arg_nodes: arg_nodes,
                call_arg_spans: arg_spans,
                is_assign_rhs: true,
            });
        }
    }

    // Commit the new writer LAST: prior bridge_read calls already
    // pulled the source's pre-assign last_writer, so it's safe to
    // overwrite `last_writer[target]` now. Self-assigns (`x = x`)
    // therefore see the prior `x` on the RHS and still update to
    // a fresh writer node post-assign.
    //
    // Field assignments (`obj.field = X`) also union the same
    // writer into the BASE name's last_writer so downstream reads
    // of `obj` (the bare carrier) see the field's taint. Without
    // this, `obj.cmd = tainted; sink(obj)` silently drops the
    // taint when the IDG bridges `obj` for the sink's CallArg —
    // last_writer["obj"] would still point at obj's pre-mutation
    // writer (or be empty). The engine collapses field-writes onto
    // the base via taint-on-read; the IDG mirrors that with a union
    // commit on the base name.
    if is_field_write {
        if let Some((base, _)) = target.split_once(['.', '[']) {
            let base = base.trim();
            if !base.is_empty() {
                ctx.union_writer(base, write_node);
            }
        }
    }
    ctx.commit_writer(target, write_node);
}

/// Walk a `Call` event. Records the call site for Phase 3 and emits
/// caller-side `Read(arg.place) → CallArg(site, idx)` edges where
/// the adapter exposed a place identifier for the argument.
fn walk_call(
    span: Span,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    args: &[CallArg],
    ctx: &mut TransferCtx<'_>,
) {
    let site = CallSiteId(span);
    // Pre-compute which arg indices are WRITE-ONLY side effects so
    // we suppress their regular input edges (otherwise a tainted
    // prior value of the carrier would leak through the call into
    // the side-effect Write — `snprintf(clean_buf, sz, "literal")`
    // would falsely propagate `clean_buf`'s prior taint).
    let side_effects = side_effect_output_args_for(name, receiver);
    let mut write_only_args: ahash::AHashSet<u8> = ahash::AHashSet::default();
    for (idx, kind) in &side_effects {
        if matches!(kind, SideEffectKind::WriteOnly) {
            write_only_args.insert(*idx);
        }
    }
    let mut arg_nodes: SmallVec<[NodeId; 4]> = SmallVec::new();
    for (idx, arg) in args.iter().enumerate() {
        let arg_idx = u8::try_from(idx).unwrap_or(u8::MAX);
        let arg_node = ctx.intern_node(Place::CallArg { site, idx: arg_idx });
        arg_nodes.push(arg_node);
        // Suppress the regular input edge for write-only args:
        // those positions are overwritten by the call, not read.
        if write_only_args.contains(&arg_idx) {
            continue;
        }
        // Connect every NAMED carrier the adapter exposed for this
        // arg expression to the CallArg node, not just the
        // canonical `place`. Some adapters (csharp, scala,
        // solidity, elixir) only populate `place` for bare
        // identifiers; for compound expressions (`"-c " + tmp`)
        // they fall back to `source_names = ["tmp"]`. Walking both
        // gives the IDG closure parity with the engine's name-based
        // propagation.
        let arg_meta = crate::edge::EdgeMeta {
            precision: Precision::Exact,
            kind: IdgEdgeKind::IntraRead,
            call_kind: bonsai_callgraph::EdgeKind::Direct,
            via_span: span,
        };
        let mut emitted: ahash::AHashSet<StrId> = ahash::AHashSet::new();
        if let Some(place) = arg.place.as_deref() {
            if !place.is_empty() {
                let sid = ctx.intern_name(place);
                if emitted.insert(sid) {
                    ctx.bridge_read(place, arg_node, arg_meta);
                }
            }
        }
        for source in &arg.source_names {
            if source.is_empty() {
                continue;
            }
            let sid = ctx.intern_name(source);
            if !emitted.insert(sid) {
                continue;
            }
            ctx.bridge_read(source, arg_node, arg_meta);
        }
        // Tokenise `value_text` to extract bare identifiers from
        // compound expressions (`"-c " + tmp`, `[obj method:tmp]`).
        // Scala / Solidity / obj-c adapters don't always populate
        // `place` / `source_names` for non-bare-identifier args.
        // Engage the fallback when nothing was emitted yet OR
        // the adapter populated `place` with an obj-c
        // message-expression literal (starts with `[`) — that
        // pattern's bridge_read routes through a never-written
        // Read("[NSString ...]") node, missing the actual carrier
        // (`token`) embedded inside. Mirrors the engine's
        // `identifier_tokens_outside_strings` extractor.
        // Tokenise value_text when no carrier was emitted yet, or
        // when the only carriers wired in were compound (non-bare)
        // expressions whose bridge_read never reaches the actual
        // data carrier — see obj-c's
        // `place="[NSString ...]"` / source_names=class-and-selector
        // pattern where the param identifier (`token`) is only
        // recoverable via value_text tokenisation.
        let value_text_starts_with_bracket = arg.value_text.trim_start().starts_with('[');
        let need_tokenise_fallback =
            emitted.is_empty() || (value_text_starts_with_bracket && arg.place.is_none());
        if need_tokenise_fallback && !arg.value_text.is_empty() {
            for token in extract_identifiers_outside_strings(&arg.value_text) {
                if token.is_empty() {
                    continue;
                }
                let sid = ctx.intern_name(&token);
                if !emitted.insert(sid) {
                    continue;
                }
                ctx.bridge_read(&token, arg_node, arg_meta);
            }
        }
    }
    let ret_node = ctx.intern_node(Place::CallRet { site });

    // Receiver: for method calls, the receiver expression's value
    // flows implicitly into the call (the callee can read from the
    // receiver). Bridge the receiver's identifier-tokens into a
    // synthetic `CallArg(site, 0)` slot if no explicit args
    // already exist there, so solidity-style `t.delegatecall("")`
    // captures the flow from `t` into the call. Method calls only —
    // free functions don't carry implicit receiver flow.
    if matches!(call_kind, CallKind::Method) {
        if let Some(recv) = receiver.filter(|r| !r.is_empty()) {
            let recv_meta = crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraRead,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: span,
            };
            // Use a synthetic receiver slot. Pick a high arg index
            // (u8::MAX) so we don't collide with positional arg
            // indices the call may have.
            let recv_slot = ctx.intern_node(Place::CallArg { site, idx: u8::MAX });
            // Tokenise the receiver expression — it may be a bare
            // name (`t`) or a chain (`obj.field`); both cases
            // surface the relevant identifiers.
            let tokens = extract_identifiers_outside_strings(recv);
            if tokens.is_empty() && is_bare_identifier(recv) {
                ctx.bridge_read(recv, recv_slot, recv_meta);
            } else {
                for token in tokens {
                    if !token.is_empty() {
                        ctx.bridge_read(&token, recv_slot, recv_meta);
                    }
                }
            }
        }
    }

    // Side-effecting calls: certain library functions write back
    // through their arguments (POSIX `fgets(buf, ...)`, `read(fd,
    // buf, ...)`, scanf-family, etc.). Adapters emit them as plain
    // `FlowEvent::Call` events; the IDG models the side effect by
    // emitting `CallArg(site, i) → Write(arg_place, span)` edges
    // for each output-arg index AND committing those Writes as
    // last_writer for the affected name so subsequent reads pick
    // up the post-call value. This lets fgets-style sources flow
    // into downstream consumers without per-adapter changes.
    //
    // "Pipe-style" side-effects (sprintf / snprintf / strcpy /
    // memcpy / strcat / sscanf) additionally route each non-output
    // CallArg → output Write so a tainted format-arg (`payload` in
    // `snprintf(buf, sz, "[%s]", payload)`) flows into `buf`. Without
    // this, the chain breaks at the first POSIX formatter on the
    // hot path. Sink-style side-effects (fgets / read / getline)
    // get their data from external file descriptors, not from other
    // args, so no input-to-output edges are emitted there.
    let pipe_input_indices: ahash::AHashSet<u8> = pipe_input_args_for(name, receiver, arg_nodes.len())
        .iter()
        .copied()
        .collect();
    for (out_idx, _kind) in &side_effects {
        let out_idx = *out_idx;
        let Some(arg_node) = arg_nodes.get(out_idx as usize).copied() else {
            continue;
        };
        let Some(arg) = args.get(out_idx as usize) else {
            continue;
        };
        // Resolve the carrier name: prefer arg.place; fall back to
        // arg.value_text if it's a bare identifier (some adapters
        // populate value_text but not place).
        let carrier = arg.place.as_deref().filter(|p| !p.is_empty()).or_else(|| {
            let trimmed = arg.value_text.trim();
            if is_bare_identifier(trimmed) {
                Some(trimmed)
            } else {
                None
            }
        });
        let Some(name_str) = carrier else { continue };
        let write_node = ctx.write_node(name_str, span);
        ctx.commit_writer(name_str, write_node);
        ctx.emit(IdgEdge {
            from: arg_node,
            to: write_node,
            meta: crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraAssign,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: span,
            },
        });
        // Also flow the call's return value into the side-effect
        // write — many side-effecting calls return a status/length
        // that propagates the same taint provenance as the data
        // they wrote (e.g. `read(fd, buf, n)` returns bytes-read,
        // which downstream code uses as a length tied to `buf`).
        ctx.emit(IdgEdge {
            from: ret_node,
            to: write_node,
            meta: crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraAssign,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: span,
            },
        });
        // Pipe-style: route every non-output CallArg into this
        // output Write so input-arg taint reaches the formatted /
        // copied buffer.
        for in_idx in &pipe_input_indices {
            let Some(input_arg) = arg_nodes.get(*in_idx as usize).copied() else {
                continue;
            };
            ctx.emit(IdgEdge {
                from: input_arg,
                to: write_node,
                meta: crate::edge::EdgeMeta {
                    precision: Precision::OverApproximate,
                    kind: IdgEdgeKind::IntraAssign,
                    call_kind: bonsai_callgraph::EdgeKind::Direct,
                    via_span: span,
                },
            });
        }
    }

    // Receiver / call-name tokenisation: when an adapter encodes the
    // entire call expression (`Seq("sh", "-c", tmp).!`) into the
    // call name + receiver and reports `args.len() == 0`, the IDG
    // would otherwise miss every name embedded in that text. Mirror
    // the engine's identifier-tokenisation fallback so closure
    // analysis stays consistent. Each tokenised name flows into
    // `CallArg{site, idx=0}` as a synthetic carrier — we deliberately
    // collapse onto idx 0 since the underlying expression has no
    // positional argument shape from the IDG's perspective. Only
    // engages when the caller passed no explicit args.
    if args.is_empty() {
        let mut emitted_arg_zero: Option<NodeId> = None;
        // Tokenise the call name and receiver — both are raw
        // expression text in adapters that flatten compound
        // method-chains. Each token routes through CFG-narrowing
        // bridge_read so a clean overwrite later in the function
        // doesn't keep an old value alive on this synthetic CallArg.
        let mut seen_tokens: ahash::AHashSet<String> = ahash::AHashSet::new();
        let token_meta = crate::edge::EdgeMeta {
            precision: Precision::Exact,
            kind: IdgEdgeKind::IntraRead,
            call_kind: bonsai_callgraph::EdgeKind::Direct,
            via_span: span,
        };
        for source_text in [Some(name), receiver].iter().flatten() {
            for token in extract_identifiers_outside_strings(source_text) {
                if token.is_empty() || !seen_tokens.insert(token.clone()) {
                    continue;
                }
                let arg_zero = match emitted_arg_zero {
                    Some(n) => n,
                    None => {
                        let n = ctx.intern_node(Place::CallArg { site, idx: 0 });
                        emitted_arg_zero = Some(n);
                        n
                    }
                };
                ctx.bridge_read(&token, arg_zero, token_meta);
            }
        }
        // Synchronise arg_nodes so Phase 3 stitching sees this
        // synthetic CallArg{idx=0} when resolving the callee's
        // Param(0). Otherwise cross-call edges miss the synthetic
        // edge entirely.
        if let Some(n) = emitted_arg_zero {
            arg_nodes.push(n);
        }
    }

    let mut arg_spans: SmallVec<[Span; 4]> = SmallVec::new();
    for arg in args {
        arg_spans.push(arg.span);
    }
    // The synthetic args.is_empty() fallback above pushes one
    // extra arg_node into `arg_nodes` without a corresponding
    // arg span — pad `arg_spans` with the call's own span so
    // the two vectors stay aligned for the post-walk
    // compound-expression bridger.
    while arg_spans.len() < arg_nodes.len() {
        arg_spans.push(span);
    }
    ctx.out.call_sites.push(CallSiteRef {
        site,
        callee_name: name.to_string(),
        receiver: receiver.map(str::to_string),
        receiver_types: receiver_types.to_vec(),
        call_kind,
        args_count: u8::try_from(arg_nodes.len()).unwrap_or(u8::MAX),
        call_ret_node: ret_node,
        call_arg_nodes: arg_nodes,
        call_arg_spans: arg_spans,
        is_assign_rhs: false,
    });
}

/// Walk a `Throw` event. Emits `Read(value_name) → Throw(ty)` edge
/// and records the throw site for Phase 3 cross-function stitching.
fn walk_throw(span: Span, value_name: Option<&str>, thrown_type: Option<&str>, ctx: &mut TransferCtx<'_>) {
    let ty_id = thrown_type.map(|t| TypeId(ctx.intern_name(t)));
    let throw_place = match ty_id {
        Some(ty) => Place::Throw { ty },
        None => {
            // Untyped throw: use a sentinel "*" type id. Phase 3
            // treats this as a catch-all match.
            let star = TypeId(ctx.intern_name("*"));
            Place::Throw { ty: star }
        }
    };
    let throw_node = ctx.intern_node(throw_place);
    if let Some(name) = value_name {
        if !name.is_empty() {
            ctx.bridge_read(
                name,
                throw_node,
                crate::edge::EdgeMeta {
                    precision: Precision::Exact,
                    kind: IdgEdgeKind::IntraThrow,
                    call_kind: bonsai_callgraph::EdgeKind::Direct,
                    via_span: span,
                },
            );
        }
    }
    ctx.out.throw_sites.push(ThrowSite {
        throw_node,
        thrown_type: ty_id,
        span,
    });
}

/// Walk a `Try` event. Recursively walks body / catch / finally
/// blocks. For each declared catch type, emits `Throw(ty) → Catch(ty)`
/// edges from in-body throws of matching type, and a
/// `Catch(ty) → Write(catch_param)` edge if the adapter named the
/// caught binding.
fn walk_try(
    span: Span,
    body: &[FlowEvent],
    catch_events: &[FlowEvent],
    finally_events: &[FlowEvent],
    catch_param: Option<&str>,
    catch_types: &[String],
    ctx: &mut TransferCtx<'_>,
) {
    // SSA-style join for try-catch: snapshot last_writer at try
    // entry, walk body with an independent copy, then walk catch
    // starting from the entry snapshot, then merge body+catch
    // last_writer states. Either branch's writer remains live for
    // post-`try` code, so a tainted write inside the body reaches
    // downstream consumers even when the catch overwrites the same
    // name with a clean value (and vice versa). Without this, a
    // single-branch overwrite (e.g. `t = ""` in the catch arm)
    // silently kills the body's tainted writer, making try/except
    // act like a sanitizer for the source — not what the engine
    // does and not what the audit tests expect.
    let entry_writers = ctx.last_writer.clone();
    let throws_before = ctx.out.throw_sites.len();
    walk_events(body, ctx);
    let body_throws = ctx.out.throw_sites[throws_before..].to_vec();
    let after_body = std::mem::replace(&mut ctx.last_writer, entry_writers);

    for catch_type in catch_types {
        if catch_type.is_empty() {
            continue;
        }
        let catch_ty = TypeId(ctx.intern_name(catch_type));
        let catch_node = ctx.intern_node(Place::Catch { ty: catch_ty });

        for throw in &body_throws {
            // Match by type id. Adapter-emitted thrown types are
            // already canonicalised; same type → same id.
            // Untyped throws use the "*" sentinel which never
            // matches a concrete catch type — fall back to the
            // catch-all branch below.
            let matches = match throw.thrown_type {
                Some(thrown) => thrown == catch_ty,
                None => false,
            };
            if matches {
                ctx.emit(IdgEdge {
                    from: throw.throw_node,
                    to: catch_node,
                    meta: crate::edge::EdgeMeta {
                        precision: Precision::Exact,
                        kind: IdgEdgeKind::IntraThrow,
                        call_kind: bonsai_callgraph::EdgeKind::Direct,
                        via_span: throw.span,
                    },
                });
            }
        }

        if let Some(param) = catch_param {
            if !param.is_empty() {
                let bind_target = ctx.write_node(param, span);
                ctx.commit_writer(param, bind_target);
                ctx.emit(IdgEdge {
                    from: catch_node,
                    to: bind_target,
                    meta: crate::edge::EdgeMeta {
                        precision: Precision::Exact,
                        kind: IdgEdgeKind::IntraAssign,
                        call_kind: bonsai_callgraph::EdgeKind::Direct,
                        via_span: span,
                    },
                });
            }
        }
    }

    // If the catch is type-untyped (catch-all): connect every body
    // throw to a catch-all node, and bind the param if present.
    if catch_types.is_empty() && !body_throws.is_empty() {
        let any_ty = TypeId(ctx.intern_name("*"));
        let catch_node = ctx.intern_node(Place::Catch { ty: any_ty });
        for throw in &body_throws {
            ctx.emit(IdgEdge {
                from: throw.throw_node,
                to: catch_node,
                meta: crate::edge::EdgeMeta {
                    precision: Precision::Exact,
                    kind: IdgEdgeKind::IntraThrow,
                    call_kind: bonsai_callgraph::EdgeKind::Direct,
                    via_span: throw.span,
                },
            });
        }
        if let Some(param) = catch_param {
            if !param.is_empty() {
                let bind_target = ctx.write_node(param, span);
                ctx.commit_writer(param, bind_target);
                ctx.emit(IdgEdge {
                    from: catch_node,
                    to: bind_target,
                    meta: crate::edge::EdgeMeta {
                        precision: Precision::Exact,
                        kind: IdgEdgeKind::IntraAssign,
                        call_kind: bonsai_callgraph::EdgeKind::Direct,
                        via_span: span,
                    },
                });
            }
        }
    }

    walk_events(catch_events, ctx);
    // Merge after_body into ctx.last_writer (which now holds the
    // post-catch state). Per-name union: each name's writer set
    // is the union of body-end writers and catch-end writers, so
    // post-`try` reads see the writers from whichever branch
    // actually committed them.
    for (name, writers) in after_body {
        let merged = ctx.last_writer.entry(name).or_default();
        for w in writers {
            if !merged.contains(&w) {
                merged.push(w);
            }
        }
    }
    walk_events(finally_events, ctx);
}

/// Build the destination Place for an assignment target. Returns
/// `(write_node, is_field_write)` where `is_field_write` reports
/// whether the target is a field path projection.
///
/// Handles two adapter-emitted forms:
/// - bare identifier (`x`) → `Place::Write { name, path: [] }`
/// - field path (`obj.field`, `obj.a.b`) → `Place::Write { name = "obj", path = ["field" / "a", "b"] }`
///
/// Subscript notation (`obj[key]`) is treated as field path with the
/// literal subscript text as the segment, mirroring how other
/// engine layers handle it.
fn build_target_node(target: &str, span: Span, ctx: &mut TransferCtx<'_>) -> (NodeId, bool) {
    let trimmed = target.trim();
    if !trimmed.contains('.') && !trimmed.contains('[') {
        return (ctx.write_node(trimmed, span), false);
    }
    // Tokenise into bare segments. A leading `obj` followed by
    // `.field` or `[k]` forms the field path.
    let mut head: Option<&str> = None;
    let mut segments: SmallVec<[StrId; 4]> = SmallVec::new();
    let mut cursor = 0;
    let bytes = trimmed.as_bytes();
    while cursor < bytes.len() {
        // Read identifier-ish segment until next separator.
        let start = cursor;
        while cursor < bytes.len() && !matches!(bytes[cursor], b'.' | b'[' | b']') {
            cursor += 1;
        }
        let seg = trimmed[start..cursor].trim();
        if !seg.is_empty() {
            if head.is_none() {
                head = Some(seg);
            } else {
                let id = ctx.intern_name(seg);
                segments.push(id);
            }
        }
        if cursor < bytes.len() {
            // Skip the separator(s).
            cursor += 1;
        }
    }
    let name = head.unwrap_or(trimmed);
    let name_id = ctx.intern_name(name);
    let place = Place::Write {
        name: name_id,
        path: segments,
        span,
    };
    let pid = ctx.out.places.intern(place);
    let nid = ctx.out.nodes.intern(ctx.out.func, pid);
    // Caller (walk_assign) is responsible for committing the
    // writer to `last_writer` AFTER it has emitted source bridges
    // from the prior writers. For field writes we still treat the
    // base name as overwritten (conservative — field mutation
    // affects the object), so the caller commits the write.
    (nid, true)
}

/// Heuristic: is `s` a bare identifier? Used for `Yield::value_text`
/// Side-effect classification for a single output argument.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SideEffectKind {
    /// The argument is *write-only* — the call overwrites it
    /// without reading the prior value. Suppresses the regular
    /// `Read(arg) → CallArg` input edge so a tainted prior value
    /// of the carrier doesn't leak through the call.
    /// `strcpy`, `snprintf`, `read`, `fgets`.
    WriteOnly,
    /// The argument is *read-write* — the call appends to or
    /// otherwise composes with the prior value. The input edge
    /// remains so the prior taint flows into the new write.
    /// `strcat`, `strncat`.
    ReadWrite,
}

/// Return the set of output argument indices (and their kind) for
/// known side-effecting library calls. POSIX I/O functions like
/// `fgets(buf, sz, stream)`, `read(fd, buf, n)`, scanf-family
/// `fscanf(stream, fmt, &out, ...)` all write back through one or
/// more of their arguments — without modeling that, the IDG
/// closure misses the data flow from a tainted stream into the
/// argument buffer. Returning an explicit `(index, kind)` list per
/// call name keeps the modelling conservative (false-positive-safe):
/// we only emit a synthetic write when we KNOW the function
/// mutates the named argument, and we mark WriteOnly entries so
/// the transfer pass suppresses the regular input edge — that
/// avoids tainting `snprintf(clean_buf, sz, "literal")`'s output
/// just because `clean_buf` was tainted before.
///
/// The set is intentionally limited to widely-used C/POSIX
/// functions. Higher-level languages don't usually have
/// side-effecting calls of this shape; their adapters emit
/// `FlowEvent::Assign` directly.
/// For pipe-style side-effects, list the arg indices that carry
/// VALUE-bearing input into the side-effect output. Differs from
/// "every non-output arg" because snprintf-style functions take
/// size/format args that don't carry data — only the format
/// arguments after the format string do. Returns an empty
/// `SmallVec` for sink-style side-effects (fgets/read/getline/recv).
pub(crate) fn pipe_input_args_for(
    name: &str,
    receiver: Option<&str>,
    args_count: usize,
) -> smallvec::SmallVec<[u8; 4]> {
    let mut out: smallvec::SmallVec<[u8; 4]> = smallvec::SmallVec::new();
    if receiver.is_some_and(|r| {
        !r.is_empty() && r != "stdio" && r != "stdlib" && r != "io" && r != "std" && r != "fs"
    }) {
        return out;
    }
    let bare = bare_function_name(name);
    match bare {
        // snprintf(buf, size, fmt, args...) — value-bearing inputs
        // are everything from the format string onward (idx 2+).
        // size (idx 1) is structural: counting it as a taint carrier
        // would propagate `sizeof(buf)` into buf's data.
        "sprintf" | "snprintf" | "vsprintf" | "vsnprintf" => {
            for i in 2..args_count {
                if let Ok(b) = u8::try_from(i) {
                    out.push(b);
                }
            }
        }
        // strcpy(dst, src) / memcpy(dst, src, n): src carries the
        // payload. n is structural.
        "strcpy" | "strncpy" | "memcpy" | "memmove" => {
            if args_count > 1 {
                out.push(1);
            }
        }
        // strcat(dst, src) / strncat(dst, src, n): src + prior
        // contents of dst carry the payload. ReadWrite-style on dst,
        // but we already preserve dst's prior taint through the
        // regular bridge_read (strcat is ReadWrite, not WriteOnly).
        "strcat" | "strncat" => {
            if args_count > 1 {
                out.push(1);
            }
        }
        // sscanf(input, fmt, *outputs): input (idx 0) is the data
        // source; fmt (idx 1) is structural; outputs are the
        // WriteOnly args. Propagate from idx 0 to each output.
        "sscanf" => {
            out.push(0);
        }
        // fscanf(stream, fmt, *outputs): the stream carries data
        // from outside the program; fmt is structural. Skip.
        _ => {}
    }
    out
}

pub(crate) fn side_effect_output_args_for(
    name: &str,
    receiver: Option<&str>,
) -> smallvec::SmallVec<[(u8, SideEffectKind); 4]> {
    let mut out: smallvec::SmallVec<[(u8, SideEffectKind); 4]> = smallvec::SmallVec::new();
    let bare = bare_function_name(name);
    // Reject method calls on user-defined objects — these
    // knowledge-base entries are for free C-like functions.
    if receiver.is_some_and(|r| {
        !r.is_empty() && r != "stdio" && r != "stdlib" && r != "io" && r != "std" && r != "fs"
    }) {
        return out;
    }
    use SideEffectKind::{ReadWrite, WriteOnly};
    match bare {
        // POSIX/C stdio reads: write the buffer arg.
        "fgets" | "gets" | "gets_s" => out.push((0, WriteOnly)),
        // read/recv: write the second arg buffer.
        "read" | "pread" | "recv" | "recvfrom" | "recvmsg" => out.push((1, WriteOnly)),
        // scanf family: write every arg after the format string.
        "scanf" => {
            for i in 1..=4u8 {
                out.push((i, WriteOnly));
            }
        }
        "fscanf" | "sscanf" => {
            for i in 2..=4u8 {
                out.push((i, WriteOnly));
            }
        }
        // getline: writes lineptr (arg 0) and n (arg 1).
        "getline" => {
            out.push((0, WriteOnly));
            out.push((1, WriteOnly));
        }
        // strcpy / strncpy / memcpy / memmove: dest arg overwrites.
        "strcpy" | "strncpy" | "memcpy" | "memmove" => out.push((0, WriteOnly)),
        // strcat / strncat: dest arg appends — read-write.
        "strcat" | "strncat" => out.push((0, ReadWrite)),
        // sprintf-family writes formatted output to arg 0.
        "sprintf" | "snprintf" | "vsprintf" | "vsnprintf" => out.push((0, WriteOnly)),
        _ => {}
    }
    out
}

/// Strip a leading `mod.` / `mod::` / `Cls.` prefix from `name`
/// so `os.read` / `std::io::Read::read` / `Foo.bar` all reduce to
/// the bare function name `read` / `read` / `bar`.
fn bare_function_name(name: &str) -> &str {
    // Scan for the last `.` or `::` separator; everything after is
    // the bare name.
    let mut last = 0;
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' && i + 1 < bytes.len() && bytes[i + 1] == b':' {
            last = i + 2;
            i += 2;
            continue;
        }
        if bytes[i] == b'.' {
            last = i + 1;
        }
        i += 1;
    }
    &name[last..]
}

/// Extract every bare-identifier token from `text`, ignoring runs
/// inside string literals (`"..."`, `'...'`, `` `...` ``). Mirrors
/// the engine's `identifier_tokens_outside_strings` so the IDG
/// captures the same name set the engine did when an adapter only
/// populates `value_text` for compound argument expressions.
pub(crate) fn extract_identifiers_outside_strings(text: &str) -> Vec<String> {
    // First strip every `sizeof(...)` / `alignof(...)` / `_Alignof(...)`
    // / `typeof(...)` payload — these are type-introspection
    // expressions whose enclosed identifier is structural, not a
    // value-bearing read. Treating them as taint carriers leaks
    // structural reads into argument-tainted constraint checks
    // (e.g. `memcpy(dst, src, sizeof(it_node))` would tag the
    // length arg as tainted just because `it_node`'s value is
    // tainted). The replacement preserves source length so any
    // downstream span reasoning stays consistent.
    let scrubbed = strip_typeof_subexpressions(text);
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in scrubbed.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if matches!(c, '\'' | '"' | '`') {
            push_id_token(&mut tokens, &mut current);
            quote = Some(c);
            continue;
        }
        if c == '_' || c.is_ascii_alphanumeric() {
            current.push(c);
        } else {
            push_id_token(&mut tokens, &mut current);
        }
    }
    push_id_token(&mut tokens, &mut current);
    tokens
}

/// Replace every `sizeof(...)` / `alignof(...)` / `_Alignof(...)`
/// / `typeof(...)` / `__typeof__(...)` payload with whitespace,
/// so the surrounding tokeniser doesn't pull identifiers out of
/// them. C's `sizeof EXPR` (no parens) form is a corner case the
/// adapters reliably surface with parens, so the parsed rewrite
/// covers the common path. The replacement preserves source
/// length so any downstream span reasoning stays consistent.
fn strip_typeof_subexpressions(text: &str) -> String {
    const KEYWORDS: &[&str] = &["sizeof", "alignof", "_Alignof", "typeof", "__typeof__"];
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        // Identifier-shaped prefix at byte i?
        let start = i;
        while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
            i += 1;
        }
        let ident = &bytes[start..i];
        let matched_keyword = KEYWORDS.iter().any(|kw| kw.as_bytes() == ident);
        if !matched_keyword {
            if i == start {
                i += 1;
            }
            continue;
        }
        // Skip whitespace before the open paren.
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b'(' {
            // `sizeof EXPR` form — adapters rarely emit; bail out
            // so we don't accidentally erase the whole tail.
            continue;
        }
        let open = j;
        let mut depth: i32 = 1;
        let mut k = open + 1;
        while k < bytes.len() && depth > 0 {
            match bytes[k] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                break;
            }
            k += 1;
        }
        if depth != 0 {
            continue;
        }
        // Replace bytes (start..=k) with spaces — clears the
        // keyword AND the parenthesised payload while keeping the
        // overall byte length identical.
        for byte in out.iter_mut().take(k + 1).skip(start) {
            *byte = b' ';
        }
        i = k + 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Flush `current` as an identifier token if it looks like one
/// (starts with a letter or underscore, not a digit).
fn push_id_token(tokens: &mut Vec<String>, current: &mut String) {
    if current
        .chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_')
    {
        tokens.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

/// which the adapter emits as raw expression text. The strict shape
/// is "ASCII alphanumeric + underscore, starts with non-digit".
/// Matches the convention the existing engine uses for bare-identifier
/// detection.
fn is_bare_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().expect("non-empty checked above");
    if !(first.is_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// Convenience re-export for callers driving the transfer pass
/// over many functions sequentially. Each output carries its own
/// name pool ([`TransferOutput::names`]) so the segment merge can
/// remap StrIds independently per function.
pub fn transfer_for_many<'d>(decls: impl IntoIterator<Item = &'d Decl>) -> Vec<TransferOutput> {
    decls.into_iter().map(transfer_function_for).collect()
}

/// Discard helper: tests sometimes want to assert the FuncId of a
/// `&Arc<Decl>` without unwrapping the Arc.
#[doc(hidden)]
#[must_use]
pub fn func_id_of(decl: &Arc<Decl>) -> FuncId {
    FuncId::new(decl.symbol.raw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::{FileId, Span as CommonSpan, SymbolId};
    use bonsai_lang_api::{CallArg, ModulePath, Visibility};

    fn span(lo: u64, hi: u64) -> CommonSpan {
        CommonSpan::new(FileId::new(0), lo, hi)
    }

    fn empty_decl(sym: u32, name: &str) -> Decl {
        Decl {
            symbol: SymbolId::new(sym),
            kind: bonsai_lang_api::DeclKind::Function,
            name: name.to_string(),
            qualified_name: None,
            module_path: ModulePath::default(),
            span: span(0, 100),
            name_span: span(0, 10),
            visibility: Visibility::Public,
            parent: None,
            body_span: Some(span(10, 100)),
            flow_events: Vec::new(),
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
        }
    }

    fn count_edges_of(out: &TransferOutput, kind: IdgEdgeKind) -> usize {
        out.edges.iter().filter(|e| e.meta.kind == kind).count()
    }

    #[test]
    fn empty_decl_emits_no_edges() {
        let decl = empty_decl(1, "f");
        let out = transfer_function_for(&decl);
        assert_eq!(out.edges.len(), 0);
        assert_eq!(out.call_sites.len(), 0);
        assert_eq!(out.throw_sites.len(), 0);
    }

    #[test]
    fn parameter_seeding_creates_param_to_read_bridge() {
        let mut decl = empty_decl(1, "f");
        decl.params = vec!["x".to_string(), "y".to_string()];
        let out = transfer_function_for(&decl);
        // Two Param→Read bridge edges, one per param.
        assert_eq!(out.edges.len(), 2);
        for edge in &out.edges {
            assert_eq!(edge.meta.kind, IdgEdgeKind::IntraAssign);
            assert_eq!(edge.meta.precision, Precision::Exact);
        }
    }

    #[test]
    fn empty_param_name_skipped() {
        let mut decl = empty_decl(1, "f");
        decl.params = vec!["x".to_string(), String::new(), "z".to_string()];
        let out = transfer_function_for(&decl);
        // Only x and z get bridge edges.
        assert_eq!(out.edges.len(), 2);
    }

    #[test]
    fn assign_simple_emits_read_to_write_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Assign {
            span: span(20, 30),
            target: "y".to_string(),
            source_name: Some("x".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }];
        let out = transfer_function_for(&decl);
        // One IntraAssign edge: `Read(x) → Write(y, span=20..30)`.
        // The CFG-narrowing transfer pass routes any subsequent
        // reads of `y` directly from the new `Write(y, span)` to
        // the consumer (per-use last_writer bridge), so no shared
        // `Write→Read(y)` bridge is needed.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
    }

    #[test]
    fn assign_compound_emits_one_edge_per_source_name() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Assign {
            span: span(20, 40),
            target: "z".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: vec!["x".to_string(), "y".to_string()],
            declares_new_binding: false,
            value_kind: None,
        }];
        let out = transfer_function_for(&decl);
        // Two IntraAssign edges: one per source name into Write(z).
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 2);
    }

    #[test]
    fn assign_call_rhs_records_call_site_and_emits_arg_and_ret_edges() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Assign {
            span: span(50, 70),
            target: "y".to_string(),
            source_name: None,
            source_call: Some("transform".to_string()),
            source_call_args: vec!["x".to_string()],
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }];
        let out = transfer_function_for(&decl);
        // Read(x) → CallArg(site, 0)
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 1);
        // CallRet(site) → Write(y).
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
        assert_eq!(out.call_sites.len(), 1);
        assert_eq!(out.call_sites[0].callee_name, "transform");
        assert_eq!(out.call_sites[0].args_count, 1);
    }

    /// Phase 8 SSA-style narrowing test: a clean overwrite of a
    /// previously-tainted name should produce per-statement Write
    /// nodes so closure analysis doesn't smear the original taint
    /// into post-overwrite reads.
    #[test]
    fn clean_overwrite_kills_prior_writer() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![
            // t = source_local
            FlowEvent::Assign {
                span: span(10, 20),
                target: "t".to_string(),
                source_name: Some("source_local".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            },
            // sink_a(t)
            FlowEvent::Call {
                span: span(25, 40),
                name: "sink_a".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: vec![CallArg {
                    span: span(32, 33),
                    name: None,
                    value_text: "t".to_string(),
                    place: Some("t".to_string()),
                    source_names: Vec::new(),
                }],
            },
            // t = "literal" (clean overwrite, no source name)
            FlowEvent::Assign {
                span: span(45, 55),
                target: "t".to_string(),
                source_name: None,
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            },
            // sink_b(t)
            FlowEvent::Call {
                span: span(60, 75),
                name: "sink_b".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                args: vec![CallArg {
                    span: span(67, 68),
                    name: None,
                    value_text: "t".to_string(),
                    place: Some("t".to_string()),
                    source_names: Vec::new(),
                }],
            },
        ];
        let out = transfer_function_for(&decl);
        // Two distinct Write(t, span) nodes — one per assign event —
        // so post-overwrite reads bridge from the second writer
        // only. Without span-distinguished Writes the closure from
        // source_local would smear into sink_b too.
        let write_count = out
            .places
            .places
            .iter()
            .filter(|p| matches!(p, Place::Write { name: _, path, .. } if path.is_empty()))
            .count();
        // Two Write(t) variants (one per span).
        assert!(
            write_count >= 2,
            "expected per-statement Write(t) nodes, got {} write places",
            write_count
        );
        // sink_a should bridge from the FIRST writer (which was
        // bridged from Read(source_local)). sink_b should bridge
        // from the SECOND writer (no incoming flow). The closure
        // walker test in builder/service confirms this end-to-end.
    }

    #[test]
    fn standalone_call_records_site_with_arg_nodes() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Call {
            span: span(10, 25),
            name: "log".to_string(),
            receiver: Some("logger".to_string()),
            receiver_types: vec!["Logger".to_string()],
            call_kind: CallKind::Method,
            args: vec![
                CallArg {
                    span: span(11, 15),
                    name: None,
                    value_text: "user".to_string(),
                    place: Some("user".to_string()),
                    source_names: Vec::new(),
                },
                CallArg {
                    span: span(17, 22),
                    name: None,
                    value_text: "level".to_string(),
                    place: Some("level".to_string()),
                    source_names: Vec::new(),
                },
            ],
        }];
        let out = transfer_function_for(&decl);
        // Three IntraRead edges: two for the explicit args (user,
        // level) plus one for the implicit receiver (logger) flowing
        // into the synthetic receiver slot.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 3);
        assert_eq!(out.call_sites.len(), 1);
        let site = &out.call_sites[0];
        assert_eq!(site.callee_name, "log");
        assert_eq!(site.args_count, 2);
        assert_eq!(site.receiver.as_deref(), Some("logger"));
        assert_eq!(site.receiver_types, vec!["Logger".to_string()]);
        assert_eq!(site.call_kind, CallKind::Method);
        assert_eq!(site.call_arg_nodes.len(), 2);
    }

    #[test]
    fn call_arg_without_place_still_records_arg_node() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Call {
            span: span(10, 25),
            name: "f".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: span(11, 25),
                name: None,
                // Quoted string-literal value_text — the adapter
                // passed a literal, not a name. The IDG should NOT
                // tokenise the inner text as an identifier.
                value_text: "\"literal_string\"".to_string(),
                place: None,
                source_names: Vec::new(),
            }],
        }];
        let out = transfer_function_for(&decl);
        // No Read edge (no place identifier, value_text is a quoted
        // literal), but the arg node is still interned for Phase 3.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 0);
        assert_eq!(out.call_sites.len(), 1);
        assert_eq!(out.call_sites[0].call_arg_nodes.len(), 1);
    }

    #[test]
    fn call_arg_value_text_tokenises_identifier_outside_strings() {
        // Adapter that doesn't populate `place` / `source_names` but
        // does pass the compound expression as `value_text`. The IDG
        // tokenises and emits a Read edge for `tmp` so closure
        // analysis catches the flow — matches the engine's behaviour.
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Call {
            span: span(10, 30),
            name: "exec".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: CallKind::Function,
            args: vec![CallArg {
                span: span(11, 30),
                name: None,
                value_text: "\"-c \" + tmp".to_string(),
                place: None,
                source_names: Vec::new(),
            }],
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraRead), 1);
    }

    #[test]
    fn return_with_value_name_emits_intra_return_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Return {
            span: span(40, 50),
            value_name: Some("result".to_string()),
            value_text: Some("result".to_string()),
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraReturn), 1);
    }

    #[test]
    fn return_without_value_name_emits_no_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Return {
            span: span(40, 50),
            value_name: None,
            value_text: None,
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraReturn), 0);
    }

    #[test]
    fn throw_with_value_name_records_throw_site_and_emits_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Throw {
            span: span(20, 35),
            value_name: Some("err".to_string()),
            thrown_type: Some("IOException".to_string()),
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 1);
        assert_eq!(out.throw_sites.len(), 1);
        assert!(out.throw_sites[0].thrown_type.is_some());
    }

    #[test]
    fn try_catch_typed_match_emits_throw_to_catch_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Try {
            span: span(0, 80),
            body: vec![FlowEvent::Throw {
                span: span(10, 25),
                value_name: Some("e".to_string()),
                thrown_type: Some("IOException".to_string()),
            }],
            catch_events: Vec::new(),
            finally_events: Vec::new(),
            catch_param: Some("ex".to_string()),
            catch_types: vec!["IOException".to_string()],
        }];
        let out = transfer_function_for(&decl);
        // 1 IntraThrow from the body's Read(e) → Throw(IOException)
        // 1 IntraThrow from Throw(IOException) → Catch(IOException)
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 2);
        // 1 IntraAssign from Catch(IOException) → Write(ex)
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
    }

    #[test]
    fn try_catch_all_matches_typed_throw_via_star_sentinel() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Try {
            span: span(0, 80),
            body: vec![FlowEvent::Throw {
                span: span(10, 25),
                value_name: Some("e".to_string()),
                thrown_type: None,
            }],
            catch_events: Vec::new(),
            finally_events: Vec::new(),
            catch_param: Some("ex".to_string()),
            catch_types: Vec::new(),
        }];
        let out = transfer_function_for(&decl);
        // Body throw: Read(e) → Throw(*) (1 IntraThrow)
        // Catch-all: Throw(*) → Catch(*) (1 IntraThrow)
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 2);
        // Catch(*) → Write(ex) (1 IntraAssign)
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
    }

    #[test]
    fn branch_walks_both_arms() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Branch {
            span: span(0, 100),
            condition: Some("flag".to_string()),
            then_events: vec![FlowEvent::Assign {
                span: span(10, 20),
                target: "x".to_string(),
                source_name: Some("a".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            }],
            else_events: vec![FlowEvent::Assign {
                span: span(30, 40),
                target: "x".to_string(),
                source_name: Some("b".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            }],
        }];
        let out = transfer_function_for(&decl);
        // Each arm emits one IntraAssign edge (Read(src) →
        // Write(x, arm_span)). Two distinct Write(x) nodes (per
        // span) so the SSA-style branch join unions them — both
        // are live for any read after the merge.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 2);
    }

    #[test]
    fn loop_body_walks_through() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Loop {
            span: span(0, 60),
            loop_kind: bonsai_lang_api::LoopKind::While,
            body: vec![FlowEvent::Assign {
                span: span(10, 20),
                target: "x".to_string(),
                source_name: Some("y".to_string()),
                source_call: None,
                source_call_args: Vec::new(),
                source_names: Vec::new(),
                declares_new_binding: false,
                value_kind: None,
            }],
        }];
        let out = transfer_function_for(&decl);
        // Body's assign produces ONE Write(x, span) and the loop
        // body is walked twice (fixpoint approximation), so the
        // assign edge is emitted twice — once per pass — but both
        // are deduped in the place dict because they share the same
        // (target span, source name). The transfer pass's emit list
        // does NOT dedup, so two parallel edges land in `edges`.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 2);
    }

    #[test]
    fn defer_body_walks_through() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Defer {
            span: span(0, 30),
            body: vec![FlowEvent::Return {
                span: span(10, 20),
                value_name: Some("x".to_string()),
                value_text: None,
            }],
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraReturn), 1);
    }

    #[test]
    fn yield_with_bare_identifier_emits_yield_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Yield {
            span: span(20, 30),
            value_text: Some("value".to_string()),
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraYield), 1);
    }

    #[test]
    fn yield_with_complex_expression_emits_no_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Yield {
            span: span(20, 30),
            // Complex expression — not a bare identifier.
            value_text: Some("x + 1".to_string()),
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraYield), 0);
    }

    #[test]
    fn await_with_value_name_emits_await_edge() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Await {
            span: span(20, 30),
            value_name: Some("promise".to_string()),
        }];
        let out = transfer_function_for(&decl);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAwait), 1);
    }

    #[test]
    fn break_continue_lifecycle_emit_no_edges() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![
            FlowEvent::Break {
                span: span(10, 15),
                label: None,
            },
            FlowEvent::Continue {
                span: span(20, 28),
                label: None,
            },
        ];
        let out = transfer_function_for(&decl);
        assert_eq!(out.edges.len(), 0);
    }

    #[test]
    fn field_assign_creates_field_write_kind() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Assign {
            span: span(20, 30),
            target: "obj.field".to_string(),
            source_name: Some("x".to_string()),
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: None,
        }];
        let out = transfer_function_for(&decl);
        // The source-name → target edge should be an IntraFieldWrite,
        // not a plain IntraAssign, because the target is a field path.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraFieldWrite), 1);
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 0);
    }

    #[test]
    fn nested_branch_in_try_walks_all_arms() {
        let mut decl = empty_decl(1, "f");
        decl.flow_events = vec![FlowEvent::Try {
            span: span(0, 100),
            body: vec![FlowEvent::Branch {
                span: span(10, 60),
                condition: None,
                then_events: vec![FlowEvent::Throw {
                    span: span(20, 28),
                    value_name: Some("a".to_string()),
                    thrown_type: Some("E".to_string()),
                }],
                else_events: vec![FlowEvent::Throw {
                    span: span(40, 48),
                    value_name: Some("b".to_string()),
                    thrown_type: Some("E".to_string()),
                }],
            }],
            catch_events: Vec::new(),
            finally_events: Vec::new(),
            catch_param: Some("ex".to_string()),
            catch_types: vec!["E".to_string()],
        }];
        let out = transfer_function_for(&decl);
        // 2 body throws (Read(a)→Throw, Read(b)→Throw) + 2 throw→catch
        // = 4 IntraThrow.
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraThrow), 4);
        // 1 catch→write(ex)
        assert_eq!(count_edges_of(&out, IdgEdgeKind::IntraAssign), 1);
        assert_eq!(out.throw_sites.len(), 2);
    }

    #[test]
    fn each_transfer_output_owns_its_name_pool() {
        // Each call to `transfer_function_for` returns a
        // `TransferOutput` whose `names` pool is independent. The
        // segment merge re-interns names into the segment-level
        // pool, so per-function pool isolation is the contract.
        let mut decl_a = empty_decl(1, "a");
        decl_a.flow_events = vec![FlowEvent::Return {
            span: span(0, 10),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let mut decl_b = empty_decl(2, "b");
        decl_b.flow_events = vec![FlowEvent::Return {
            span: span(0, 10),
            value_name: Some("x".to_string()),
            value_text: None,
        }];
        let out_a = transfer_function_for(&decl_a);
        let out_b = transfer_function_for(&decl_b);
        // Both pools have "x" as their first interned identifier.
        assert!(out_a.names.lookup("x").is_some());
        assert!(out_b.names.lookup("x").is_some());
    }

    #[test]
    fn is_bare_identifier_acceptance() {
        assert!(is_bare_identifier("x"));
        assert!(is_bare_identifier("user_id"));
        assert!(is_bare_identifier("_internal"));
        assert!(is_bare_identifier("a1"));
        assert!(!is_bare_identifier(""));
        assert!(!is_bare_identifier("1abc"));
        assert!(!is_bare_identifier("x.y"));
        assert!(!is_bare_identifier("x + 1"));
        assert!(!is_bare_identifier("\"literal\""));
    }

    #[test]
    fn transfer_for_many_processes_all_decls() {
        let decls: Vec<Decl> = (0..3).map(|i| empty_decl(i, &format!("f{i}"))).collect();
        let outs = transfer_for_many(decls.iter());
        assert_eq!(outs.len(), 3);
        for (i, o) in outs.iter().enumerate() {
            assert_eq!(o.func, FuncId::new(i as u32));
        }
    }
}
