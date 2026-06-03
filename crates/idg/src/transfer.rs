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
//!   - When the adapter also emits the sibling `Call { name: f }`,
//!     `site` is that semantic call event's span rather than the
//!     whole assignment span, so return stitching and assignment
//!     binding share one `CallRet`.
//! - `Assign { source_names: [..., f, ...] }` with a sibling
//!   `Call { name: f }` in the assignment span also binds that
//!   sibling `CallRet` to the target. This covers iterator/coroutine
//!   lowering where the semantic call is emitted separately from the
//!   loop-variable assignment.
//! - `Call { name, args }` → for each arg with a `place`:
//!   `Read(place) → CallArg(site, idx)` (intra). Phase 3 adds the
//!   `CallArg(site, idx) → callee.Param(idx)` cross edge.
//! - `Return { value_name: Some(name) }` → `Read(name) → Return`
//! - `Throw { value_name: Some(name), thrown_type }` →
//!   `Read(name) → Throw(ty)`. Compound throw expressions whose
//!   adapters emit an inner constructor/call also bridge the inner
//!   argument carriers into `Throw(ty)`. Phase 3 stitches the
//!   inter-function `callee.Throw(ty) → caller.Catch(ty)` edges.
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
//! - `Loop { body }` → walk body once for may-run edges and once
//!   more with body-end writers live so loop-carried reads see the
//!   previous iteration. Duplicate edges are suppressed by the
//!   transfer context.
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

pub(crate) const RETURN_FIELD_BASE: &str = "__bonsai_return";
pub(crate) const YIELD_FIELD_BASE: &str = "__bonsai_yield";

/// Transfer-time options supplied by higher layers.
///
/// The IDG core keeps library/API knowledge out of the graph builder.
/// Security analysis may pass declarative shapes extracted from an
/// editable rulepack; ordinary code-intelligence callers use the empty
/// default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferOptions {
    /// Configured output-argument overwrite shapes.
    pub clean_output_overwrites: Vec<CleanOutputOverwriteSpec>,
    /// Configured source calls that write untrusted data into output arguments.
    pub source_output_args: Vec<SourceOutputArgSpec>,
    /// Whether to add diagnostic, over-approximate receiver-field
    /// propagation. Security/default semantic queries cap precision at
    /// `Narrowed`, so they can skip this expensive graph expansion.
    pub include_diagnostic_field_flows: bool,
    /// Whether to add broad implicit-receiver method propagation. The
    /// default graph keeps this compatibility heuristic; large security
    /// scans can skip it and rely on exact call/arg/return propagation.
    pub include_receiver_method_propagation: bool,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            clean_output_overwrites: Vec::new(),
            source_output_args: Vec::new(),
            include_diagnostic_field_flows: true,
            include_receiver_method_propagation: true,
        }
    }
}

impl TransferOptions {
    /// True when no optional transfer behavior is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clean_output_overwrites.is_empty()
            && self.source_output_args.is_empty()
            && self.include_diagnostic_field_flows
            && self.include_receiver_method_propagation
    }

    /// Return a semantically equivalent option set in deterministic
    /// order. Rulepack extraction can traverse hash-backed maps, so
    /// callers should canonicalize before hashing, persisting, or
    /// building a graph from configured transfer shapes.
    #[must_use]
    pub fn canonicalized(mut self) -> Self {
        self.clean_output_overwrites.sort_by(|a, b| {
            (&a.callee, a.output_arg_index, a.value_start_arg_index).cmp(&(
                &b.callee,
                b.output_arg_index,
                b.value_start_arg_index,
            ))
        });
        self.clean_output_overwrites.dedup();

        for spec in &mut self.source_output_args {
            spec.output_arg_indices.sort_unstable();
            spec.output_arg_indices.dedup();
        }
        self.source_output_args
            .sort_by(|a, b| (&a.callee, &a.output_arg_indices).cmp(&(&b.callee, &b.output_arg_indices)));
        self.source_output_args.dedup();
        self
    }
}

/// Declarative call shape whose output argument is overwritten by the
/// call result. Value-bearing inputs are wired into the fresh writer,
/// so clean inputs kill stale taint while tainted inputs still flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanOutputOverwriteSpec {
    /// Callee name or `regex:`-prefixed matcher.
    pub callee: String,
    /// Positional argument index that receives the overwritten value.
    pub output_arg_index: usize,
    /// First positional argument index containing value-bearing inputs.
    pub value_start_arg_index: usize,
}

/// Declarative source call shape whose output arguments receive
/// untrusted data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceOutputArgSpec {
    /// Callee name or `regex:`-prefixed matcher.
    pub callee: String,
    /// Positional argument indices written by the source call.
    pub output_arg_indices: Vec<usize>,
}

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
    /// Caller-side synthetic receiver slot for method calls. This
    /// is intentionally separate from positional `call_arg_nodes`
    /// because adapters model grammar receivers via
    /// `Decl::receiver_param_index`; the builder maps this node to
    /// that formal receiver slot without shifting user arguments.
    pub receiver_arg_node: Option<NodeId>,
    /// Source span of each argument expression. Used by the
    /// post-walk compound-expression bridger to wire inner-call
    /// returns into outer-call args (`Repository.search(source())`
    /// — `source()`'s CallRet bridges to `search`'s CallArg).
    pub call_arg_spans: SmallVec<[Span; 4]>,
    /// Adapter-normalized source place for each argument when one
    /// exists. The workspace stitcher uses this to carry precise
    /// field writers (`env.cmd`) into callee field reads
    /// (`param.cmd`) without tainting the whole container.
    pub call_arg_places: SmallVec<[String; 4]>,
    /// Adapter-extracted keyword / label names for call arguments.
    /// Phase 3 uses these to stitch named arguments to the matching
    /// callee parameter instead of relying only on positional order.
    pub call_arg_names: SmallVec<[Option<String>; 4]>,
    /// True when this call site arose from `target = callee(args)`
    /// (a `FlowEvent::Assign` with `source_call`). Resolution still
    /// needs an explicit semantic callee or summary before any
    /// interprocedural flow is stitched.
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
    /// Index of the declared receiver parameter, when the adapter
    /// exposes a method receiver as a normal formal parameter.
    pub receiver_param_index: Option<usize>,
    /// Receiver/container bases that this declaration writes via
    /// adapter-derived receiver-field metadata. Languages with
    /// implicit receivers (Kotlin / Scala / Swift data constructors,
    /// Ruby `@ivars`, etc.) do not have a receiver parameter index,
    /// so Phase 3 uses these bases to forward constructor-return
    /// fields back to the assigned object.
    pub receiver_field_bases: Vec<String>,
    /// Receiver-state base names used by methods whose receiver is
    /// implicit in the language body (`self`, `super`, `this`, etc.).
    /// Phase 3 uses these bases to forward caller receiver fields into
    /// the callee even when there is no explicit receiver parameter.
    pub implicit_receiver_bases: Vec<String>,
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
            receiver_param_index: None,
            receiver_field_bases: Vec::new(),
            implicit_receiver_bases: Vec::new(),
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
    transfer_function_for_with_options(decl, &TransferOptions::default())
}

/// Run the transfer-function pass with caller-provided options.
pub fn transfer_function_for_with_options(decl: &Decl, options: &TransferOptions) -> TransferOutput {
    let func = FuncId::new(decl.symbol.raw());
    let mut out = TransferOutput::new(func);
    out.params.clone_from(&decl.params);
    out.receiver_param_index = decl.receiver_param_index;
    out.receiver_field_bases = receiver_field_bases(decl);
    out.implicit_receiver_bases = implicit_receiver_bases(decl);
    let mut ctx = TransferCtx {
        out: &mut out,
        options,
        last_writer: ahash::AHashMap::new(),
        catch_projection_receivers: ahash::AHashSet::default(),
        emitted_edges: ahash::AHashSet::default(),
        field_precise_container_assigns: collect_field_precise_container_assigns(&decl.flow_events),
        method_receiver_bases: collect_method_receiver_bases(&decl.flow_events),
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

    emit_receiver_field_writes(decl, &mut ctx);
    walk_events(&decl.flow_events, &mut ctx);
    bridge_compound_expression_calls(&mut ctx);
    out
}

fn receiver_field_bases(decl: &Decl) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = ahash::AHashSet::default();
    for write in &decl.receiver_field_writes {
        let Some(base) = field_base_name(&write.target) else {
            continue;
        };
        let base = base.trim();
        if !base.is_empty() && seen.insert(base.to_string()) {
            out.push(base.to_string());
        }
    }
    out
}

fn implicit_receiver_bases(decl: &Decl) -> Vec<String> {
    let mut out = Vec::new();
    for name in decl
        .implicit_receiver_names
        .iter()
        .chain(decl.receiver_state_sources.iter())
    {
        push_implicit_receiver_base(&mut out, name);
    }
    for write in &decl.receiver_field_writes {
        push_implicit_receiver_base(&mut out, &write.target);
    }
    collect_implicit_receiver_bases(&decl.flow_events, &mut out);
    out
}

fn collect_implicit_receiver_bases(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Call { name, receiver, .. } => {
                push_implicit_receiver_base(out, name);
                if let Some(receiver) = receiver {
                    push_implicit_receiver_base(out, receiver);
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
                push_implicit_receiver_base(out, target);
                if let Some(source_name) = source_name {
                    push_implicit_receiver_base(out, source_name);
                }
                if let Some(source_call) = source_call {
                    push_implicit_receiver_base(out, source_call);
                }
                for source in source_names {
                    push_implicit_receiver_base(out, source);
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if let Some(value_text) = value_text {
                    push_implicit_receiver_base(out, value_text);
                }
                if let Some(value_name) = value_name {
                    push_implicit_receiver_base(out, value_name);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_implicit_receiver_bases(then_events, out);
                collect_implicit_receiver_bases(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_implicit_receiver_bases(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_implicit_receiver_bases(body, out);
                collect_implicit_receiver_bases(catch_events, out);
                collect_implicit_receiver_bases(finally_events, out);
            }
            _ => {}
        }
    }
}

fn push_implicit_receiver_base(out: &mut Vec<String>, text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    let candidate = field_base_name(trimmed).unwrap_or(trimmed).trim();
    let bare = candidate.trim_start_matches(['$', '@', '%']);
    if !matches!(bare, "self" | "this" | "super" | "base" | "Self") {
        return;
    }
    for value in [candidate, bare] {
        if !value.is_empty() && !out.iter().any(|existing| existing == value) {
            out.push(value.to_string());
        }
    }
}

fn emit_receiver_field_writes(decl: &Decl, ctx: &mut TransferCtx<'_>) {
    for write in &decl.receiver_field_writes {
        let target = write.target.trim();
        if target.is_empty() {
            continue;
        }
        let (write_node, is_field_write) = build_target_node(target, write.span, ctx);
        let edge_meta = crate::edge::EdgeMeta {
            precision: Precision::Exact,
            kind: if is_field_write {
                IdgEdgeKind::IntraFieldWrite
            } else {
                IdgEdgeKind::IntraAssign
            },
            call_kind: bonsai_callgraph::EdgeKind::Direct,
            via_span: write.span,
        };
        for &param_idx in &write.source_param_indices {
            let Some(param_name) = decl.params.get(param_idx).map(String::as_str) else {
                continue;
            };
            if !param_name.is_empty() {
                ctx.bridge_read(param_name, write_node, edge_meta);
            }
        }
        ctx.commit_writer(target, write_node);
    }
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
                ctx.emit(IdgEdge {
                    from: inner.call_ret_node,
                    to: outer_arg_node,
                    meta: crate::edge::EdgeMeta {
                        precision: Precision::Narrowed,
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
    options: &'a TransferOptions,
    /// Per-name "current writers" — the `Write` nodes that the
    /// transfer pass considers most-recent for each name in CFG
    /// order. Each entry is a small set because branch joins union
    /// the writers from both arms. The CFG-narrowing pass uses
    /// this to emit `Write(name, span_W) → consumer-node` edges
    /// instead of routing through a shared `Read(name)` node — that
    /// way a clean overwrite later in the function "kills" the
    /// earlier writer's bridge into subsequent reads.
    last_writer: ahash::AHashMap<StrId, smallvec::SmallVec<[NodeId; 4]>>,
    /// Catch parameters whose member projections should be treated as
    /// exception-value reads while walking the active catch body.
    catch_projection_receivers: ahash::AHashSet<StrId>,
    /// Exact duplicate edge suppression for this transfer output.
    /// Loop-carried modeling and compound-call bridging can revisit
    /// the same source event; retaining one edge is enough for all
    /// reachability queries and keeps downstream IDG closures smaller.
    emitted_edges: ahash::AHashSet<IdgEdge>,
    /// Bare container assignments whose same statement also emits
    /// explicit field writes (`payload`, `payload.cmd`,
    /// `payload.user`). The bare write is a structural carrier in
    /// that shape; feeding every literal identifier into it collapses
    /// sibling fields.
    field_precise_container_assigns: ahash::AHashSet<(Span, String)>,
    /// Bare names that appear as the receiver of a method call in this
    /// function (`raw` in `raw.dup`, `routed` in `routed.to_s`). A
    /// method invocation derives its result from the *whole* receiver
    /// value, so a sibling method projection (`raw.dup`) must NOT
    /// demote bare `raw` to a structural field-only base the way a
    /// genuine field/index access (`obj.field`, `data[:cmd]`) does.
    method_receiver_bases: ahash::AHashSet<String>,
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
        let writers: smallvec::SmallVec<[NodeId; 4]> =
            self.last_writer.get(&sid).cloned().unwrap_or_default();
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

    /// Mark `node` as an additional may-write for `name` without
    /// killing existing writers. This is for collection-like writes
    /// whose read semantics can observe any previously written value
    /// rather than a scalar overwrite.
    fn append_writer(&mut self, name: &str, node: NodeId) {
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

    /// Append an edge to the output's edge list.
    fn emit(&mut self, edge: IdgEdge) {
        if self.emitted_edges.insert(edge) {
            self.out.edges.push(edge);
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct AssignCallSiteHint {
    site_span: Span,
    sibling_call_event: bool,
}

fn collect_field_precise_container_assigns(events: &[FlowEvent]) -> ahash::AHashSet<(Span, String)> {
    let mut out = ahash::AHashSet::default();
    collect_field_precise_container_assigns_into(events, &mut out);
    out
}

fn collect_field_precise_container_assigns_into(
    events: &[FlowEvent],
    out: &mut ahash::AHashSet<(Span, String)>,
) {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. } => {
                if let Some(base) = field_base_name(target) {
                    out.insert((*span, base.to_string()));
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_field_precise_container_assigns_into(then_events, out);
                collect_field_precise_container_assigns_into(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_field_precise_container_assigns_into(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_field_precise_container_assigns_into(body, out);
                collect_field_precise_container_assigns_into(catch_events, out);
                collect_field_precise_container_assigns_into(finally_events, out);
            }
            _ => {}
        }
    }
}

fn field_base_name(target: &str) -> Option<&str> {
    let trimmed = target.trim();
    let split = trimmed.find(['.', '['])?;
    let base = trimmed[..split].trim();
    (!base.is_empty()).then_some(base)
}

/// Collect the bare base names that are used as a method-call receiver
/// somewhere in the function. `raw.dup` / `routed.to_s` contribute
/// `raw` / `routed`; chained calls like `routed.to_s.empty?` also
/// contribute the intermediate `routed` (via the receiver's base).
/// Used by [`SemanticSourceFilter`] to keep a whole-value receiver
/// from being demoted to a field-only structural base.
fn collect_method_receiver_bases(events: &[FlowEvent]) -> ahash::AHashSet<String> {
    let mut out = ahash::AHashSet::default();
    collect_method_receiver_bases_into(events, &mut out);
    out
}

fn collect_method_receiver_bases_into(events: &[FlowEvent], out: &mut ahash::AHashSet<String>) {
    for event in events {
        match event {
            FlowEvent::Call {
                receiver, call_kind, ..
            } => {
                if matches!(call_kind, CallKind::Method) {
                    push_method_receiver_base(receiver.as_deref(), out);
                }
            }
            FlowEvent::Assign { source_call, .. } => {
                // `a = raw.dup` carries the method projection through
                // `source_call` rather than a `source_names` entry.
                if let Some(call) = source_call.as_deref() {
                    push_method_receiver_base(method_chain_receiver_carrier(call).as_deref(), out);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_method_receiver_bases_into(then_events, out);
                collect_method_receiver_bases_into(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_method_receiver_bases_into(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_method_receiver_bases_into(body, out);
                collect_method_receiver_bases_into(catch_events, out);
                collect_method_receiver_bases_into(finally_events, out);
            }
            _ => {}
        }
    }
}

fn push_method_receiver_base(receiver: Option<&str>, out: &mut ahash::AHashSet<String>) {
    let Some(receiver) = receiver.map(str::trim).filter(|r| !r.is_empty()) else {
        return;
    };
    // The receiver itself is a whole value (`routed.to_s` as the
    // receiver of `.empty?`), and so is its base (`routed`).
    out.insert(receiver.to_string());
    if let Some(base) = field_base_name(receiver) {
        out.insert(base.to_string());
    }
}

#[derive(Default)]
struct SemanticSourceFilter {
    structural_bases: ahash::AHashSet<String>,
}

impl SemanticSourceFilter {
    fn from_sources(
        primary: Option<&str>,
        sources: &[String],
        method_receiver_bases: &ahash::AHashSet<String>,
    ) -> Self {
        let mut filter = Self::default();
        for source in primary.into_iter().chain(sources.iter().map(String::as_str)) {
            let Some(base) = field_base_name(source) else {
                continue;
            };
            if source_uses_index_projection(source, base) {
                continue;
            }
            // A method projection (`raw.dup`, `routed.to_s`) derives
            // its value from the whole receiver, so it must not demote
            // bare `raw`/`routed` to a field-only structural base — the
            // receiver legitimately flows whole when it is also read
            // directly (`cmd: "#{raw}"`, `cmd: routed`). Genuine field
            // / index projections (`obj.field`, `data[:cmd]`,
            // Solidity `routed.length`) keep their base structural.
            if method_receiver_bases.contains(base) {
                continue;
            }
            filter.structural_bases.insert(base.to_string());
        }
        filter
    }

    fn is_structural_base_token(&self, source: &str) -> bool {
        let trimmed = source.trim();
        !trimmed.is_empty() && !trimmed.contains(['.', '[']) && self.structural_bases.contains(trimmed)
    }
}

fn source_uses_index_projection(source: &str, base: &str) -> bool {
    let trimmed = source.trim();
    let Some(rest) = trimmed.strip_prefix(base.trim()) else {
        return false;
    };
    let Some(tail) = rest.strip_prefix('.').or_else(|| rest.strip_prefix('[')) else {
        return false;
    };
    let first = tail
        .trim_start_matches(['"', '\'', '`'])
        .split(['.', '[', ']', '"', '\'', '`'])
        .next()
        .unwrap_or("")
        .trim();
    !first.is_empty() && first.chars().all(|ch| ch.is_ascii_digit())
}

/// Walk a slice of FlowEvents, dispatching each to its handler.
fn walk_events(events: &[FlowEvent], ctx: &mut TransferCtx<'_>) {
    for (index, event) in events.iter().enumerate() {
        let assign_call_site = assign_call_site_hint(events, index);
        walk_event(event, assign_call_site, ctx);
    }
}

/// Dispatch one FlowEvent to the appropriate handler.
fn walk_event(event: &FlowEvent, assign_call_site: Option<AssignCallSiteHint>, ctx: &mut TransferCtx<'_>) {
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
            assign_call_site,
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
            let field_precise_return = value_text
                .as_deref()
                .is_some_and(|text| emit_container_field_writes(RETURN_FIELD_BASE, text, *span, ctx));
            if let Some(name) = value_name.as_deref() {
                if !name.is_empty() {
                    let sid = ctx.intern_name(name);
                    if bridged.insert(sid) {
                        ctx.bridge_read(name, return_node, return_meta);
                    }
                    emit_storage_copy_to_special_base(RETURN_FIELD_BASE, name, *span, ctx);
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
            if !field_precise_return {
                if let Some(text) = value_text.as_deref() {
                    let trimmed = text.trim();
                    if is_bare_identifier(trimmed) {
                        emit_storage_copy_to_special_base(RETURN_FIELD_BASE, trimmed, *span, ctx);
                    }
                    if !text.is_empty() {
                        // Use the same expression bridge as assignments so
                        // value-preserving method calls (`return x.upper()`,
                        // `return @cmd.upcase`) carry the receiver while
                        // string/keyword noise stays out.
                        bridge_value_expr_to_node(text, return_node, *span, IdgEdgeKind::IntraReturn, ctx);
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
            // Loop body may run zero or more times. The first pass
            // emits may-run edges and establishes body-end writers;
            // the second pass lets reads in the body see those
            // previous-iteration writers. Because there is one
            // stable Write node per source write span, the second
            // pass completes the loop-carried structural edges.
            // `emit` suppresses duplicate edges from rewalking the
            // same statements.
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
                let field_precise_yield = emit_container_field_writes(YIELD_FIELD_BASE, text, *span, ctx);
                let trimmed = text.trim();
                if is_bare_identifier(trimmed) {
                    emit_storage_copy_to_special_base(YIELD_FIELD_BASE, trimmed, *span, ctx);
                }
                if !field_precise_yield && is_bare_identifier(trimmed) {
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

fn emit_storage_copy_to_special_base(
    special_base: &str,
    source: &str,
    span: Span,
    ctx: &mut TransferCtx<'_>,
) -> NodeId {
    let write_node = ctx.write_node(special_base, span);
    bridge_value_expr_to_node(source, write_node, span, IdgEdgeKind::IntraAssign, ctx);
    write_node
}

fn emit_container_field_writes(
    special_base: &str,
    text: &str,
    span: Span,
    ctx: &mut TransferCtx<'_>,
) -> bool {
    let fields = container_field_initializers(text);
    let spreads = container_spreads(text);
    if fields.is_empty() && spreads.is_empty() {
        return false;
    }
    for (field, value) in fields {
        let target = format!("{special_base}.{field}");
        let write_node = ctx.write_node(&target, span);
        bridge_value_expr_to_node(&value, write_node, span, IdgEdgeKind::IntraFieldWrite, ctx);
    }
    if !spreads.is_empty() {
        let write_node = ctx.write_node(special_base, span);
        for spread in spreads {
            bridge_value_expr_to_node(&spread, write_node, span, IdgEdgeKind::IntraAssign, ctx);
        }
    }
    true
}

fn bridge_value_expr_to_node(
    value: &str,
    target: NodeId,
    span: Span,
    kind: IdgEdgeKind,
    ctx: &mut TransferCtx<'_>,
) {
    let meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    let mut bridged: ahash::AHashSet<StrId> = ahash::AHashSet::default();
    let qualified_accesses = extract_qualified_accesses_outside_strings(value);
    for (access, start, end) in &qualified_accesses {
        let sid = ctx.intern_name(access);
        if bridged.insert(sid) {
            ctx.bridge_read(access, target, meta);
        }
        let source_slice = value.get(*start..*end).unwrap_or(access);
        if !source_slice.contains('[') {
            if let Some(receiver) = method_chain_receiver_carrier(access) {
                let sid = ctx.intern_name(&receiver);
                if bridged.insert(sid) {
                    ctx.bridge_read(&receiver, target, meta);
                }
            }
        } else if !source_slice.trim_end().ends_with(']') {
            if let Some(receiver) = static_subscript_method_receiver(access) {
                let sid = ctx.intern_name(&receiver);
                if bridged.insert(sid) {
                    ctx.bridge_read(&receiver, target, meta);
                }
            }
        }
    }
    let token_text = text_without_qualified_ranges(value, &qualified_accesses);
    for token in extract_identifiers_outside_strings(&token_text) {
        if token.is_empty() || is_non_value_token(&token) {
            continue;
        }
        let sid = ctx.intern_name(&token);
        if bridged.insert(sid) {
            ctx.bridge_read(&token, target, meta);
        }
    }
}

fn is_non_value_token(token: &str) -> bool {
    matches!(
        token,
        "return"
            | "yield"
            | "from"
            | "lambda"
            | "if"
            | "else"
            | "case"
            | "match"
            | "true"
            | "false"
            | "True"
            | "False"
            | "None"
            | "null"
            | "nil"
    )
}

fn container_field_initializers(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for body in brace_bodies(text) {
        for part in split_top_level(&body, ',') {
            let trimmed = part.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("**")
                || trimmed.starts_with("...")
                || trimmed.starts_with('*')
            {
                continue;
            }
            if let Some((key, value)) = split_top_level_once(trimmed, ':') {
                if let Some(field) = static_container_key(&key) {
                    out.push((field, value.trim().to_string()));
                }
                continue;
            }
            if is_bare_identifier(trimmed) {
                out.push((trimmed.to_string(), trimmed.to_string()));
            }
        }
    }
    out
}

fn container_spreads(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for body in brace_bodies(text) {
        for part in split_top_level(&body, ',') {
            let trimmed = part.trim();
            let spread = trimmed
                .strip_prefix("**")
                .or_else(|| trimmed.strip_prefix("..."))
                .map(str::trim);
            if let Some(spread) = spread.filter(|spread| !spread.is_empty()) {
                out.push(spread.to_string());
            }
        }
    }
    out
}

fn brace_bodies(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<(char, usize)> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' => stack.push((ch, idx)),
            '[' | '(' => stack.push((ch, idx)),
            '}' => {
                let Some((open, start)) = stack.pop() else {
                    continue;
                };
                if open == '{' && stack.is_empty() {
                    out.push(text[start + 1..idx].to_string());
                }
            }
            ']' => {
                if stack.last().is_some_and(|(open, _)| *open == '[') {
                    stack.pop();
                }
            }
            ')' => {
                if stack.last().is_some_and(|(open, _)| *open == '(') {
                    stack.pop();
                }
            }
            _ => {}
        }
    }
    out
}

fn split_top_level(text: &str, delimiter: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ if ch == delimiter && depth == 0 => {
                out.push(text[start..idx].to_string());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(text[start..].to_string());
    out
}

fn split_top_level_once(text: &str, delimiter: char) -> Option<(String, String)> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            _ if ch == delimiter && depth == 0 => {
                return Some((text[..idx].to_string(), text[idx + ch.len_utf8()..].to_string()));
            }
            _ => {}
        }
    }
    None
}

fn static_container_key(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_start_matches(':').trim();
    let key = trimmed
        .strip_prefix('"')
        .and_then(|part| part.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|part| part.strip_suffix('\''))
        })
        .unwrap_or(trimmed)
        .trim();
    if key.is_empty()
        || !key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        || !key.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(key.to_string())
}

fn assign_call_site_hint(events: &[FlowEvent], index: usize) -> Option<AssignCallSiteHint> {
    let FlowEvent::Assign {
        span: assign_span,
        source_name,
        source_call,
        source_names,
        ..
    } = events.get(index)?
    else {
        return None;
    };

    // Many adapters emit `target = callee(args)` as an Assign event
    // next to the real semantic Call event. Use the Call event's
    // span as the call-site identity; the assignment span is only the
    // write location. This keeps Phase-3 return stitching keyed to
    // the same span the resolver/callgraph uses. Iterator/generator
    // lowerings can place the Call before the Assign, so check both
    // adjacent directions while staying inside the assignment span.
    for sibling in events[..index].iter().rev() {
        let sibling_span = flow_event_span(sibling);
        if sibling_span.file != assign_span.file || sibling_span.end < assign_span.start {
            break;
        }
        let FlowEvent::Call {
            span: call_span,
            name,
            ..
        } = sibling
        else {
            continue;
        };
        if span_contains_or_equal(*assign_span, *call_span)
            && assign_sources_match_call(source_call.as_deref(), source_name.as_deref(), source_names, name)
        {
            return Some(AssignCallSiteHint {
                site_span: *call_span,
                sibling_call_event: true,
            });
        }
    }
    for sibling in events.iter().skip(index + 1) {
        let sibling_span = flow_event_span(sibling);
        if sibling_span.file != assign_span.file || sibling_span.start > assign_span.end {
            break;
        }
        let FlowEvent::Call {
            span: call_span,
            name,
            ..
        } = sibling
        else {
            continue;
        };
        if span_contains_or_equal(*assign_span, *call_span)
            && assign_sources_match_call(source_call.as_deref(), source_name.as_deref(), source_names, name)
        {
            return Some(AssignCallSiteHint {
                site_span: *call_span,
                sibling_call_event: true,
            });
        }
    }
    None
}

fn assign_sources_match_call(
    source_call: Option<&str>,
    source_name: Option<&str>,
    source_names: &[String],
    call_name: &str,
) -> bool {
    if call_name.is_empty() {
        return false;
    }
    if let Some(source_call) = source_call.filter(|source_call| !source_call.is_empty()) {
        return source_call == call_name;
    }
    source_name.is_some_and(|source_name| source_name == call_name)
        || source_names.iter().any(|source_name| source_name == call_name)
}

fn span_contains_or_equal(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

fn flow_event_span(event: &FlowEvent) -> Span {
    match event {
        FlowEvent::Assign { span, .. }
        | FlowEvent::Call { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Lifecycle { span, .. } => *span,
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

#[allow(clippy::too_many_arguments)] // FlowEvent::Assign lowering carries the event fields verbatim.
fn walk_assign(
    span: Span,
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
    _declares_new_binding: bool,
    value_kind: Option<bonsai_lang_api::AssignValueKind>,
    source_call_site_hint: Option<AssignCallSiteHint>,
    ctx: &mut TransferCtx<'_>,
) {
    if target.is_empty() {
        return;
    }
    let rhs_is_literal = matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::Literal));
    if is_structural_index_metadata_target(target) {
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
    // A bare container assign is field-precise when the same statement
    // also emits explicit field writes for that container. Adapters
    // anchor those field writes either at the whole container-literal
    // span (equality) or, when a field value is itself a span-anchored
    // source (`user: msg.sender`), at the narrower field-value span —
    // so link by span CONTAINMENT, not equality. Containment is a
    // superset of the old equality match, so existing field-precise
    // shapes are unchanged.
    let suppress_broad_container_inputs = !is_field_write && {
        let bare_target = target.trim();
        ctx.field_precise_container_assigns
            .iter()
            .any(|(field_span, base)| base == bare_target && span_contains_or_equal(span, *field_span))
    };
    if is_structural_index_base_write(target, source_name, source_names, suppress_broad_container_inputs) {
        return;
    }
    if rhs_is_literal {
        // Skip name-bridging; commit the writer as-is so reads
        // of `target` after this point see the literal write.
        ctx.commit_writer(target, write_node);
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
    let suppress_direct_rhs_inputs = suppress_broad_container_inputs
        || (source_call.is_some()
            && !source_call_args.is_empty()
            && matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::CallResult)));
    let source_filter =
        SemanticSourceFilter::from_sources(source_name, source_names, &ctx.method_receiver_bases);
    if !suppress_direct_rhs_inputs {
        if let Some(src) = source_name {
            if !src.is_empty()
                && !source_filter.is_structural_base_token(src)
                && !direct_rhs_source_is_call_internals(src, source_call, source_call_args)
            {
                ctx.bridge_read(src, write_node, edge_meta);
            }
        }
        for src in source_names {
            if src.is_empty()
                || source_filter.is_structural_base_token(src)
                || direct_rhs_source_is_call_internals(src, source_call, source_call_args)
            {
                continue;
            }
            ctx.bridge_read(src, write_node, edge_meta);
        }
    }
    if !suppress_broad_container_inputs {
        if let Some(callee) = source_call.and_then(method_chain_receiver_carrier) {
            if !callee.is_empty() && callee != target {
                ctx.bridge_read(&callee, write_node, edge_meta);
            }
        }
    }

    // Call-RHS shape: `target = callee(args...)`. Two intra edges per
    // arg (Read(arg) → CallArg(site, idx)) plus one
    // CallRet(site) → Write(target). Phase 3 stitches the
    // CallArg → callee.Param and callee.Return → CallRet edges.
    if let Some(callee) = source_call.filter(|_| !suppress_broad_container_inputs) {
        if !callee.is_empty() {
            let site_span = source_call_site_hint.map(|hint| hint.site_span).unwrap_or(span);
            let site = CallSiteId(site_span);
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
            let mut arg_places: SmallVec<[String; 4]> = SmallVec::new();
            let mut arg_names: SmallVec<[Option<String>; 4]> = SmallVec::new();
            for _ in 0..source_call_args.len() {
                arg_spans.push(span);
                arg_names.push(None);
            }
            for arg in source_call_args {
                arg_places.push(arg.clone());
            }
            if !source_call_site_hint.is_some_and(|hint| hint.sibling_call_event) {
                ctx.out.call_sites.push(CallSiteRef {
                    site,
                    callee_name: callee.to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    call_kind: CallKind::Function,
                    args_count: u8::try_from(source_call_args.len()).unwrap_or(u8::MAX),
                    call_ret_node: ret_node,
                    call_arg_nodes: arg_nodes,
                    receiver_arg_node: None,
                    call_arg_spans: arg_spans,
                    call_arg_places: arg_places,
                    call_arg_names: arg_names,
                    is_assign_rhs: true,
                });
            }
        }
    } else if !suppress_broad_container_inputs {
        if let Some(hint) = source_call_site_hint {
            let ret_node = ctx.intern_node(Place::CallRet {
                site: CallSiteId(hint.site_span),
            });
            ctx.emit(IdgEdge {
                from: ret_node,
                to: write_node,
                meta: edge_meta,
            });
        }
    }

    // Commit the new writer LAST: prior bridge_read calls already
    // pulled the source's pre-assign last_writer, so it's safe to
    // overwrite `last_writer[target]` now. Self-assigns (`x = x`)
    // therefore see the prior `x` on the RHS and still update to
    // a fresh writer node post-assign.
    ctx.commit_writer(target, write_node);
}

fn is_structural_index_metadata_target(target: &str) -> bool {
    let trimmed = target.trim();
    trimmed == "sizeof" || trimmed.contains("sizeof(")
}

fn is_structural_index_base_write(
    target: &str,
    source_name: Option<&str>,
    source_names: &[String],
    has_precise_sibling_write: bool,
) -> bool {
    if !has_precise_sibling_write {
        return false;
    }
    let target = target.trim();
    if target.is_empty() {
        return false;
    }
    let mut saw_source = false;
    source_name
        .into_iter()
        .chain(source_names.iter().map(String::as_str))
        .all(|source| {
            let source = source.trim();
            if source.is_empty() {
                return true;
            }
            saw_source = true;
            source == target || source_is_projected_from_target(target, source)
        })
        && saw_source
}

fn source_is_projected_from_target(target: &str, source: &str) -> bool {
    source
        .strip_prefix(target)
        .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('['))
}

fn direct_rhs_source_is_call_internals(
    src: &str,
    source_call: Option<&str>,
    source_call_args: &[String],
) -> bool {
    let src = src.trim();
    if src.is_empty() {
        return true;
    }
    let Some(callee) = source_call.map(str::trim).filter(|callee| !callee.is_empty()) else {
        return false;
    };
    if src == callee || src == bare_function_name(callee) {
        return true;
    }
    if callee
        .split(['.', ':'])
        .filter(|part| !part.is_empty())
        .any(|part| part == src)
    {
        return true;
    }
    source_call_args.iter().any(|arg| arg.trim() == src)
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
    let mut arg_nodes: SmallVec<[NodeId; 4]> = SmallVec::new();
    let mut arg_places: SmallVec<[String; 4]> = SmallVec::new();
    let mut arg_names: SmallVec<[Option<String>; 4]> = SmallVec::new();
    for (idx, arg) in args.iter().enumerate() {
        let arg_idx = u8::try_from(idx).unwrap_or(u8::MAX);
        let arg_node = ctx.intern_node(Place::CallArg { site, idx: arg_idx });
        arg_nodes.push(arg_node);
        let arg_place = call_arg_place_name(arg);
        if output_candidate_place_needs_field_node(&arg_place) {
            let _ = build_target_node(&arg_place, span, ctx);
        }
        arg_places.push(arg_place);
        arg_names.push(arg.name.clone());
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
        let source_filter = SemanticSourceFilter::from_sources(
            arg.place.as_deref(),
            &arg.source_names,
            &ctx.method_receiver_bases,
        );
        if let Some(place) = arg.place.as_deref() {
            if !place.is_empty() && !source_filter.is_structural_base_token(place) {
                let sid = ctx.intern_name(place);
                if emitted.insert(sid) {
                    ctx.bridge_read(place, arg_node, arg_meta);
                }
            }
        }
        for source in &arg.source_names {
            if source.is_empty() || source_filter.is_structural_base_token(source) {
                continue;
            }
            let sid = ctx.intern_name(source);
            if !emitted.insert(sid) {
                continue;
            }
            ctx.bridge_read(source, arg_node, arg_meta);
        }
        bridge_projection_receiver_to_node(arg, arg_node, arg_meta, &mut emitted, ctx);
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
    if name == "send" && args.len() >= 2 {
        if let Some(channel) = args
            .first()
            .map(call_arg_place_name)
            .filter(|place| !place.is_empty())
        {
            let value = &args[1];
            let write_node = ctx.write_node(&channel, span);
            bridge_value_expr_to_node(&value.value_text, write_node, span, IdgEdgeKind::IntraAssign, ctx);
            for source in &value.source_names {
                if !source.is_empty() {
                    ctx.bridge_read(
                        source,
                        write_node,
                        crate::edge::EdgeMeta {
                            precision: Precision::Exact,
                            kind: IdgEdgeKind::IntraAssign,
                            call_kind: bonsai_callgraph::EdgeKind::Direct,
                            via_span: span,
                        },
                    );
                }
            }
            ctx.append_writer(&channel, write_node);
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
    let mut receiver_arg_node = None;
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
            receiver_arg_node = Some(recv_slot);
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
            arg_places.push(String::new());
            arg_names.push(None);
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
    while arg_places.len() < arg_nodes.len() {
        arg_places.push(String::new());
    }
    while arg_names.len() < arg_nodes.len() {
        arg_names.push(None);
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
        receiver_arg_node,
        call_arg_spans: arg_spans,
        call_arg_places: arg_places,
        call_arg_names: arg_names,
        is_assign_rhs: false,
    });
    apply_source_output_arg_writes(span, name, args, ctx);
    apply_clean_output_overwrite_call(span, name, args, ctx);
}

fn apply_source_output_arg_writes(span: Span, name: &str, args: &[CallArg], ctx: &mut TransferCtx<'_>) {
    let output_indices: Vec<usize> = ctx
        .options
        .source_output_args
        .iter()
        .filter(|shape| configured_name_match(&shape.callee, name))
        .flat_map(|shape| shape.output_arg_indices.iter().copied())
        .collect();
    for output_arg_index in output_indices {
        let Some(output) = args.get(output_arg_index).map(call_arg_place_name) else {
            continue;
        };
        let output = output.trim();
        if output.is_empty() || quoted_literal_text(output) {
            continue;
        }
        let (write_node, _) = build_target_node(output, span, ctx);
        ctx.commit_writer(output, write_node);
    }
}

fn apply_clean_output_overwrite_call(span: Span, name: &str, args: &[CallArg], ctx: &mut TransferCtx<'_>) {
    let Some((output_arg_index, value_start_arg_index)) = ctx
        .options
        .clean_output_overwrites
        .iter()
        .find(|shape| configured_name_match(&shape.callee, name))
        .map(|shape| (shape.output_arg_index, shape.value_start_arg_index))
    else {
        return;
    };
    let Some(output) = args.get(output_arg_index).map(call_arg_place_name) else {
        return;
    };
    let output = output.trim();
    if output.is_empty() || quoted_literal_text(output) {
        return;
    }
    let (write_node, _) = build_target_node(output, span, ctx);
    let meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: IdgEdgeKind::IntraAssign,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    for arg in args.iter().skip(value_start_arg_index) {
        bridge_call_arg_value_to_node(arg, write_node, meta, span, ctx);
    }
    ctx.commit_writer(output, write_node);
}

fn bridge_call_arg_value_to_node(
    arg: &CallArg,
    node: NodeId,
    meta: crate::edge::EdgeMeta,
    span: Span,
    ctx: &mut TransferCtx<'_>,
) {
    let source_filter = SemanticSourceFilter::from_sources(
        arg.place.as_deref(),
        &arg.source_names,
        &ctx.method_receiver_bases,
    );
    let mut emitted: ahash::AHashSet<StrId> = ahash::AHashSet::new();
    if let Some(place) = arg.place.as_deref() {
        if !place.is_empty() && !source_filter.is_structural_base_token(place) {
            let sid = ctx.intern_name(place);
            if emitted.insert(sid) {
                ctx.bridge_read(place, node, meta);
            }
        }
    }
    for source in &arg.source_names {
        if source.is_empty() || source_filter.is_structural_base_token(source) {
            continue;
        }
        let sid = ctx.intern_name(source);
        if emitted.insert(sid) {
            ctx.bridge_read(source, node, meta);
        }
    }
    bridge_projection_receiver_to_node(arg, node, meta, &mut emitted, ctx);
    bridge_value_expr_to_node(&arg.value_text, node, span, IdgEdgeKind::IntraAssign, ctx);
}

fn bridge_projection_receiver_to_node(
    arg: &CallArg,
    node: NodeId,
    meta: crate::edge::EdgeMeta,
    emitted: &mut ahash::AHashSet<StrId>,
    ctx: &mut TransferCtx<'_>,
) {
    for receiver in projection_receiver_candidates(arg) {
        let method_projection = arg_has_method_projection_for_receiver(arg, &receiver);
        let catch_projection = catch_projection_receiver_matches(ctx, &receiver);
        if receiver.is_empty()
            || (!method_projection && !catch_projection)
            || !arg_sources_mention_projection_receiver(arg, &receiver)
        {
            continue;
        }
        let sid = ctx.intern_name(&receiver);
        if emitted.insert(sid) {
            ctx.bridge_read(&receiver, node, meta);
        }
        let stripped = receiver.trim_start_matches(['$', '@', '%', '&']);
        if !stripped.is_empty()
            && stripped != receiver
            && arg_sources_mention_projection_receiver(arg, stripped)
        {
            let sid = ctx.intern_name(stripped);
            if emitted.insert(sid) {
                ctx.bridge_read(stripped, node, meta);
            }
        }
    }
}

fn catch_projection_receiver_matches(ctx: &mut TransferCtx<'_>, receiver: &str) -> bool {
    let receiver = receiver.trim();
    if receiver.is_empty() {
        return false;
    }
    let sid = ctx.intern_name(receiver);
    if ctx.catch_projection_receivers.contains(&sid) {
        return true;
    }
    let stripped = receiver.trim_start_matches(['$', '@', '%', '&']);
    if stripped.is_empty() || stripped == receiver {
        return false;
    }
    let stripped_sid = ctx.intern_name(stripped);
    ctx.catch_projection_receivers.contains(&stripped_sid)
}

fn arg_has_method_projection_for_receiver(arg: &CallArg, receiver: &str) -> bool {
    std::iter::once(arg.value_text.as_str())
        .chain(arg.place.as_deref())
        .chain(arg.source_names.iter().map(String::as_str))
        .any(|text| text.contains('(') && projection_receiver_from_text(text).as_deref() == Some(receiver))
}

fn projection_receiver_candidates(arg: &CallArg) -> Vec<String> {
    let mut out = Vec::new();
    for text in std::iter::once(arg.value_text.as_str())
        .chain(arg.place.as_deref())
        .chain(arg.source_names.iter().map(String::as_str))
    {
        if let Some(receiver) = projection_receiver_from_text(text) {
            push_unique_string(&mut out, receiver);
        }
    }
    out
}

fn projection_receiver_from_text(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let normalised = text.replace("->", ".").replace("::", ".");
    let before_call = normalised
        .find('(')
        .map_or(normalised.as_str(), |idx| &normalised[..idx])
        .trim_end();
    let start = before_call
        .char_indices()
        .rev()
        .find(|&(_, ch)| {
            !(ch == '.'
                || ch == '_'
                || ch == '$'
                || ch == '@'
                || ch == '%'
                || ch == '&'
                || ch.is_ascii_alphanumeric())
        })
        .map_or(0, |(idx, ch)| idx + ch.len_utf8());
    let candidate = before_call[start..].trim();
    let (receiver, member) = candidate.rsplit_once('.')?;
    let receiver = receiver.trim();
    let member = member.trim();
    if receiver.is_empty() || member.is_empty() {
        return None;
    }
    Some(receiver.to_string())
}

fn arg_sources_mention_projection_receiver(arg: &CallArg, receiver: &str) -> bool {
    let receiver = receiver.trim();
    if receiver.is_empty() {
        return false;
    }
    let receiver_bare = receiver.trim_start_matches(['$', '@', '%', '&']);
    let source_matches = |source: &str| {
        let source = source.trim();
        let source_bare = source.trim_start_matches(['$', '@', '%', '&']);
        source == receiver
            || (!receiver_bare.is_empty() && source == receiver_bare)
            || source_bare == receiver
            || (!receiver_bare.is_empty() && source_bare == receiver_bare)
            || source
                .strip_prefix(receiver)
                .is_some_and(|rest| rest.starts_with('.'))
            || (!receiver_bare.is_empty()
                && source_bare
                    .strip_prefix(receiver_bare)
                    .is_some_and(|rest| rest.starts_with('.')))
    };
    arg.place.as_deref().is_some_and(source_matches) || arg.source_names.iter().any(|s| source_matches(s))
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn configured_name_match(configured: &str, observed: &str) -> bool {
    if let Some(regex) = configured.trim().strip_prefix("regex:") {
        return regex::Regex::new(regex)
            .ok()
            .is_some_and(|re| re.is_match(observed.trim()));
    }
    let configured = normalise_callee_text(configured);
    let observed = normalise_callee_text(observed);
    if configured.is_empty() || observed.is_empty() {
        return false;
    }
    configured == observed || configured == short_tail(&observed)
}

fn normalise_callee_text(text: &str) -> String {
    text.trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
        .replace("::", ".")
        .replace("->", ".")
        .replace(':', ".")
}

fn short_tail(text: &str) -> &str {
    text.rsplit('.').find(|part| !part.is_empty()).unwrap_or(text)
}

fn quoted_literal_text(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('`') && trimmed.ends_with('`')))
}

fn call_arg_place_name(arg: &CallArg) -> String {
    if let Some(place) = arg.place.as_deref().filter(|place| !place.is_empty()) {
        return normalized_call_arg_storage_place(place).to_string();
    }
    let value = arg.value_text.trim();
    if is_bare_identifier(value) {
        return value.to_string();
    }
    String::new()
}

fn output_candidate_place_needs_field_node(place: &str) -> bool {
    let place = place.trim();
    !place.is_empty() && (place.contains('.') || place.contains('['))
}

fn normalized_call_arg_storage_place(place: &str) -> &str {
    let mut out = place.trim();
    while let Some(inner) = out.strip_prefix('&') {
        out = inner.trim_start();
    }
    out
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
    bridge_compound_throw_sources(body, &body_throws, ctx);
    let after_body = std::mem::replace(&mut ctx.last_writer, entry_writers);

    for catch_type in catch_types {
        if catch_type.is_empty() {
            continue;
        }
        let catch_ty = TypeId(ctx.intern_name(catch_type));
        let catch_node = ctx.intern_node(Place::Catch { ty: catch_ty });

        for throw in &body_throws {
            let matches = thrown_type_matches_catch(throw.thrown_type, catch_ty, catch_type);
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

    let previous_catch_projection_receivers = ctx.catch_projection_receivers.clone();
    if let Some(param) = catch_param {
        if !param.is_empty() {
            let sid = ctx.intern_name(param);
            ctx.catch_projection_receivers.insert(sid);
        }
    }
    walk_events(catch_events, ctx);
    ctx.catch_projection_receivers = previous_catch_projection_receivers;
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

fn bridge_compound_throw_sources(body: &[FlowEvent], throws: &[ThrowSite], ctx: &mut TransferCtx<'_>) {
    for throw in throws {
        bridge_call_args_inside_throw(body, throw.span, throw.throw_node, ctx);
    }
}

fn bridge_call_args_inside_throw(
    events: &[FlowEvent],
    throw_span: Span,
    throw_node: NodeId,
    ctx: &mut TransferCtx<'_>,
) {
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } if span_contains_or_equal(throw_span, *span) => {
                for arg in args {
                    bridge_call_arg_value_to_throw(arg, throw_node, throw_span, ctx);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                bridge_call_args_inside_throw(then_events, throw_span, throw_node, ctx);
                bridge_call_args_inside_throw(else_events, throw_span, throw_node, ctx);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                bridge_call_args_inside_throw(body, throw_span, throw_node, ctx);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                bridge_call_args_inside_throw(body, throw_span, throw_node, ctx);
                bridge_call_args_inside_throw(catch_events, throw_span, throw_node, ctx);
                bridge_call_args_inside_throw(finally_events, throw_span, throw_node, ctx);
            }
            _ => {}
        }
    }
}

fn bridge_call_arg_value_to_throw(arg: &CallArg, throw_node: NodeId, span: Span, ctx: &mut TransferCtx<'_>) {
    let meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: IdgEdgeKind::IntraThrow,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    let source_filter = SemanticSourceFilter::from_sources(
        arg.place.as_deref(),
        &arg.source_names,
        &ctx.method_receiver_bases,
    );
    let mut emitted: ahash::AHashSet<StrId> = ahash::AHashSet::new();
    if let Some(place) = arg.place.as_deref() {
        if !place.is_empty() && !source_filter.is_structural_base_token(place) {
            let sid = ctx.intern_name(place);
            if emitted.insert(sid) {
                ctx.bridge_read(place, throw_node, meta);
            }
        }
    }
    for source in &arg.source_names {
        if source.is_empty() || source_filter.is_structural_base_token(source) {
            continue;
        }
        let sid = ctx.intern_name(source);
        if emitted.insert(sid) {
            ctx.bridge_read(source, throw_node, meta);
        }
    }
    bridge_value_expr_to_node(&arg.value_text, throw_node, span, IdgEdgeKind::IntraThrow, ctx);
}

fn thrown_type_matches_catch(thrown_type: Option<TypeId>, catch_ty: TypeId, catch_type_name: &str) -> bool {
    match thrown_type {
        Some(thrown) if thrown == catch_ty => true,
        Some(_) => is_root_exception_catch_type(catch_type_name),
        None => is_root_exception_catch_type(catch_type_name),
    }
}

fn is_root_exception_catch_type(name: &str) -> bool {
    matches!(
        normalise_exception_type_name(name).as_str(),
        "exception" | "throwable" | "error" | "object"
    )
}

fn normalise_exception_type_name(name: &str) -> String {
    name.trim()
        .trim_start_matches('\\')
        .replace("::", ".")
        .rsplit('.')
        .find(|part| !part.is_empty())
        .unwrap_or(name)
        .to_ascii_lowercase()
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

fn method_chain_receiver_carrier(source_call: &str) -> Option<String> {
    let text = source_call
        .trim()
        .trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .trim();
    if text.is_empty() || text.starts_with('(') {
        return None;
    }

    let mut end = 0usize;
    for (idx, ch) in text.char_indices() {
        if idx == 0 {
            if !(ch.is_alphabetic() || ch == '_') {
                return None;
            }
        } else if !(ch.is_alphanumeric() || ch == '_') {
            break;
        }
        end = idx + ch.len_utf8();
    }
    let candidate = text[..end].trim();
    if !is_bare_identifier(candidate) {
        return None;
    }
    let tail = text[end..].trim_start();
    if !(tail.starts_with('.') || tail.starts_with("->") || tail.starts_with('[')) {
        return None;
    }
    if candidate.chars().next().is_some_and(|ch| ch.is_uppercase()) {
        return None;
    }
    Some(candidate.to_string())
}

fn static_subscript_method_receiver(access: &str) -> Option<String> {
    let (receiver, field_or_method) = access.rsplit_once('.')?;
    if field_or_method.starts_with('@') || !receiver.contains('.') {
        return None;
    }
    Some(receiver.to_string())
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
    // structural reads into argument-tainted constraint checks:
    // a size/type expression should not become tainted just because
    // the referenced identifier's runtime value is tainted. The
    // replacement preserves source length so any
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
        if (matches!(c, '@' | '$' | '%') && current.is_empty()) || c == '_' || c.is_ascii_alphanumeric() {
            current.push(c);
        } else {
            push_id_token(&mut tokens, &mut current);
        }
    }
    push_id_token(&mut tokens, &mut current);
    tokens
}

fn extract_qualified_accesses_outside_strings(text: &str) -> Vec<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(b, b'\'' | b'"' | b'`') {
            quote = Some(b);
            i += 1;
            continue;
        }
        if !is_ident_start_byte_for_access(bytes, i) {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < bytes.len() && is_ident_continue_byte_for_access(bytes[i]) {
            i += 1;
        }
        let mut access = text[start..i].to_string();
        let mut end = i;
        let mut saw_field = false;
        loop {
            if i < bytes.len() && bytes[i] == b'.' {
                let field_start = i + 1;
                if field_start >= bytes.len() || !is_ident_start_byte_for_access(bytes, field_start) {
                    break;
                }
                let mut field_end = field_start + 1;
                while field_end < bytes.len() && is_ident_continue_byte_for_access(bytes[field_end]) {
                    field_end += 1;
                }
                access.push('.');
                access.push_str(&text[field_start..field_end]);
                saw_field = true;
                i = field_end;
                end = i;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'>' {
                let field_start = i + 2;
                if field_start >= bytes.len() || !is_ident_start_byte_for_access(bytes, field_start) {
                    break;
                }
                let mut field_end = field_start + 1;
                while field_end < bytes.len() && is_ident_continue_byte_for_access(bytes[field_end]) {
                    field_end += 1;
                }
                access.push('.');
                access.push_str(&text[field_start..field_end]);
                saw_field = true;
                i = field_end;
                end = i;
                continue;
            }
            if i < bytes.len() && bytes[i] == b'[' {
                let Some((field, field_end)) = parse_static_subscript_access_segment(text, bytes, i) else {
                    break;
                };
                access.push('.');
                access.push_str(&field);
                saw_field = true;
                i = field_end;
                end = i;
                continue;
            }
            break;
        }
        if saw_field && !out.iter().any(|(existing, _, _)| existing == &access) {
            out.push((access, start, end));
        }
    }
    out
}

fn parse_static_subscript_access_segment(text: &str, bytes: &[u8], open: usize) -> Option<(String, usize)> {
    let mut cursor = open.checked_add(1)?;
    skip_ascii_ws(bytes, &mut cursor);
    if cursor >= bytes.len() {
        return None;
    }

    let mut objc_string_key = false;
    let mut symbol_key = false;
    if bytes[cursor] == b':' {
        symbol_key = true;
        cursor += 1;
        skip_ascii_ws(bytes, &mut cursor);
    } else if bytes[cursor] == b'@' {
        objc_string_key = true;
        cursor += 1;
        skip_ascii_ws(bytes, &mut cursor);
    }

    let key = if cursor < bytes.len() && matches!(bytes[cursor], b'\'' | b'"') {
        let quote = bytes[cursor];
        cursor += 1;
        let key_start = cursor;
        let mut escaped = false;
        while cursor < bytes.len() {
            let b = bytes[cursor];
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == quote {
                break;
            }
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != quote {
            return None;
        }
        let key = &text[key_start..cursor];
        cursor += 1;
        key
    } else if symbol_key {
        let key_start = cursor;
        if key_start >= bytes.len() || !is_ident_start_byte_for_access(bytes, key_start) {
            return None;
        }
        cursor += 1;
        while cursor < bytes.len() && is_ident_continue_byte_for_access(bytes[cursor]) {
            cursor += 1;
        }
        &text[key_start..cursor]
    } else {
        return None;
    };

    skip_ascii_ws(bytes, &mut cursor);
    if cursor >= bytes.len() || bytes[cursor] != b']' {
        return None;
    }
    if key.is_empty() || !key.bytes().all(is_static_field_key_byte) {
        return None;
    }

    let mut field = String::with_capacity(key.len() + usize::from(objc_string_key));
    if objc_string_key {
        field.push('@');
    }
    field.push_str(key);
    Some((field, cursor + 1))
}

fn skip_ascii_ws(bytes: &[u8], cursor: &mut usize) {
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
}

fn text_without_qualified_ranges(text: &str, ranges: &[(String, usize, usize)]) -> String {
    if ranges.is_empty() {
        return text.to_string();
    }
    let mut bytes = text.as_bytes().to_vec();
    for (_, start, end) in ranges {
        for idx in *start..(*end).min(bytes.len()) {
            bytes[idx] = b' ';
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| text.to_string())
}

fn is_ident_start_byte_for_access(bytes: &[u8], i: usize) -> bool {
    let b = bytes[i];
    (b == b'_' || b.is_ascii_alphabetic()) && (i == 0 || !is_ident_continue_byte_for_access(bytes[i - 1]))
}

fn is_ident_continue_byte_for_access(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn is_static_field_key_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
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
    let token = current.as_str();
    let stripped = token.trim_start_matches(['@', '$', '%']);
    if !stripped.is_empty()
        && stripped
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

/// Run the transfer-function pass over many declarations with options.
pub fn transfer_for_many_with_options<'d>(
    decls: impl IntoIterator<Item = &'d Decl>,
    options: &TransferOptions,
) -> Vec<TransferOutput> {
    decls
        .into_iter()
        .map(|decl| transfer_function_for_with_options(decl, options))
        .collect()
}

/// Discard helper: tests sometimes want to assert the FuncId of a
/// `&Arc<Decl>` without unwrapping the Arc.
#[doc(hidden)]
#[must_use]
pub fn func_id_of(decl: &Arc<Decl>) -> FuncId {
    FuncId::new(decl.symbol.raw())
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
