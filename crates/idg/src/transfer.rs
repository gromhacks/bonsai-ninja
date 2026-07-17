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
//! - `Return { value_flow }` → AST-derived scalar operands/call results
//!   flow to `Return`; aggregate members flow to field-sensitive return places.
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
//! - `Loop { body }` → preserve entry writers for the zero-iteration
//!   exit, walk once for may-run edges, and replay once with body-end
//!   writers live so loop-carried reads see the previous iteration.
//!   Nested replay is flattened and duplicate edges are suppressed.
//! - `Defer { body }` → walk body normally; we don't separate
//!   deferred edges from immediate ones in the IDG (path
//!   sensitivity is a query-time concern, not a graph-construction
//!   one).
//! - `Yield { value_flow }` → the same structured scalar/aggregate
//!   lowering into the generator's yield places.
//! - `Await { value_name }` → `Read(name) → Place::Await`.

use bonsai_common::{FuncId, Precision, Span};
use bonsai_factstore::{StrId, StringPoolBuilder};
use bonsai_lang_api::{
    call_receiver_fact_for_span, kit::SYNTHETIC_TUPLE_RESULT_PREFIX, AssignValueKind, AssignmentValueFact,
    CallArg, CallKind, CallReceiverFact, Decl, DeclKind, ExpressionFlow, ExpressionProjection, FlowEvent,
};
use smallvec::SmallVec;
use std::sync::Arc;

use crate::dict::{NodeDict, PlaceDict};
use crate::edge::{IdgEdge, IdgEdgeKind};
use crate::node::NodeId;
use crate::place::{CallSiteId, Place, TypeId};

pub(crate) const RETURN_FIELD_BASE: &str = "__bonsai_return";
pub(crate) const YIELD_FIELD_BASE: &str = "__bonsai_yield";
pub(crate) const TEMPORARY_RECEIVER_BASE_PREFIX: &str = "__bonsai_receiver";

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
    /// Configured source calls that deliver untrusted data to callback
    /// parameters.
    pub source_callback_args: Vec<SourceCallbackArgSpec>,
    /// Declarative external-call summaries whose selected inputs flow to the
    /// call result. Materialized once into the IDG rather than replayed per
    /// source closure.
    pub call_result_passthroughs: Vec<CallResultPassthroughSpec>,
    /// Declarative external-call summaries whose selected inputs are written
    /// back through an output argument. These are compiler transfer edges,
    /// materialized once per call site rather than reinterpreted per source.
    pub output_arg_flows: Vec<OutputArgFlowSpec>,
    /// Declarative method summaries whose explicit arguments mutate the
    /// receiver state. Materialized as ordinary def-use edges at the call.
    pub receiver_state_propagations: Vec<ReceiverStatePropagationSpec>,
    /// Whether to add diagnostic, over-approximate receiver-field
    /// propagation. Security/default semantic queries cap precision at
    /// `Narrowed`, so they can skip this expensive graph expansion.
    pub include_diagnostic_field_flows: bool,
    /// Whether to add broad implicit-receiver method propagation. This is a
    /// compatibility heuristic, not exact compiler-derived call evidence.
    pub include_receiver_method_propagation: bool,
    /// Whether Phase 3 eagerly materializes interprocedural object-field
    /// forwarding edges. Completeness-preserving semantic graphs keep this
    /// enabled; disabling it is only appropriate for diagnostic graph builds.
    pub include_field_argument_forwarding: bool,
    /// Whether complete adapter field places use the compact symbolic
    /// access-path relation instead of materialized base × suffix edges.
    pub symbolic_field_forwarding: bool,
    /// Adapter language ids whose emitted field places are complete enough
    /// for symbolic forwarding. Production workspace builds populate this
    /// from adapter capabilities, never from a hard-coded language inventory.
    pub symbolic_field_languages: Vec<String>,
    /// When a call result cannot be resolved to a workspace body,
    /// conservatively carry its explicit arguments (and a syntax-classified
    /// method receiver) into the result at narrowed precision. This name-
    /// agnostic unknown-code summary is independent of exact receiver-state
    /// mutation compatibility below.
    pub include_unresolved_call_result_passthrough: bool,
    /// Whether an unresolved, syntax-classified method call conservatively
    /// carries its receiver into the call result. This is narrower than the
    /// compatibility option above: explicit arguments are not propagated,
    /// and the decision uses only adapter-emitted `CallKind::Method` plus the
    /// receiver operand—not a library/API name inventory.
    pub include_unresolved_receiver_result_passthrough: bool,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            clean_output_overwrites: Vec::new(),
            source_output_args: Vec::new(),
            source_callback_args: Vec::new(),
            call_result_passthroughs: Vec::new(),
            output_arg_flows: Vec::new(),
            receiver_state_propagations: Vec::new(),
            include_diagnostic_field_flows: true,
            include_receiver_method_propagation: true,
            include_field_argument_forwarding: true,
            symbolic_field_forwarding: false,
            symbolic_field_languages: Vec::new(),
            include_unresolved_call_result_passthrough: false,
            // A syntax-classified method consumes its receiver even when the
            // external body is unavailable. Conservatively preserving that
            // receiver in the result is the name-agnostic compiler fallback
            // used for chains such as `value.clone()` / `value.strip()`.
            // Explicit arguments remain excluded unless the broader option
            // above is enabled.
            include_unresolved_receiver_result_passthrough: true,
        }
    }
}

impl TransferOptions {
    /// Canonical compiler graph semantics for ordinary analysis surfaces.
    ///
    /// `field_place_languages` comes from adapter capability metadata. Those
    /// adapters use the compact symbolic access-path relation; all others
    /// retain eager field forwarding. No API or library spellings participate
    /// in this choice.
    #[must_use]
    pub fn compiler_semantics(field_place_languages: Vec<String>) -> Self {
        Self {
            include_diagnostic_field_flows: false,
            include_receiver_method_propagation: false,
            symbolic_field_forwarding: !field_place_languages.is_empty(),
            symbolic_field_languages: field_place_languages,
            include_unresolved_call_result_passthrough: true,
            include_unresolved_receiver_result_passthrough: true,
            ..Self::default()
        }
        .canonicalized()
    }

    /// True when no optional transfer behavior is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clean_output_overwrites.is_empty()
            && self.source_output_args.is_empty()
            && self.source_callback_args.is_empty()
            && self.call_result_passthroughs.is_empty()
            && self.output_arg_flows.is_empty()
            && self.receiver_state_propagations.is_empty()
            && self.include_diagnostic_field_flows
            && self.include_receiver_method_propagation
            && self.include_field_argument_forwarding
            && !self.symbolic_field_forwarding
            && self.symbolic_field_languages.is_empty()
            && !self.include_unresolved_call_result_passthrough
            && self.include_unresolved_receiver_result_passthrough
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
        for spec in &mut self.source_callback_args {
            spec.source_param_indices.sort_unstable();
            spec.source_param_indices.dedup();
        }
        self.source_callback_args.sort_by(|a, b| {
            (&a.callee, a.callback_arg_index, &a.source_param_indices).cmp(&(
                &b.callee,
                b.callback_arg_index,
                &b.source_param_indices,
            ))
        });
        self.source_callback_args.dedup();
        for spec in &mut self.call_result_passthroughs {
            spec.input_arg_indices.sort_unstable();
            spec.input_arg_indices.dedup();
        }
        self.call_result_passthroughs.sort_by(|a, b| {
            (
                &a.callee,
                &a.receiver_type,
                &a.input_arg_indices,
                a.input_receiver,
            )
                .cmp(&(
                    &b.callee,
                    &b.receiver_type,
                    &b.input_arg_indices,
                    b.input_receiver,
                ))
        });
        self.call_result_passthroughs.dedup();
        for spec in &mut self.output_arg_flows {
            spec.value_arg_indices.sort_unstable();
            spec.value_arg_indices.dedup();
        }
        self.output_arg_flows.sort_by(|a, b| {
            (
                &a.callee,
                a.output_arg_index,
                &a.value_arg_indices,
                a.value_start_arg_index,
            )
                .cmp(&(
                    &b.callee,
                    b.output_arg_index,
                    &b.value_arg_indices,
                    b.value_start_arg_index,
                ))
        });
        self.output_arg_flows.dedup();
        self.receiver_state_propagations
            .sort_by(|a, b| (&a.method, &a.receiver_type).cmp(&(&b.method, &b.receiver_type)));
        self.receiver_state_propagations.dedup();
        self.symbolic_field_languages.sort();
        self.symbolic_field_languages.dedup();
        self
    }

    /// Stable identity for every option that changes emitted graph edges.
    /// Database and sidecar caches use this key so differently configured
    /// IDGs cannot alias through one shared service slot.
    #[must_use]
    pub fn semantic_fingerprint(&self) -> u64 {
        use bonsai_hash::Hasher as StableHasher;

        fn absorb_u64(hasher: &mut StableHasher, value: u64) {
            hasher.absorb(&value.to_le_bytes());
            hasher.absorb_separator();
        }

        fn absorb_str(hasher: &mut StableHasher, value: &str) {
            hasher.absorb(value.as_bytes());
            hasher.absorb_separator();
        }

        let options = self.clone().canonicalized();
        let mut hasher = StableHasher::new();
        absorb_str(&mut hasher, "bonsai-idg-transfer-options-v14");
        absorb_u64(&mut hasher, u64::from(options.include_diagnostic_field_flows));
        absorb_u64(
            &mut hasher,
            u64::from(options.include_receiver_method_propagation),
        );
        absorb_u64(&mut hasher, u64::from(options.include_field_argument_forwarding));
        absorb_u64(&mut hasher, u64::from(options.symbolic_field_forwarding));
        absorb_u64(&mut hasher, options.symbolic_field_languages.len() as u64);
        for language in &options.symbolic_field_languages {
            absorb_str(&mut hasher, language);
        }
        absorb_u64(
            &mut hasher,
            u64::from(options.include_unresolved_call_result_passthrough),
        );
        absorb_u64(
            &mut hasher,
            u64::from(options.include_unresolved_receiver_result_passthrough),
        );
        absorb_u64(&mut hasher, options.clean_output_overwrites.len() as u64);
        for spec in &options.clean_output_overwrites {
            absorb_str(&mut hasher, "clean-output-overwrite");
            absorb_str(&mut hasher, &spec.callee);
            absorb_u64(&mut hasher, spec.output_arg_index as u64);
            absorb_u64(&mut hasher, spec.value_start_arg_index as u64);
        }
        absorb_u64(&mut hasher, options.source_output_args.len() as u64);
        for spec in &options.source_output_args {
            absorb_str(&mut hasher, "source-output-args");
            absorb_str(&mut hasher, &spec.callee);
            absorb_u64(&mut hasher, spec.output_arg_indices.len() as u64);
            for index in &spec.output_arg_indices {
                absorb_u64(&mut hasher, *index as u64);
            }
        }
        absorb_u64(&mut hasher, options.source_callback_args.len() as u64);
        for spec in &options.source_callback_args {
            absorb_str(&mut hasher, "source-callback-args");
            absorb_str(&mut hasher, &spec.callee);
            absorb_u64(&mut hasher, spec.callback_arg_index as u64);
            absorb_u64(&mut hasher, spec.source_param_indices.len() as u64);
            for index in &spec.source_param_indices {
                absorb_u64(&mut hasher, *index as u64);
            }
        }
        absorb_u64(&mut hasher, options.call_result_passthroughs.len() as u64);
        for spec in &options.call_result_passthroughs {
            absorb_str(&mut hasher, "call-result-passthrough");
            absorb_str(&mut hasher, &spec.callee);
            absorb_str(&mut hasher, spec.receiver_type.as_deref().unwrap_or_default());
            absorb_u64(&mut hasher, u64::from(spec.input_receiver));
            absorb_u64(&mut hasher, spec.input_arg_indices.len() as u64);
            for index in &spec.input_arg_indices {
                absorb_u64(&mut hasher, *index as u64);
            }
        }
        absorb_u64(&mut hasher, options.output_arg_flows.len() as u64);
        for spec in &options.output_arg_flows {
            absorb_str(&mut hasher, "output-arg-flow");
            absorb_str(&mut hasher, &spec.callee);
            absorb_u64(&mut hasher, spec.output_arg_index as u64);
            absorb_u64(&mut hasher, spec.value_arg_indices.len() as u64);
            for index in &spec.value_arg_indices {
                absorb_u64(&mut hasher, *index as u64);
            }
            absorb_u64(
                &mut hasher,
                spec.value_start_arg_index.map_or(u64::MAX, |index| index as u64),
            );
        }
        absorb_u64(&mut hasher, options.receiver_state_propagations.len() as u64);
        for spec in &options.receiver_state_propagations {
            absorb_str(&mut hasher, "receiver-state-propagation");
            absorb_str(&mut hasher, &spec.method);
            absorb_str(&mut hasher, spec.receiver_type.as_deref().unwrap_or_default());
        }
        hasher.finish()
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

/// Declarative source call shape whose callback receives untrusted data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceCallbackArgSpec {
    /// Callee name or `regex:`-prefixed matcher.
    pub callee: String,
    /// Positional argument index containing the callback function.
    pub callback_arg_index: usize,
    /// Callback parameter indices that receive source data.
    pub source_param_indices: Vec<usize>,
}

/// Declarative external-call dependency summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallResultPassthroughSpec {
    /// Exact or `regex:`-prefixed callee matcher from the rulepack.
    pub callee: String,
    /// Optional adapter-derived receiver type required by the summary.
    pub receiver_type: Option<String>,
    /// Positional call arguments that flow into the result.
    pub input_arg_indices: Vec<usize>,
    /// Whether the method receiver also flows into the result.
    pub input_receiver: bool,
}

/// Declarative external-call output-parameter dependency summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputArgFlowSpec {
    /// Exact or `regex:`-prefixed callee matcher from the rulepack.
    pub callee: String,
    /// Positional argument written by the call.
    pub output_arg_index: usize,
    /// Individual value-bearing positional arguments.
    pub value_arg_indices: Vec<usize>,
    /// Optional first value-bearing argument; all later arguments flow to the
    /// output except the output argument itself.
    pub value_start_arg_index: Option<usize>,
}

/// Declarative external-method summary whose explicit arguments flow into
/// the receiver's post-call state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverStatePropagationSpec {
    /// Exact or `regex:`-prefixed method matcher from the rulepack.
    pub method: String,
    /// Optional adapter-derived receiver type required by the summary.
    pub receiver_type: Option<String>,
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
    /// Adapter rendering of the receiver for resolution and diagnostics.
    /// Value-flow lowering uses `receiver_storage_base`, which comes from
    /// the file-local Tree-sitter receiver fact rather than this string.
    pub receiver: Option<String>,
    /// Adapter-derived static receiver types used by Phase 3 resolution.
    pub receiver_types: Vec<String>,
    /// Compiler-owned storage identity for receiver field forwarding. A
    /// normal addressable receiver uses its canonical place; a nested call
    /// receiver uses a span-derived temporary populated from structured
    /// receiver flow. Phase 3 never derives this by parsing `receiver`.
    pub receiver_storage_base: Option<String>,
    /// Adapter's classification for this call (Free / Method /
    /// Constructor / etc.). Mirrors the FlowEvent::Call::call_kind.
    pub call_kind: CallKind,
    /// Number of arguments at the site. Phase 3 uses this to bound
    /// the param-index edges it stitches.
    pub args_count: u32,
    /// Number of explicit source-level arguments. The implicit receiver is
    /// represented separately by `receiver_arg_node`.
    pub explicit_args_count: u32,
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
    /// Source text for each explicit argument. Callback resolution uses it
    /// only as a callable-reference spelling; write-back semantics use the
    /// AST-derived targets below.
    pub call_arg_values: SmallVec<[String; 4]>,
    /// Addressable caller places whose arguments have adapter-emitted
    /// write-back passing semantics, parallel to `call_arg_nodes`.
    pub call_arg_writeback_targets: SmallVec<[Option<String>; 4]>,
    /// Adapter-extracted keyword / label names for call arguments.
    /// Phase 3 uses these to stitch named arguments to the matching
    /// callee parameter instead of relying only on positional order.
    pub call_arg_names: SmallVec<[Option<String>; 4]>,
    /// Source-callback transfer specs matching this call site.
    pub source_callback_args: Vec<SourceCallbackArgSpec>,
    /// True when this call site arose from `target = callee(args)`
    /// (a `FlowEvent::Assign` with `source_call`). Resolution still
    /// needs an explicit semantic callee or summary before any
    /// interprocedural flow is stitched.
    pub is_assign_rhs: bool,
    /// Whether Phase 3 may add a conservative argument/receiver → result
    /// edge if this call has no semantic callee.
    pub unresolved_result_passthrough: bool,
    /// Whether the unresolved-call compatibility fallback may carry the
    /// method receiver into the result. This comes from the adapter's call
    /// classification; syntax-level field/property access must not emit a
    /// method call site.
    pub unresolved_receiver_result_passthrough: bool,
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

/// Field projection returned as a scalar value, e.g.
/// `return self.data.cmd` / `&self.data.cmd`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReturnFieldProjection {
    /// Storage base that owns the returned field, e.g. `self.data`.
    pub base: String,
    /// Field segment returned from `base`, e.g. `cmd`.
    pub field: String,
}

/// AST-proven scalar aggregate forwarding inside one function, such as
/// `yield value` or `return value`. Phase 3 turns this into a field-copy
/// transform so descendant fields materialized by interprocedural stitching
/// later in the build are preserved as well.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DescendantCopy {
    /// Local aggregate place whose known descendants are forwarded.
    pub source_base: String,
    /// Synthetic return/yield aggregate place receiving those descendants.
    pub target_base: String,
    /// Source expression span proving the forwarding relationship.
    pub span: Span,
}

/// Compact control-flow evidence for statements nested in loop bodies.
///
/// A context is created only when the adapter-emitted [`FlowEvent`] tree
/// enters a `Loop::body`.  Loop header events remain in their surrounding
/// context, matching the CFG: only body execution participates in the
/// loop's back-edge.  Phase 3 uses this to distinguish a real loop-carried
/// reaching definition from a lexically later straight-line write.
#[derive(Clone, Debug)]
pub(crate) struct FlowControlFacts {
    /// Parent context by one-based context id. Context zero is the
    /// implicit non-loop root and is not stored.
    loop_context_parents: Vec<usize>,
    /// Innermost loop contexts in which an event span occurs. A small vector
    /// handles adapters that emit multiple structured facts at one AST span.
    span_loop_contexts: ahash::AHashMap<Span, smallvec::SmallVec<[usize; 1]>>,
}

impl Default for FlowControlFacts {
    fn default() -> Self {
        Self {
            loop_context_parents: Vec::new(),
            span_loop_contexts: ahash::AHashMap::new(),
        }
    }
}

impl FlowControlFacts {
    fn from_events(events: &[FlowEvent]) -> Self {
        let mut facts = Self::default();
        facts.collect_events(events, 0);
        facts
    }

    fn collect_events(&mut self, events: &[FlowEvent], loop_context: usize) {
        for event in events {
            if loop_context != 0 {
                let contexts = self.span_loop_contexts.entry(event.span()).or_default();
                if !contexts.contains(&loop_context) {
                    contexts.push(loop_context);
                }
            }
            match event {
                FlowEvent::Loop { body, .. } => {
                    // Zero is the implicit non-loop root; stored contexts are
                    // one-based so loop-free functions allocate nothing.
                    let child_context = self.loop_context_parents.len() + 1;
                    self.loop_context_parents.push(loop_context);
                    self.collect_events(body, child_context);
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    self.collect_events(then_events, loop_context);
                    self.collect_events(else_events, loop_context);
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    self.collect_events(body, loop_context);
                    self.collect_events(catch_events, loop_context);
                    self.collect_events(finally_events, loop_context);
                }
                FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                    self.collect_events(body, loop_context);
                }
                _ => {}
            }
        }
    }

    pub(crate) fn spans_share_loop_back_edge(&self, first: Span, second: Span) -> bool {
        let Some(first_contexts) = self.span_loop_contexts.get(&first) else {
            return false;
        };
        let Some(second_contexts) = self.span_loop_contexts.get(&second) else {
            return false;
        };
        first_contexts.iter().copied().any(|first_context| {
            second_contexts
                .iter()
                .copied()
                .any(|second_context| self.contexts_share_loop(first_context, second_context))
        })
    }

    fn contexts_share_loop(&self, mut first: usize, second: usize) -> bool {
        while first != 0 {
            let mut cursor = second;
            while cursor != 0 {
                if first == cursor {
                    return true;
                }
                cursor = self.parent_context(cursor);
            }
            first = self.parent_context(first);
        }
        false
    }

    fn parent_context(&self, context: usize) -> usize {
        self.loop_context_parents
            .get(context.saturating_sub(1))
            .copied()
            .unwrap_or(0)
    }
}

/// Output of the transfer-function pass for one function.
#[derive(Clone, Debug)]
pub struct TransferOutput {
    /// FuncId this transfer-function pass ran for.
    pub func: FuncId,
    /// True when this output belongs to a constructor body.
    pub is_constructor: bool,
    /// Whether the adapter emitted a semantic return event, including a
    /// literal/void return with no inbound value edge. Phase 3 uses this AST
    /// fact to keep a function that also yields from exposing its Yield node
    /// as the ordinary call result.
    pub(crate) has_return_event: bool,
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
    /// Adapter-declared receiver spellings for this declaration. This is
    /// the syntax boundary for the IDG: core transfer/stitching code must
    /// compare against these facts instead of maintaining a cross-language
    /// receiver-token inventory.
    pub receiver_names: Vec<String>,
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
    /// Scalar return projections. Phase 3 uses these to map
    /// `callee` field writes into the caller's assigned scalar
    /// target (`let c = self.cmd()`), without treating sibling fields
    /// as taint on that scalar.
    pub return_field_projections: Vec<ReturnFieldProjection>,
    /// Formal parameters returned as the whole scalar value (`return x`).
    /// Phase 3 uses this identity fact to preserve explicit descendant
    /// taint through wrappers without promoting ordinary scalar taint.
    pub return_passthrough_param_indices: Vec<usize>,
    /// Scalar return/yield aggregate copies derived from expression places.
    pub descendant_copies: Vec<DescendantCopy>,
    /// AST/HIR-derived loop-body nesting used by Phase 3 to validate
    /// loop-carried field copies without accepting arbitrary later writes.
    pub(crate) flow_control: FlowControlFacts,
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
            is_constructor: false,
            has_return_event: false,
            params: Vec::new(),
            receiver_param_index: None,
            receiver_field_bases: Vec::new(),
            implicit_receiver_bases: Vec::new(),
            receiver_names: Vec::new(),
            places: PlaceDict::new(),
            nodes: NodeDict::new(),
            edges: Vec::new(),
            call_sites: Vec::new(),
            throw_sites: Vec::new(),
            return_field_projections: Vec::new(),
            return_passthrough_param_indices: Vec::new(),
            descendant_copies: Vec::new(),
            flow_control: FlowControlFacts::default(),
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
    transfer_function_for_with_options_and_syntax_facts(decl, &TransferOptions::default(), &[], &[])
}

/// Run the transfer-function pass with caller-provided options.
pub fn transfer_function_for_with_options(decl: &Decl, options: &TransferOptions) -> TransferOutput {
    transfer_function_for_with_options_and_syntax_facts(decl, options, &[], &[])
}

/// Run the transfer pass with exact assignment-to-RHS syntax facts from the
/// declaration index. This is the production compiler path: nested call
/// results are joined to their assignment writes by Tree-sitter spans rather
/// than by reparsing source text or guessing from callee names.
pub fn transfer_function_for_with_options_and_assignment_values(
    decl: &Decl,
    options: &TransferOptions,
    assignment_values: &[AssignmentValueFact],
) -> TransferOutput {
    transfer_function_for_with_options_and_syntax_facts(decl, options, assignment_values, &[])
}

/// Run the transfer pass with all file-local compiler syntax facts needed by
/// graph lowering. Receiver and assignment semantics arrive as structured
/// tree-sitter facts; rendered source strings are not reparsed here.
pub fn transfer_function_for_with_options_and_syntax_facts(
    decl: &Decl,
    options: &TransferOptions,
    assignment_values: &[AssignmentValueFact],
    call_receivers: &[CallReceiverFact],
) -> TransferOutput {
    let func = FuncId::new(decl.symbol.raw());
    let mut out = TransferOutput::new(func);
    out.is_constructor = matches!(decl.kind, DeclKind::Constructor);
    out.has_return_event = flow_events_contain_return(&decl.flow_events);
    out.params.clone_from(&decl.params);
    out.receiver_param_index = decl.receiver_param_index;
    out.receiver_names = declared_receiver_names(decl);
    out.receiver_field_bases = receiver_field_bases(decl, &out.receiver_names);
    out.implicit_receiver_bases = implicit_receiver_bases(decl, &out.receiver_names);
    out.return_field_projections = return_field_projections(&decl.flow_events, &out.receiver_names);
    out.return_passthrough_param_indices = return_passthrough_param_indices(&decl.flow_events, &decl.params);
    out.flow_control = FlowControlFacts::from_events(&decl.flow_events);
    let method_receiver_projections = collect_method_receiver_projections(&decl.flow_events);
    let method_selector_fields = collect_method_selector_fields(&decl.flow_events);
    let field_precise_source_projections =
        collect_field_precise_source_projections(&decl.flow_events, &method_receiver_projections);
    let mut ctx = TransferCtx {
        out: &mut out,
        options,
        last_writer: ahash::AHashMap::new(),
        catch_projection_receivers: ahash::AHashSet::default(),
        emitted_edges: ahash::AHashSet::default(),
        field_precise_container_assigns: collect_field_precise_container_assigns(&decl.flow_events),
        method_receiver_projections,
        method_selector_fields,
        field_precise_source_projections,
        yield_callback_names: collect_yield_callback_names(&decl.flow_events),
        pending_expression_calls: Vec::new(),
        assignment_values,
        call_receivers,
        in_loop_replay: false,
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
        // Strip a rest/spread sigil so the param binds to the name the
        // body reads: TypeScript `function f(...p)` surfaces the param as
        // `"...p"` while the body reads `"p"` (the JS adapter already
        // normalises this). Without stripping, `Param(idx) → Write("...p")`
        // never reaches any `Read("p")`, so a variadic tainted arg
        // dead-ends at the parameter.
        let param_name = param_name.strip_prefix("...").unwrap_or(param_name);
        if param_name.is_empty() {
            continue;
        }
        let param_idx = u32::try_from(idx).unwrap_or(u32::MAX);
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
    let mut flow_call_sites = Vec::new();
    collect_flow_call_sites(&decl.flow_events, &mut flow_call_sites);
    flow_call_sites.sort_unstable_by_key(|span| (span.file.raw(), span.start, span.end));
    flow_call_sites.dedup();
    let mut assignment_call_sites = ahash::AHashSet::default();
    collect_assignment_call_sites(
        &decl.flow_events,
        assignment_values,
        &flow_call_sites,
        &mut assignment_call_sites,
    );
    for site in &mut ctx.out.call_sites {
        if assignment_call_sites.contains(&site.site.0) {
            site.is_assign_rhs = true;
            site.unresolved_result_passthrough = ctx.options.include_unresolved_call_result_passthrough;
        }
    }
    // A call at a given span is one call; loop replay (and any
    // re-entry) pushes a duplicate `CallSiteRef` per visit with no
    // interning. Dedup by site span so the O(sites^2) compound-expression
    // bridge below scales with the number of DISTINCT calls, not the
    // (potentially exponential) number of re-walks.
    ctx.out
        .call_sites
        .sort_by_key(|site| (site.site.0.file.raw(), site.site.0.start, site.site.0.end));
    ctx.out.call_sites.dedup_by_key(|site| site.site.0);
    bridge_expression_value_calls(&mut ctx);
    bridge_compound_expression_calls(&mut ctx);
    out
}

fn return_field_projections(events: &[FlowEvent], receiver_names: &[String]) -> Vec<ReturnFieldProjection> {
    let mut out = Vec::new();
    collect_return_field_projections(events, receiver_names, &mut out);
    out
}

fn flow_events_contain_return(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => flow_events_contain_return(then_events) || flow_events_contain_return(else_events),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_events_contain_return(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_events_contain_return(body)
                || flow_events_contain_return(catch_events)
                || flow_events_contain_return(finally_events)
        }
        _ => false,
    })
}

fn return_passthrough_param_indices(events: &[FlowEvent], params: &[String]) -> Vec<usize> {
    fn collect(events: &[FlowEvent], params: &[String], out: &mut Vec<usize>) {
        for event in events {
            match event {
                FlowEvent::Return { value_flow, .. } => {
                    let candidate = value_flow.place.as_deref().map(normalize_return_binding);
                    let Some(candidate) = candidate else {
                        continue;
                    };
                    if candidate.is_empty()
                        || !candidate.chars().all(|ch| {
                            ch == '_' || ch == '$' || ch == '@' || ch == '%' || ch.is_alphanumeric()
                        })
                    {
                        continue;
                    }
                    if let Some(index) = params
                        .iter()
                        .position(|param| same_return_binding(param, candidate))
                    {
                        if !out.contains(&index) {
                            out.push(index);
                        }
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect(then_events, params, out);
                    collect(else_events, params, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect(body, params, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect(body, params, out);
                    collect(catch_events, params, out);
                    collect(finally_events, params, out);
                }
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    collect(events, params, &mut out);
    out.sort_unstable();
    out
}

fn same_return_binding(param: &str, returned: &str) -> bool {
    let param = normalize_return_binding(param);
    let returned = normalize_return_binding(returned);
    !param.is_empty() && param == returned
}

fn normalize_return_binding(name: &str) -> &str {
    name.trim().trim_start_matches(['$', '@', '%'])
}

fn collect_return_field_projections(
    events: &[FlowEvent],
    receiver_names: &[String],
    out: &mut Vec<ReturnFieldProjection>,
) {
    for event in events {
        match event {
            FlowEvent::Return { value_flow, .. } => {
                let projection = value_flow
                    .projection
                    .as_ref()
                    .and_then(|projection| return_field_projection(projection, receiver_names));
                if let Some(projection) = projection {
                    if !out.iter().any(|existing| existing == &projection) {
                        out.push(projection);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_field_projections(then_events, receiver_names, out);
                collect_return_field_projections(else_events, receiver_names, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_field_projections(body, receiver_names, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_field_projections(body, receiver_names, out);
                collect_return_field_projections(catch_events, receiver_names, out);
                collect_return_field_projections(finally_events, receiver_names, out);
            }
            _ => {}
        }
    }
}

fn return_field_projection(
    projection: &ExpressionProjection,
    receiver_names: &[String],
) -> Option<ReturnFieldProjection> {
    let mut path = projection.path.clone();
    let field = path.pop()?;
    let mut base = normalize_return_projection_part(&projection.base, receiver_names);
    for part in path {
        base.push('.');
        base.push_str(&normalize_return_projection_part(&part, receiver_names));
    }
    Some(ReturnFieldProjection {
        base,
        field: normalize_return_projection_part(&field, receiver_names),
    })
}

fn normalize_return_projection_part(part: &str, receiver_names: &[String]) -> String {
    if receiver_name_matches(part, receiver_names) {
        canonical_receiver_token(part).to_string()
    } else {
        part.to_string()
    }
}

pub(crate) fn declared_receiver_names(decl: &Decl) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in decl.implicit_receiver_names.iter().chain(
        decl.receiver_param_index
            .and_then(|idx| decl.params.get(idx))
            .into_iter(),
    ) {
        let name = name.trim();
        if !name.is_empty() && !out.iter().any(|existing| receiver_tokens_equal(existing, name)) {
            out.push(name.to_string());
        }
    }
    out
}

fn receiver_field_bases(decl: &Decl, receiver_names: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = ahash::AHashSet::default();
    for write in &decl.receiver_field_writes {
        for base in implicit_receiver_storage_prefixes(&write.target, receiver_names) {
            if seen.insert(base.clone()) {
                out.push(base);
            }
        }
    }
    out
}

fn implicit_receiver_bases(decl: &Decl, receiver_names: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for name in decl
        .implicit_receiver_names
        .iter()
        .chain(decl.receiver_state_sources.iter())
    {
        push_implicit_receiver_base(&mut out, name, receiver_names);
    }
    for write in &decl.receiver_field_writes {
        push_implicit_receiver_base(&mut out, &write.target, receiver_names);
    }
    collect_implicit_receiver_bases(&decl.flow_events, receiver_names, &mut out);
    out
}

fn collect_implicit_receiver_bases(events: &[FlowEvent], receiver_names: &[String], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Call { name, receiver, .. } => {
                push_implicit_receiver_base(out, name, receiver_names);
                if let Some(receiver) = receiver {
                    push_implicit_receiver_base(out, receiver, receiver_names);
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
                push_implicit_receiver_base(out, target, receiver_names);
                if let Some(source_name) = source_name {
                    push_implicit_receiver_base(out, source_name, receiver_names);
                }
                if let Some(source_call) = source_call {
                    push_implicit_receiver_base(out, source_call, receiver_names);
                }
                for source in source_names {
                    push_implicit_receiver_base(out, source, receiver_names);
                }
            }
            FlowEvent::Return { value_flow, .. } => {
                collect_expression_flow_receiver_bases(value_flow, receiver_names, out);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_implicit_receiver_bases(then_events, receiver_names, out);
                collect_implicit_receiver_bases(else_events, receiver_names, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_implicit_receiver_bases(body, receiver_names, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_implicit_receiver_bases(body, receiver_names, out);
                collect_implicit_receiver_bases(catch_events, receiver_names, out);
                collect_implicit_receiver_bases(finally_events, receiver_names, out);
            }
            _ => {}
        }
    }
}

fn collect_expression_flow_receiver_bases(
    flow: &ExpressionFlow,
    receiver_names: &[String],
    out: &mut Vec<String>,
) {
    if let Some(place) = flow.place.as_deref() {
        push_implicit_receiver_base(out, place, receiver_names);
    }
    for source in &flow.source_names {
        push_implicit_receiver_base(out, source, receiver_names);
    }
    for field in &flow.aggregate_fields {
        collect_expression_flow_receiver_bases(&field.value, receiver_names, out);
    }
    for item in &flow.tuple_items {
        collect_expression_flow_receiver_bases(item, receiver_names, out);
    }
    for spread in &flow.spreads {
        collect_expression_flow_receiver_bases(spread, receiver_names, out);
    }
}

fn push_implicit_receiver_base(out: &mut Vec<String>, text: &str, receiver_names: &[String]) {
    for value in implicit_receiver_storage_prefixes(text, receiver_names) {
        if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
            out.push(value);
        }
    }
}

fn implicit_receiver_storage_prefixes(text: &str, receiver_names: &[String]) -> Vec<String> {
    let normalized = text
        .trim()
        .trim_start_matches('&')
        .trim_start_matches('*')
        .replace("->", ".");
    let mut parts = Vec::new();
    for part in normalized.split(['.', '[', ']']) {
        let part = part.trim().trim_start_matches(['$', '@', '%']);
        if part.is_empty() {
            continue;
        }
        if !part.chars().all(|ch| ch == '_' || ch.is_alphanumeric()) {
            break;
        }
        parts.push(part.to_string());
    }
    let Some(root) = parts.first().map(String::as_str) else {
        return Vec::new();
    };
    if !receiver_name_matches(root, receiver_names) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for len in 1..=parts.len() {
        out.push(parts[..len].join("."));
    }
    out
}

pub(crate) fn receiver_name_matches(candidate: &str, receiver_names: &[String]) -> bool {
    receiver_names
        .iter()
        .any(|receiver| receiver_tokens_equal(candidate, receiver))
}

pub(crate) fn receiver_tokens_equal(left: &str, right: &str) -> bool {
    let left = canonical_receiver_token(left);
    let right = canonical_receiver_token(right);
    !left.is_empty() && left == right
}

fn canonical_receiver_token(token: &str) -> &str {
    token
        .trim()
        .trim_start_matches('&')
        .trim_start_matches('*')
        .trim_start_matches(['$', '@', '%'])
        .trim_end_matches("()")
        .trim()
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
                // A receiver-field assignment copies the parameter value as
                // an aggregate too. Record the parsed storage relationship so
                // Phase 3 can preserve any exact descendant fields that are
                // materialized by cross-call stitching after this local
                // transfer has run (`data.cmd -> this.data.cmd`).
                let copy = DescendantCopy {
                    source_base: param_name.to_string(),
                    target_base: target.to_string(),
                    span: write.span,
                };
                if !ctx.out.descendant_copies.contains(&copy) {
                    ctx.out.descendant_copies.push(copy);
                }
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

/// Resolve AST-identified expression calls after the event walk. Adapters are
/// free to emit a Return/Yield before or after its nested Call events, so the
/// call-result edge cannot depend on traversal order. The exact tree-sitter
/// call span is the join key; no return text or callee spelling is parsed.
fn bridge_expression_value_calls(ctx: &mut TransferCtx<'_>) {
    if ctx.pending_expression_calls.is_empty() {
        return;
    }
    let sites = ctx.out.call_sites.clone();
    let pending = std::mem::take(&mut ctx.pending_expression_calls);
    for value_call in pending {
        for site in &sites {
            if !span_contains_or_equal(value_call.call_span, site.site.0) {
                continue;
            }
            let nested_in_another_call_argument = sites.iter().any(|outer| {
                !std::ptr::eq(site, outer)
                    && span_contains_or_equal(value_call.call_span, outer.site.0)
                    && outer
                        .call_arg_spans
                        .iter()
                        .any(|arg_span| span_contains_or_equal(*arg_span, site.site.0))
            });
            if nested_in_another_call_argument {
                continue;
            }
            ctx.emit(IdgEdge {
                from: site.call_ret_node,
                to: value_call.target,
                meta: value_call.meta,
            });
        }
    }
}

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
    /// Exact method projections seen in this function (`raw.dup`,
    /// `routed.to_s`). A method invocation derives its result from the
    /// *whole* receiver value, so the projection itself must NOT demote
    /// bare `raw`/`routed` to a structural field-only base. Other
    /// sibling projections (`item.flag` beside `item.get`) remain
    /// field-sensitive.
    method_receiver_projections: ahash::AHashSet<String>,
    /// Literal-key method calls keyed by their adapter-emitted projection
    /// (`request.args.get` -> `request.args.cmd`). These are syntax facts,
    /// not API names; paired exact field Assigns let mixed expressions keep
    /// keyed selectors field-scoped while ordinary transforms still consume
    /// their whole receiver value.
    method_selector_fields: ahash::AHashMap<String, ahash::AHashSet<String>>,
    /// Exact projected sources grouped by assignment identity. Multiple
    /// adapter events can describe the same assignment span/target (a broad
    /// call-result event plus precise selected-field events), so the group is
    /// the compiler-level unit used to disambiguate selector calls.
    field_precise_source_projections: ahash::AHashMap<(Span, String), ahash::AHashSet<String>>,
    /// Local callback variables assigned from a yielding closure such
    /// as Ruby's `callback = Proc.new { |part| yield part }`. Calls
    /// through these names forward their arguments into `Place::Yield`.
    yield_callback_names: ahash::AHashSet<String>,
    /// AST call spans and the exact Return/Yield/aggregate node that consumes
    /// each result. Resolved after all Call events have been lowered so event
    /// order cannot affect dataflow.
    pending_expression_calls: Vec<PendingExpressionCall>,
    /// Exact Tree-sitter assignment/RHS relationships for this file. The
    /// facts are sorted by assignment span, so lookups remain logarithmic and
    /// do not turn transfer into an assignments-squared pass on large files.
    assignment_values: &'a [AssignmentValueFact],
    /// Tree-sitter receiver-expression facts keyed by semantic call span.
    call_receivers: &'a [CallReceiverFact],
    /// Whether the walker is replaying an enclosing loop body to establish
    /// loop-carried edges. A nested loop encountered during replay gets one
    /// body visit: its own normal visit already established its local carry
    /// edges, while the enclosing replay supplies the outer-iteration state.
    /// This keeps nested-loop transfer polynomial without imposing a semantic
    /// nesting ceiling.
    in_loop_replay: bool,
}

#[derive(Copy, Clone, Debug)]
struct PendingExpressionCall {
    call_span: Span,
    target: NodeId,
    meta: crate::edge::EdgeMeta,
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
        if writers.is_empty() {
            let stripped = name.trim_start_matches(['$', '@', '%', '&']);
            if !stripped.is_empty() && stripped != name {
                let alias_sid = self.intern_name(stripped);
                writers = self.last_writer.get(&alias_sid).cloned().unwrap_or_default();
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
            FlowEvent::AggregateAssign {
                span,
                target,
                value_flow,
                ..
            } if !value_flow.aggregate_fields.is_empty() => {
                out.insert((*span, target.clone()));
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

/// Collect exact receiver-method projections from adapter-emitted call
/// events. Dotted assignment text alone is never enough to classify a
/// field/property access as a method invocation.
fn collect_method_receiver_projections(events: &[FlowEvent]) -> ahash::AHashSet<String> {
    let mut out = ahash::AHashSet::default();
    collect_method_receiver_projections_into(events, &mut out);
    out
}

fn collect_method_selector_fields(events: &[FlowEvent]) -> ahash::AHashMap<String, ahash::AHashSet<String>> {
    fn collect(events: &[FlowEvent], out: &mut ahash::AHashMap<String, ahash::AHashSet<String>>) {
        for event in events {
            match event {
                FlowEvent::Call {
                    name,
                    receiver: Some(receiver),
                    call_kind: CallKind::Method,
                    args,
                    ..
                } => {
                    let Some(key) = args
                        .first()
                        .and_then(|arg| quoted_storage_selector(&arg.value_text))
                    else {
                        continue;
                    };
                    let receiver = receiver.trim();
                    let name = name.trim();
                    if receiver.is_empty() || name.is_empty() {
                        continue;
                    }
                    out.entry(name.to_string())
                        .or_default()
                        .insert(format!("{receiver}.{key}"));
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect(then_events, out);
                    collect(else_events, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect(body, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect(body, out);
                    collect(catch_events, out);
                    collect(finally_events, out);
                }
                _ => {}
            }
        }
    }

    let mut out = ahash::AHashMap::default();
    collect(events, &mut out);
    out
}

fn collect_field_precise_source_projections(
    events: &[FlowEvent],
    method_receiver_projections: &ahash::AHashSet<String>,
) -> ahash::AHashMap<(Span, String), ahash::AHashSet<String>> {
    fn collect(
        events: &[FlowEvent],
        methods: &ahash::AHashSet<String>,
        out: &mut ahash::AHashMap<(Span, String), ahash::AHashSet<String>>,
    ) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target,
                    source_name,
                    source_names,
                    ..
                } => {
                    for source in source_name
                        .iter()
                        .map(String::as_str)
                        .chain(source_names.iter().map(String::as_str))
                    {
                        let source = source.trim();
                        if field_base_name(source).is_some() && !methods.contains(source) {
                            out.entry((*span, target.clone()))
                                .or_default()
                                .insert(source.to_string());
                        }
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect(then_events, methods, out);
                    collect(else_events, methods, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect(body, methods, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect(body, methods, out);
                    collect(catch_events, methods, out);
                    collect(finally_events, methods, out);
                }
                _ => {}
            }
        }
    }

    let mut out = ahash::AHashMap::default();
    collect(events, method_receiver_projections, &mut out);
    out
}

fn quoted_storage_selector(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"' | b'`') || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let value = text.get(1..text.len().checked_sub(1)?)?.trim();
    (!value.is_empty()
        && value
            .chars()
            .all(|ch| ch == '_' || ch == '$' || ch == '@' || ch.is_alphanumeric()))
    .then_some(value)
}

fn collect_yield_callback_names(events: &[FlowEvent]) -> ahash::AHashSet<String> {
    if !events_contain_yield(events) {
        return ahash::AHashSet::default();
    }
    let mut yielding_call_assignments = Vec::new();
    collect_yield_result_call_assignments(events, &mut yielding_call_assignments);
    let mut out = ahash::AHashSet::default();
    collect_yield_callback_names_into(events, &yielding_call_assignments, &mut out);
    out
}

fn collect_yield_callback_names_into(
    events: &[FlowEvent],
    yielding_call_assignments: &[(Span, String)],
    out: &mut ahash::AHashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call: Some(source_call),
                value_kind,
                ..
            } if !matches!(value_kind, Some(AssignValueKind::YieldResult))
                && yielding_call_assignments.iter().any(|(yield_span, yield_call)| {
                    yield_call == source_call
                        && yield_span.file == span.file
                        && span.start <= yield_span.start
                        && yield_span.end <= span.end
                }) =>
            {
                let target = target.trim();
                if is_bare_identifier(target) {
                    out.insert(target.to_string());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_yield_callback_names_into(then_events, yielding_call_assignments, out);
                collect_yield_callback_names_into(else_events, yielding_call_assignments, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_yield_callback_names_into(body, yielding_call_assignments, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_yield_callback_names_into(body, yielding_call_assignments, out);
                collect_yield_callback_names_into(catch_events, yielding_call_assignments, out);
                collect_yield_callback_names_into(finally_events, yielding_call_assignments, out);
            }
            _ => {}
        }
    }
}

fn collect_yield_result_call_assignments(events: &[FlowEvent], out: &mut Vec<(Span, String)>) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                source_call: Some(source_call),
                value_kind: Some(AssignValueKind::YieldResult),
                ..
            } => out.push((*span, source_call.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_yield_result_call_assignments(then_events, out);
                collect_yield_result_call_assignments(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_yield_result_call_assignments(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_yield_result_call_assignments(body, out);
                collect_yield_result_call_assignments(catch_events, out);
                collect_yield_result_call_assignments(finally_events, out);
            }
            _ => {}
        }
    }
}

fn events_contain_yield(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Yield { .. } => true,
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => events_contain_yield(then_events) || events_contain_yield(else_events),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            events_contain_yield(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            events_contain_yield(body)
                || events_contain_yield(catch_events)
                || events_contain_yield(finally_events)
        }
        _ => false,
    })
}

fn collect_method_receiver_projections_into(events: &[FlowEvent], out: &mut ahash::AHashSet<String>) {
    for event in events {
        match event {
            FlowEvent::Call { name, call_kind, .. } => {
                if matches!(call_kind, CallKind::Method) {
                    push_method_projection(name, out);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_method_receiver_projections_into(then_events, out);
                collect_method_receiver_projections_into(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_method_receiver_projections_into(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_method_receiver_projections_into(body, out);
                collect_method_receiver_projections_into(catch_events, out);
                collect_method_receiver_projections_into(finally_events, out);
            }
            _ => {}
        }
    }
}

fn push_method_projection(projection: &str, out: &mut ahash::AHashSet<String>) {
    let projection = projection.trim();
    if projection.is_empty() || !projection.contains('.') {
        return;
    }
    out.insert(projection.to_string());
}

#[derive(Default)]
struct SemanticSourceFilter {
    structural_bases: ahash::AHashSet<String>,
}

impl SemanticSourceFilter {
    fn from_sources(
        primary: Option<&str>,
        sources: &[String],
        method_receiver_projections: &ahash::AHashSet<String>,
        exact_projections: Option<&ahash::AHashSet<String>>,
        method_selector_fields: &ahash::AHashMap<String, ahash::AHashSet<String>>,
    ) -> Self {
        let mut filter = Self::default();
        for projection in exact_projections.into_iter().flatten() {
            if let Some(base) = field_base_name(projection) {
                if !source_uses_index_projection(projection, base) {
                    filter.structural_bases.insert(base.to_string());
                }
            }
        }
        for source in primary.into_iter().chain(sources.iter().map(String::as_str)) {
            let source = source.trim();
            let Some(base) = field_base_name(source) else {
                continue;
            };
            if source_uses_index_projection(source, base) {
                continue;
            }
            // A projection backed by an actual method Call event derives
            // from the receiver. Genuine field/index projections have no
            // such event and keep their base structural.
            if method_receiver_projections.contains(source)
                && !method_projection_has_exact_selected_source(
                    source,
                    exact_projections,
                    method_selector_fields,
                )
            {
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

fn method_projection_has_exact_selected_source(
    projection: &str,
    exact_projections: Option<&ahash::AHashSet<String>>,
    method_selector_fields: &ahash::AHashMap<String, ahash::AHashSet<String>>,
) -> bool {
    let Some(exact_projections) = exact_projections else {
        return false;
    };
    let projection = projection.trim();
    let receiver_is_exact = dotted_projection_receiver(projection)
        .is_some_and(|receiver| exact_projections.contains(receiver.trim()));
    receiver_is_exact
        || method_selector_fields.get(projection).is_some_and(|selected| {
            selected
                .iter()
                .any(|field| exact_projections.contains(field.as_str()))
        })
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

/// Merge an alternate control-flow exit into the active writer state.
/// Writer vectors are tiny in ordinary code, so preserving their stable
/// insertion order is cheaper than introducing a second per-name set.
fn merge_writer_states(
    current: &mut ahash::AHashMap<StrId, smallvec::SmallVec<[NodeId; 4]>>,
    alternate: ahash::AHashMap<StrId, smallvec::SmallVec<[NodeId; 4]>>,
) {
    for (name, writers) in alternate {
        let merged = current.entry(name).or_default();
        for writer in writers {
            if !merged.contains(&writer) {
                merged.push(writer);
            }
        }
    }
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
        FlowEvent::AggregateAssign {
            span,
            target,
            value_flow,
            ..
        } => emit_local_expression_aggregate(target, value_flow, *span, ctx),
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
        FlowEvent::Return { span, value_flow, .. } => {
            let return_node = ctx.intern_node(Place::Return);
            let return_meta = crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraReturn,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: *span,
            };
            let field_precise_return = emit_expression_aggregate(RETURN_FIELD_BASE, value_flow, *span, ctx);
            if !field_precise_return && !value_flow.is_empty() {
                let return_base = ctx.write_node(RETURN_FIELD_BASE, *span);
                emit_expression_scalar_to_node(value_flow, return_base, return_meta, ctx);
                copy_expression_descendants_to_special_base(RETURN_FIELD_BASE, value_flow, *span, ctx);
                ctx.emit(IdgEdge {
                    from: return_base,
                    to: return_node,
                    meta: return_meta,
                });
            }
        }
        FlowEvent::Throw {
            span,
            value_name,
            thrown_type,
        } => walk_throw(*span, value_name.as_deref(), thrown_type.as_deref(), ctx),
        FlowEvent::Branch {
            span: _,
            condition: _,
            then_events,
            else_events,
        } => {
            // Reachability is language semantics, not spelling: `0` is false
            // in C/Python but true in Ruby, Lua, and Elixir. Until adapters
            // carry an AST-derived constant value, conservatively join both
            // grammar branches rather than dropping a real flow.
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
            // A loop may execute zero or more times. Preserve its entry
            // writer state for the zero-iteration exit, walk the body once
            // for ordinary may-run edges, then replay it once so body reads
            // observe prior-iteration writes. Stable node identities plus
            // exact edge suppression make one replay sufficient for the
            // structural closure.
            //
            // Nested loops do not recursively replay while an enclosing
            // replay is active. They already established their local carry
            // edges during the normal walk, and this visit lets those nodes
            // observe the enclosing loop's carried state without 2^depth
            // traversal or a correctness-reducing nesting cap.
            let entry_writers = ctx.last_writer.clone();
            walk_events(body, ctx);
            if !ctx.in_loop_replay {
                ctx.in_loop_replay = true;
                walk_events(body, ctx);
                ctx.in_loop_replay = false;
            }
            merge_writer_states(&mut ctx.last_writer, entry_writers);
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
        FlowEvent::Yield { span, value_flow, .. } => {
            let yield_meta = crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraYield,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: *span,
            };
            if !emit_expression_aggregate(YIELD_FIELD_BASE, value_flow, *span, ctx) {
                let to = ctx.intern_node(Place::Yield);
                emit_expression_scalar_to_node(value_flow, to, yield_meta, ctx);
                copy_expression_descendants_to_special_base(YIELD_FIELD_BASE, value_flow, *span, ctx);
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

/// Materialize a named aggregate initializer as exact local field writes.
/// Positional items are intentionally ignored here: the workspace semantic
/// pass must first prove their field identity from a parsed type layout.
fn emit_local_expression_aggregate(base: &str, flow: &ExpressionFlow, span: Span, ctx: &mut TransferCtx<'_>) {
    let field_meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: IdgEdgeKind::IntraFieldWrite,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    for field in &flow.aggregate_fields {
        if field.name.is_empty() {
            continue;
        }
        let target = format!("{base}.{}", field.name);
        let (write_node, _) = build_target_node(&target, span, ctx);
        if field.value.aggregate_fields.is_empty() {
            emit_expression_scalar_to_node(&field.value, write_node, field_meta, ctx);
        } else {
            emit_local_expression_aggregate(&target, &field.value, span, ctx);
        }
        ctx.commit_writer(&target, write_node);
    }
    for spread in &flow.spreads {
        let source = spread
            .place
            .as_deref()
            .or_else(|| (spread.source_names.len() == 1).then(|| spread.source_names[0].as_str()));
        if let Some(source) = source {
            emit_spread_field_copies_to_special_base(base, source, span, ctx);
        }
    }
}

fn emit_expression_aggregate(
    special_base: &str,
    flow: &ExpressionFlow,
    span: Span,
    ctx: &mut TransferCtx<'_>,
) -> bool {
    if flow.aggregate_fields.is_empty() && flow.tuple_items.is_empty() && flow.spreads.is_empty() {
        return false;
    }

    let field_meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: IdgEdgeKind::IntraFieldWrite,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    for field in &flow.aggregate_fields {
        if field.name.is_empty() {
            continue;
        }
        let target = format!("{special_base}.{}", field.name);
        let write_node = ctx.write_node(&target, span);
        if !emit_expression_aggregate(&target, &field.value, span, ctx) {
            emit_expression_scalar_to_node(&field.value, write_node, field_meta, ctx);
        }
    }
    for (index, item) in flow.tuple_items.iter().enumerate() {
        let target = format!("{special_base}.{index}");
        let write_node = ctx.write_node(&target, span);
        if !emit_expression_aggregate(&target, item, span, ctx) {
            emit_expression_scalar_to_node(item, write_node, field_meta, ctx);
        }
    }
    for spread in &flow.spreads {
        let source = spread
            .place
            .as_deref()
            .or_else(|| (spread.source_names.len() == 1).then(|| spread.source_names[0].as_str()));
        if let Some(source) = source {
            emit_spread_field_copies_to_special_base(special_base, source, span, ctx);
        }
    }
    true
}

/// Bridge compiler-owned expression operands into one semantic value node.
/// `value_text` is intentionally absent: all reads and nested calls were
/// extracted from tree-sitter nodes by the language adapter boundary.
fn emit_expression_scalar_to_node(
    flow: &ExpressionFlow,
    target: NodeId,
    meta: crate::edge::EdgeMeta,
    ctx: &mut TransferCtx<'_>,
) {
    let mut bridged = ahash::AHashSet::default();
    let raw_projection = flow
        .projection
        .as_ref()
        .map(ExpressionProjection::canonical_place);
    let canonical_projection = flow
        .projection
        .as_ref()
        .map(|projection| canonical_expression_projection_place(projection, &ctx.out.receiver_names));
    {
        let mut bridge_source = |source: &str| {
            let source = source.trim();
            if source.is_empty() {
                return;
            }
            let source = if raw_projection.as_deref() == Some(source) {
                canonical_projection.as_deref().unwrap_or(source)
            } else {
                source
            };
            let sid = ctx.intern_name(source);
            if bridged.insert(sid) {
                ctx.bridge_read(source, target, meta);
            }
        };
        if let Some(projection) = canonical_projection.as_deref() {
            bridge_source(projection);
        }
        for source in flow.place.iter().chain(&flow.source_names) {
            bridge_source(source);
        }
    }
    for call_span in &flow.call_sites {
        let pending = PendingExpressionCall {
            call_span: *call_span,
            target,
            meta,
        };
        if !ctx.pending_expression_calls.iter().any(|existing| {
            existing.call_span == pending.call_span
                && existing.target == pending.target
                && existing.meta == pending.meta
        }) {
            ctx.pending_expression_calls.push(pending);
        }
    }
}

fn canonical_expression_projection_place(
    projection: &ExpressionProjection,
    receiver_names: &[String],
) -> String {
    std::iter::once(projection.base.as_str())
        .chain(projection.path.iter().map(String::as_str))
        .map(|part| normalize_return_projection_part(part, receiver_names))
        .collect::<Vec<_>>()
        .join(".")
}

fn emit_spread_field_copies_to_special_base(
    special_base: &str,
    spread: &str,
    span: Span,
    ctx: &mut TransferCtx<'_>,
) {
    let spread = spread.trim();
    if spread.is_empty() {
        return;
    }
    let prefix = format!("{spread}.");
    let mut copies: Vec<(String, smallvec::SmallVec<[NodeId; 4]>)> = Vec::new();
    for (name_id, writers) in &ctx.last_writer {
        let Some(name) = ctx.out.names.get(*name_id) else {
            continue;
        };
        let Some(field) = name.strip_prefix(&prefix) else {
            continue;
        };
        if field.is_empty() {
            continue;
        }
        copies.push((field.to_string(), writers.clone()));
    }
    copies.sort_by(|a, b| a.0.cmp(&b.0));
    copies.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    let meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: IdgEdgeKind::IntraFieldWrite,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    for (field, writers) in copies {
        let target = format!("{special_base}.{field}");
        let write_node = ctx.write_node(&target, span);
        for writer in writers {
            ctx.emit(IdgEdge {
                from: writer,
                to: write_node,
                meta,
            });
        }
    }
}

/// Preserve already-materialized descendant places when a scalar expression
/// returns or yields an aggregate local (`return value`, `yield value`). The
/// CST expression identifies the source base; only concrete descendant
/// writers in the current flow state are copied, so field-only taint remains
/// field-only and no synthetic member inventory is introduced.
fn copy_expression_descendants_to_special_base(
    special_base: &str,
    flow: &ExpressionFlow,
    span: Span,
    ctx: &mut TransferCtx<'_>,
) {
    let source = flow
        .place
        .as_deref()
        .or_else(|| (flow.source_names.len() == 1).then(|| flow.source_names[0].as_str()))
        .map(str::trim)
        .filter(|source| !source.is_empty());
    if let Some(source) = source {
        emit_spread_field_copies_to_special_base(special_base, source, span, ctx);
        let copy = DescendantCopy {
            source_base: source.to_string(),
            target_base: special_base.to_string(),
            span,
        };
        if !ctx.out.descendant_copies.contains(&copy) {
            ctx.out.descendant_copies.push(copy);
        }
    }
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

fn collect_assignment_call_sites(
    events: &[FlowEvent],
    assignment_values: &[AssignmentValueFact],
    flow_call_sites: &[Span],
    out: &mut ahash::AHashSet<Span>,
) {
    for (index, event) in events.iter().enumerate() {
        match event {
            FlowEvent::Assign {
                span,
                source_call: Some(_),
                ..
            } => {
                out.insert(assign_call_site_hint(events, index).map_or(*span, |hint| hint.site_span));
            }
            FlowEvent::Assign { span, value_kind, .. }
                if !matches!(value_kind, Some(AssignValueKind::CallableReference)) =>
            {
                let expression_spans = assignment_call_sites_for_span(assignment_values, *span);
                for expression_span in expression_spans {
                    collect_contained_call_sites(expression_span, flow_call_sites, out);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assignment_call_sites(then_events, assignment_values, flow_call_sites, out);
                collect_assignment_call_sites(else_events, assignment_values, flow_call_sites, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assignment_call_sites(body, assignment_values, flow_call_sites, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assignment_call_sites(body, assignment_values, flow_call_sites, out);
                collect_assignment_call_sites(catch_events, assignment_values, flow_call_sites, out);
                collect_assignment_call_sites(finally_events, assignment_values, flow_call_sites, out);
            }
            _ => {}
        }
    }
}

fn collect_flow_call_sites(events: &[FlowEvent], out: &mut Vec<Span>) {
    for event in events {
        match event {
            FlowEvent::Call { span, .. } => out.push(*span),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_flow_call_sites(then_events, out);
                collect_flow_call_sites(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_flow_call_sites(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_flow_call_sites(body, out);
                collect_flow_call_sites(catch_events, out);
                collect_flow_call_sites(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_contained_call_sites(
    expression_span: Span,
    flow_call_sites: &[Span],
    out: &mut ahash::AHashSet<Span>,
) {
    let expression_key = (expression_span.file.raw(), expression_span.start);
    let start = flow_call_sites.partition_point(|span| (span.file.raw(), span.start) < expression_key);
    for call_site in flow_call_sites.iter().skip(start) {
        if call_site.file != expression_span.file || call_site.start >= expression_span.end {
            break;
        }
        if span_contains_or_equal(expression_span, *call_site) {
            out.insert(*call_site);
        }
    }
}

fn assignment_call_sites_for_span(facts: &[AssignmentValueFact], span: Span) -> SmallVec<[Span; 2]> {
    let key = |candidate: Span| (candidate.file.raw(), candidate.start, candidate.end);
    let wanted = key(span);
    let start = facts.partition_point(|fact| key(fact.assignment_span) < wanted);
    let mut call_sites = SmallVec::new();
    for fact in facts.iter().skip(start) {
        let candidate = key(fact.assignment_span);
        if candidate != wanted {
            break;
        }
        for call_site in &fact.call_sites {
            if !call_sites.contains(call_site) {
                call_sites.push(*call_site);
            }
        }
    }
    call_sites
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
        | FlowEvent::AggregateAssign { span, .. }
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
    let indexed_call_sites = assignment_call_sites_for_span(ctx.assignment_values, span);
    let indexed_value_flow = bonsai_lang_api::assignment_value_fact_for_span(ctx.assignment_values, span)
        .and_then(|fact| {
            (!fact.value_flow.aggregate_fields.is_empty() || !fact.value_flow.spreads.is_empty())
                .then(|| fact.value_flow.clone())
        });
    let has_indexed_named_aggregate = indexed_value_flow.is_some();
    let rhs_is_literal = matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::Literal));
    if is_structural_index_metadata_target(target) {
        return;
    }

    // Field-write detection: targets like `obj.field` or `obj["k"]`.
    // Tuple destructuring keeps a synthetic result-position suffix on
    // the storage node while `last_writer` remains keyed by the user's
    // binding name. Phase 3 uses the suffix to stitch only the matching
    // positional return field into this writer.
    let tuple_result_index = tuple_result_index(source_names);
    let tuple_target =
        tuple_result_index.map(|index| format!("{target}.{SYNTHETIC_TUPLE_RESULT_PREFIX}{index}"));
    let (write_node, is_field_write) = if let Some(tuple_target) = tuple_target.as_deref() {
        (ctx.write_node(tuple_target, span), false)
    } else {
        build_target_node(target, span, ctx)
    };
    if let Some(flow) = indexed_value_flow
        .as_ref()
        .filter(|_| has_indexed_named_aggregate)
    {
        emit_local_expression_aggregate(target, flow, span, ctx);
    }

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
    let suppress_broad_container_inputs = !is_field_write
        && (has_indexed_named_aggregate || {
            let bare_target = target.trim();
            ctx.field_precise_container_assigns
                .iter()
                .any(|(field_span, base)| base == bare_target && span_contains_or_equal(span, *field_span))
        });
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
    // A compound RHS can contain calls without being a direct call itself:
    // PHP's `$raw = readline(...) ?: ""` is one example. The declaration
    // index records the exact RHS call nodes, so join those CallRet places to
    // this write without rebuilding expression structure from text. Callable
    // references are values, not invocations, and therefore never receive
    // this edge.
    if source_call.is_none() && !matches!(value_kind, Some(AssignValueKind::CallableReference)) {
        for call_span in indexed_call_sites {
            let pending = PendingExpressionCall {
                call_span,
                target: write_node,
                meta: edge_meta,
            };
            if !ctx.pending_expression_calls.iter().any(|existing| {
                existing.call_span == pending.call_span
                    && existing.target == pending.target
                    && existing.meta == pending.meta
            }) {
                ctx.pending_expression_calls.push(pending);
            }
        }
    }

    // Bridge each source's most-recent writer to the new target's
    // Write node. CFG narrowing: bridge_read consults
    // `last_writer[src]` so a stale earlier write of `src` doesn't
    // cross-pollute. The shared `Place::Read` node is used only as
    // a fallback when `src` has no recorded writer (unrooted reads).
    let suppress_direct_rhs_inputs = suppress_broad_container_inputs
        || (source_call.is_some()
            && !source_call_args.is_empty()
            && matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::CallResult)));
    let exact_projections = if matches!(value_kind, Some(bonsai_lang_api::AssignValueKind::Destructure)) {
        None
    } else {
        ctx.field_precise_source_projections
            .get(&(span, target.to_string()))
            .cloned()
    };
    let source_filter = SemanticSourceFilter::from_sources(
        source_name,
        source_names,
        &ctx.method_receiver_projections,
        exact_projections.as_ref(),
        &ctx.method_selector_fields,
    );
    if !suppress_direct_rhs_inputs {
        if let Some(src) = source_name {
            if !src.is_empty()
                && !source_filter.is_structural_base_token(src)
                && !direct_rhs_source_is_call_internals(src, source_call, source_call_args)
            {
                ctx.bridge_read(src, write_node, edge_meta);
                if !method_projection_has_exact_selected_source(
                    src,
                    exact_projections.as_ref(),
                    &ctx.method_selector_fields,
                ) {
                    bridge_method_projection_receiver_source(src, write_node, edge_meta, ctx);
                }
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
            if !method_projection_has_exact_selected_source(
                src,
                exact_projections.as_ref(),
                &ctx.method_selector_fields,
            ) {
                bridge_method_projection_receiver_source(src, write_node, edge_meta, ctx);
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
                let arg_idx = u32::try_from(idx).unwrap_or(u32::MAX);
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
            let mut arg_values: SmallVec<[String; 4]> = SmallVec::new();
            let mut arg_writeback_targets: SmallVec<[Option<String>; 4]> = SmallVec::new();
            let mut arg_names: SmallVec<[Option<String>; 4]> = SmallVec::new();
            for _ in 0..source_call_args.len() {
                arg_spans.push(span);
                arg_names.push(None);
                arg_writeback_targets.push(None);
            }
            for arg in source_call_args {
                arg_places.push(arg.clone());
                arg_values.push(arg.clone());
            }
            if !source_call_site_hint.is_some_and(|hint| hint.sibling_call_event) {
                apply_call_result_passthrough_edges(site_span, callee, &[], &arg_nodes, None, ret_node, ctx);
                ctx.out.call_sites.push(CallSiteRef {
                    site,
                    callee_name: callee.to_string(),
                    receiver: None,
                    receiver_types: Vec::new(),
                    receiver_storage_base: None,
                    call_kind: CallKind::Function,
                    args_count: u32::try_from(source_call_args.len()).unwrap_or(u32::MAX),
                    explicit_args_count: u32::try_from(source_call_args.len()).unwrap_or(u32::MAX),
                    call_ret_node: ret_node,
                    call_arg_nodes: arg_nodes,
                    receiver_arg_node: None,
                    call_arg_spans: arg_spans,
                    call_arg_places: arg_places,
                    call_arg_values: arg_values,
                    call_arg_writeback_targets: arg_writeback_targets,
                    call_arg_names: arg_names,
                    source_callback_args: Vec::new(),
                    is_assign_rhs: true,
                    unresolved_result_passthrough: ctx.options.include_unresolved_call_result_passthrough,
                    unresolved_receiver_result_passthrough: false,
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

fn tuple_result_index(source_names: &[String]) -> Option<usize> {
    source_names.iter().find_map(|source| {
        source
            .strip_prefix(SYNTHETIC_TUPLE_RESULT_PREFIX)
            .and_then(|index| index.parse::<usize>().ok())
    })
}

fn bridge_method_projection_receiver_source(
    source: &str,
    node: NodeId,
    meta: crate::edge::EdgeMeta,
    ctx: &mut TransferCtx<'_>,
) {
    let source = source.trim();
    if source.is_empty() || !ctx.method_receiver_projections.contains(source) {
        return;
    }
    let Some(receiver) = dotted_projection_receiver(source) else {
        return;
    };
    if receiver.is_empty() {
        return;
    }
    ctx.bridge_read(&receiver, node, meta);
}

fn dotted_projection_receiver(source: &str) -> Option<String> {
    let source = source.trim();
    let (receiver, member) = source.rsplit_once('.')?;
    let receiver = receiver.trim();
    let member = member.trim();
    if receiver.is_empty() || member.is_empty() {
        return None;
    }
    Some(receiver.to_string())
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
    let mut arg_values: SmallVec<[String; 4]> = SmallVec::new();
    let mut arg_writeback_targets: SmallVec<[Option<String>; 4]> = SmallVec::new();
    let mut arg_names: SmallVec<[Option<String>; 4]> = SmallVec::new();
    for (idx, arg) in args.iter().enumerate() {
        let arg_idx = u32::try_from(idx).unwrap_or(u32::MAX);
        let arg_node = ctx.intern_node(Place::CallArg { site, idx: arg_idx });
        arg_nodes.push(arg_node);
        let arg_place = call_arg_place_name(arg);
        if output_candidate_place_needs_field_node(&arg_place) {
            let _ = build_target_node(&arg_place, span, ctx);
        }
        arg_places.push(arg_place);
        arg_values.push(arg.value_text.clone());
        arg_writeback_targets.push(
            matches!(arg.passing_mode, bonsai_lang_api::ArgumentPassingMode::WriteBack)
                .then(|| arg.place.clone())
                .flatten(),
        );
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
            &ctx.method_receiver_projections,
            None,
            &ctx.method_selector_fields,
        );
        if let Some(place) = arg.place.as_deref() {
            if !place.is_empty() && !source_filter.is_structural_base_token(place) {
                let sid = ctx.intern_name(place);
                if emitted.insert(sid) {
                    // `CallArg::place` is already canonicalized from the
                    // tree-sitter argument node by the adapter layer.
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
    }
    apply_yield_callback_call(span, name, receiver, args, ctx);
    if matches!(call_kind, CallKind::ChannelSend) && args.len() >= 2 {
        if let Some(channel) = args
            .first()
            .map(call_arg_place_name)
            .filter(|place| !place.is_empty())
        {
            let value = &args[1];
            let write_node = ctx.write_node(&channel, span);
            bridge_call_arg_sources_to_node(
                value,
                write_node,
                crate::edge::EdgeMeta {
                    precision: Precision::Exact,
                    kind: IdgEdgeKind::IntraAssign,
                    call_kind: bonsai_callgraph::EdgeKind::Direct,
                    via_span: span,
                },
                ctx,
            );
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
    let mut receiver_storage_base = None;
    if matches!(call_kind, CallKind::Method) {
        let receiver_flow =
            call_receiver_fact_for_span(ctx.call_receivers, span).map(|fact| fact.value_flow.clone());
        if receiver_flow.is_some() || receiver.is_some_and(|recv| !recv.is_empty()) {
            let recv_meta = crate::edge::EdgeMeta {
                precision: Precision::Exact,
                kind: IdgEdgeKind::IntraRead,
                call_kind: bonsai_callgraph::EdgeKind::Direct,
                via_span: span,
            };
            // Use a synthetic receiver slot. Pick a high arg index
            // (u32::MAX) so we don't collide with positional arg
            // indices the call may have.
            let recv_slot = ctx.intern_node(Place::CallArg { site, idx: u32::MAX });
            receiver_arg_node = Some(recv_slot);
            if let Some(flow) = receiver_flow.as_ref() {
                emit_expression_scalar_to_node(flow, recv_slot, recv_meta, ctx);
                if !flow.call_sites.is_empty() {
                    let base = format!(
                        "{}_{}_{}_{}",
                        TEMPORARY_RECEIVER_BASE_PREFIX,
                        span.file.raw(),
                        span.start,
                        span.end
                    );
                    let write = ctx.write_node(&base, span);
                    emit_expression_scalar_to_node(flow, write, recv_meta, ctx);
                    ctx.commit_writer(&base, write);
                    receiver_storage_base = Some(base);
                } else {
                    receiver_storage_base = flow.place.as_ref().and_then(|place| {
                        // A bare implicit receiver is a callee-relative token,
                        // not the caller object's storage identity. Leave it
                        // unresolved so Phase 3 can map it through the
                        // declaration's adapter-provided receiver metadata.
                        (!receiver_name_matches(place, &ctx.out.receiver_names)).then(|| place.clone())
                    });
                }
            } else if let Some(recv) = receiver.filter(|recv| !recv.is_empty()) {
                // Adapter-specific calls without a file-level receiver fact
                // may still provide an already-normalized place. Treat it as
                // opaque compiler IR for the receiver edge, but leave the
                // storage base unset: Phase 3 must still map an implicit
                // `this`/`self` token onto the caller's declared object-state
                // base instead of freezing the token as literal storage.
                ctx.bridge_read(recv, recv_slot, recv_meta);
            }
        }
    }

    let mut arg_spans: SmallVec<[Span; 4]> = SmallVec::new();
    for arg in args {
        arg_spans.push(arg.span);
    }
    debug_assert_eq!(arg_spans.len(), arg_nodes.len());
    debug_assert_eq!(arg_places.len(), arg_nodes.len());
    debug_assert_eq!(arg_values.len(), arg_nodes.len());
    debug_assert_eq!(arg_writeback_targets.len(), arg_nodes.len());
    debug_assert_eq!(arg_names.len(), arg_nodes.len());
    apply_call_result_passthrough_edges(
        span,
        name,
        receiver_types,
        &arg_nodes,
        receiver_arg_node,
        ret_node,
        ctx,
    );
    ctx.out.call_sites.push(CallSiteRef {
        site,
        callee_name: name.to_string(),
        receiver: receiver.map(str::to_string),
        receiver_types: receiver_types.to_vec(),
        receiver_storage_base,
        call_kind,
        args_count: u32::try_from(arg_nodes.len()).unwrap_or(u32::MAX),
        explicit_args_count: u32::try_from(args.len()).unwrap_or(u32::MAX),
        call_ret_node: ret_node,
        call_arg_nodes: arg_nodes,
        receiver_arg_node,
        call_arg_spans: arg_spans,
        call_arg_places: arg_places,
        call_arg_values: arg_values,
        call_arg_writeback_targets: arg_writeback_targets,
        call_arg_names: arg_names,
        source_callback_args: source_callback_args_for_call(name, ctx),
        is_assign_rhs: false,
        unresolved_result_passthrough: ctx.options.include_unresolved_call_result_passthrough,
        unresolved_receiver_result_passthrough: (ctx.options.include_unresolved_call_result_passthrough
            || ctx.options.include_unresolved_receiver_result_passthrough)
            && matches!(call_kind, CallKind::Method)
            && receiver.is_some(),
    });
    apply_source_output_arg_writes(span, name, args, ctx);
    apply_output_arg_flow_call(span, name, args, ctx);
    apply_receiver_state_propagation_call(span, name, receiver, receiver_types, args, ctx);
    apply_clean_output_overwrite_call(span, name, args, ctx);
}

fn apply_call_result_passthrough_edges(
    span: Span,
    name: &str,
    receiver_types: &[String],
    arg_nodes: &[NodeId],
    receiver_arg_node: Option<NodeId>,
    ret_node: NodeId,
    ctx: &mut TransferCtx<'_>,
) {
    let selected: Vec<(Vec<usize>, bool)> = ctx
        .options
        .call_result_passthroughs
        .iter()
        .filter(|shape| configured_name_match(&shape.callee, name))
        .filter(|shape| {
            shape
                .receiver_type
                .as_deref()
                .is_none_or(|expected| receiver_name_matches(expected, receiver_types))
        })
        .map(|shape| (shape.input_arg_indices.clone(), shape.input_receiver))
        .collect();
    if selected.is_empty() {
        return;
    }
    let meta = crate::edge::EdgeMeta {
        precision: Precision::Narrowed,
        kind: IdgEdgeKind::IntraAssign,
        call_kind: bonsai_callgraph::EdgeKind::Unknown,
        via_span: span,
    };
    let mut emitted = ahash::AHashSet::default();
    for (indices, input_receiver) in selected {
        for index in indices {
            if let Some(node) = arg_nodes.get(index).copied() {
                if emitted.insert(node) {
                    ctx.emit(IdgEdge {
                        from: node,
                        to: ret_node,
                        meta,
                    });
                }
            }
        }
        if input_receiver {
            if let Some(node) = receiver_arg_node {
                if emitted.insert(node) {
                    ctx.emit(IdgEdge {
                        from: node,
                        to: ret_node,
                        meta,
                    });
                }
            }
        }
    }
}

fn apply_yield_callback_call(
    span: Span,
    name: &str,
    receiver: Option<&str>,
    args: &[CallArg],
    ctx: &mut TransferCtx<'_>,
) {
    if ctx.yield_callback_names.is_empty() || args.is_empty() {
        return;
    }
    let callback = receiver
        .map(str::trim)
        .filter(|recv| !recv.is_empty())
        .or_else(|| {
            let name = name.trim();
            is_bare_identifier(name).then_some(name)
        });
    let Some(callback) = callback else {
        return;
    };
    if !ctx.yield_callback_names.contains(callback) {
        return;
    }
    let yield_node = ctx.intern_node(Place::Yield);
    let meta = crate::edge::EdgeMeta {
        precision: Precision::Exact,
        kind: IdgEdgeKind::IntraYield,
        call_kind: bonsai_callgraph::EdgeKind::Direct,
        via_span: span,
    };
    for arg in args {
        bridge_call_arg_sources_to_node(arg, yield_node, meta, ctx);
    }
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

fn apply_output_arg_flow_call(span: Span, name: &str, args: &[CallArg], ctx: &mut TransferCtx<'_>) {
    let selected: Vec<(usize, Vec<usize>, Option<usize>)> = ctx
        .options
        .output_arg_flows
        .iter()
        .filter(|shape| configured_name_match(&shape.callee, name))
        .map(|shape| {
            (
                shape.output_arg_index,
                shape.value_arg_indices.clone(),
                shape.value_start_arg_index,
            )
        })
        .collect();
    for (output_arg_index, explicit_indices, value_start_arg_index) in selected {
        let Some(output) = args.get(output_arg_index).map(call_arg_place_name) else {
            continue;
        };
        let output = output.trim();
        if output.is_empty() || quoted_literal_text(output) {
            continue;
        }
        let (write_node, _) = build_target_node(output, span, ctx);
        let meta = crate::edge::EdgeMeta {
            precision: Precision::Narrowed,
            kind: IdgEdgeKind::IntraAssign,
            call_kind: bonsai_callgraph::EdgeKind::Unknown,
            via_span: span,
        };
        let mut value_indices: ahash::AHashSet<usize> = explicit_indices.into_iter().collect();
        if let Some(start) = value_start_arg_index {
            value_indices.extend(start..args.len());
        }
        value_indices.remove(&output_arg_index);
        let mut value_indices: Vec<usize> = value_indices.into_iter().collect();
        value_indices.sort_unstable();
        for index in value_indices {
            if let Some(arg) = args.get(index) {
                bridge_call_arg_sources_to_node(arg, write_node, meta, ctx);
            }
        }
        ctx.commit_writer(output, write_node);
    }
}

fn apply_receiver_state_propagation_call(
    span: Span,
    name: &str,
    receiver: Option<&str>,
    receiver_types: &[String],
    args: &[CallArg],
    ctx: &mut TransferCtx<'_>,
) {
    let Some(receiver) = receiver.map(str::trim).filter(|receiver| !receiver.is_empty()) else {
        return;
    };
    let matches = ctx.options.receiver_state_propagations.iter().any(|shape| {
        configured_name_match(&shape.method, name)
            && shape
                .receiver_type
                .as_deref()
                .is_none_or(|expected| receiver_name_matches(expected, receiver_types))
    });
    if !matches || args.is_empty() {
        return;
    }
    let (write_node, _) = build_target_node(receiver, span, ctx);
    let meta = crate::edge::EdgeMeta {
        precision: Precision::Narrowed,
        kind: IdgEdgeKind::IntraAssign,
        call_kind: bonsai_callgraph::EdgeKind::Unknown,
        via_span: span,
    };
    // Mutation extends receiver state; it does not replace the whole object
    // with the explicit arguments. Preserve the reaching receiver definition
    // so a later clean argument cannot erase an earlier tainted mutation.
    ctx.bridge_read(receiver, write_node, meta);
    for arg in args {
        bridge_call_arg_sources_to_node(arg, write_node, meta, ctx);
    }
    ctx.commit_writer(receiver, write_node);
}

fn source_callback_args_for_call(name: &str, ctx: &TransferCtx<'_>) -> Vec<SourceCallbackArgSpec> {
    ctx.options
        .source_callback_args
        .iter()
        .filter(|shape| configured_name_match(&shape.callee, name))
        .cloned()
        .collect()
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
        bridge_call_arg_sources_to_node(arg, write_node, meta, ctx);
    }
    ctx.commit_writer(output, write_node);
}

fn bridge_call_arg_sources_to_node(
    arg: &CallArg,
    node: NodeId,
    meta: crate::edge::EdgeMeta,
    ctx: &mut TransferCtx<'_>,
) {
    let source_filter = SemanticSourceFilter::from_sources(
        arg.place.as_deref(),
        &arg.source_names,
        &ctx.method_receiver_projections,
        None,
        &ctx.method_selector_fields,
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
}

fn bridge_projection_receiver_to_node(
    arg: &CallArg,
    node: NodeId,
    meta: crate::edge::EdgeMeta,
    emitted: &mut ahash::AHashSet<StrId>,
    ctx: &mut TransferCtx<'_>,
) {
    for receiver in projection_receiver_candidates(arg) {
        let method_projection =
            arg_has_method_projection_for_receiver(arg, &receiver, &ctx.method_receiver_projections);
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

fn arg_has_method_projection_for_receiver(
    arg: &CallArg,
    receiver: &str,
    method_receiver_projections: &ahash::AHashSet<String>,
) -> bool {
    method_receiver_projections.iter().any(|projection| {
        dotted_projection_receiver(projection).as_deref() == Some(receiver)
            && arg
                .place
                .as_deref()
                .into_iter()
                .chain(arg.source_names.iter().map(String::as_str))
                .any(|text| text.contains(projection))
    })
}

fn projection_receiver_candidates(arg: &CallArg) -> Vec<String> {
    let mut out = Vec::new();
    for text in arg
        .place
        .as_deref()
        .into_iter()
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
                || ch.is_alphanumeric())
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
            if let Some(precision) = thrown_type_catch_precision(throw.thrown_type, catch_ty) {
                ctx.emit(IdgEdge {
                    from: throw.throw_node,
                    to: catch_node,
                    meta: crate::edge::EdgeMeta {
                        precision,
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
                    bridge_call_arg_sources_to_node(
                        arg,
                        throw_node,
                        crate::edge::EdgeMeta {
                            precision: Precision::Exact,
                            kind: IdgEdgeKind::IntraThrow,
                            call_kind: bonsai_callgraph::EdgeKind::Direct,
                            via_span: throw_span,
                        },
                        ctx,
                    );
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

fn thrown_type_catch_precision(thrown_type: Option<TypeId>, catch_ty: TypeId) -> Option<Precision> {
    match thrown_type {
        Some(thrown) if thrown == catch_ty => Some(Precision::Exact),
        // Distinct syntax types are not assignable merely because both are
        // exception-shaped names. The workspace pass consults declared base
        // types and adds a precise subtype edge when the AST hierarchy proves
        // it. An untyped throw remains conservative.
        Some(_) => None,
        None => Some(Precision::Narrowed),
    }
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

/// Validate a canonical identifier carried by adapter-owned compiler facts.
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
